import base64
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import audit, crypto
from app.auth import security
from app.auth.deps import CSRF_COOKIE, SESSION_COOKIE, User, require_auth
from app.core import config, ratelimit
from app.db import get_conn

router = APIRouter(prefix="/auth")
GENERIC_LOGIN_ERROR = "이메일 또는 비밀번호가 올바르지 않거나 계정을 사용할 수 없습니다"


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=security.PASSWORD_MAX)


class MfaIn(BaseModel):
    code: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, max_length=32)


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=security.PASSWORD_MAX)
    new_password: str = Field(max_length=security.PASSWORD_MAX)


class StepUpIn(BaseModel):
    password: str = Field(max_length=security.PASSWORD_MAX)
    code: str = Field(pattern=r"^\d{6}$")


def email_bidx(email: str) -> bytes:
    return crypto.blind_index("user_email", email.strip().lower())


def user_dek(row) -> bytes:
    return crypto.unwrap_dek(row["dek_wrapped"], row["key_version"], f"user:{row['id']}")


def _set_cookies(response: Response, token: str, csrf: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True, samesite="strict", path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=True, samesite="strict", path="/")


def _new_session(conn, user_id, request: Request, response: Response, mfa_ok: bool) -> None:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, mfa_ok, csrf_token, ip) VALUES (%s, %s, %s, %s, %s)",
        (security.hash_token(token), user_id, mfa_ok, csrf, audit.client_ip(request)),
    )
    _set_cookies(response, token, csrf)


def _rotate_session(conn, user: User, request: Request, response: Response, mfa_ok: bool) -> None:
    # 권한 상승 시점마다 세션 ID 교체(세션 고정 공격 방지)
    conn.execute("DELETE FROM sessions WHERE id = %s", (user.session_id,))
    _new_session(conn, user.id, request, response, mfa_ok)


def _register_failure(conn, user_id, request: Request, what: str) -> JSONResponse:
    row = conn.execute(
        "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = %s RETURNING failed_attempts", (user_id,)
    ).fetchone()
    if row["failed_attempts"] >= config.LOGIN_MAX_FAILURES:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = %s WHERE id = %s",
            (datetime.now(UTC) + timedelta(minutes=config.LOCKOUT_MINUTES), user_id),
        )
        audit.alert("account_locked", request=request, actor_id=user_id)
    audit.record(f"auth.{what}.fail", request=request, actor_id=user_id)
    # 예외 대신 응답을 반환해야 실패 횟수 갱신이 커밋된다.
    return JSONResponse(status_code=401, content={"detail": GENERIC_LOGIN_ERROR if what == "login" else "인증 실패"})


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, conn=Depends(get_conn)):
    ratelimit.limit(f"login:{audit.client_ip(request)}", 20, 300)
    u = conn.execute(
        "SELECT id, password_hash, locked_until, disabled, mfa_enabled FROM users WHERE email_bidx = %s",
        (email_bidx(body.email),),
    ).fetchone()
    locked = u and u["locked_until"] and u["locked_until"] > datetime.now(UTC)
    if not u or u["disabled"] or locked:
        security.verify_password(security.DUMMY_HASH, body.password)  # 응답 시간으로 계정 존재를 알 수 없게
        audit.record(
            "auth.login.fail",
            request=request,
            actor_id=u["id"] if u else None,
            detail={"reason": "unknown" if not u else "locked_or_disabled"},
        )
        return JSONResponse(status_code=401, content={"detail": GENERIC_LOGIN_ERROR})
    if not security.verify_password(u["password_hash"], body.password):
        return _register_failure(conn, u["id"], request, "login")
    if security.ph.check_needs_rehash(u["password_hash"]):
        conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (security.hash_password(body.password), u["id"])
        )
    conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s", (u["id"],))
    _new_session(conn, u["id"], request, response, mfa_ok=False)
    audit.record("auth.login.password_ok", request=request, actor_id=u["id"])
    return {"next": "mfa_verify" if u["mfa_enabled"] else "mfa_enroll"}


@router.post("/mfa/enroll")
def mfa_enroll(request: Request, user: User = Depends(require_auth), conn=Depends(get_conn)):
    u = conn.execute(
        "SELECT id, email_enc, dek_wrapped, key_version, mfa_enabled FROM users WHERE id = %s", (user.id,)
    ).fetchone()
    if u["mfa_enabled"]:
        raise HTTPException(409, "MFA already enabled")
    dek = user_dek(u)
    secret = security.new_totp_secret()
    conn.execute(
        "UPDATE users SET mfa_secret_enc = %s WHERE id = %s",
        (crypto.encrypt(dek, f"user:{u['id']}|mfa_secret", secret), u["id"]),
    )
    email = crypto.decrypt_str(dek, f"user:{u['id']}|email", u["email_enc"])
    audit.record("auth.mfa.enroll_start", request=request)
    return {"secret": base64.b32encode(secret).decode().rstrip("="), "otpauth_uri": security.otpauth_uri(secret, email)}


@router.post("/mfa/verify")
def mfa_verify(
    body: MfaIn, request: Request, response: Response, user: User = Depends(require_auth), conn=Depends(get_conn)
):
    ratelimit.limit(f"mfa:{user.id}", 5, 300)
    u = conn.execute("SELECT * FROM users WHERE id = %s", (user.id,)).fetchone()
    if not u["mfa_secret_enc"]:
        raise HTTPException(400, "MFA enrollment required")
    recovery_codes = None
    if body.code:
        secret = crypto.decrypt(user_dek(u), f"user:{u['id']}|mfa_secret", u["mfa_secret_enc"])
        step = security.verify_totp(secret, body.code, u["mfa_last_step"])
        if step is None:
            return _register_failure(conn, u["id"], request, "mfa")
        conn.execute("UPDATE users SET mfa_last_step = %s WHERE id = %s", (step, u["id"]))
        if not u["mfa_enabled"]:
            recovery_codes = security.new_recovery_codes()
            conn.execute(
                "UPDATE users SET mfa_enabled = true, recovery_codes = %s WHERE id = %s",
                ([security.hash_token(c) for c in recovery_codes], u["id"]),
            )
            audit.record("auth.mfa.enabled", request=request)
    elif body.recovery_code and u["mfa_enabled"]:
        h = security.hash_token(body.recovery_code.strip().lower())
        if h not in [bytes(c) for c in u["recovery_codes"]]:
            return _register_failure(conn, u["id"], request, "mfa")
        conn.execute("UPDATE users SET recovery_codes = array_remove(recovery_codes, %s) WHERE id = %s", (h, u["id"]))
        audit.record("auth.mfa.recovery_code_used", request=request)
    else:
        raise HTTPException(422, "code or recovery_code required")

    conn.execute("UPDATE users SET failed_attempts = 0, last_login_at = now() WHERE id = %s", (u["id"],))
    _rotate_session(conn, user, request, response, mfa_ok=True)
    audit.check_login_anomalies(conn, user.id, request)
    audit.record("auth.login.success", request=request)
    return {"recovery_codes": recovery_codes, "must_change_password": u["must_change_password"]}


@router.post("/password")
def change_password(
    body: PasswordIn, request: Request, response: Response, user: User = Depends(require_auth), conn=Depends(get_conn)
):
    ratelimit.limit(f"password:{user.id}", 5, 300)
    u = conn.execute("SELECT password_hash FROM users WHERE id = %s", (user.id,)).fetchone()
    if not security.verify_password(u["password_hash"], body.current_password):
        return _register_failure(conn, user.id, request, "password_change")
    if body.new_password == body.current_password:
        raise HTTPException(422, "새 비밀번호는 현재 비밀번호와 달라야 합니다")
    security.check_password_policy(body.new_password)
    conn.execute(
        "UPDATE users SET password_hash = %s, must_change_password = false WHERE id = %s",
        (security.hash_password(body.new_password), user.id),
    )
    conn.execute("DELETE FROM sessions WHERE user_id = %s AND id <> %s", (user.id, user.session_id))
    _rotate_session(conn, user, request, response, mfa_ok=True)
    audit.record("auth.password.changed", request=request)
    return {"ok": True}


@router.post("/step-up")
def step_up(body: StepUpIn, request: Request, user: User = Depends(require_auth), conn=Depends(get_conn)):
    ratelimit.limit(f"stepup:{user.id}", 5, 300)
    u = conn.execute("SELECT * FROM users WHERE id = %s", (user.id,)).fetchone()
    if not security.verify_password(u["password_hash"], body.password):
        return _register_failure(conn, user.id, request, "stepup")
    secret = crypto.decrypt(user_dek(u), f"user:{u['id']}|mfa_secret", u["mfa_secret_enc"])
    step = security.verify_totp(secret, body.code, u["mfa_last_step"])
    if step is None:
        return _register_failure(conn, user.id, request, "stepup")
    conn.execute("UPDATE users SET mfa_last_step = %s, failed_attempts = 0 WHERE id = %s", (step, user.id))
    conn.execute("UPDATE sessions SET stepup_at = now() WHERE id = %s", (user.session_id,))
    audit.record("auth.stepup", request=request)
    return {"valid_minutes": config.STEPUP_MINUTES}


@router.post("/logout")
def logout(request: Request, response: Response, user: User = Depends(require_auth), conn=Depends(get_conn)):
    conn.execute("DELETE FROM sessions WHERE id = %s", (user.session_id,))
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=True, samesite="strict")
    audit.record("auth.logout", request=request)
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(require_auth), conn=Depends(get_conn)):
    u = conn.execute("SELECT mfa_enabled, must_change_password FROM users WHERE id = %s", (user.id,)).fetchone()
    stepup = bool(user.stepup_at and datetime.now(UTC) - user.stepup_at < timedelta(minutes=config.STEPUP_MINUTES))
    return {
        "id": user.id,
        "role": user.role,
        "mfa_ok": user.mfa_ok,
        "mfa_enabled": u["mfa_enabled"],
        "must_change_password": u["must_change_password"],
        "stepup_valid": stepup,
    }
