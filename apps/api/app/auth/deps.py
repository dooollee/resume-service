import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request

from app import audit
from app.auth.security import hash_token
from app.core import config
from app.db import get_conn, set_rls_context

SESSION_COOKIE = "__Host-sid"
CSRF_COOKIE = "__Host-csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# 인증 없이 접근 가능한 경로. 추가할 때는 반드시 리뷰를 거친다(CLAUDE.md 규칙 5).
PUBLIC_PATHS = frozenset({"/health", "/auth/login"})
# 1차 인증(비밀번호)만 통과한 세션이 접근 가능한 경로
PRE_MFA_PATHS = frozenset({"/auth/mfa/enroll", "/auth/mfa/verify", "/auth/logout", "/auth/me"})
# 비밀번호 변경이 강제된 상태에서 접근 가능한 경로
PASSWORD_CHANGE_PATHS = frozenset({"/auth/password", "/auth/logout", "/auth/me"})


@dataclass(frozen=True)
class User:
    id: str
    role: str
    session_id: str
    mfa_ok: bool
    stepup_at: datetime | None


def require_auth(request: Request, conn=Depends(get_conn)) -> User | None:
    """전역 의존성: 기본 거부. 세션 + CSRF + MFA + 비밀번호 변경 강제 + RLS 컨텍스트."""
    path = request.url.path
    if path in PUBLIC_PATHS:
        set_rls_context(conn, None, "anonymous")
        return None
    token = request.cookies.get(SESSION_COOKIE)
    row = token and conn.execute(
        "SELECT s.id, s.user_id, s.mfa_ok, s.csrf_token, s.created_at, s.last_seen_at, s.stepup_at,"
        " u.role, u.disabled, u.must_change_password"
        " FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s",
        (hash_token(token),),
    ).fetchone()
    now = datetime.now(UTC)
    if (
        not row
        or row["disabled"]
        or now - row["last_seen_at"] > timedelta(minutes=config.SESSION_IDLE_MINUTES)
        or now - row["created_at"] > timedelta(hours=config.SESSION_ABSOLUTE_HOURS)
    ):
        raise HTTPException(401, "Not authenticated")
    if request.method not in SAFE_METHODS and not hmac.compare_digest(
        request.headers.get("x-csrf-token", ""), row["csrf_token"]
    ):
        raise HTTPException(403, "CSRF token mismatch")
    if not row["mfa_ok"] and path not in PRE_MFA_PATHS:
        raise HTTPException(401, "MFA required")
    if row["mfa_ok"] and row["must_change_password"] and path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(403, "Password change required")

    conn.execute("UPDATE sessions SET last_seen_at = now() WHERE id = %s", (row["id"],))
    user = User(str(row["user_id"]), row["role"], str(row["id"]), row["mfa_ok"], row["stepup_at"])
    request.state.user = user
    set_rls_context(conn, user.id, user.role if user.mfa_ok else "anonymous")
    return user


def current_user(request: Request) -> User:
    return request.state.user


def require_role(*roles: str):
    def dep(request: Request, user: User = Depends(require_auth)) -> User:
        if user.role not in roles:
            audit.record("authz.denied", request=request, detail={"path": request.url.path, "role": user.role})
            raise HTTPException(403, "Forbidden")
        return user

    return dep


def require_stepup(request: Request, user: User = Depends(require_role("admin"))) -> User:
    """관리자 기능: 최근 STEPUP_MINUTES 안에 비밀번호+TOTP 재인증을 요구한다."""
    if not user.stepup_at or datetime.now(UTC) - user.stepup_at > timedelta(minutes=config.STEPUP_MINUTES):
        raise HTTPException(403, "Step-up authentication required")
    return user
