import re
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app import audit, crypto
from app.auth import security
from app.auth.deps import require_stepup
from app.auth.routes import email_bidx, user_dek
from app.db import get_conn

# 모든 관리자 기능: admin 역할 + 최근 재인증(step-up)
router = APIRouter(dependencies=[Depends(require_stepup)])

Role = Literal["admin", "recruiter", "viewer"]
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


class UserCreate(BaseModel):
    email: str = Field(max_length=254)
    role: Role
    password: str = Field(max_length=security.PASSWORD_MAX)


class UserPatch(BaseModel):
    role: Role | None = None
    disabled: bool | None = None
    unlock: bool = False
    reset_mfa: bool = False
    password: str | None = Field(default=None, max_length=security.PASSWORD_MAX)


def create_user(conn, email: str, role: str, password: str) -> str:
    """관리자 API와 CLI(create-admin)가 공유. 초기 비밀번호는 첫 로그인 때 변경 강제."""
    email = email.strip().lower()
    if not email.isascii() or not EMAIL_RE.match(email):  # 한글 입력 모드 오타(ㅁadmin@…) 방지
        raise HTTPException(422, "이메일 형식이 올바르지 않습니다")
    security.check_password_policy(password)
    if conn.execute("SELECT 1 FROM users WHERE email_bidx = %s", (email_bidx(email),)).fetchone():
        raise HTTPException(409, "이미 등록된 사용자입니다")
    user_id = str(uuid.uuid4())
    dek = crypto.new_dek()
    wrapped, version = crypto.wrap_dek(dek, f"user:{user_id}")
    conn.execute(
        "INSERT INTO users (id, email_bidx, email_enc, dek_wrapped, key_version, password_hash, role)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            user_id,
            email_bidx(email),
            crypto.encrypt(dek, f"user:{user_id}|email", email),
            wrapped,
            version,
            security.hash_password(password),
            role,
        ),
    )
    return user_id


@router.get("/admin/users")
def list_users(request: Request, conn=Depends(get_conn)):
    rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    audit.record("admin.user.list", request=request)
    return [
        {
            "id": str(r["id"]),
            "email": crypto.decrypt_str(user_dek(r), f"user:{r['id']}|email", r["email_enc"]),
            "role": r["role"],
            "mfa_enabled": r["mfa_enabled"],
            "disabled": r["disabled"],
            "locked": bool(r["locked_until"] and r["locked_until"] > datetime.now(r["locked_until"].tzinfo)),
            "created_at": r["created_at"],
            "last_login_at": r["last_login_at"],
        }
        for r in rows
    ]


@router.post("/admin/users", status_code=201)
def add_user(body: UserCreate, request: Request, conn=Depends(get_conn)):
    user_id = create_user(conn, body.email, body.role, body.password)
    audit.record(
        "admin.user.create", request=request, resource_type="user", resource_id=user_id, detail={"role": body.role}
    )
    return {"id": user_id}


@router.patch("/admin/users/{user_id}")
def update_user(user_id: uuid.UUID, body: UserPatch, request: Request, conn=Depends(get_conn)):
    target = conn.execute("SELECT id, role, disabled FROM users WHERE id = %s FOR UPDATE", (user_id,)).fetchone()
    if not target:
        raise HTTPException(404, "Not found")
    demoting = target["role"] == "admin" and ((body.role and body.role != "admin") or body.disabled)
    if demoting:
        others = conn.execute(
            "SELECT count(*) AS n FROM users WHERE role = 'admin' AND NOT disabled AND id <> %s", (user_id,)
        ).fetchone()["n"]
        if others == 0:
            raise HTTPException(409, "마지막 관리자는 강등하거나 비활성화할 수 없습니다")

    changed = []
    if body.role and body.role != target["role"]:
        conn.execute("UPDATE users SET role = %s WHERE id = %s", (body.role, user_id))
        changed.append("role")
    if body.disabled is not None and body.disabled != target["disabled"]:
        conn.execute("UPDATE users SET disabled = %s WHERE id = %s", (body.disabled, user_id))
        changed.append("disabled")
    if body.unlock:
        conn.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = %s", (user_id,))
        changed.append("unlock")
    if body.reset_mfa:
        conn.execute(
            "UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, recovery_codes = '{}' WHERE id = %s",
            (user_id,),
        )
        changed.append("reset_mfa")
    if body.password:
        security.check_password_policy(body.password)
        conn.execute(
            "UPDATE users SET password_hash = %s, must_change_password = true WHERE id = %s",
            (security.hash_password(body.password), user_id),
        )
        changed.append("password")
    if set(changed) - {"unlock"}:
        conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))  # 권한 변경 즉시 반영
    audit.record(
        "admin.user.update",
        request=request,
        resource_type="user",
        resource_id=user_id,
        detail={"changed": changed, "role": body.role},
    )
    return {"changed": changed}


@router.get("/audit-logs")
def list_audit_logs(
    request: Request,
    action: str | None = Query(default=None, max_length=64),
    actor_id: uuid.UUID | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=100),
    conn=Depends(get_conn),
):
    rows = conn.execute(
        "SELECT id, ts, actor_id, action, resource_type, resource_id, ip, user_agent, reason, detail"
        " FROM audit_logs WHERE (%(action)s::text IS NULL OR action LIKE %(action)s || '%%')"
        " AND (%(actor)s::uuid IS NULL OR actor_id = %(actor)s)"
        " ORDER BY id DESC LIMIT %(size)s OFFSET %(offset)s",
        {"action": action, "actor": actor_id, "size": size, "offset": (page - 1) * size},
    ).fetchall()
    audit.record("audit.view", request=request, detail={"action": action, "page": page})
    return rows


@router.get("/audit-logs/verify")
def verify_audit_chain(request: Request, conn=Depends(get_conn)):
    broken = audit.verify_chain(conn)
    audit.record("audit.verify", request=request, detail={"ok": broken is None})
    if broken is not None:
        audit.alert("audit_chain_broken", request=request, detail={"broken_id": broken})
    return {"ok": broken is None, "broken_id": broken}
