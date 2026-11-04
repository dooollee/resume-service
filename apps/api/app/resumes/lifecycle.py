"""삭제 요청, 정보주체 요청(열람·정정·삭제) 처리, 동의 기록, 보존·파기 현황."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit, normalize, retention
from app.auth.deps import User, require_stepup
from app.db import get_conn
from app.resumes import store
from app.resumes.review import ReasonIn
from app.resumes.routes import get_owned, require_uploader

router = APIRouter()


@router.delete("/resumes/{rid}")
def request_deletion(rid: uuid.UUID, request: Request, user: User = Depends(require_uploader), conn=Depends(get_conn)):
    """즉시 비활성화(검색·조회 제외) → 유예기간 후 파기 배치가 영구 삭제."""
    get_owned(conn, rid, user)
    ok = conn.execute(
        "SELECT request_resume_deletion(%s, %s) AS ok", (rid, timedelta(days=retention.GRACE_DAYS))
    ).fetchone()
    if not ok["ok"]:
        raise HTTPException(404, "Not found")
    conn.execute("DELETE FROM reveal_grants WHERE resume_id = %s", (rid,))
    purge_after = datetime.now(UTC) + timedelta(days=retention.GRACE_DAYS)
    audit.record("resume.delete_request", request=request, resource_type="resume", resource_id=rid)
    return {"id": str(rid), "purge_after": purge_after}


@router.get("/resumes/{rid}/consent")
def consent(rid: uuid.UUID, user: User = Depends(require_uploader), conn=Depends(get_conn)):
    get_owned(conn, rid, user, allow_others=True)
    return conn.execute(
        "SELECT version, agreed_at, purpose, items, retention_months, recorded_at FROM consents WHERE resume_id = %s"
        " ORDER BY id",
        (rid,),
    ).fetchall()


@router.post("/resumes/{rid}/export")
def export_for_data_subject(
    rid: uuid.UUID, body: ReasonIn, request: Request, user: User = Depends(require_stepup), conn=Depends(get_conn)
):
    """정보주체 열람 요청 대응: 보유 중인 해당인 정보 전체(admin + 재인증 + 사유)."""
    row = get_owned(conn, rid, user)
    data = store.load(conn, rid, store.load_dek(conn, rid))
    consents = conn.execute(
        "SELECT version, agreed_at, purpose, items, retention_months FROM consents WHERE resume_id = %s", (rid,)
    ).fetchall()
    audit.record("resume.export", request=request, resource_type="resume", resource_id=rid, reason=body.reason)
    dump = data.model_dump()
    dump["identity"]["phone"] = normalize.phone_display(dump["identity"]["phone"])
    return {
        "resume_id": str(rid),
        "collected_at": row["created_at"],
        "retention_until": row["retention_until"],
        "data": dump,
        "consents": consents,
    }


@router.get("/admin/retention")
def retention_status(request: Request, user: User = Depends(require_stepup), conn=Depends(get_conn)):
    """보존·파기 현황(개인정보 없이 ID와 날짜만)."""
    counts = conn.execute(
        "SELECT count(*) FILTER (WHERE deleted_at IS NULL) AS active,"
        " count(*) FILTER (WHERE deleted_at IS NOT NULL) AS pending_deletion,"
        " count(*) FILTER (WHERE deleted_at IS NULL AND retention_until < now() + interval '30 days') AS expiring_30d"
        " FROM resumes"
    ).fetchone()
    pending = conn.execute(
        "SELECT id, deleted_at, purge_after FROM resumes WHERE deleted_at IS NOT NULL ORDER BY purge_after LIMIT 100"
    ).fetchall()
    expiring = conn.execute(
        "SELECT id, retention_until FROM resumes WHERE deleted_at IS NULL"
        " AND retention_until < now() + interval '30 days' ORDER BY retention_until LIMIT 100"
    ).fetchall()
    purged = conn.execute(
        "SELECT count(*) AS n FROM audit_logs WHERE action = 'resume.purge' AND ts > now() - interval '30 days'"
    ).fetchone()["n"]
    audit.record("admin.retention.view", request=request)
    return {
        **counts,
        "purged_30d": purged,
        "pending": pending,
        "expiring": expiring,
        "grace_days": retention.GRACE_DAYS,
    }
