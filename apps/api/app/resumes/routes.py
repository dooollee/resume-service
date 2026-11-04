import uuid
from datetime import UTC, date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from app import audit, crypto
from app.auth.deps import User, require_role
from app.core import ratelimit
from app.db import get_conn
from app.extraction import validate
from app.resumes import store

router = APIRouter(prefix="/resumes")
require_uploader = require_role("admin", "recruiter")

KST = timezone(timedelta(hours=9))
IN_PROGRESS = ("UPLOADED", "SCANNING", "EXTRACTING")
MAX_CONCURRENT_UPLOADS = 3
CONSENT_ITEMS = {"신원", "연락처", "사진", "학력", "경력", "기술", "자격", "자기소개"}


def add_months(d: datetime, months: int) -> datetime:
    y, m = divmod(d.month - 1 + months, 12)
    return d.replace(year=d.year + y, month=m + 1, day=min(d.day, 28))


def get_owned(conn, rid, user: User, *, allow_others: bool = False):
    """객체 단위 권한(IDOR 방지). RLS가 2차로 다시 거른다. 없거나 권한 없음은 모두 404."""
    row = conn.execute("SELECT * FROM resumes WHERE id = %s", (rid,)).fetchone()
    if not row or (not allow_others and user.role != "admin" and str(row["uploaded_by"]) != user.id):
        raise HTTPException(404, "Not found")
    return row


@router.post("", status_code=202)
def upload(
    request: Request,
    file: UploadFile = File(...),
    consent_agreed: bool = Form(...),
    consent_version: str = Form(max_length=20, pattern=r"^[\w.\-]+$"),
    consent_purpose: str = Form(max_length=200),
    consent_items: str = Form(max_length=200),
    retention_months: int = Form(ge=1, le=60),
    agreed_on: date = Form(...),
    user: User = Depends(require_uploader),
    conn=Depends(get_conn),
):
    ratelimit.limit(f"upload:{user.id}", 30, 3600)
    items = {i.strip() for i in consent_items.split(",") if i.strip()}
    if not consent_agreed or not items or not items <= CONSENT_ITEMS:
        raise HTTPException(422, "개인정보 수집·이용 동의 정보가 올바르지 않습니다")
    if agreed_on > datetime.now(KST).date():
        raise HTTPException(422, "동의일이 미래일 수 없습니다")
    busy = conn.execute(
        "SELECT count(*) AS n FROM resumes WHERE uploaded_by = %s AND status = ANY(%s)", (user.id, list(IN_PROGRESS))
    ).fetchone()["n"]
    if busy >= MAX_CONCURRENT_UPLOADS:
        raise HTTPException(429, "처리 중인 업로드가 많습니다. 잠시 후 다시 시도하세요")

    content = file.file.read(validate.MAX_BYTES + 1)
    filename = (file.filename or "")[:255]
    try:
        mime = validate.sniff(content, filename)
    except validate.Rejected as e:
        audit.record("resume.upload.rejected", request=request, detail={"code": e.code})
        raise HTTPException(413 if e.code == "too_large" else 415, f"업로드할 수 없는 파일입니다 ({e.code})") from None

    rid = str(uuid.uuid4())
    consent_at = datetime.combine(agreed_on, datetime.min.time(), KST)
    retention_until = add_months(consent_at, retention_months)
    dek = store.create(
        conn,
        rid,
        user.id,
        consent_at=consent_at,
        consent_version=consent_version,
        retention_until=retention_until,
        sha256=crypto.sha256(content),
        mime=mime,
    )
    store.put_file(conn, rid, dek, "source", content, filename)
    conn.execute(
        "INSERT INTO consents (resume_id, version, agreed_at, purpose, items, retention_months, recorded_by)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (rid, consent_version, consent_at, consent_purpose, sorted(items), retention_months, user.id),
    )
    audit.record(
        "resume.upload",
        request=request,
        resource_type="resume",
        resource_id=rid,
        detail={"mime": mime, "size": len(content), "retention_months": retention_months},
    )
    return {"id": rid, "status": "UPLOADED", "retention_until": retention_until.astimezone(UTC).date()}


@router.get("/{rid}/status")
def status(rid: uuid.UUID, user: User = Depends(require_uploader), conn=Depends(get_conn)):
    row = get_owned(conn, rid, user)
    return {
        "id": str(row["id"]),
        "status": row["status"],
        "failure_code": row["failure_code"],
        "warnings": row["warnings"],
    }
