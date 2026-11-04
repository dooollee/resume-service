"""검수(REVIEW)·수정·확정, 원본 다운로드."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app import audit, normalize, skills
from app.auth.deps import User
from app.core import config
from app.db import get_conn
from app.extraction.parse import RRN_RE
from app.extraction.validate import EXTENSIONS
from app.resumes import store
from app.resumes.routes import get_owned, require_uploader
from app.resumes.schemas import ResumeData

router = APIRouter(prefix="/resumes")
EDITABLE = ("REVIEW", "CONFIRMED")


class UpdateIn(ResumeData):
    confirm: bool = False


class ReasonIn(BaseModel):
    reason: str = Field(min_length=2, max_length=300)


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _normalized(data: ResumeData) -> ResumeData:
    if any(RRN_RE.search(s) for s in _strings(data.model_dump())):
        raise HTTPException(422, "주민등록번호는 저장할 수 없습니다")
    ident = data.identity
    phone = normalize.phone(ident.phone) if ident.phone else None
    email = normalize.email(ident.email) if ident.email else None
    if (ident.phone and not phone) or (ident.email and not email):
        raise HTTPException(422, "전화번호 또는 이메일 형식이 올바르지 않습니다")
    return data.model_copy(
        update={
            "identity": ident.model_copy(update={"phone": phone, "email": email}),
            "skills": [s.model_copy(update={"name": skills.canonical(s.name)}) for s in data.skills],
        }
    )


def _changed(old: ResumeData, new: ResumeData) -> list[str]:
    fields = [f"identity.{f}" for f in store.IDENTITY_FIELDS if getattr(old.identity, f) != getattr(new.identity, f)]
    return fields + [
        k for k in ("intro", "education", "career", "skills", "certs") if getattr(old, k) != getattr(new, k)
    ]


@router.get("/{rid}/review")
def get_review(rid: uuid.UUID, request: Request, user: User = Depends(require_uploader), conn=Depends(get_conn)):
    row = get_owned(conn, rid, user)
    if row["status"] not in EDITABLE:
        raise HTTPException(409, "검수할 수 있는 상태가 아닙니다")
    data = store.load(conn, rid, store.load_dek(conn, rid))
    has_photo = bool(
        conn.execute("SELECT 1 FROM resume_files WHERE resume_id = %s AND kind = 'photo'", (rid,)).fetchone()
    )
    audit.record("resume.review.view", request=request, resource_type="resume", resource_id=rid)
    return {"id": str(rid), "status": row["status"], "warnings": row["warnings"], "has_photo": has_photo, "data": data}


@router.put("/{rid}")
def update(
    rid: uuid.UUID, body: UpdateIn, request: Request, user: User = Depends(require_uploader), conn=Depends(get_conn)
):
    row = get_owned(conn, rid, user)
    if row["status"] not in EDITABLE:
        raise HTTPException(409, "수정할 수 있는 상태가 아닙니다")
    dek = store.load_dek(conn, rid)
    new = _normalized(ResumeData.model_validate(body.model_dump(exclude={"confirm"})))
    changed = _changed(store.load(conn, rid, dek), new)
    store.save(conn, rid, dek, new)
    if body.confirm and row["status"] == "REVIEW":
        conn.execute("UPDATE resumes SET status = 'CONFIRMED', confirmed_at = now() WHERE id = %s", (rid,))
    # 수정 이력: 바뀐 필드명·행위자·시각만 기록(값 자체는 감사 로그에 남기지 않음)
    audit.record(
        "resume.update",
        request=request,
        resource_type="resume",
        resource_id=rid,
        detail={"changed": changed, "confirm": body.confirm},
    )
    return {"id": str(rid), "status": "CONFIRMED" if body.confirm else row["status"], "changed": changed}


@router.post("/{rid}/source")
def download_source(
    rid: uuid.UUID, body: ReasonIn, request: Request, user: User = Depends(require_uploader), conn=Depends(get_conn)
):
    """원본은 admin(재인증 필요) 또는 검수 중인 업로더 본인만. 사유 필수, 파일명은 UUID로 대체."""
    row = get_owned(conn, rid, user)
    if user.role != "admin" and row["status"] != "REVIEW":
        raise HTTPException(404, "Not found")
    if user.role == "admin" and (
        not user.stepup_at or datetime.now(UTC) - user.stepup_at > timedelta(minutes=config.STEPUP_MINUTES)
    ):
        raise HTTPException(403, "Step-up authentication required")
    found = store.get_file(conn, rid, store.load_dek(conn, rid), "source")
    if not found:
        raise HTTPException(404, "Not found")
    audit.record("resume.source", request=request, resource_type="resume", resource_id=rid, reason=body.reason)
    filename = f"{rid}{EXTENSIONS[row['source_mime']]}"
    return Response(
        found[0], media_type=row["source_mime"], headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
