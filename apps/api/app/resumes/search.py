"""검색 · 상세(기본 마스킹) · 마스킹 해제(사유 필수) · 사진.

- 검색은 POST(JSON 본문): 이름·전화·이메일 검색어가 URL/브라우저 기록/프록시 로그에 남지 않게.
- 식별정보 검색은 블라인드 인덱스 정확 일치만(부분 검색 없음, OPEN_QUESTIONS #1).
- viewer: 식별정보 없음 + 회사명·학교명 일반화(재식별 방지). 자유서술·사진은 마스킹 해제 후에만.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from psycopg import sql
from pydantic import BaseModel, Field

from app import audit, normalize, skills
from app.auth.deps import User, require_auth, require_role
from app.core import ratelimit
from app.db import get_conn
from app.resumes import store

router = APIRouter(prefix="/resumes")
require_revealer = require_role("admin", "recruiter")

PAGE_MAX = 50
RESULT_CAP = 1000  # 한 검색으로 훑을 수 있는 최대 결과(대량 수집 억제)
REVEAL_MINUTES = 5


class SearchIn(BaseModel):
    skills: list[str] = Field(default=[], max_length=10)
    skill_mode: Literal["and", "or"] = "and"
    min_years: float | None = Field(default=None, ge=0, le=60)
    company: str | None = Field(default=None, max_length=100)
    title: str | None = Field(default=None, max_length=100)
    school: str | None = Field(default=None, max_length=100)
    major: str | None = Field(default=None, max_length=100)
    name: str | None = Field(default=None, max_length=50)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=254)
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=PAGE_MAX)


class RevealIn(BaseModel):
    reason: str = Field(min_length=5, max_length=300)


# --- 마스킹 ---


def mask_name(v: str | None) -> str | None:
    if not v:
        return v
    if len(v) <= 2:
        return v[0] + "*"
    return v[0] + "*" * (len(v) - 2) + v[-1]


def mask_phone(e164: str | None) -> str | None:
    if not e164:
        return e164
    national = "0" + e164[3:] if e164.startswith("+82") else e164
    return f"{national[:3]}-****-{national[-4:]}"


def mask_email(v: str | None) -> str | None:
    if not v or "@" not in v:
        return v
    local, domain = v.split("@", 1)
    return f"{local[:2]}***@{domain}"


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _summary(conn, rids: list, user: User, masked_identity: bool = True) -> dict:
    """검색 카드/상세 공통: 역할별로 허용된 필드만."""
    viewer = user.role == "viewer"
    out = {rid: {"id": str(rid), "skills": [], "career": [], "education": []} for rid in rids}
    for s in conn.execute(
        "SELECT * FROM resume_skills WHERE resume_id = ANY(%s) ORDER BY years DESC NULLS LAST", (rids,)
    ):
        out[s["resume_id"]]["skills"].append(
            {"name": s["name"], "level": s["level"], "years": float(s["years"]) if s["years"] is not None else None}
        )
    for c in conn.execute("SELECT * FROM resume_career WHERE resume_id = ANY(%s) ORDER BY pos", (rids,)):
        out[c["resume_id"]]["career"].append(
            {
                "company": None if viewer else c["company"],
                "title": c["title"],
                "start_ym": c["start_ym"],
                "end_ym": c["end_ym"],
            }
        )
    for e in conn.execute("SELECT * FROM resume_education WHERE resume_id = ANY(%s) ORDER BY pos", (rids,)):
        out[e["resume_id"]]["education"].append(
            {"school": None if viewer else e["school"], "major": e["major"], "degree": e["degree"]}
        )
    if not viewer and masked_identity:
        for rid in rids:
            ident = store.load_identity(conn, rid, store.load_dek(conn, rid))
            out[rid]["identity"] = {
                "name": mask_name(ident.get("name")),
                "phone": mask_phone(ident.get("phone")),
                "email": mask_email(ident.get("email")),
            }
    return out


@router.post("/search")
def search(body: SearchIn, request: Request, user: User = Depends(require_auth), conn=Depends(get_conn)):
    ratelimit.limit(f"search:{user.id}", 60, 60)
    identity_terms = {k: getattr(body, k) for k in ("name", "phone", "email") if getattr(body, k)}
    if identity_terms and user.role == "viewer":
        raise HTTPException(403, "신원 정보 검색 권한이 없습니다")
    if body.page * body.size > RESULT_CAP:
        raise HTTPException(422, f"최대 {RESULT_CAP}건까지만 조회할 수 있습니다. 조건을 좁혀주세요")

    where = [sql.SQL("r.status = 'CONFIRMED' AND r.deleted_at IS NULL")]
    params: list = []
    names = sorted({skills.canonical(s) for s in body.skills if s.strip()})
    if names:
        years = sql.SQL(" AND years >= %s") if body.min_years is not None else sql.SQL("")
        if body.skill_mode == "and":
            where.append(
                sql.SQL(
                    "r.id IN (SELECT resume_id FROM resume_skills WHERE name = ANY(%s){} "
                    "GROUP BY resume_id HAVING count(DISTINCT name) = %s)"
                ).format(years)
            )
            params += [names, *([body.min_years] if body.min_years is not None else []), len(names)]
        else:
            where.append(sql.SQL("r.id IN (SELECT resume_id FROM resume_skills WHERE name = ANY(%s){})").format(years))
            params += [names, *([body.min_years] if body.min_years is not None else [])]
    for field, table in (
        ("company", "resume_career"),
        ("title", "resume_career"),
        ("school", "resume_education"),
        ("major", "resume_education"),
    ):
        value = getattr(body, field)
        if value and value.strip():
            if user.role == "viewer" and field in ("company", "school"):
                raise HTTPException(403, "회사·학교명 검색 권한이 없습니다")
            where.append(
                sql.SQL("EXISTS (SELECT 1 FROM {} t WHERE t.resume_id = r.id AND t.{} ILIKE %s)").format(
                    sql.Identifier(table), sql.Identifier(field)
                )
            )
            params.append(_like(value.strip()))
    hashed = {}
    for field, value in identity_terms.items():
        b = store.bidx(field, value)
        if b is None:
            raise HTTPException(422, f"{field} 형식이 올바르지 않습니다")
        hashed[field] = b.hex()[:12]  # 감사 로그에는 검색어 대신 해시 일부만
        where.append(
            sql.SQL("EXISTS (SELECT 1 FROM resume_identity i WHERE i.resume_id = r.id AND i.{} = %s)").format(
                sql.Identifier(f"{field}_bidx")
            )
        )
        params.append(b)

    query = sql.SQL(
        "SELECT r.id, count(*) OVER () AS total FROM resumes r WHERE {} ORDER BY r.confirmed_at DESC LIMIT %s OFFSET %s"
    ).format(sql.SQL(" AND ").join(where))
    rows = conn.execute(query, [*params, body.size, (body.page - 1) * body.size]).fetchall()
    rids = [r["id"] for r in rows]
    summaries = _summary(conn, rids, user) if rids else {}
    total = rows[0]["total"] if rows else 0
    audit.record(
        "resume.search",
        request=request,
        detail={
            "skills": names,
            "skill_mode": body.skill_mode,
            "min_years": body.min_years,
            "filters": [f for f in ("company", "title", "school", "major") if getattr(body, f)],
            "identity_bidx": hashed,
            "page": body.page,
            "results": len(rids),
            "total": total,
        },
    )
    return {
        "total": min(total, RESULT_CAP),
        "page": body.page,
        "size": body.size,
        "items": [summaries[rid] for rid in rids],
    }


def _confirmed(conn, rid):
    row = conn.execute(
        "SELECT * FROM resumes WHERE id = %s AND status = 'CONFIRMED' AND deleted_at IS NULL", (rid,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    return row


@router.get("/{rid}")
def detail(rid: uuid.UUID, request: Request, user: User = Depends(require_auth), conn=Depends(get_conn)):
    _confirmed(conn, rid)
    item = _summary(conn, [rid], user)[rid]
    certs = conn.execute(
        "SELECT name, issuer, acquired_ym FROM resume_certs WHERE resume_id = %s ORDER BY pos", (rid,)
    ).fetchall()
    has_photo = user.role != "viewer" and bool(
        conn.execute("SELECT 1 FROM resume_files WHERE resume_id = %s AND kind = 'photo'", (rid,)).fetchone()
    )
    audit.record("resume.view", request=request, resource_type="resume", resource_id=rid)
    return {**item, "certs": certs, "has_photo": has_photo, "can_reveal": user.role != "viewer"}


@router.post("/{rid}/reveal")
def reveal(
    rid: uuid.UUID, body: RevealIn, request: Request, user: User = Depends(require_revealer), conn=Depends(get_conn)
):
    ratelimit.limit(f"reveal:{user.id}", 30, 3600)
    _confirmed(conn, rid)
    data = store.load(conn, rid, store.load_dek(conn, rid))
    expires = datetime.now(UTC) + timedelta(minutes=REVEAL_MINUTES)
    conn.execute(
        "INSERT INTO reveal_grants (session_id, resume_id, expires_at) VALUES (%s, %s, %s)"
        " ON CONFLICT (session_id, resume_id) DO UPDATE SET expires_at = EXCLUDED.expires_at",
        (user.session_id, rid, expires),
    )
    audit.record("resume.reveal", request=request, resource_type="resume", resource_id=rid, reason=body.reason)
    return {
        "expires_at": expires,
        "identity": {**data.identity.model_dump(), "phone": normalize.phone_display(data.identity.phone)},
        "intro": data.intro,
        "career_descriptions": [c.description for c in data.career],
    }


@router.get("/{rid}/photo")
def photo(rid: uuid.UUID, request: Request, user: User = Depends(require_revealer), conn=Depends(get_conn)):
    """사진: 이 세션에 유효한 마스킹 해제 허가가 있거나, 검수 중인 업로더 본인일 때만."""
    granted = conn.execute(
        "SELECT 1 FROM reveal_grants WHERE session_id = %s AND resume_id = %s AND expires_at > now()",
        (user.session_id, rid),
    ).fetchone()
    if not granted:
        row = conn.execute("SELECT status, uploaded_by FROM resumes WHERE id = %s", (rid,)).fetchone()
        reviewing = row and row["status"] == "REVIEW" and (user.role == "admin" or str(row["uploaded_by"]) == user.id)
        if not reviewing:
            raise HTTPException(403, "마스킹 해제(열람 사유 입력) 후 볼 수 있습니다")
    found = store.get_file(conn, rid, store.load_dek(conn, rid), "photo")
    if not found:
        raise HTTPException(404, "Not found")
    audit.record("resume.photo", request=request, resource_type="resume", resource_id=rid)
    return Response(found[0], media_type="image/jpeg", headers={"Content-Disposition": "inline"})
