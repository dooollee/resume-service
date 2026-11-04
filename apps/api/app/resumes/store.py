"""이력서 저장소: 봉투 암호화를 여기서만 다룬다. 다른 모듈은 평문 모델(ResumeData)만 본다.

모든 쿼리는 요청 연결(RLS 컨텍스트 설정됨)로 실행되므로 DB가 2차로 권한을 강제한다.
"""

from app import crypto, normalize
from app.resumes.schemas import ResumeData

IDENTITY_FIELDS = ("name", "phone", "email", "birth", "gender", "address")


def _aad(rid, field: str) -> str:
    return f"resume:{rid}|{field}"


def bidx(field: str, value: str | None) -> bytes | None:
    """검색어와 저장값이 같은 정규화를 거쳐야 정확 일치가 성립한다."""
    norm = {"name": lambda v: crypto.normalize_name(v or ""), "phone": normalize.phone, "email": normalize.email}[field]
    return crypto.blind_index(f"resume_{field}", norm(value))


def create(conn, rid, uploaded_by, *, consent_at, consent_version, retention_until, sha256: bytes, mime: str) -> bytes:
    dek = crypto.new_dek()
    wrapped, version = crypto.wrap_dek(dek, f"resume:{rid}")
    conn.execute(
        "INSERT INTO resumes (id, uploaded_by, dek_wrapped, key_version, consent_at, consent_version, retention_until,"
        " source_sha256, source_mime) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (rid, uploaded_by, wrapped, version, consent_at, consent_version, retention_until, sha256, mime),
    )
    return dek


def load_dek(conn, rid) -> bytes | None:
    row = conn.execute("SELECT id, dek_wrapped, key_version FROM resumes WHERE id = %s", (rid,)).fetchone()
    return crypto.unwrap_dek(row["dek_wrapped"], row["key_version"], f"resume:{rid}") if row else None


def put_file(conn, rid, dek, kind: str, content: bytes, original_name: str | None = None) -> None:
    conn.execute(
        "INSERT INTO resume_files (resume_id, kind, ciphertext, original_name_enc, size) VALUES (%s, %s, %s, %s, %s)"
        " ON CONFLICT (resume_id, kind) DO UPDATE SET ciphertext = EXCLUDED.ciphertext,"
        " original_name_enc = EXCLUDED.original_name_enc, size = EXCLUDED.size",
        (
            rid,
            kind,
            crypto.encrypt(dek, _aad(rid, f"file.{kind}"), content),
            crypto.encrypt(dek, _aad(rid, f"file.{kind}.name"), original_name),
            len(content),
        ),
    )


def get_file(conn, rid, dek, kind: str) -> tuple[bytes, str | None] | None:
    row = conn.execute(
        "SELECT ciphertext, original_name_enc FROM resume_files WHERE resume_id = %s AND kind = %s", (rid, kind)
    ).fetchone()
    if not row:
        return None
    return (
        crypto.decrypt(dek, _aad(rid, f"file.{kind}"), row["ciphertext"]),
        crypto.decrypt_str(dek, _aad(rid, f"file.{kind}.name"), row["original_name_enc"]),
    )


def save(conn, rid, dek, data: ResumeData) -> None:
    """추출 결과/수정값 전체 교체. 전화·이메일은 저장 경계에서 항상 정규화(블라인드 인덱스 일치 보장)."""
    ident = data.identity.model_copy(
        update={
            "phone": normalize.phone(data.identity.phone) or data.identity.phone,
            "email": normalize.email(data.identity.email) or data.identity.email,
        }
    )
    enc = {f: crypto.encrypt(dek, _aad(rid, f), getattr(ident, f)) for f in IDENTITY_FIELDS}
    conn.execute(
        "INSERT INTO resume_identity (resume_id, name_enc, name_bidx, phone_enc, phone_bidx, email_enc, email_bidx,"
        " birth_enc, gender_enc, address_enc, intro_enc)"
        " VALUES (%(rid)s, %(name)s, %(name_b)s, %(phone)s, %(phone_b)s, %(email)s, %(email_b)s, %(birth)s, %(gender)s,"
        " %(address)s, %(intro)s)"
        " ON CONFLICT (resume_id) DO UPDATE SET name_enc = EXCLUDED.name_enc, name_bidx = EXCLUDED.name_bidx,"
        " phone_enc = EXCLUDED.phone_enc, phone_bidx = EXCLUDED.phone_bidx, email_enc = EXCLUDED.email_enc,"
        " email_bidx = EXCLUDED.email_bidx, birth_enc = EXCLUDED.birth_enc, gender_enc = EXCLUDED.gender_enc,"
        " address_enc = EXCLUDED.address_enc, intro_enc = EXCLUDED.intro_enc",
        {
            **enc,
            "rid": rid,
            "name_b": bidx("name", ident.name),
            "phone_b": bidx("phone", ident.phone),
            "email_b": bidx("email", ident.email),
            "intro": crypto.encrypt(dek, _aad(rid, "intro"), data.intro),
        },
    )
    for table in ("resume_education", "resume_career", "resume_skills", "resume_certs"):
        conn.execute(f"DELETE FROM {table} WHERE resume_id = %s", (rid,))  # noqa: S608 — 고정 테이블명
    for pos, e in enumerate(data.education):
        conn.execute(
            "INSERT INTO resume_education VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (rid, pos, e.school, e.major, e.degree, e.start_ym, e.end_ym),
        )
    for pos, c in enumerate(data.career):
        conn.execute(
            "INSERT INTO resume_career VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                rid,
                pos,
                c.company,
                c.title,
                c.start_ym,
                c.end_ym,
                crypto.encrypt(dek, _aad(rid, f"career.{pos}.description"), c.description),
            ),
        )
    seen = set()
    for s in data.skills:
        if s.name not in seen:
            seen.add(s.name)
            conn.execute("INSERT INTO resume_skills VALUES (%s, %s, %s, %s)", (rid, s.name, s.level, s.years))
    for pos, c in enumerate(data.certs):
        conn.execute(
            "INSERT INTO resume_certs VALUES (%s, %s, %s, %s, %s)", (rid, pos, c.name, c.issuer, c.acquired_ym)
        )
    conn.execute("UPDATE resumes SET updated_at = now() WHERE id = %s", (rid,))


def load_identity(conn, rid, dek: bytes) -> dict:
    row = conn.execute("SELECT * FROM resume_identity WHERE resume_id = %s", (rid,)).fetchone()
    return {f: crypto.decrypt_str(dek, _aad(rid, f), row[f"{f}_enc"]) for f in IDENTITY_FIELDS} if row else {}


def load(conn, rid, dek: bytes | None) -> ResumeData:
    """dek=None이면 식별정보·자유서술 없이 검색용 정보만 반환한다(viewer/마스킹 화면)."""
    q = lambda sql: conn.execute(sql, (rid,)).fetchall()  # noqa: E731
    ident, intro, descs = {}, None, {}
    if dek is not None:
        row = conn.execute("SELECT * FROM resume_identity WHERE resume_id = %s", (rid,)).fetchone()
        if row:
            ident = {f: crypto.decrypt_str(dek, _aad(rid, f), row[f"{f}_enc"]) for f in IDENTITY_FIELDS}
            intro = crypto.decrypt_str(dek, _aad(rid, "intro"), row["intro_enc"])
    careers = q("SELECT * FROM resume_career WHERE resume_id = %s ORDER BY pos")
    if dek is not None:
        descs = {
            c["pos"]: crypto.decrypt_str(dek, _aad(rid, f"career.{c['pos']}.description"), c["description_enc"])
            for c in careers
        }
    return ResumeData(
        identity=ident,
        intro=intro,
        education=q(
            "SELECT school, major, degree, start_ym, end_ym FROM resume_education WHERE resume_id = %s ORDER BY pos"
        ),
        career=[{**c, "description": descs.get(c["pos"])} for c in careers],
        skills=[
            {**s, "years": float(s["years"]) if s["years"] is not None else None}
            for s in q("SELECT name, level, years FROM resume_skills WHERE resume_id = %s ORDER BY name")
        ],
        certs=q("SELECT name, issuer, acquired_ym FROM resume_certs WHERE resume_id = %s ORDER BY pos"),
    )
