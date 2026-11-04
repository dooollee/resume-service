"""M2: 필드 암호화 저장 + RLS 2차 방어 + 키 로테이션. 합성 데이터만 사용."""

import psycopg
import pytest
from conftest import SAMPLE, admin_conn, ctx, make_resume, make_user

from app import cli, crypto
from app.db import pool
from app.resumes import store


def test_roundtrip_through_store():
    owner = make_user("recruiter")
    rid = make_resume(owner)
    with pool.connection() as conn:
        ctx(conn, owner)
        data = store.load(conn, rid, store.load_dek(conn, rid))
    assert data.identity.name == "김가상" and data.career[0].description == "합성 담당업무 설명"
    assert data.skills[0].name == "Python"


def db_dump() -> bytes:
    """슈퍼유저로 전체 테이블을 덤프(공격자가 DB 덤프를 가져갔다고 가정)."""
    with admin_conn() as c:
        tables = [r["tablename"] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")]
        dump = b""
        for t in tables:
            for row in c.execute(f'SELECT * FROM "{t}"'):  # noqa: S608 — 카탈로그에서 온 테이블명
                dump += repr(row).encode()
                dump += b"".join(bytes(v) for v in row.values() if isinstance(v, bytes | memoryview))
    return dump


PLAINTEXTS = [
    "김가상",
    "010-2222-3333",
    "01022223333",
    "kim.gasang",
    "1995-04-12",
    "가상구",
    "합성 자기소개",
    "합성 담당업무",
    "synthetic",
]


def test_db_dump_contains_no_plaintext_pii():
    make_resume(make_user("recruiter"))
    dump = db_dump()
    for s in PLAINTEXTS:
        assert s.encode() not in dump, s


def test_rls_recruiter_cannot_modify_others_resume():
    a, b = make_user("recruiter"), make_user("recruiter")
    rid = make_resume(a)
    with pool.connection() as conn:
        ctx(conn, b)
        assert conn.execute("SELECT count(*) AS n FROM resumes WHERE id = %s", (rid,)).fetchone()["n"] == 1
        assert conn.execute("UPDATE resumes SET status = 'FAILED' WHERE id = %s", (rid,)).rowcount == 0
        assert conn.execute("DELETE FROM resume_skills WHERE resume_id = %s", (rid,)).rowcount == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO resume_skills VALUES (%s, 'Evil', NULL, NULL)", (rid,))


def test_rls_cannot_insert_resume_as_someone_else():
    a, b = make_user("recruiter"), make_user("recruiter")
    with pool.connection() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        ctx(conn, b)
        store.create(
            conn,
            "33333333-3333-4333-8333-333333333333",
            a["id"],
            consent_at="2026-01-01",
            consent_version="v1",
            retention_until="2027-01-01",
            sha256=b"x",
            mime="application/pdf",
        )


def test_rls_viewer_never_reads_identity_or_files():
    owner, viewer = make_user("recruiter"), make_user("viewer")
    rid = make_resume(owner)
    with pool.connection() as conn:
        ctx(conn, viewer)
        assert conn.execute("SELECT count(*) AS n FROM resume_identity").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM resume_files").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM resume_skills WHERE resume_id = %s", (rid,)).fetchone()["n"] == 2


def test_rls_viewer_sees_only_confirmed():
    owner, viewer = make_user("recruiter"), make_user("viewer")
    make_resume(owner, status="REVIEW")
    with pool.connection() as conn:
        ctx(conn, viewer)
        assert conn.execute("SELECT count(*) AS n FROM resumes").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM resume_skills").fetchone()["n"] == 0


def test_rls_deleted_hidden_from_non_admin():
    owner, admin = make_user("recruiter"), make_user("admin")
    rid = make_resume(owner)
    with pool.connection() as conn:
        ctx(conn, make_user("recruiter"))  # 남의 이력서는 삭제 요청 불가
        assert conn.execute("SELECT request_resume_deletion(%s, '7 days') AS ok", (rid,)).fetchone()["ok"] is None
    with pool.connection() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        ctx(conn, owner)  # 직접 UPDATE로 숨기는 것은 RLS가 거부 → 함수 경유만 가능
        conn.execute("UPDATE resumes SET deleted_at = now() WHERE id = %s", (rid,))
    with pool.connection() as conn:
        ctx(conn, owner)
        assert conn.execute("SELECT request_resume_deletion(%s, '7 days') AS ok", (rid,)).fetchone()["ok"] is True
    with pool.connection() as conn:
        ctx(conn, owner)
        assert conn.execute("SELECT count(*) AS n FROM resume_identity").fetchone()["n"] == 0
        ctx(conn, admin)
        assert conn.execute("SELECT count(*) AS n FROM resumes").fetchone()["n"] == 1


@pytest.mark.parametrize("role", ["anonymous", ""])
def test_rls_no_context_sees_nothing(role):
    make_resume(make_user("recruiter"))
    with pool.connection() as conn:
        if role:
            ctx(conn, None, role)
        for t in ("resumes", "resume_identity", "resume_files", "resume_skills", "consents"):
            assert conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"] == 0, t  # noqa: S608


def test_only_system_can_hard_delete():
    owner, admin = make_user("recruiter"), make_user("admin")
    rid = make_resume(owner)
    with pool.connection() as conn:
        ctx(conn, admin)
        assert conn.execute("DELETE FROM resumes WHERE id = %s", (rid,)).rowcount == 0
        ctx(conn, None, "system")
        assert conn.execute("DELETE FROM resumes WHERE id = %s", (rid,)).rowcount == 1


def test_ciphertext_cannot_be_moved_between_resumes():
    owner = make_user("recruiter")
    a, b = make_resume(owner), make_resume(owner)
    with admin_conn() as c:  # DB 쓰기 권한을 가진 공격자가 다른 행의 암호문을 복사
        c.execute(
            "UPDATE resume_identity SET name_enc = (SELECT name_enc FROM resume_identity WHERE resume_id = %s)"
            " WHERE resume_id = %s",
            (a, b),
        )
    with pool.connection() as conn:
        ctx(conn, owner)
        with pytest.raises(Exception):  # noqa: B017 — InvalidTag
            store.load(conn, b, store.load_dek(conn, b))


def test_rotate_kek_rewraps_users_and_resumes(monkeypatch):
    owner = make_user("recruiter")
    monkeypatch.setattr(crypto, "KEK_CURRENT", 1)
    rid = make_resume(owner)
    monkeypatch.setattr(crypto, "KEK_CURRENT", 2)
    cli.cmd_rotate_kek(None)
    with admin_conn() as c:
        versions = {
            r["key_version"] for r in c.execute("SELECT key_version FROM resumes UNION SELECT key_version FROM users")
        }
    assert versions == {2}
    with pool.connection() as conn:
        ctx(conn, owner)
        assert store.load(conn, rid, store.load_dek(conn, rid)).identity.email == SAMPLE["identity"]["email"]


def test_blind_index_matches_across_formats():
    p = store.bidx
    assert p("phone", "010-2222-3333") == p("phone", "+82 10 2222 3333") == p("phone", "01022223333")
    assert p("email", "Kim.Gasang@Example.test") == p("email", "kim.gasang@example.test")
