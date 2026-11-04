"""테스트는 실제 PostgreSQL에서 돈다(RLS·권한·트리거 검증 때문).

- CI: TEST_ADMIN_DATABASE_URL (Postgres 서비스 컨테이너의 슈퍼유저)
- 로컬: 미설정 시 pgserver(개발 전용 의존성)로 임시 Postgres를 띄운다.
값은 모두 합성 데이터 / 테스트 전용 난수 키.
"""

import base64
import os
import tempfile
import time
import uuid

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

_k = lambda: base64.b64encode(os.urandom(32)).decode()  # noqa: E731
os.environ.update(
    APP_ENV="production",
    WEB_ORIGINS="https://web.example.test",
    KEK_KEYS=f"1:{_k()},2:{_k()}",
    KEK_CURRENT="2",
    BIDX_KEY=_k(),
    HIBP_ENABLED="false",
)

_server_url = os.environ.get("TEST_ADMIN_DATABASE_URL")
if not _server_url:
    import logging

    import pgserver

    logging.getLogger("pgserver").disabled = True  # 종료 시 닫힌 스트림에 쓰는 잡음 제거

    _srv = pgserver.get_server(os.path.join(tempfile.gettempdir(), "resume_service_pgtest"), cleanup_mode="stop")
    _server_url = _srv.get_uri()

DB_NAME = f"rs_test_{uuid.uuid4().hex[:8]}"
with psycopg.connect(_server_url, autocommit=True) as _c:
    _c.execute(f'CREATE DATABASE "{DB_NAME}"')
ADMIN_URL = make_conninfo(_server_url, dbname=DB_NAME)
APP_PASSWORD = "test-only-app-password"  # noqa: S105 — 테스트 DB 전용

from app.migrate import bootstrap, migrate  # noqa: E402

bootstrap(ADMIN_URL, APP_PASSWORD)
migrate(ADMIN_URL)
os.environ["DATABASE_URL"] = make_conninfo(ADMIN_URL, user="resume_app", password=APP_PASSWORD)

from fastapi.testclient import TestClient  # noqa: E402

from app.auth import security  # noqa: E402
from app.core import ratelimit  # noqa: E402
from app.db import pool  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "correct-horse-battery-staple"  # noqa: S105 — 합성 테스트 비밀번호


def admin_conn():
    """슈퍼유저 연결(테스트 준비/검증 전용, RLS 우회)."""
    return psycopg.connect(ADMIN_URL, autocommit=True, row_factory=psycopg.rows.dict_row)


@pytest.fixture(scope="session", autouse=True)
def _pool():
    pool.open(wait=True)
    yield
    pool.close()
    with psycopg.connect(_server_url, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{DB_NAME}" WITH (FORCE)')


@pytest.fixture(autouse=True)
def _clean():
    ratelimit.reset()
    with admin_conn() as c:
        c.execute("SET session_replication_role = replica")  # append-only 트리거 우회(테스트 정리용)
        tables = [
            r["tablename"]
            for r in c.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'schema_migrations'"
            )
        ]
        c.execute("TRUNCATE " + ", ".join(f'"{t}"' for t in tables) + " CASCADE")
    yield


@pytest.fixture
def client():
    return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)


def make_user(role="recruiter", *, mfa=True, must_change=False, email=None):
    from app import crypto
    from app.admin import create_user
    from app.auth.routes import user_dek

    email = email or f"{role}-{uuid.uuid4().hex[:6]}@example.test"
    with pool.connection() as conn:
        user_id = create_user(conn, email, role, PASSWORD)
        secret = security.new_totp_secret()
        if mfa:
            u = conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()
            conn.execute(
                "UPDATE users SET mfa_secret_enc = %s, mfa_enabled = true WHERE id = %s",
                (crypto.encrypt(user_dek(u), f"user:{user_id}|mfa_secret", secret), user_id),
            )
        conn.execute("UPDATE users SET must_change_password = %s WHERE id = %s", (must_change, user_id))
    return {"id": user_id, "email": email, "secret": secret, "role": role}


def next_code(user) -> str:
    """재사용 방지를 통과하는, 아직 안 쓴 가장 이른 TOTP step의 코드."""
    with admin_conn() as c:
        last = c.execute("SELECT mfa_last_step FROM users WHERE id = %s", (user["id"],)).fetchone()["mfa_last_step"]
    now = int(time.time()) // security.TOTP_STEP
    candidates = [s for s in (now - 1, now, now + 1) if s > last]
    if not candidates:
        time.sleep(security.TOTP_STEP)
        return next_code(user)
    return security.totp_at(user["secret"], candidates[0])


def login(client, user, *, stepup=False):
    r = client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    r = client.post("/auth/mfa/verify", json={"code": next_code(user)})
    assert r.status_code == 200, r.text
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    if stepup:
        r = client.post("/auth/step-up", json={"password": PASSWORD, "code": next_code(user)})
        assert r.status_code == 200, r.text
    return client


def audit_actions():
    with admin_conn() as c:
        return [r["action"] for r in c.execute("SELECT action FROM audit_logs ORDER BY id")]


def ctx(conn, user, role=None):
    from app.db import set_rls_context

    set_rls_context(conn, user["id"] if user else None, role or user["role"])
    return conn


SAMPLE = {
    "identity": {
        "name": "김가상",
        "phone": "010-2222-3333",
        "email": "kim.gasang@example.test",
        "birth": "1995-04-12",
        "gender": "여",
        "address": "서울특별시 가상구 테스트로 1",
    },
    "intro": "합성 자기소개 문장입니다.",
    "education": [
        {"school": "가상대학교", "major": "컴퓨터공학", "degree": "학사", "start_ym": "2014-03", "end_ym": "2018-02"}
    ],
    "career": [
        {
            "company": "예시주식회사",
            "title": "백엔드 개발자",
            "start_ym": "2018-03",
            "end_ym": "2022-12",
            "description": "합성 담당업무 설명",
        }
    ],
    "skills": [{"name": "Python", "level": "고급", "years": 5}, {"name": "React", "level": "중급", "years": 2}],
    "certs": [{"name": "정보처리기사", "issuer": "한국산업인력공단", "acquired_ym": "2017-11"}],
}


def make_resume(owner, data=None, status="CONFIRMED"):
    """RLS를 거쳐(소유자 컨텍스트로) 합성 이력서를 만든다."""
    from datetime import UTC, datetime, timedelta

    from app import crypto
    from app.resumes import store
    from app.resumes.schemas import ResumeData

    rid = str(uuid.uuid4())
    with pool.connection() as conn:
        ctx(conn, owner)
        dek = store.create(
            conn,
            rid,
            owner["id"],
            consent_at=datetime.now(UTC),
            consent_version="v1",
            retention_until=datetime.now(UTC) + timedelta(days=365),
            sha256=crypto.sha256(rid.encode()),
            mime="application/pdf",
        )
        store.save(conn, rid, dek, ResumeData.model_validate(data or SAMPLE))
        store.put_file(conn, rid, dek, "source", b"%PDF-1.7 synthetic", "synthetic.pdf")
        conn.execute("UPDATE resumes SET status = %s WHERE id = %s", (status, rid))
    return rid
