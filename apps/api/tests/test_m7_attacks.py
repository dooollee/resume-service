"""M7: 모의 공격 시나리오 + 전체 업무 흐름에서의 수용 기준(§9) 종합 검증. 합성 데이터만."""

import logging

import pytest
import synthetic
from conftest import PASSWORD, admin_conn, login, make_user
from fastapi.testclient import TestClient
from test_m3_upload import upload

from app import audit, retention, scanner, worker
from app.core.middleware import SECURITY_HEADERS
from app.db import pool
from app.main import app


@pytest.fixture(autouse=True)
def _scanner(monkeypatch):
    monkeypatch.setattr(scanner, "scan", lambda data: False)


def _new(role):
    user = make_user(role)
    return login(TestClient(app, base_url="https://testserver", raise_server_exceptions=False), user), user


def test_full_workflow_logs_no_pii_headers_everywhere_and_chain_intact(caplog):
    t = synthetic.resume_truth(42)
    pii = [
        t["identity"]["name"],
        t["raw_phone"],
        t["identity"]["phone"],
        t["identity"]["email"],
        t["identity"]["address"],
        t["raw_birth"],
        t["intro"][:10],
        "900101-1234567",
    ]
    responses = []
    with caplog.at_level(logging.DEBUG):
        rec, _ = _new("recruiter")
        r = upload(rec, synthetic.make_docx(t, with_rrn=True), f"{t['identity']['name']}_이력서.docx")
        rid = r.json()["id"]
        responses.append(r)
        assert worker.run_once() == "review"
        data = rec.get(f"/resumes/{rid}/review").json()["data"]
        responses.append(rec.put(f"/resumes/{rid}", json={**data, "confirm": True}))
        responses.append(rec.post("/resumes/search", json={"name": t["identity"]["name"], "phone": t["raw_phone"]}))
        responses.append(rec.post(f"/resumes/{rid}/reveal", json={"reason": "면접 일정 안내"}))
        responses.append(rec.put(f"/resumes/{rid}", json={**data, "identity": {"phone": "invalid-phone"}}))  # 422
        responses.append(rec.get("/resumes/not-a-uuid"))  # 422
        viewer, _ = _new("viewer")
        responses.append(viewer.post(f"/resumes/{rid}/reveal", json={"reason": "권한 없는 시도"}))  # 403
        responses.append(rec.delete(f"/resumes/{rid}"))
        with admin_conn() as c:
            c.execute("UPDATE resumes SET purge_after = now() - interval '1 minute'")
        assert retention.purge() == 1

    raw = "\n".join(logging.Formatter("%(name)s %(message)s").format(r) for r in caplog.records)
    for value in pii:
        assert value not in raw, value  # 마스킹 '전' 원시 로그에도 없어야 한다(이름·주소는 정규식으로 못 잡음)
    for resp in responses:
        assert resp.headers.get("cache-control") == "no-store"
        for name, value in SECURITY_HEADERS:
            assert resp.headers[name.decode()] == value.decode()
        for value in pii[:2]:
            if resp.request.url.path != f"/resumes/{rid}/reveal":
                assert value not in resp.text
    with pool.connection() as c:
        assert audit.verify_chain(c) is None


@pytest.mark.parametrize(
    "payload",
    ["' OR 1=1 --", '"; DROP TABLE resumes; --', "%' UNION SELECT * FROM users --", "\\x00", "React') OR ('1'='1"],
)
def test_sql_injection_probes_are_inert(payload):
    c, _ = _new("recruiter")
    for body in ({"company": payload}, {"skills": [payload]}, {"name": payload}, {"title": payload}):
        r = c.post("/resumes/search", json=body)
        assert r.status_code in (200, 422), (body, r.status_code)
        if r.status_code == 200:
            assert r.json()["items"] == []
    with admin_conn() as a:
        assert a.execute("SELECT to_regclass('public.resumes') IS NOT NULL AS ok").fetchone()["ok"]


def test_content_type_confusion_csrf_on_login():
    # <form enctype="text/plain">로 JSON 모양 본문을 보내는 고전적 CSRF: Origin 검사와 JSON 파싱 둘 다에서 막힘
    c = TestClient(app, base_url="https://testserver")
    body = '{"email": "x@example.test", "password": "aaaaaaaaaaaa", "z": "="}'
    assert (
        c.post(
            "/auth/login", content=body, headers={"content-type": "text/plain", "origin": "https://evil.example.test"}
        ).status_code
        == 403
    )
    assert c.post("/auth/login", content=body, headers={"content-type": "text/plain"}).status_code == 422


def test_csrf_token_from_other_session_rejected():
    a, _ = _new("recruiter")
    b, _ = _new("recruiter")
    a.headers["x-csrf-token"] = b.cookies["__Host-csrf"]
    assert a.post("/auth/logout").status_code == 403


def test_forged_session_cookie_rejected():
    c = TestClient(app, base_url="https://testserver", cookies={"__Host-sid": "forged-token"})
    assert c.get("/auth/me").status_code == 401


@pytest.mark.parametrize("path", ["/resumes/../admin/users", "/resumes/%2e%2e%2fadmin", "/resumes/1;DROP"])
def test_path_tricks(path):
    c, _ = _new("viewer")
    assert c.get(path).status_code in (401, 403, 404, 422)


def test_role_escalation_via_body_ignored():
    c, user = _new("recruiter")
    c.post(
        "/auth/password", json={"current_password": PASSWORD, "new_password": "new-password-123456", "role": "admin"}
    )
    assert c.get("/auth/me").json()["role"] == "recruiter"
    assert c.get("/admin/users").status_code == 403


def test_stepup_does_not_carry_to_new_session():
    admin = make_user("admin")
    a = login(TestClient(app, base_url="https://testserver"), admin, stepup=True)
    assert a.get("/admin/users").status_code == 200
    b = login(TestClient(app, base_url="https://testserver"), admin)
    assert b.get("/admin/users").status_code == 403


def test_brute_force_mfa_is_rate_limited_and_locks():
    user = make_user("recruiter")
    c = TestClient(app, base_url="https://testserver")
    c.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    c.headers["x-csrf-token"] = c.cookies["__Host-csrf"]
    codes = [c.post("/auth/mfa/verify", json={"code": f"{i:06d}"}).status_code for i in range(7)]
    assert codes[:5] == [401] * 5 and 429 in codes[5:]
    fresh = TestClient(app, base_url="https://testserver")  # 5회 실패로 계정 잠김 → 올바른 비밀번호도 거부
    assert fresh.post("/auth/login", json={"email": user["email"], "password": PASSWORD}).status_code == 401
