"""M1: 인증(argon2id·TOTP), 세션, RBAC, 감사 로그 해시 체인. 합성 데이터만 사용."""

import io
import re
import uuid

import psycopg
import pytest
from conftest import PASSWORD, admin_conn, audit_actions, login, make_user, next_code
from fastapi.testclient import TestClient

from app import audit
from app.auth import security
from app.db import pool
from app.main import api, app

# --- 기본 요소 ---


def test_totp_rfc6238_vector():
    # RFC 6238 부록 B: T=59s, 8자리 94287082 → 6자리 287082
    assert security.totp_at(b"12345678901234567890", 59 // 30) == "287082"


def test_password_hash_is_argon2id():
    assert security.hash_password("x" * 12).startswith("$argon2id$")


def test_hibp_parsing(monkeypatch):
    import hashlib

    suffix = hashlib.sha1(b"hunter2hunter2").hexdigest().upper()[5:]  # noqa: S324

    def fake_urlopen(req, timeout):
        assert req.full_url.endswith(hashlib.sha1(b"hunter2hunter2").hexdigest().upper()[:5])  # noqa: S324
        return io.BytesIO(f"{suffix}:3\r\nABCDEF:0".encode())

    monkeypatch.setattr(security.urllib.request, "urlopen", fake_urlopen)
    assert security.is_pwned("hunter2hunter2")
    monkeypatch.setattr(security.urllib.request, "urlopen", lambda req, timeout: io.BytesIO(f"{suffix}:0".encode()))
    assert not security.is_pwned("hunter2hunter2")  # 패딩(count 0)은 무시


def test_hibp_fail_closed(monkeypatch):
    monkeypatch.setattr(security.config, "HIBP_ENABLED", True)

    def down(*a, **k):
        raise OSError("offline")

    monkeypatch.setattr(security.urllib.request, "urlopen", down)
    with pytest.raises(Exception) as e:
        security.check_password_policy("a-long-enough-password")
    assert e.value.status_code == 503


# --- 로그인 · MFA ---


def test_full_login_flow_and_session_rotation(client):
    user = make_user("recruiter")
    r = client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.json() == {"next": "mfa_verify"}
    pre_mfa = client.cookies["__Host-sid"]
    set_cookie = r.headers.get_list("set-cookie")
    sid_cookie = next(c for c in set_cookie if c.startswith("__Host-sid="))
    assert all(flag in sid_cookie.lower() for flag in ("httponly", "secure", "samesite=strict", "path=/"))

    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    assert client.get("/admin/users").status_code == 401  # MFA 전에는 아무것도 안 됨
    assert client.post("/auth/mfa/verify", json={"code": next_code(user)}).status_code == 200
    assert client.cookies["__Host-sid"] != pre_mfa  # 세션 교체
    stale = TestClient(app, base_url="https://testserver", cookies={"__Host-sid": pre_mfa})
    assert stale.get("/auth/me").status_code == 401
    assert client.get("/auth/me").json()["mfa_ok"] is True
    assert "auth.login.success" in audit_actions()


def test_wrong_password_and_unknown_account_look_identical(client):
    make_user(email="exists@example.test")
    a = client.post("/auth/login", json={"email": "exists@example.test", "password": "wrong-password-123"})
    b = client.post("/auth/login", json={"email": "nobody@example.test", "password": "wrong-password-123"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_lockout_after_5_failures(client):
    user = make_user()
    for _ in range(5):
        client.post("/auth/login", json={"email": user["email"], "password": "wrong-password-123"})
    r = client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.status_code == 401
    assert "alert.account_locked" in audit_actions()


def test_login_rate_limited_per_ip(client):
    codes = [client.post("/auth/login", json={"email": "x@example.test", "password": "y" * 12}).status_code
             for _ in range(21)]
    assert codes[-1] == 429


def test_totp_code_cannot_be_reused(client):
    user = make_user()
    client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    code = next_code(user)
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 200
    other = TestClient(app, base_url="https://testserver")
    other.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    other.headers["x-csrf-token"] = other.cookies["__Host-csrf"]
    assert other.post("/auth/mfa/verify", json={"code": code}).status_code == 401


def test_enrollment_recovery_codes_and_forced_password_change(client):
    user = make_user("admin", mfa=False, must_change=True)
    r = client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.json() == {"next": "mfa_enroll"}
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    enroll = client.post("/auth/mfa/enroll").json()
    assert enroll["otpauth_uri"].startswith("otpauth://totp/")
    import base64

    user["secret"] = base64.b32decode(enroll["secret"] + "=" * (-len(enroll["secret"]) % 8))
    r = client.post("/auth/mfa/verify", json={"code": next_code(user)})
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10 and r.json()["must_change_password"] is True
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    assert client.post("/auth/mfa/enroll").status_code == 403  # 비밀번호 변경 전엔 차단

    new_pw = "a-brand-new-password-42"
    r = client.post("/auth/password", json={"current_password": PASSWORD, "new_password": new_pw})
    assert r.status_code == 200
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    assert client.get("/auth/me").json()["must_change_password"] is False

    with admin_conn() as c:  # 복구 코드는 해시로만 저장
        stored = c.execute("SELECT recovery_codes FROM users WHERE id = %s", (user["id"],)).fetchone()
    assert all(code.encode() not in bytes(h) for h in stored["recovery_codes"] for code in codes)

    def recover(code):
        c = TestClient(app, base_url="https://testserver")
        c.post("/auth/login", json={"email": user["email"], "password": new_pw})
        c.headers["x-csrf-token"] = c.cookies["__Host-csrf"]
        return c.post("/auth/mfa/verify", json={"recovery_code": code}).status_code

    assert recover(codes[0]) == 200
    assert recover(codes[0]) == 401  # 1회용


def test_csrf_required_for_state_changes(client):
    login(client, make_user())
    del client.headers["x-csrf-token"]
    assert client.post("/auth/logout").status_code == 403


def test_idle_timeout(client):
    login(client, make_user())
    with admin_conn() as c:
        c.execute("UPDATE sessions SET last_seen_at = now() - interval '31 minutes'")
    assert client.get("/auth/me").status_code == 401


def test_logout_invalidates_session(client):
    login(client, make_user())
    sid = client.cookies["__Host-sid"]
    assert client.post("/auth/logout").status_code == 200
    assert TestClient(app, base_url="https://testserver", cookies={"__Host-sid": sid}).get("/auth/me").status_code == 401


def test_password_policy_min_length(client):
    login(client, make_user())
    r = client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "short"})
    assert r.status_code == 422


# --- 모든 엔드포인트: 인증·MFA 없이 접근 불가 (새 라우트가 생겨도 자동 검사) ---

PUBLIC = {"/health", "/auth/login"}
PRE_MFA = {"/auth/mfa/enroll", "/auth/mfa/verify", "/auth/logout", "/auth/me"}


def _all_routes():
    for route in api.routes:
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            if route.path.startswith("/_test") or route.path in PUBLIC:
                continue
            yield method, re.sub(r"\{[^}]+\}", str(uuid.uuid4()), route.path)


def test_every_route_requires_auth(client):
    for method, path in _all_routes():
        assert client.request(method, path).status_code == 401, (method, path)


def test_every_route_requires_mfa(client):
    user = make_user()
    client.post("/auth/login", json={"email": user["email"], "password": PASSWORD})
    client.headers["x-csrf-token"] = client.cookies["__Host-csrf"]
    for method, path in _all_routes():
        if path not in PRE_MFA:
            assert client.request(method, path).status_code == 401, (method, path)


# --- RBAC · 재인증 ---


@pytest.mark.parametrize("role", ["recruiter", "viewer"])
def test_non_admin_cannot_use_admin_api(client, role):
    login(client, make_user(role))
    for method, path in [("GET", "/admin/users"), ("GET", "/audit-logs"), ("POST", "/admin/users")]:
        assert client.request(method, path, json={}).status_code == 403
    assert "authz.denied" in audit_actions()


def test_admin_requires_stepup(client):
    admin = make_user("admin")
    login(client, admin)
    assert client.get("/admin/users").status_code == 403
    assert client.post("/auth/step-up", json={"password": PASSWORD, "code": next_code(admin)}).status_code == 200
    assert client.get("/admin/users").status_code == 200


@pytest.fixture
def admin_client(client):
    user = make_user("admin")
    return login(client, user, stepup=True), user


def test_admin_user_management(admin_client):
    client, admin = admin_client
    r = client.post("/admin/users", json={"email": "New.Recruiter@Example.test", "role": "recruiter",
                                          "password": "initial-password-123"})
    assert r.status_code == 201
    new_id = r.json()["id"]
    users = client.get("/admin/users").json()
    assert any(u["email"] == "new.recruiter@example.test" for u in users)
    assert client.post("/admin/users", json={"email": "new.recruiter@example.test", "role": "viewer",
                                             "password": "initial-password-123"}).status_code == 409
    # 비활성화하면 세션도 즉시 폐기
    target = login(TestClient(app, base_url="https://testserver"), make_user("viewer"))
    target_id = target.get("/auth/me").json()["id"]
    assert client.patch(f"/admin/users/{target_id}", json={"disabled": True}).status_code == 200
    assert target.get("/auth/me").status_code == 401
    assert client.patch(f"/admin/users/{new_id}", json={"role": "viewer"}).json()["changed"] == ["role"]


def test_last_admin_cannot_be_demoted(admin_client):
    client, admin = admin_client
    assert client.patch(f"/admin/users/{admin['id']}", json={"role": "viewer"}).status_code == 409
    assert client.patch(f"/admin/users/{admin['id']}", json={"disabled": True}).status_code == 409


def test_user_email_encrypted_at_rest():
    make_user(email="plain.text.check@example.test")
    with admin_conn() as c:
        dump = c.execute("SELECT email_bidx, email_enc FROM users").fetchone()
    assert b"plain.text.check" not in bytes(dump["email_enc"]) + bytes(dump["email_bidx"])


# --- 감사 로그 ---


def test_audit_chain_verifies_and_detects_tampering(admin_client):
    client, _ = admin_client
    client.get("/admin/users")
    assert client.get("/audit-logs/verify").json() == {"ok": True, "broken_id": None}
    with admin_conn() as c:
        c.execute("SET session_replication_role = replica")  # 공격자가 트리거까지 우회했다고 가정
        target = c.execute("SELECT id FROM audit_logs ORDER BY id LIMIT 1 OFFSET 2").fetchone()["id"]
        c.execute("UPDATE audit_logs SET action = 'tampered' WHERE id = %s", (target,))
    assert client.get("/audit-logs/verify").json() == {"ok": False, "broken_id": target}
    assert "alert.audit_chain_broken" in audit_actions()


def test_audit_log_append_only_for_app_role():
    audit.record("test.event")
    with pool.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE audit_logs SET action = 'x'")
    with pool.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM audit_logs")


def test_audit_log_trigger_blocks_even_superuser():
    audit.record("test.event")
    with admin_conn() as c, pytest.raises(psycopg.errors.RaiseException):
        c.execute("DELETE FROM audit_logs")


def test_audit_reason_is_redacted():
    audit.record("test.event", reason="010-9999-8888 로 연락한 지원자 test.user@example.test")
    with admin_conn() as c:
        reason = c.execute("SELECT reason FROM audit_logs").fetchone()["reason"]
    assert "010-9999-8888" not in reason and "example.test" not in reason


def test_app_role_has_no_ddl_or_superuser():
    with pool.connection() as conn:
        role = conn.execute("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles"
                            " WHERE rolname = current_user").fetchone()
        assert not any(role.values())
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("CREATE TABLE evil (id int)")
