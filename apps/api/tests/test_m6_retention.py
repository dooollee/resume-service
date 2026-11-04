"""M6: 삭제 요청(즉시 비활성화) → 유예 후 파기, 보존기간 만료 파기, crypto-shredding, 정보주체 요청. 합성 데이터만."""

import pytest
from conftest import PASSWORD, SAMPLE, admin_conn, audit_actions, ctx, login, make_resume, make_user, next_code
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient
from test_m2_data import PLAINTEXTS, db_dump

from app import crypto, retention
from app.db import pool
from app.main import app
from app.resumes import store

RESUME_TABLES = [
    "resumes",
    "resume_identity",
    "resume_files",
    "resume_education",
    "resume_career",
    "resume_skills",
    "resume_certs",
    "consents",
    "reveal_grants",
]


def _client(user):
    return login(TestClient(app, base_url="https://testserver"), user)


def _rows_for(rid) -> dict:
    with admin_conn() as c:
        return {
            t: c.execute(
                f"SELECT count(*) AS n FROM {t} WHERE {'id' if t == 'resumes' else 'resume_id'} = %s",  # noqa: S608
                (rid,),
            ).fetchone()["n"]
            for t in RESUME_TABLES
        }


@pytest.fixture
def owner_and_resume():
    owner = make_user("recruiter")
    rid = make_resume(owner)
    with pool.connection() as conn:
        ctx(conn, owner)
        store.put_file(conn, rid, store.load_dek(conn, rid), "photo", b"\xff\xd8 synthetic")
        conn.execute(
            "INSERT INTO consents (resume_id, version, agreed_at, purpose, items, retention_months, recorded_by)"
            " VALUES (%s, 'v1', now(), '채용', '{신원}', 12, %s)",
            (rid, owner["id"]),
        )
    return owner, rid


def test_delete_request_deactivates_immediately(owner_and_resume):
    owner, rid = owner_and_resume
    c = _client(owner)
    c.post(f"/resumes/{rid}/reveal", json={"reason": "삭제 전 열람 테스트"})
    r = c.delete(f"/resumes/{rid}")
    assert r.status_code == 200 and "purge_after" in r.json()
    assert c.get(f"/resumes/{rid}").status_code == 404
    assert c.post("/resumes/search", json={"name": "김가상"}).json()["items"] == []
    assert c.get(f"/resumes/{rid}/photo").status_code == 403  # 열람 허가도 즉시 회수
    assert _rows_for(rid)["resumes"] == 1  # 유예기간 동안은 아직 존재(복구 여지)
    assert "resume.delete_request" in audit_actions()


def test_delete_request_permissions(owner_and_resume):
    _, rid = owner_and_resume
    assert _client(make_user("recruiter")).delete(f"/resumes/{rid}").status_code == 404
    assert _client(make_user("viewer")).delete(f"/resumes/{rid}").status_code == 403
    assert _client(make_user("admin")).delete(f"/resumes/{rid}").status_code == 200


def test_purge_after_grace_is_unrecoverable(owner_and_resume):
    owner, rid = owner_and_resume
    with admin_conn() as c:  # 파기 전 공격자가 확보한 암호문 사본(예: 백업)
        stolen = c.execute(
            "SELECT i.name_enc, r.dek_wrapped, r.key_version FROM resume_identity i"
            " JOIN resumes r ON r.id = i.resume_id WHERE r.id = %s",
            (rid,),
        ).fetchone()
    _client(owner).delete(f"/resumes/{rid}")
    assert retention.purge() == 0  # 유예기간 전에는 파기 안 함

    with admin_conn() as c:
        c.execute("UPDATE resumes SET purge_after = now() - interval '1 minute' WHERE id = %s", (rid,))
    assert retention.purge() == 1
    assert set(_rows_for(rid).values()) == {0}  # DB 레코드·파일·사진·검색 인덱스·동의·허가 모두 삭제
    dump = db_dump()
    assert bytes(stolen["name_enc"]) not in dump and bytes(stolen["dek_wrapped"]) not in dump
    for s in PLAINTEXTS:
        assert s.encode() not in dump

    # DEK가 DB에서 사라졌으므로, 다른 DEK로는 사본 암호문을 풀 수 없다(crypto-shredding)
    with pytest.raises(InvalidTag):
        crypto.decrypt(crypto.new_dek(), f"resume:{rid}|name", stolen["name_enc"])
    with admin_conn() as c:
        log = c.execute("SELECT detail FROM audit_logs WHERE action = 'resume.purge'").fetchone()
    assert log["detail"] == {"cause": "deletion_request"}


def test_retention_expiry_purges_automatically(owner_and_resume):
    _, rid = owner_and_resume
    keep = make_resume(make_user("recruiter"))
    with admin_conn() as c:
        c.execute("UPDATE resumes SET retention_until = now() - interval '1 day' WHERE id = %s", (rid,))
    assert retention.purge() == 1
    assert set(_rows_for(rid).values()) == {0}
    assert _rows_for(keep)["resumes"] == 1


def test_data_subject_export_requires_admin_stepup_and_reason(owner_and_resume):
    owner, rid = owner_and_resume
    assert _client(owner).post(f"/resumes/{rid}/export", json={"reason": "정보주체 열람 요청"}).status_code == 403
    admin = make_user("admin")
    c = _client(admin)
    assert c.post(f"/resumes/{rid}/export", json={"reason": "정보주체 열람 요청"}).status_code == 403  # step-up 전
    c.post("/auth/step-up", json={"password": PASSWORD, "code": next_code(admin)})
    assert c.post(f"/resumes/{rid}/export", json={}).status_code == 422
    r = c.post(f"/resumes/{rid}/export", json={"reason": "정보주체 열람 요청 #2026-001"})
    assert r.status_code == 200
    body = r.json()
    assert body["data"]["identity"]["name"] == SAMPLE["identity"]["name"] and body["consents"]
    assert "resume.export" in audit_actions()


def test_correction_after_confirm(owner_and_resume):
    owner, rid = owner_and_resume
    c = _client(owner)
    data = c.get(f"/resumes/{rid}/review").json()["data"]
    data["identity"]["address"] = "가상시 정정구 1"
    assert c.put(f"/resumes/{rid}", json=data).json()["changed"] == ["identity.address"]


def test_retention_dashboard_has_no_pii(owner_and_resume):
    owner, rid = owner_and_resume
    _client(owner).delete(f"/resumes/{rid}")
    admin = make_user("admin")
    c = login(TestClient(app, base_url="https://testserver"), admin, stepup=True)
    r = c.get("/admin/retention")
    assert r.status_code == 200
    body = r.json()
    assert body["pending_deletion"] == 1 and body["pending"][0]["id"] == rid
    for s in PLAINTEXTS:
        assert s not in r.text


def test_consent_record_visible_to_recruiters(owner_and_resume):
    _, rid = owner_and_resume
    r = _client(make_user("recruiter")).get(f"/resumes/{rid}/consent")
    assert r.status_code == 200 and r.json()[0]["retention_months"] == 12
    assert _client(make_user("viewer")).get(f"/resumes/{rid}/consent").status_code == 403
