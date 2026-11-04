"""M5: 검색, 역할별 마스킹, 열람 사유 흐름, 사진 접근, 이상 탐지. 합성 데이터만."""

import copy

import pytest
from conftest import SAMPLE, admin_conn, audit_actions, ctx, login, make_resume, make_user
from fastapi.testclient import TestClient

from app.db import pool
from app.main import app
from app.resumes import store


def _variant(**changes):
    d = copy.deepcopy(SAMPLE)
    for path, value in changes.items():
        target, key = d, path.split(".")
        for k in key[:-1]:
            target = target[int(k)] if k.isdigit() else target[k]
        target[key[-1]] = value
    return d


@pytest.fixture
def corpus():
    owner = make_user("recruiter")
    a = make_resume(owner)  # Python(5) + React(2), 예시주식회사, 가상대학교, 김가상
    b = make_resume(
        owner,
        _variant(
            **{
                "identity.name": "이샘플",
                "identity.phone": "010-4444-5555",
                "identity.email": "lee.sample@example.test",
                "skills": [{"name": "TypeScript", "level": "고급", "years": 3}],
                "career.0.company": "100%가상",
            }
        ),
    )
    review = make_resume(owner, status="REVIEW")
    with pool.connection() as conn:  # 사진 하나 추가
        ctx(conn, owner)
        store.put_file(conn, a, store.load_dek(conn, a), "photo", b"\xff\xd8\xff synthetic jpeg")
    return {"owner": owner, "a": a, "b": b, "review": review}


def _client(role):
    user = make_user(role)
    return login(TestClient(app, base_url="https://testserver"), user), user


def ids(r):
    assert r.status_code == 200, r.text
    return {i["id"] for i in r.json()["items"]}


def test_skill_search_and_or_alias_years(corpus):
    c, _ = _client("recruiter")
    s = lambda **b: ids(c.post("/resumes/search", json=b))  # noqa: E731
    assert s(skills=["python", "리액트"]) == {corpus["a"]}  # 별칭 + AND
    assert s(skills=["Python", "TypeScript"]) == set()
    assert s(skills=["Python", "ts"], skill_mode="or") == {corpus["a"], corpus["b"]}
    assert s(skills=["React"], min_years=3) == set()
    assert corpus["review"] not in s(skills=["Python"])  # 확정 전에는 검색 제외


def test_text_filters_escape_wildcards(corpus):
    c, _ = _client("recruiter")
    assert ids(c.post("/resumes/search", json={"company": "예시"})) == {corpus["a"]}
    assert ids(c.post("/resumes/search", json={"company": "%"})) == {corpus["b"]}  # '%'는 문자 그대로
    assert ids(c.post("/resumes/search", json={"company": "_"})) == set()
    assert ids(c.post("/resumes/search", json={"school": "가상대"})) == {corpus["a"], corpus["b"]}


def test_identity_exact_match_only(corpus):
    c, _ = _client("recruiter")
    assert ids(c.post("/resumes/search", json={"name": "김 가상"})) == {corpus["a"]}  # 공백 정규화
    assert ids(c.post("/resumes/search", json={"name": "김가"})) == set()  # 부분 일치 없음
    assert ids(c.post("/resumes/search", json={"phone": "+82 10 4444 5555"})) == {corpus["b"]}
    assert ids(c.post("/resumes/search", json={"email": "LEE.SAMPLE@example.test"})) == {corpus["b"]}


def test_results_masked_for_recruiter(corpus):
    c, _ = _client("recruiter")
    r = c.post("/resumes/search", json={"name": "김가상"})
    item = r.json()["items"][0]
    assert item["identity"] == {"name": "김*상", "phone": "010-****-3333", "email": "ki***@example.test"}
    for plain in ("김가상", "2222-3333", "kim.gasang", "합성 자기소개", "합성 담당업무", "가상구"):
        assert plain not in r.text


def test_viewer_gets_generalized_results(corpus):
    c, _ = _client("viewer")
    r = c.post("/resumes/search", json={"skills": ["Python"]})
    item = r.json()["items"][0]
    assert "identity" not in item
    assert item["career"][0]["company"] is None and item["education"][0]["school"] is None
    assert item["career"][0]["title"] == "백엔드 개발자"
    assert c.post("/resumes/search", json={"name": "김가상"}).status_code == 403
    assert c.post("/resumes/search", json={"company": "예시"}).status_code == 403
    d = c.get(f"/resumes/{corpus['a']}").json()
    assert "identity" not in d and d["has_photo"] is False and d["can_reveal"] is False
    assert c.get(f"/resumes/{corpus['review']}").status_code == 404


def test_viewer_cannot_reveal_or_see_photo(corpus):
    c, _ = _client("viewer")
    assert c.post(f"/resumes/{corpus['a']}/reveal", json={"reason": "면접 일정 연락"}).status_code == 403
    assert c.get(f"/resumes/{corpus['a']}/photo").status_code == 403


def test_reveal_flow_with_reason_and_expiry(corpus):
    c, user = _client("recruiter")
    rid = corpus["a"]
    detail = c.get(f"/resumes/{rid}").json()
    assert detail["identity"]["name"] == "김*상" and "intro" not in detail
    assert c.get(f"/resumes/{rid}/photo").status_code == 403  # 해제 전 사진 불가
    assert c.post(f"/resumes/{rid}/reveal", json={}).status_code == 422  # 사유 필수
    assert c.post(f"/resumes/{rid}/reveal", json={"reason": "짧음"}).status_code == 422

    r = c.post(f"/resumes/{rid}/reveal", json={"reason": "1차 면접 일정 안내 연락"})
    assert r.status_code == 200
    body = r.json()
    assert body["identity"]["name"] == "김가상" and body["identity"]["phone"] == "010-2222-3333"
    assert body["intro"] == SAMPLE["intro"] and body["career_descriptions"] == ["합성 담당업무 설명"]
    assert c.get(f"/resumes/{rid}/photo").status_code == 200

    with admin_conn() as a:
        log = a.execute("SELECT * FROM audit_logs WHERE action = 'resume.reveal'").fetchone()
        a.execute("UPDATE reveal_grants SET expires_at = now() - interval '1 second'")
    assert log["reason"] == "1차 면접 일정 안내 연락" and str(log["actor_id"]) == user["id"]
    assert c.get(f"/resumes/{rid}/photo").status_code == 403  # 만료 후 다시 차단


def test_reveal_grant_is_per_session(corpus):
    c, user = _client("recruiter")
    c.post(f"/resumes/{corpus['a']}/reveal", json={"reason": "면접 일정 안내 연락"})
    other_session = login(TestClient(app, base_url="https://testserver"), user)
    assert other_session.get(f"/resumes/{corpus['a']}/photo").status_code == 403


def test_search_audit_hashes_identity_terms(corpus):
    c, _ = _client("recruiter")
    c.post("/resumes/search", json={"name": "김가상", "phone": "010-2222-3333", "skills": ["Python"]})
    with admin_conn() as a:
        detail = str(a.execute("SELECT detail FROM audit_logs WHERE action = 'resume.search'").fetchone()["detail"])
    assert "김가상" not in detail and "2222" not in detail and "Python" in detail and "identity_bidx" in detail


def test_result_cap_and_page_size(corpus):
    c, _ = _client("recruiter")
    assert c.post("/resumes/search", json={"size": 51}).status_code == 422
    assert c.post("/resumes/search", json={"page": 51, "size": 20}).status_code == 422


def test_bulk_reveal_triggers_alert(corpus):
    c, _ = _client("recruiter")
    for _ in range(21):
        assert c.post(f"/resumes/{corpus['a']}/reveal", json={"reason": "대량 열람 테스트"}).status_code == 200
    assert "alert.bulk_resume_reveal" in audit_actions()


def test_detail_and_search_audited(corpus):
    c, _ = _client("recruiter")
    c.post("/resumes/search", json={})
    c.get(f"/resumes/{corpus['a']}")
    actions = audit_actions()
    assert "resume.search" in actions and "resume.view" in actions
