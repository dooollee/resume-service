"""M4: 규칙 파서 정확도, 사진 메타데이터 제거, 주민번호 폐기, 검수·확정, 원본 다운로드 권한. 합성 데이터만."""

import io

import pytest
import synthetic
from conftest import PASSWORD, admin_conn, audit_actions, ctx, login, make_user, next_code
from fastapi.testclient import TestClient
from test_m2_data import db_dump
from test_m3_upload import CONSENT, upload

from app import normalize, scanner, skills, worker
from app.db import pool
from app.extraction import parse, validate
from app.main import app
from app.resumes import store

needs_font = pytest.mark.skipif(not synthetic.korean_font(), reason="한글 TTF 폰트 필요 (CI는 fonts-nanum 설치)")


@pytest.fixture(autouse=True)
def _scanner(monkeypatch):
    monkeypatch.setattr(scanner, "scan", lambda data: False)


def _score(data: dict, exp: dict) -> tuple[int, int]:
    total = ok = 0
    for f, v in exp["identity"].items():
        total += 1
        ok += data["identity"].get(f) == v
    for section in ("education", "career", "skills", "certs"):
        for i, row in enumerate(exp[section]):
            for f, v in row.items():
                total += 1
                got = data[section][i].get(f) if i < len(data[section]) else None
                ok += got == v
    total += 1
    ok += data["intro"] == exp["intro"]
    return ok, total


@needs_font
def test_field_accuracy_on_20_synthetic_resumes():
    ok = total = 0
    for seed in range(20):
        t = synthetic.resume_truth(seed)
        make, mime = (synthetic.make_docx, validate.DOCX) if seed % 2 else (synthetic.make_pdf, validate.PDF)
        out = parse.extract(mime, make(t))
        o, n = _score(out["data"], synthetic.expected(t))
        ok, total = ok + o, total + n
    accuracy = ok / total
    print(f"field accuracy: {ok}/{total} = {accuracy:.1%}")
    assert accuracy >= 0.95


@pytest.mark.parametrize(
    ("raw", "e164"),
    [
        ("010-1234-5678", "+821012345678"),
        ("010 1234 5678", "+821012345678"),
        ("+82-10-1234-5678", "+821012345678"),
        ("82 10 1234 5678", "+821012345678"),
        ("02-123-4567", "+8221234567"),
        ("1234", None),
        ("", None),
    ],
)
def test_phone_e164(raw, e164):
    assert normalize.phone(raw) == e164


def test_dates_and_skill_aliases():
    assert normalize.ym("2019.3") == normalize.ym("2019년 3월") == normalize.ym("2019-03") == "2019-03"
    assert normalize.ym("2019.13") is None
    assert normalize.ymd("1995.04.12") == "1995-04-12"
    assert [skills.canonical(s) for s in ["js", "리액트", "k8s", "Spring Boot", "Unknown Tool"]] == [
        "JavaScript",
        "React",
        "Kubernetes",
        "Spring",
        "Unknown Tool",
    ]


@pytest.fixture
def recruiter(client):
    user = make_user("recruiter")
    return login(client, user), user


def _process(client, content, filename):
    rid = upload(client, content, filename).json()["id"]
    assert worker.run_once() == "review"
    return rid


@pytest.mark.parametrize("kind", ["docx", pytest.param("pdf", marks=needs_font)])
def test_rrn_never_stored_and_photo_metadata_stripped(recruiter, kind):
    client, owner = recruiter
    t = synthetic.resume_truth(7)
    make = synthetic.make_docx if kind == "docx" else synthetic.make_pdf
    rid = _process(client, make(t, with_rrn=True), f"r.{kind}")  # 실제 사이즈 sandbox 경유

    review = client.get(f"/resumes/{rid}/review").json()
    assert "rrn_removed" in review["warnings"] and review["has_photo"]
    assert review["data"]["identity"]["name"] == t["identity"]["name"]
    with pool.connection() as conn:
        ctx(conn, owner)
        photo, _ = store.get_file(conn, rid, store.load_dek(conn, rid), "photo")
    from PIL import Image

    img = Image.open(io.BytesIO(photo))
    assert not img.getexif() and img.format == "JPEG" and img.width <= 600

    # 원본 파일 암호문에도, 추출 데이터에도 주민번호가 평문으로 존재하지 않음
    dump = db_dump()
    assert b"900101" not in dump and b"1234567" not in dump


def test_review_permissions(recruiter):
    client, _ = recruiter
    rid = _process(client, synthetic.make_docx(synthetic.resume_truth(3)), "r.docx")
    other = login(TestClient(app, base_url="https://testserver"), make_user("recruiter"))
    viewer = login(TestClient(app, base_url="https://testserver"), make_user("viewer"))
    assert other.get(f"/resumes/{rid}/review").status_code == 404
    assert viewer.get(f"/resumes/{rid}/review").status_code == 403
    assert other.put(f"/resumes/{rid}", json={}).status_code == 404
    assert "authz.denied" in audit_actions()


def test_update_confirm_normalizes_and_audits_field_names_only(recruiter):
    client, _ = recruiter
    t = synthetic.resume_truth(4)
    rid = _process(client, synthetic.make_docx(t), "r.docx")
    data = client.get(f"/resumes/{rid}/review").json()["data"]
    data["identity"]["phone"] = "010 9876 5432"
    data["skills"].append({"name": "리액트", "level": "중급", "years": 1})
    r = client.put(f"/resumes/{rid}", json={**data, "confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "CONFIRMED"
    assert set(r.json()["changed"]) == {"identity.phone", "skills"}
    saved = client.get(f"/resumes/{rid}/review").json()["data"]
    assert saved["identity"]["phone"] == "+821098765432"
    assert any(s["name"] == "React" for s in saved["skills"])
    with admin_conn() as c:
        details = [str(r["detail"]) for r in c.execute("SELECT detail FROM audit_logs WHERE action = 'resume.update'")]
    assert details and all("9876" not in d for d in details)


def test_manual_rrn_entry_rejected(recruiter):
    client, _ = recruiter
    rid = _process(client, synthetic.make_docx(synthetic.resume_truth(5)), "r.docx")
    data = client.get(f"/resumes/{rid}/review").json()["data"]
    data["intro"] = "주민번호 900101-1234567 입니다"
    assert client.put(f"/resumes/{rid}", json=data).status_code == 422


def test_source_download_rules(recruiter):
    client, owner = recruiter
    content = synthetic.make_docx(synthetic.resume_truth(6))
    rid = _process(client, content, "홍길동_이력서.docx")
    assert client.post(f"/resumes/{rid}/source", json={}).status_code == 422  # 사유 필수
    r = client.post(f"/resumes/{rid}/source", json={"reason": "검수 대조"})
    assert r.status_code == 200 and r.content == content
    assert r.headers["content-disposition"] == f'attachment; filename="{rid}.docx"'  # 원본 파일명(PII) 미노출
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"

    data = client.get(f"/resumes/{rid}/review").json()["data"]
    client.put(f"/resumes/{rid}", json={**data, "confirm": True})
    assert client.post(f"/resumes/{rid}/source", json={"reason": "x" * 5}).status_code == 404  # 확정 후 업로더 불가

    admin_user = make_user("admin")
    admin = login(TestClient(app, base_url="https://testserver"), admin_user)
    assert admin.post(f"/resumes/{rid}/source", json={"reason": "감사 대응"}).status_code == 403  # step-up 필요
    admin.post("/auth/step-up", json={"password": PASSWORD, "code": next_code(admin_user)})
    assert admin.post(f"/resumes/{rid}/source", json={"reason": "감사 대응"}).status_code == 200
    assert audit_actions().count("resume.source") == 2


def test_upload_form_constant_is_used():
    assert CONSENT["consent_version"] == "2026-11-v1"
