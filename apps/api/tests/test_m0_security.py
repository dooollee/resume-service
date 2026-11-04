"""M0 보안 수용 기준(명세 §9 중 해당 항목). 모든 값은 합성 데이터."""

import logging
import sys

import pytest
from fastapi import Query
from fastapi.testclient import TestClient

from app.auth.deps import require_auth
from app.core.logging import PIIRedactingFormatter, redact
from app.core.middleware import SECURITY_HEADERS
from app.main import api, app

FAKE_EMAIL = "hong.gildong@example.test"
FAKE_PHONE = "010-1234-5678"
FAKE_RRN = "900101-1234567"


@api.get("/_test/boom")
async def boom():
    raise ValueError(f"parse failed for {FAKE_EMAIL} {FAKE_PHONE}")


@api.get("/_test/typed")
async def typed(age: int = Query()):
    return {"age": age}


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def authed():
    api.dependency_overrides[require_auth] = lambda: None
    yield
    api.dependency_overrides.clear()


# --- 로그·에러에 개인정보 없음 ---


@pytest.mark.parametrize(
    "pii",
    [
        FAKE_EMAIL,
        "hong.gildong%40example.test",
        FAKE_PHONE,
        "01012345678",
        "+82-10-1234-5678",
        "+821012345678",
        "02-123-4567",
        FAKE_RRN,
        "9001011234567",
    ],
)
def test_redact_removes_pii(pii):
    out = redact(f"user value={pii} end")
    assert pii not in out
    assert out.startswith("user value=[") and out.endswith("] end")


@pytest.mark.parametrize(
    "safe",
    ["2026-11-04 12:30:00", "3f2b8c1e-9a7d-4e21-8f00-1c2d3e4f5a6b", "GET /resumes/42 200 3.1ms"],
)
def test_redact_keeps_non_pii(safe):
    assert redact(safe) == safe


def test_formatter_redacts_args_and_traceback():
    fmt = PIIRedactingFormatter("%(message)s")
    try:
        raise ValueError(f"bad {FAKE_RRN}")
    except ValueError:
        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "contact %s", (FAKE_EMAIL,), sys.exc_info())
    out = fmt.format(record)
    assert FAKE_EMAIL not in out and FAKE_RRN not in out
    assert "Traceback" in out


def test_root_logger_uses_redacting_formatter():
    # pytest가 자체 캡처 핸들러를 추가하므로 우리 핸들러 존재 여부만 확인
    assert any(isinstance(h.formatter, PIIRedactingFormatter) for h in logging.getLogger().handlers)
    assert logging.getLogger("uvicorn.access").disabled


def test_access_log_has_no_query_string(client, caplog):
    with caplog.at_level(logging.INFO, logger="app.access"):
        client.get(f"/health?email={FAKE_EMAIL}")
    lines = [r.getMessage() for r in caplog.records if r.name == "app.access"]
    assert lines and all("example.test" not in line and "?" not in line for line in lines)


def test_500_returns_generic_message(client, authed):
    r = client.get("/_test/boom")
    assert r.status_code == 500
    assert r.text == "Internal Server Error"
    assert r.headers["x-content-type-options"] == "nosniff"  # 500에도 보안 헤더


def test_422_does_not_echo_input(client, authed):
    r = client.get("/_test/typed", params={"age": FAKE_EMAIL})
    assert r.status_code == 422
    assert "example.test" not in r.text
    assert "input" not in r.json()["detail"][0]


# --- 보안 헤더 · CORS ---


@pytest.mark.parametrize("path", ["/health", "/does-not-exist"])
def test_security_headers(client, path):
    r = client.get(path)
    for name, value in SECURITY_HEADERS:
        assert r.headers[name.decode()] == value.decode()


def test_cors_allows_only_whitelisted_origin(client):
    pre = {"access-control-request-method": "GET"}
    ok = client.options("/health", headers={"origin": "https://web.example.test", **pre})
    assert ok.headers.get("access-control-allow-origin") == "https://web.example.test"
    bad = client.options("/health", headers={"origin": "https://evil.example.test", **pre})
    assert "access-control-allow-origin" not in bad.headers


# --- 기본 거부 ---


def test_health_is_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_non_public_routes_denied_by_default(client):
    assert client.get("/_test/typed", params={"age": 1}).status_code == 401


def test_openapi_hidden_outside_dev(client):
    assert client.get("/openapi.json").status_code == 404
