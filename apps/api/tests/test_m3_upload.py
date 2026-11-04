"""M3: 업로드 검증, 악성코드 스캔(fail closed), 격리 샌드박스. 합성 파일만 사용."""

import io
import socket
import struct
import subprocess
import sys
import threading
import zipfile

import pytest
import samples
from conftest import admin_conn, audit_actions, login, make_user
from fastapi.testclient import TestClient

from app import scanner, worker
from app.extraction import sandbox
from app.main import app

CONSENT = {
    "consent_agreed": "true",
    "consent_version": "2026-11-v1",
    "consent_purpose": "채용 전형 진행",
    "consent_items": "신원,연락처,학력,경력,기술",
    "retention_months": "12",
    "agreed_on": "2026-11-01",
}


def upload(client, content: bytes, filename: str = "resume.docx", **form):
    return client.post("/resumes", files={"file": (filename, content)}, data={**CONSENT, **form})


@pytest.fixture
def recruiter(client):
    user = make_user("recruiter")
    return login(client, user), user


@pytest.fixture
def clean_scanner(monkeypatch):
    # clamd 대역: 실제 clamd처럼 ZIP 내부까지 열어 EICAR 문자열이 있으면 감염으로 판정
    def fake_scan(data: bytes) -> bool:
        if samples.EICAR in data:
            return True
        if data.startswith(b"PK"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    return any(samples.EICAR in z.read(n) for n in z.namelist() if z.getinfo(n).file_size < 1 << 20)
            except zipfile.BadZipFile:
                return False
        return False

    monkeypatch.setattr(scanner, "scan", fake_scan)


def status(client, rid):
    return client.get(f"/resumes/{rid}/status").json()


# --- 업로드 API ---


def test_upload_stores_encrypted_and_records_consent(recruiter):
    client, _ = recruiter
    r = upload(client, samples.raw_docx(), "홍길동_이력서.docx")
    assert r.status_code == 202, r.text
    rid = r.json()["id"]
    with admin_conn() as c:
        f = c.execute("SELECT * FROM resume_files WHERE resume_id = %s", (rid,)).fetchone()
        consent = c.execute("SELECT * FROM consents WHERE resume_id = %s", (rid,)).fetchone()
    assert b"synthetic" not in bytes(f["ciphertext"]) and "홍길동".encode() not in bytes(f["original_name_enc"])
    assert consent["retention_months"] == 12 and "연락처" in consent["items"]
    assert "resume.upload" in audit_actions()


def test_viewer_cannot_upload(client):
    login(client, make_user("viewer"))
    assert upload(client, samples.raw_docx()).status_code == 403


@pytest.mark.parametrize(
    "form",
    [
        {"consent_agreed": "false"},
        {"consent_items": "주민등록번호"},
        {"retention_months": "0"},
        {"retention_months": "61"},
        {"agreed_on": "2999-01-01"},
    ],
)
def test_consent_required(recruiter, form):
    client, _ = recruiter
    assert upload(client, samples.raw_docx(), **form).status_code == 422


@pytest.mark.parametrize(
    ("content", "filename", "code"),
    [
        (samples.clean_pdf(), "resume.docx", 415),  # 확장자 위조
        (samples.raw_docx(), "resume.pdf", 415),
        (b"MZ\x90\x00 fake exe", "resume.pdf", 415),  # 실행 파일을 PDF로 위장
        (b"<html><script>alert(1)</script>", "resume.pdf", 415),
        (b"%PDF-" + b"0" * (10 * 1024 * 1024), "resume.pdf", 413),
    ],
)
def test_upload_rejects_spoofed_or_oversized(recruiter, content, filename, code):
    client, _ = recruiter
    assert upload(client, content, filename).status_code == code
    assert "resume.upload.rejected" in audit_actions()


def test_concurrent_upload_limit(recruiter):
    client, _ = recruiter
    codes = [upload(client, samples.raw_docx()).status_code for _ in range(4)]
    assert codes == [202, 202, 202, 429]


def test_status_idor(recruiter):
    client, _ = recruiter
    rid = upload(client, samples.raw_docx()).json()["id"]
    other = login(TestClient(app, base_url="https://testserver"), make_user("recruiter"))
    assert other.get(f"/resumes/{rid}/status").status_code == 404
    admin = login(TestClient(app, base_url="https://testserver"), make_user("admin"))
    assert admin.get(f"/resumes/{rid}/status").status_code == 200


# --- 워커: 스캔 → 샌드박스 검증 ---


@pytest.mark.parametrize(
    ("content", "filename", "expected"),
    [
        (samples.raw_docx(), "a.docx", ("REVIEW", None)),
        (samples.hyperlink_docx(), "a.docx", ("REVIEW", None)),
        (samples.clean_pdf(), "a.pdf", ("REVIEW", None)),
        (samples.macro_docx(), "a.docx", ("FAILED", "active_content")),
        (samples.external_template_docx(), "a.docx", ("FAILED", "external_reference")),
        (samples.zip_bomb_docx(), "a.docx", ("FAILED", "zip_bomb")),
        (samples.nested_archive_docx(), "a.docx", ("FAILED", "nested_archive")),
        (samples.js_pdf(), "a.pdf", ("FAILED", "active_content")),
        (samples.escaped_name_js_pdf(), "a.pdf", ("FAILED", "active_content")),
        (samples.objstm_hidden_js_pdf(), "a.pdf", ("FAILED", "active_content")),
        (b"PK\x03\x04 not really a zip", "a.docx", ("FAILED", "invalid_file")),
        (b"%PDF-1.7 garbage", "a.pdf", ("FAILED", "invalid_file")),
    ],
)
def test_worker_pipeline(recruiter, clean_scanner, content, filename, expected):
    client, _ = recruiter
    rid = upload(client, content, filename).json()["id"]
    worker.run_once()
    s = status(client, rid)
    assert (s["status"], s["failure_code"]) == expected


def test_malware_rejected_and_deleted(recruiter, clean_scanner):
    client, _ = recruiter
    rid = upload(client, samples.raw_docx({"word/media/x.txt": samples.EICAR})).json()["id"]
    assert worker.run_once() == "malware"
    assert status(client, rid)["status"] == "FAILED"
    with admin_conn() as c:
        assert c.execute("SELECT count(*) AS n FROM resume_files WHERE resume_id = %s", (rid,)).fetchone()["n"] == 0
    assert "alert.malware_upload" in audit_actions()


def test_scanner_unavailable_fails_closed(recruiter, monkeypatch):
    client, _ = recruiter
    rid = upload(client, samples.raw_docx()).json()["id"]

    def down(data):
        raise scanner.ScannerUnavailable("down")

    monkeypatch.setattr(scanner, "scan", down)
    called = []
    monkeypatch.setattr(sandbox, "run", lambda *a: called.append(1))
    assert worker.run_once() == "retry"
    assert status(client, rid)["status"] == "UPLOADED" and not called  # 파싱하지 않고 대기열로


def test_stuck_jobs_fail_instead_of_retrying(recruiter):
    client, _ = recruiter
    rid = upload(client, samples.raw_docx()).json()["id"]
    with admin_conn() as c:
        c.execute("UPDATE resumes SET status = 'EXTRACTING', updated_at = now() - interval '11 minutes'")
    worker.recover_stuck()
    assert status(client, rid) | {} == {"id": rid, "status": "FAILED", "failure_code": "timeout", "warnings": []}


# --- clamd 프로토콜 (가짜 clamd 서버) ---


def _fake_clamd(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    received = []

    def serve():
        conn, _ = srv.accept()
        data = b""
        while not data.endswith(struct.pack(">I", 0)):
            data += conn.recv(65536)
        received.append(data)
        conn.sendall(reply)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], received


@pytest.mark.parametrize(
    ("reply", "infected"), [(b"stream: OK\0", False), (b"stream: Eicar-Test-Signature FOUND\0", True)]
)
def test_clamd_instream_protocol(monkeypatch, reply, infected):
    port, received = _fake_clamd(reply)
    monkeypatch.setattr(scanner, "CLAMD_HOST", "127.0.0.1")
    monkeypatch.setattr(scanner, "CLAMD_PORT", port)
    assert scanner.scan(b"payload") is infected
    assert received[0] == b"zINSTREAM\0" + struct.pack(">I", 7) + b"payload" + struct.pack(">I", 0)


def test_clamd_error_reply_is_not_clean(monkeypatch):
    port, _ = _fake_clamd(b"INSTREAM size limit exceeded. ERROR\0")
    monkeypatch.setattr(scanner, "CLAMD_HOST", "127.0.0.1")
    monkeypatch.setattr(scanner, "CLAMD_PORT", port)
    with pytest.raises(scanner.ScannerUnavailable):
        scanner.scan(b"x")


def test_scanner_without_host_fails_closed(monkeypatch):
    monkeypatch.setattr(scanner, "CLAMD_HOST", "")
    with pytest.raises(scanner.ScannerUnavailable):
        scanner.scan(b"x")


# --- 샌드박스 격리 ---


def test_sandbox_gets_no_secrets(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw["env"])
        return subprocess.CompletedProcess(cmd, 0, b'{"ok": false, "code": "x"}', b"")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    sandbox.run(b"", "application/pdf")
    assert set(seen) <= {"PATH", "PYTHONIOENCODING", "SYSTEMROOT"}


@pytest.mark.parametrize(
    "action",
    [
        "import socket; socket.create_connection(('127.0.0.1', 9))",
        "import subprocess; subprocess.run(['whoami'])",
        "open('pwned.txt', 'w')",
        "import os; os.open('pwned.txt', os.O_WRONLY | os.O_CREAT)",
    ],
)
def test_sandbox_audit_hook_blocks(action, tmp_path):
    code = f"import sys; from app.extraction.sandbox import _audit_hook; sys.addaudithook(_audit_hook); {action}"
    p = subprocess.run([sys.executable, "-c", code], cwd=sandbox.API_ROOT, capture_output=True, timeout=60)
    assert p.returncode != 0 and b"blocked in sandbox" in p.stderr


def test_sandbox_stderr_never_surfaces(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, b"", "Traceback ... 김가상 010-2222-3333".encode())

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    assert sandbox.run(b"", "application/pdf") == {"ok": False, "code": "parse_error"}
