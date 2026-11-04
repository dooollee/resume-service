"""백그라운드 워커: 업로드 → 악성코드 스캔 → 격리 샌드박스 추출 → 검수 대기(REVIEW).

작업 큐는 PostgreSQL(SELECT ... FOR UPDATE SKIP LOCKED). 별도 큐 서비스·자격증명이 필요 없다.
실행: python -m app.worker
"""

import base64
import logging
import time

from pydantic import ValidationError

from app import audit, retention, scanner
from app.core import config
from app.core.logging import setup_logging
from app.db import pool, set_rls_context
from app.extraction import sandbox
from app.resumes import store
from app.resumes.schemas import ResumeData

log = logging.getLogger("app.worker")
STUCK_MINUTES = 10
PURGE_INTERVAL_SECONDS = 3600


def _set_status(rid, status: str, failure_code: str | None = None, warnings: list[str] | None = None) -> None:
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        conn.execute(
            "UPDATE resumes SET status = %s, failure_code = %s, warnings = coalesce(%s, warnings), updated_at = now()"
            " WHERE id = %s",
            (status, failure_code, warnings, rid),
        )


def claim_next() -> str | None:
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        row = conn.execute(
            "UPDATE resumes SET status = 'SCANNING', updated_at = now() WHERE id = ("
            " SELECT id FROM resumes WHERE status = 'UPLOADED' AND deleted_at IS NULL"
            " ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id"
        ).fetchone()
    return str(row["id"]) if row else None


def recover_stuck() -> None:
    """작업 중 죽은 워커가 남긴 건은 재시도하지 않고 실패 처리(반복 크래시 파일 방지)."""
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        conn.execute(
            "UPDATE resumes SET status = 'FAILED', failure_code = 'timeout', updated_at = now()"
            " WHERE status IN ('SCANNING', 'EXTRACTING') AND updated_at < now() - %s::interval",
            (f"{STUCK_MINUTES} minutes",),
        )


def process(rid: str) -> str:
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        mime = conn.execute("SELECT source_mime FROM resumes WHERE id = %s", (rid,)).fetchone()["source_mime"]
        dek = store.load_dek(conn, rid)
        content, _ = store.get_file(conn, rid, dek, "source")

    try:
        infected = scanner.scan(content)
    except scanner.ScannerUnavailable:
        log.warning("scanner unavailable; job %s returned to queue", rid)
        _set_status(rid, "UPLOADED")
        return "retry"
    if infected:
        with pool.connection() as conn:
            set_rls_context(conn, None, "system")
            conn.execute("DELETE FROM resume_files WHERE resume_id = %s", (rid,))  # 악성 파일은 보관하지 않음
        _set_status(rid, "FAILED", "malware")
        audit.record("resume.malware", resource_type="resume", resource_id=rid)
        audit.alert("malware_upload", detail={"resume_id": rid})
        return "malware"

    _set_status(rid, "EXTRACTING")
    result = sandbox.run(content, mime)
    if not result.get("ok"):
        code = str(result.get("code", "parse_error"))[:40]
        _set_status(rid, "FAILED", code)
        audit.record("resume.extract.failed", resource_type="resume", resource_id=rid, detail={"code": code})
        return code
    try:  # 샌드박스 출력도 신뢰하지 않는다 — 스키마 검증
        data = ResumeData.model_validate(result.get("data") or {})
        photo = base64.b64decode(result["photo"]) if result.get("photo") else None
        warnings = [w for w in result.get("warnings", []) if w in {"rrn_removed", "photo_not_found"}]
    except (ValidationError, ValueError):
        _set_status(rid, "FAILED", "parse_error")
        return "parse_error"
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        store.save(conn, rid, dek, data)
        if photo:
            store.put_file(conn, rid, dek, "photo", photo)
    _set_status(rid, "REVIEW", None, warnings)
    audit.record("resume.extracted", resource_type="resume", resource_id=rid, detail={"warnings": warnings})
    return "review"


def run_once() -> str | None:
    recover_stuck()
    rid = claim_next()
    return process(rid) if rid else None


def main() -> None:
    setup_logging(config.LOG_LEVEL)
    pool.open(wait=True)
    log.info("worker started")
    last_purge = 0.0
    while True:
        try:
            if time.monotonic() - last_purge > PURGE_INTERVAL_SECONDS:
                retention.purge()
                last_purge = time.monotonic()
            outcome = run_once()
        except Exception:
            log.exception("worker iteration failed")
            outcome = None
        if outcome in (None, "retry"):
            time.sleep(5)


if __name__ == "__main__":
    main()
