"""보존기간·삭제 요청 파기 배치 (worker가 주기적으로, 또는 `python -m app.cli purge`).

파기 = resumes 행 삭제 → ON DELETE CASCADE로 식별정보·파일·사진·검색 인덱스·동의·열람 허가가 함께 삭제되고,
레코드별 DEK(dek_wrapped)도 사라지므로 남아 있는 암호문(DB 사본·백업)은 복호화할 수 없다(crypto-shredding).
"""

import logging

from app import audit
from app.db import pool, set_rls_context

log = logging.getLogger("app.retention")
GRACE_DAYS = 7  # 삭제 요청 후 영구 파기까지 유예(오삭제 복구 여지)


def purge() -> int:
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        due = conn.execute(
            "SELECT id, CASE WHEN deleted_at IS NOT NULL AND purge_after <= now() THEN 'deletion_request'"
            " ELSE 'retention_expired' END AS cause FROM resumes"
            " WHERE (deleted_at IS NOT NULL AND purge_after <= now()) OR retention_until <= now()"
        ).fetchall()
    for row in due:
        with pool.connection() as conn:
            set_rls_context(conn, None, "system")
            conn.execute("DELETE FROM resumes WHERE id = %s", (row["id"],))
        audit.record("resume.purge", resource_type="resume", resource_id=row["id"], detail={"cause": row["cause"]})
    with pool.connection() as conn:  # 만료된 세션·열람 허가 정리
        conn.execute("DELETE FROM reveal_grants WHERE expires_at < now()")
        conn.execute("DELETE FROM sessions WHERE last_seen_at < now() - interval '1 day'")
    if due:
        log.info("purged %d resumes", len(due))
    return len(due)
