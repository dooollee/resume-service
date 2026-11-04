"""감사 로그(append-only + 해시 체인)와 이상 징후 알림.

요청 트랜잭션과 별도 연결로 즉시 커밋한다 → 요청이 실패(403 등)해도 기록이 남는다.
개인정보 값은 기록하지 않는다. 열람 사유(자유 입력)는 PII 패턴을 마스킹해 저장한다.
"""

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta, timezone

from app.core.logging import redact
from app.db import pool

GENESIS = b"\x00" * 32
_LOCK_KEY = 7_340_001  # 체인 직렬화용 advisory lock
KST = timezone(timedelta(hours=9))

alert_log = logging.getLogger("app.alert")

# (action 접두사, 창(분), 임계치) — 같은 행위자가 창 안에서 임계치를 넘으면 알림
THRESHOLDS = {
    "authz.denied": (10, 10),
    "resume.reveal": (10, 20),
    "resume.search": (10, 100),
    "resume.source": (60, 10),
}


def _digest(prev: bytes, e: dict) -> bytes:
    canonical = json.dumps(
        [
            e["ts"].astimezone(UTC).isoformat(),
            e["actor_id"],
            e["action"],
            e["resource_type"],
            e["resource_id"],
            e["ip"],
            e["user_agent"],
            e["reason"],
            e["detail"],
        ],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(bytes(prev) + canonical.encode()).digest()


def client_ip(request) -> str | None:
    return request.client.host if request is not None and request.client else None


def record(
    action: str,
    *,
    request=None,
    actor_id=None,
    resource_type=None,
    resource_id=None,
    reason: str | None = None,
    detail: dict | None = None,
) -> None:
    if actor_id is None and request is not None:
        user = getattr(request.state, "user", None)
        actor_id = user.id if user else None
    entry = {
        "ts": datetime.now(UTC),
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id else None,
        "ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:300] if request is not None else None,
        "reason": redact(reason)[:500] if reason else None,
        "detail": detail,
    }
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
        last = conn.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev = bytes(last["hash"]) if last else GENESIS
        conn.execute(
            "INSERT INTO audit_logs (ts, actor_id, action, resource_type, resource_id, ip, user_agent, reason, detail,"
            " prev_hash, hash) VALUES (%(ts)s, %(actor_id)s, %(action)s, %(resource_type)s, %(resource_id)s, %(ip)s,"
            " %(user_agent)s, %(reason)s, %(detail)s, %(prev)s, %(hash)s)",
            {
                **entry,
                "detail": json.dumps(detail) if detail is not None else None,
                "prev": prev,
                "hash": _digest(prev, entry),
            },
        )
    if not action.startswith("alert.") and entry["actor_id"]:
        _check_thresholds(entry, request)


def verify_chain(conn) -> int | None:
    """체인이 온전하면 None, 깨졌으면 처음 깨진 레코드 id."""
    prev = GENESIS
    with conn.cursor(name="audit_verify") as cur:
        cur.execute("SELECT * FROM audit_logs ORDER BY id")
        for row in cur:
            if bytes(row["prev_hash"]) != prev or bytes(row["hash"]) != _digest(prev, row):
                return row["id"]
            prev = bytes(row["hash"])
    return None


def alert(kind: str, *, request=None, actor_id=None, detail: dict | None = None) -> None:
    alert_log.warning("security alert: %s actor=%s", kind, actor_id)
    record(f"alert.{kind}", request=request, actor_id=actor_id, detail=detail)


def _check_thresholds(entry: dict, request) -> None:
    rule = THRESHOLDS.get(entry["action"])
    if not rule:
        return
    minutes, limit = rule
    with pool.connection() as conn:
        n = conn.execute(
            "SELECT count(*) AS n FROM audit_logs WHERE actor_id = %s AND action = %s AND ts > now() - %s::interval",
            (entry["actor_id"], entry["action"], f"{minutes} minutes"),
        ).fetchone()["n"]
    if n == limit + 1:  # 임계치를 처음 넘는 순간 한 번만 알림
        alert(
            "bulk_" + entry["action"].replace(".", "_"),
            request=request,
            actor_id=entry["actor_id"],
            detail={"count": n, "window_minutes": minutes},
        )


def check_login_anomalies(conn, user_id: str, request) -> None:
    ip = client_ip(request)
    hour = datetime.now(KST).hour
    if hour >= 22 or hour < 7:
        alert("off_hours_login", request=request, actor_id=user_id, detail={"hour_kst": hour})
    seen = conn.execute(
        "SELECT bool_or(ip = %s) AS same, count(*) AS n FROM audit_logs"
        " WHERE actor_id = %s AND action = 'auth.login.success' AND ts > now() - interval '90 days'",
        (ip, user_id),
    ).fetchone()
    # ponytail: 국가 판별은 GeoIP DB가 필요해 미구현. 신규 IP만 탐지.
    if seen["n"] and not seen["same"]:
        alert("new_ip_login", request=request, actor_id=user_id)
