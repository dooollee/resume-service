import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException

_hits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()


def limit(key: str, max_hits: int, window_seconds: int) -> None:
    """슬라이딩 윈도우. 초과 시 429."""
    # ponytail: 프로세스 메모리 기반 — API 인스턴스가 여러 개가 되면 DB/Redis 기반으로 교체.
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and q[0] <= now - window_seconds:
            q.popleft()
        if len(q) >= max_hits:
            raise HTTPException(status_code=429, detail="Too many requests")
        q.append(now)


def reset() -> None:
    with _lock:
        _hits.clear()
