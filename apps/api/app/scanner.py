"""ClamAV(clamd) INSTREAM 스캔. 스캔할 수 없으면 파싱하지 않는다(fail closed)."""

import logging
import os
import socket
import struct

from app.core import config

log = logging.getLogger("app.scanner")
CLAMD_HOST = os.getenv("CLAMD_HOST", "")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
# 개발 PC에 clamd가 없을 때만. APP_ENV=development가 아니면 무시된다.
_DEV_SKIP = os.getenv("CLAMAV_DISABLED_FOR_DEV") == "true" and config.IS_DEV


class ScannerUnavailable(Exception):
    pass


def scan(data: bytes) -> bool:
    """감염이면 True. clamd에 연결할 수 없으면 ScannerUnavailable."""
    if _DEV_SKIP:
        log.warning("malware scan skipped (development only)")
        return False
    if not CLAMD_HOST:
        raise ScannerUnavailable("CLAMD_HOST not configured")
    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=60) as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 64 * 1024):
                chunk = data[i : i + 64 * 1024]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                part = s.recv(4096)
                if not part:
                    break
                reply += part
    except OSError as e:
        raise ScannerUnavailable(str(e)) from None
    text = reply.rstrip(b"\0").decode(errors="replace")
    if text.endswith("OK"):
        return False
    if text.endswith("FOUND"):
        return True
    raise ScannerUnavailable("unexpected clamd reply")  # 크기 초과 등 오류도 통과시키지 않는다
