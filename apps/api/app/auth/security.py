import base64
import hashlib
import hmac
import secrets
import time
import urllib.request

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException

from app.core import config

ph = PasswordHasher()  # argon2id, t=3, m=64MiB, p=4
# 존재하지 않는 계정에도 같은 시간이 걸리게 하는 더미 해시(계정 열거 방지)
DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))

PASSWORD_MIN, PASSWORD_MAX = 12, 128


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(stored: str, password: str) -> bool:
    try:
        return ph.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False


def is_pwned(password: str) -> bool:
    """HIBP k-anonymity: SHA-1 앞 5자리만 전송한다."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324 — HIBP 프로토콜이 SHA-1을 요구
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": "resume-service"},
    )
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 — 고정된 https URL
        body = r.read().decode()
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix == suffix and int(count or 0) > 0:  # 패딩 항목은 count 0
            return True
    return False


def check_password_policy(password: str) -> None:
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise HTTPException(422, f"비밀번호는 {PASSWORD_MIN}~{PASSWORD_MAX}자여야 합니다")
    if not config.HIBP_ENABLED:
        return
    try:
        pwned = is_pwned(password)
    except OSError:
        # fail closed: 검사할 수 없으면 비밀번호를 설정하지 않는다.
        raise HTTPException(503, "유출 비밀번호 검사 서비스에 연결할 수 없습니다. 잠시 후 다시 시도하세요") from None
    if pwned:
        raise HTTPException(422, "유출된 적이 있는 비밀번호입니다. 다른 비밀번호를 사용하세요")


# --- TOTP (RFC 6238, SHA-1, 6자리, 30초) ---

TOTP_STEP = 30


def new_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def totp_at(secret: bytes, step: int) -> str:
    mac = hmac.new(secret, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def verify_totp(secret: bytes, code: str, last_step: int) -> int | None:
    """일치한 step을 반환. 이미 사용한 step 이하는 거부(재사용 공격 방지). ±1 step 허용."""
    now = int(time.time()) // TOTP_STEP
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: bytes, account: str) -> str:
    b32 = base64.b32encode(secret).decode().rstrip("=")
    return f"otpauth://totp/resume-service:{account}?secret={b32}&issuer=resume-service&digits=6&period=30"


def new_recovery_codes(n: int = 10) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]


def hash_token(token: str) -> bytes:
    # 세션 토큰·복구 코드는 고엔트로피 난수라 느린 해시가 필요 없다.
    return hashlib.sha256(token.encode()).digest()
