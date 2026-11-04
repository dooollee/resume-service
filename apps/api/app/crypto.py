"""필드 단위 암호화(봉투 암호화) + 블라인드 인덱스.

- 레코드마다 DEK(AES-256) 생성 → KEK로 감싸 `dek_wrapped`, `key_version`에 저장.
- 필드는 AES-256-GCM, AAD = "<리소스 ID>|<필드명>" → 다른 행/필드로 암호문을 옮겨 붙이면 복호화 실패.
- 블라인드 인덱스 = HMAC-SHA256(인덱스 전용 키, 필드명 + 정규화 값). 암호화 키와 분리.
"""

import base64
import hashlib
import hmac
import os
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_keks() -> tuple[dict[int, bytes], int]:
    # KEK_KEYS="1:<base64>,2:<base64>", KEK_CURRENT=2
    keys = {}
    for item in os.environ.get("KEK_KEYS", "").split(","):
        if item.strip():
            version, b64 = item.split(":", 1)
            keys[int(version)] = base64.b64decode(b64)
    current = int(os.environ.get("KEK_CURRENT", "0"))
    if current not in keys or any(len(k) != 32 for k in keys.values()):
        raise RuntimeError("KEK_KEYS/KEK_CURRENT 설정이 올바르지 않습니다 (32바이트 키 필요)")
    return keys, current


def _load_bidx_key() -> bytes:
    key = base64.b64decode(os.environ.get("BIDX_KEY", ""))
    if len(key) != 32:
        raise RuntimeError("BIDX_KEY 설정이 올바르지 않습니다 (32바이트 키 필요)")
    return key


# ponytail: 로컬 KMS 모의 구현(환경변수의 KEK). 운영은 클라우드 KMS의 wrap/unwrap 호출로 교체 (OPEN_QUESTIONS #4).
_KEKS, KEK_CURRENT = _load_keks()
_BIDX_KEY = _load_bidx_key()
if _BIDX_KEY in _KEKS.values():
    raise RuntimeError("BIDX_KEY는 KEK와 다른 키여야 합니다")


def new_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _seal(key: bytes, aad: str, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad.encode())


def _open(key: bytes, aad: str, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad.encode())


def wrap_dek(dek: bytes, context: str) -> tuple[bytes, int]:
    return _seal(_KEKS[KEK_CURRENT], f"dek|{context}", dek), KEK_CURRENT


def unwrap_dek(wrapped: bytes, version: int, context: str) -> bytes:
    return _open(_KEKS[version], f"dek|{context}", bytes(wrapped))


def encrypt(dek: bytes, aad: str, value: str | bytes | None) -> bytes | None:
    if value is None:
        return None
    return _seal(dek, aad, value.encode() if isinstance(value, str) else value)


def decrypt(dek: bytes, aad: str, blob: bytes | None) -> bytes | None:
    return None if blob is None else _open(dek, aad, bytes(blob))


def decrypt_str(dek: bytes, aad: str, blob: bytes | None) -> str | None:
    raw = decrypt(dek, aad, blob)
    return None if raw is None else raw.decode()


def normalize_name(value: str) -> str:
    return "".join(unicodedata.normalize("NFKC", value).split()).casefold()


def blind_index(field: str, normalized: str | None) -> bytes | None:
    if not normalized:
        return None
    return hmac.new(_BIDX_KEY, f"{field}\x00{normalized}".encode(), hashlib.sha256).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def rewrap(wrapped: bytes, version: int, context: str) -> tuple[bytes, int]:
    """KEK 로테이션: 데이터는 그대로 두고 DEK만 현재 KEK로 다시 감싼다."""
    return wrap_dek(unwrap_dek(wrapped, version, context), context)
