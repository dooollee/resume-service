"""정규화: 전화번호(E.164), 이메일, 날짜(ISO 8601). 블라인드 인덱스·검색·추출이 같은 규칙을 공유해야 일치한다."""

import re

_YM_RE = re.compile(r"(\d{4})\s*[.\-/년]\s*(\d{1,2})")
_YMD_RE = re.compile(r"(\d{4})\s*[.\-/년]\s*(\d{1,2})\s*[.\-/월]\s*(\d{1,2})")


def phone(value: str | None) -> str | None:
    """한국 번호 → E.164(+82...). 인식 불가면 None."""
    if not value:
        return None
    digits = re.sub(r"[^\d+]", "", value)
    if digits.startswith("+82"):
        rest = digits[3:].lstrip("0")
    elif digits.startswith("82") and len(digits) >= 11:
        rest = digits[2:].lstrip("0")
    elif digits.startswith("0"):
        rest = digits[1:]
    else:
        return None
    return f"+82{rest}" if rest.isdigit() and 8 <= len(rest) <= 10 else None


def phone_display(e164: str | None) -> str | None:
    """+821012345678 → 010-1234-5678, +8221234567 → 02-123-4567."""
    if not e164 or not e164.startswith("+82"):
        return e164
    national = "0" + e164[3:]
    head = 2 if national.startswith("02") else 3
    return f"{national[:head]}-{national[head:-4]}-{national[-4:]}"


def email(value: str | None) -> str | None:
    value = (value or "").strip().lower()
    return value if re.fullmatch(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]+", value) else None


def ym(value: str | None) -> str | None:
    """'2019.3', '2019-03', '2019년 3월' → '2019-03'."""
    m = _YM_RE.search(value or "")
    if not m or not 1 <= int(m.group(2)) <= 12:
        return None
    return f"{m.group(1)}-{int(m.group(2)):02d}"


def ymd(value: str | None) -> str | None:
    m = _YMD_RE.search(value or "")
    if not m or not (1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31):
        return None
    return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
