"""PII 마스킹 로거.

안전망이다: 이메일/전화번호/주민등록번호처럼 패턴이 있는 값만 잡는다.
이름·주소는 정규식으로 못 잡으므로 애초에 로그에 넘기지 않는 것이 원칙이다(CLAUDE.md 규칙 2).
"""

import logging
import re

_PATTERNS = [
    # 주민등록번호/외국인등록번호 — 전화번호보다 먼저 (13자리가 전화번호 패턴에 일부 걸리지 않도록)
    (re.compile(r"(?<!\d)\d{6}[-\s]?[1-8]\d{6}(?!\d)"), "[RRN]"),
    # 이메일 (URL 인코딩된 @ 포함)
    (re.compile(r"[\w.+-]+(?:@|%40)[\w-]+(?:\.[\w-]+)+", re.IGNORECASE), "[EMAIL]"),
    # 한국 휴대폰/유선 (+82 포함)
    (re.compile(r"(?<!\d)(?:\+?82[-.\s]?0?|0)\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class PIIRedactingFormatter(logging.Formatter):
    # 최종 문자열(메시지 + args + 예외 트레이스백)을 마스킹하므로 어떤 경로로 들어온 값도 걸러진다.
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(PIIRedactingFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # uvicorn 로거도 같은 마스킹 핸들러를 타게 한다.
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
    # uvicorn 액세스 로그는 쿼리스트링(검색어 등)을 남기므로 끄고, 경로만 남기는 자체 액세스 로그를 쓴다.
    logging.getLogger("uvicorn.access").disabled = True
