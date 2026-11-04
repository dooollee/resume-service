"""`.env.example`을 복사해 비밀값(change-me / REPLACE)을 난수로 채운 `.env`를 만든다. 표준 라이브러리만 사용.

기존 `.env`는 덮어쓰지 않는다 — 키가 바뀌면 이미 저장된 암호문을 영영 복호화할 수 없다.
"""

import base64
import os
import re
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
env = root / ".env"
if env.exists():
    sys.exit(".env가 이미 있습니다. 새로 만들려면 먼저 지우세요(기존 데이터는 읽을 수 없게 됩니다).")

s = (root / ".env.example").read_text(encoding="utf-8")
s = re.sub(r"change-me-long-random", lambda _: secrets.token_urlsafe(32), s)
s = re.sub(r"REPLACE_WITH_BASE64_32_BYTES", lambda _: base64.b64encode(os.urandom(32)).decode(), s)
env.write_text(s, encoding="utf-8", newline="\n")
print(".env 생성 완료")
