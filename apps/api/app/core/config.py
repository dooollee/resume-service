import os

# 설정 누락 시 안전한 쪽(production)으로 동작한다.
APP_ENV = os.getenv("APP_ENV", "production")
IS_DEV = APP_ENV == "development"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# 브라우저는 Next.js(BFF)와만 통신한다. 상태 변경 요청의 Origin이 여기 없으면 거부.
WEB_ORIGINS = {o.strip() for o in os.getenv("WEB_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"}

DATABASE_URL = os.getenv("DATABASE_URL", "")

SESSION_IDLE_MINUTES = 30
SESSION_ABSOLUTE_HOURS = 12
STEPUP_MINUTES = 10
LOGIN_MAX_FAILURES = 5
LOCKOUT_MINUTES = 15
MAX_BODY_BYTES = 11 * 1024 * 1024  # 업로드 10MB + multipart 오버헤드

# 유출 비밀번호 검사(HIBP k-anonymity). 끄는 것은 테스트/오프라인 개발에서만.
HIBP_ENABLED = os.getenv("HIBP_ENABLED", "true") != "false"
