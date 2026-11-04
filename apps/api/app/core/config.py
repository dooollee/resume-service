import os

# 설정 누락 시 안전한 쪽(production)으로 동작한다.
APP_ENV = os.getenv("APP_ENV", "production")
IS_DEV = APP_ENV == "development"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]
