import os

# app 임포트 전에 설정해야 반영된다. 값은 모두 합성 데이터.
os.environ["APP_ENV"] = "production"
os.environ["CORS_ORIGINS"] = "https://web.example.test"
