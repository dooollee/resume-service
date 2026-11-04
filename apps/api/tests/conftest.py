import base64
import os

# app 임포트 전에 설정해야 반영된다. 값은 모두 합성 데이터 / 테스트 전용 난수 키.
os.environ["APP_ENV"] = "production"
os.environ["CORS_ORIGINS"] = "https://web.example.test"
_k = lambda: base64.b64encode(os.urandom(32)).decode()  # noqa: E731
os.environ["KEK_KEYS"] = f"1:{_k()},2:{_k()}"
os.environ["KEK_CURRENT"] = "2"
os.environ["BIDX_KEY"] = _k()
