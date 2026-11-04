import logging
import time

SECURITY_HEADERS = [
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    # API는 HTML을 서빙하지 않으므로 전부 차단
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    (b"cache-control", b"no-store"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
_NAMES = {name for name, _ in SECURITY_HEADERS}

access_log = logging.getLogger("app.access")


def edge(app):
    """가장 바깥 ASGI 래퍼: 보안 헤더 + 액세스 로그.

    FastAPI 미들웨어 대신 바깥에서 감싸야 Starlette가 만드는 500 응답에도 헤더가 붙는다.
    액세스 로그에는 쿼리스트링을 남기지 않는다(검색어에 개인정보가 들어갈 수 있음).
    """

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        start = time.perf_counter()
        status = 500

        async def send_with_headers(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = [h for h in message.get("headers", []) if h[0].lower() not in _NAMES]
                message["headers"] = headers + SECURITY_HEADERS
            await send(message)

        try:
            await app(scope, receive, send_with_headers)
        finally:
            ms = (time.perf_counter() - start) * 1000
            access_log.info("%s %s %d %.1fms", scope["method"], scope["path"], status, ms)

    return wrapped
