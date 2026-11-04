from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import admin
from app.auth import routes as auth_routes
from app.auth.deps import require_auth
from app.core import config
from app.core.logging import setup_logging
from app.core.middleware import edge
from app.db import pool
from app.resumes import review as resume_review
from app.resumes import routes as resume_routes

setup_logging(config.LOG_LEVEL)


@asynccontextmanager
async def lifespan(_):
    pool.open(wait=True)
    yield
    pool.close()


api = FastAPI(
    title="resume-service",
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.IS_DEV else None,
    dependencies=[Depends(require_auth)],
    lifespan=lifespan,
)
api.include_router(auth_routes.router)
api.include_router(admin.router)
api.include_router(resume_routes.router)
api.include_router(resume_review.router)


@api.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Pydantic 기본 422 응답은 잘못된 입력값(input)을 그대로 되돌려준다 → 개인정보 노출 방지를 위해 제거.
    errors = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


# 처리되지 않은 예외: Starlette(debug=False)가 일반 메시지 "Internal Server Error"만 반환하고,
# 트레이스백은 uvicorn.error → 마스킹 포매터를 거쳐 서버 로그에만 남는다. debug=True로 바꾸지 말 것.


@api.get("/health")
async def health():
    return {"status": "ok"}


app = edge(api)
