from fastapi import HTTPException, Request

# 인증 없이 접근 가능한 경로. 추가할 때는 반드시 리뷰를 거친다(CLAUDE.md 규칙 5).
PUBLIC_PATHS = frozenset({"/health"})


async def require_auth(request: Request) -> None:
    """모든 라우트에 전역으로 걸리는 기본 거부(default-deny) 의존성."""
    if request.url.path in PUBLIC_PATHS:
        return
    # ponytail: M0에는 인증이 없으므로 전부 거부. M1에서 세션 + MFA 검증으로 교체.
    raise HTTPException(status_code=401, detail="Not authenticated")
