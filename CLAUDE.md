# CLAUDE.md — 작업 규칙

개인정보를 다루는 서비스다. **기능과 보안이 충돌하면 보안을 택한다.** 전체 명세는 `docs/SPEC.md`를 따른다(원본 명세서를 이 경로에 둔다).

1. 실제 개인정보를 코드, 테스트, 픽스처, 로그, 커밋에 절대 넣지 않는다. 테스트 데이터는 합성(가짜) 데이터만 사용한다.
2. 개인정보(이름, 연락처, 이메일, 주소, 생년월일, 사진, 이력서 원문)는 **로그, 에러 메시지, 모니터링 이벤트에 출력하지 않는다.**
   - `app/core/logging.py`의 마스킹 포매터는 안전망일 뿐이다. 이름·주소는 정규식으로 못 잡으므로 애초에 로그에 넘기지 않는다.
   - URL 경로에 개인정보를 넣지 않는다(액세스 로그에 경로가 남는다). 쿼리스트링은 로그에 남기지 않는다.
3. 비밀값(키, 비밀번호, 토큰)은 코드에 하드코딩하지 않고 환경변수/시크릿 매니저로만 주입한다. `.env`는 `.gitignore`에 포함하고 `.env.example`만 커밋한다.
4. 모든 DB 접근은 ORM 또는 파라미터 바인딩을 사용한다. 문자열 연결로 SQL을 만들지 않는다.
5. 모든 API는 기본이 "인증 필요 + 권한 검사"이다. 공개 엔드포인트는 `app/auth/deps.py`의 `PUBLIC_PATHS`에 명시적으로 등록한다.
6. 새 기능을 추가할 때마다 (a) 권한 검사 테스트 (b) 감사 로그 기록 여부를 함께 구현한다.
7. 의존성 추가 시 이유를 PR 설명에 남기고, 취약점 점검(`pip-audit`, `npm audit`)을 통과해야 한다. 버전은 정확히 고정한다.
8. 불확실한 보안 결정은 임의로 정하지 말고 `docs/OPEN_QUESTIONS.md`에 기록하고 질문한다.

## 명령어

```bash
# API (apps/api)
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt   # Windows
.venv/Scripts/python -m pytest
.venv/Scripts/ruff check .
.venv/Scripts/pip-audit -r requirements.txt

# Web (apps/web)
npm ci && npm run typecheck && npm run build && npm audit --audit-level=high

# 전체 (Docker)
cp .env.example .env   # 값 채우기
docker compose up --build
```
