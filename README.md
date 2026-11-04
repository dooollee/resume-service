# resume-service

정형 양식 이력서(PDF/DOCX)에서 정보를 추출해 암호화 저장하고, 권한 있는 사용자만 필요한 정보를 검색·조회하는 내부용 서비스.
개인정보를 다루므로 **보안이 기능보다 우선**한다. 작업 규칙은 [CLAUDE.md](CLAUDE.md)를 따른다.

```
브라우저 ──(같은 오리진)──▶ web: Next.js BFF ──▶ api: FastAPI ──▶ PostgreSQL 16 (RLS, 암호문만)
                                                                   ▲
                                         worker ──▶ clamav          │
                                           └─▶ 격리 샌드박스 파서 ───┘
```

## 문서
| 문서 | 내용 |
|---|---|
| [docs/SECURITY.md](docs/SECURITY.md) | 보안 구현 현황, 파일 격리 구조, 백업·파기, 침해 사고 대응 |
| [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md) | 명세 §9 수용 기준별 증빙, 모의 공격 결과, 남은 위험 |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | 저장 방식, 봉투 암호화 키 구조, RLS 정책 |
| [docs/RESUME_FORM.md](docs/RESUME_FORM.md) | 정형 이력서 양식 규격 |
| [docs/DATA_SUBJECT_REQUESTS.md](docs/DATA_SUBJECT_REQUESTS.md) | 정보주체 열람·정정·삭제 처리 절차 |
| [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md) | 결정 사항과 남은 질문 |

## 실행 (Docker)
```bash
cp .env.example .env   # 모든 change-me / REPLACE 값을 난수로 채운다
docker compose up --build -d
docker compose run --rm api python -m app.cli create-admin   # 첫 관리자 (첫 로그인 때 MFA 등록·비밀번호 변경 강제)
# http://localhost:3000
```
- ClamAV는 처음 기동할 때 서명 DB를 내려받느라 몇 분 걸린다. 그동안 업로드는 대기 상태로 남는다(fail closed).
- 운영 배포 전에 TLS 종단(리버스 프록시), 클라우드 KMS, 백업 암호화·만료, 법무 검토를 마쳐야 한다. 자세한 내용은 SECURITY_CHECKLIST.md의 "남은 위험"에 있다.

## 개발
```bash
# API (apps/api) — 테스트는 실제 PostgreSQL이 필요하며, 로컬에서는 pgserver가 자동으로 띄운다
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest
.venv/Scripts/ruff check . && .venv/Scripts/pip-audit -r requirements.txt

# Web (apps/web)
npm ci && npm run typecheck && npm run build && npm audit --audit-level=high
```

## 운영 명령 (`python -m app.cli …`)
| 명령 | 용도 |
|---|---|
| `migrate` | DB 역할 부트스트랩 + 마이그레이션 (슈퍼유저 URL 필요, migrate 서비스 전용) |
| `create-admin` | 관리자 생성 |
| `rotate-kek` | 모든 DEK를 `KEK_CURRENT`로 다시 감싼다 |
| `purge` | 보존기간·삭제 요청 파기 즉시 실행 (worker가 1시간마다 자동 실행) |
