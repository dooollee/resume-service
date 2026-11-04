# 데이터 모델

스키마 원본은 `apps/api/migrations/*.sql`이다. 이 문서는 보안 관점의 요약이다.

## 저장 방식

| 데이터 | 저장 형태 | 검색 |
|---|---|---|
| 이름 · 휴대폰 · 이메일 | AES-256-GCM 암호문 + HMAC 블라인드 인덱스 | 정확 일치만 |
| 생년월일 · 성별 · 주소 · 자기소개 · 경력 담당업무 | AES-256-GCM 암호문 | 불가 |
| 원본 파일 · 사진 · 원본 파일명 | AES-256-GCM 암호문 (`resume_files`, DB 내부) | — |
| 학교 · 전공 · 학위 · 회사 · 직무 · 기간 · 기술 · 자격 | 평문 + 인덱스 | 가능 |
| 주민등록번호 | **저장하지 않음** (추출 단계에서 폐기, `warnings`에 `rrn_removed`만 기록) | — |
| 사용자 이메일 · MFA 시크릿 | AES-256-GCM 암호문 (사용자별 DEK) | 이메일은 블라인드 인덱스 |
| 비밀번호 | argon2id 해시 | — |
| 세션 토큰 · 복구 코드 | SHA-256 해시 | — |

## 키 구조 (봉투 암호화)

```
KEK (KMS / 개발: 환경변수 KEK_KEYS, 버전별)
 └─ wrap ─▶ DEK (레코드별 32바이트, resumes.dek_wrapped / users.dek_wrapped + key_version)
             └─ AES-256-GCM ─▶ 필드 암호문   (AAD = "resume:<id>|<필드명>")
BIDX_KEY (KEK와 분리) ─ HMAC-SHA256 ─▶ *_bidx  (입력 = "resume_<필드>\0<정규화 값>")
```

- AAD에 레코드 ID와 필드명이 들어가므로, DB 쓰기 권한이 있는 공격자가 암호문을 다른 행이나 필드로 옮기면 복호화에 실패한다.
- KEK 로테이션: `KEK_KEYS`에 새 버전 추가 → `KEK_CURRENT` 변경 → `python -m app.cli rotate-kek`(데이터 재암호화 없이 DEK만 다시 감쌈) → 이전 키 제거.
- 파기(crypto-shredding): `resumes` 행을 삭제하면 DEK가 사라져 남아 있는 암호문(백업 포함)은 KEK가 있어도 복호화할 수 없다. 단, 백업에는 wrapped DEK도 함께 들어 있으므로 **백업 보존기간 만료가 최종 파기 시점**이다(SECURITY.md 참고).

## 정규화 규칙 (블라인드 인덱스·검색·추출 공통, `app/normalize.py`)
- 전화번호 → E.164 (`010-1234-5678` → `+821012345678`)
- 이메일 → 소문자
- 이름 → NFKC, 공백 제거, casefold
- 날짜 → `YYYY-MM` / `YYYY-MM-DD`

## Row Level Security (2차 방어)

요청마다 트랜잭션 로컬로 `app.user_id`, `app.role`이 설정된다. 설정이 없으면 아무 행도 보이지 않는다.

| 테이블 | admin | recruiter | viewer | system(배치) |
|---|---|---|---|---|
| resumes 읽기 | 전체(삭제 포함) | 삭제 안 된 것 | CONFIRMED만 | 전체 |
| resumes 수정 | ✅ | 본인 업로드만 | ❌ | ✅ |
| resumes 영구 삭제 | ❌ | ❌ | ❌ | ✅ (파기 배치만) |
| 삭제 요청 | `request_resume_deletion()` | 본인 업로드만 | ❌ | — |
| identity · files · consents 읽기 | ✅ | ✅ | **❌** | ✅ |
| education · career · skills · certs 읽기 | 부모 이력서가 보이면 가능 | 〃 | 〃 | 〃 |
| 하위 테이블 쓰기 | ✅ | 본인 업로드만 | ❌ | ✅ |

DB 계정은 다음과 같이 나뉜다.
- `resume_owner`: 테이블 소유자이며 로그인할 수 없다(NOLOGIN).
- `resume_app`: DML만 가능하고 `NOBYPASSRLS`다. `audit_logs`에 대한 UPDATE/DELETE 권한이 없다.
- 슈퍼유저: migrate 서비스만 사용한다.
