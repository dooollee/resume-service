# SECURITY

## 마일스톤별 구현 현황

| 항목 (명세 §9) | 상태 | 증명 |
|---|---|---|
| 로그·에러에 개인정보 없음 | M0 ✅ | `apps/api/tests/test_m0_security.py` |
| 보안 헤더·CSP·CORS | M0 ✅ | `apps/api/tests/test_m0_security.py`, `apps/web/proxy.ts` |
| 의존성 취약점 High 이상 없음 | M0 ✅ | CI `pip-audit`, `npm audit --audit-level=high` |
| 기본 인증 필요(공개 엔드포인트 화이트리스트) | M1 ✅ | `test_m1_auth.py::test_every_route_requires_auth` (새 라우트도 자동 검사) |
| MFA 없이는 어떤 기능도 접근 불가 | M1 ✅ | `test_m1_auth.py::test_every_route_requires_mfa` |
| RBAC·관리자 재인증(step-up) | M1 ✅ | `test_m1_auth.py` |
| 감사 로그 append-only·해시 체인 변조 탐지 | M1 ✅ | `test_m1_auth.py::test_audit_*` |
| 앱 DB 계정 DDL/슈퍼유저 권한 없음 | M1 ✅ | `test_m1_auth.py::test_app_role_has_no_ddl_or_superuser` |
| 필드 암호화·블라인드 인덱스·키 로테이션 | M2 ✅ (모듈) | `test_crypto.py` |
| 악성/변조 파일 거부(매크로, 외부 참조, 압축폭탄, 중첩 아카이브, JS·Launch PDF, 확장자 위조) | M3 ✅ | `test_m3_upload.py::test_worker_pipeline`, `test_upload_rejects_spoofed_or_oversized` |
| 악성코드 스캔 fail closed(스캐너 장애 시 파싱 안 함) | M3 ✅ | `test_scanner_unavailable_fails_closed`, `test_clamd_*` |
| 격리 파싱(비밀값 없는 환경, rlimit, 감사 훅으로 네트워크·프로세스·쓰기 차단, stderr 폐기) | M3 ✅ | `test_sandbox_*` |
| 버킷/파일 URL 직접 접근 불가 | M3 ✅ (설계) | 파일은 DB 안 암호문으로만 존재, 인증 API로만 제공 |
| 주민등록번호 비저장(추출 시 폐기, 수동 입력 거부) | M4 ✅ | `test_m4_extraction.py::test_rrn_never_stored_*`, `test_manual_rrn_entry_rejected` |
| 사진 EXIF/GPS 제거·해상도 제한 | M4 ✅ | `test_rrn_never_stored_and_photo_metadata_stripped` |
| 추출 정확도(합성 20건) | M4 ✅ 100% | `test_field_accuracy_on_20_synthetic_resumes` |
| 역할별 마스킹·열람 사유 | M5 | — |
| 보존기간 파기·crypto-shredding | M6 | — |

## 파일 처리 격리 구조

```
업로드(API) ─ 매직바이트·확장자·크기 검사 ─▶ DEK로 암호화해 DB 저장(UPLOADED)
worker ─ 복호화 → clamd INSTREAM 스캔 ─ 감염: 파일 삭제 + FAILED(malware) + 알림
                                     ─ 스캐너 장애: 대기열로 되돌림(파싱 안 함)
       └▶ sandbox 프로세스 (python -B -E -s, 비밀값 없는 env, Linux rlimit: 메모리 1GiB·CPU 30s·파일쓰기 0,
                            감사 훅: socket/subprocess/exec/쓰기 open 차단, 타임아웃 60s, stderr 폐기)
            ─ 구조 검사(PDF 객체 스트림 포함 전수 검사 / DOCX zip 메타·rels) → 추출 → JSON
       └▶ 샌드박스 출력도 스키마 검증 후 저장(REVIEW)
```

- worker 컨테이너는 외부망이 없고 DB와 clamav에만 접근한다. 읽기 전용 루트 파일시스템, 메모리 2GiB, PID 64개로 제한된다.
- 남은 위험: 샌드박스 프로세스는 같은 컨테이너의 네트워크 네임스페이스를 공유한다. 네이티브 코드 실행 취약점이 터지면 DB 포트까지는 닿을 수 있지만, 자격증명은 환경에 없다. 운영에서 더 강하게 막으려면 gVisor나 별도의 `network_mode: none` 파서 컨테이너를 쓴다.

## 개발 환경 규칙
- 운영 데이터를 개발/스테이징으로 복사하지 않는다. 테스트 데이터는 합성 데이터만.
- Docker Compose의 Postgres/Redis/MinIO 포트는 `127.0.0.1`에만 바인딩한다.
- `APP_ENV` 기본값은 `production`이다(설정 누락 시 안전한 쪽으로 동작).

## 침해 사고 대응 절차

1. **탐지** — 이상 징후 알림(대량 조회/마스킹 해제, 신규 IP·국가 로그인, 반복 권한 오류) 또는 신고 접수. 접수 시각·접수자 기록.
2. **격리** — 의심 계정 잠금·세션 전체 무효화, 관련 키(서명/블라인드 인덱스/API) 로테이션, 필요 시 서비스 읽기 전용 전환. 감사 로그·서버 로그는 즉시 보존(덮어쓰기 금지).
3. **통지** — 개인정보 보호책임자(CPO)에게 즉시 보고. 개인정보 보호법에 따른 정보주체 통지 및 개인정보보호위원회/KISA 신고 대상·기한을 CPO·법무가 판단한다(통지 기한 등은 법무 확인 후 이 문서에 확정 기재).
4. **복구** — 원인 제거 후 패치·재배포, 백업에서 무결성 확인된 시점으로 복구, 감사 로그 해시 체인 검증.
5. **사후분석** — 타임라인, 근본 원인, 영향 범위(대상 레코드 수), 재발 방지 조치를 문서화하고 이 문서와 체크리스트를 갱신.

연락처(CPO, 보안 담당, 법무)는 운영 전 확정해 기재한다.
