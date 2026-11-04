# 보안 수용 기준 체크리스트 (명세 §9) — M7 점검 결과

점검일: 2026-11-04. 테스트는 모두 실제 PostgreSQL 16에서 실행했다. 경로는 `apps/api/tests/` 기준이다.

| # | 기준 | 결과 | 증빙 |
|---|---|---|---|
| 1 | 로그·에러·모니터링에 개인정보가 없다 (자동 테스트로 검증) | ✅ | `test_m7_attacks.py::test_full_workflow_logs_no_pii_*`: 전체 업무 흐름의 **마스킹 전 원시 로그**에 이름·주소·전화·이메일·주민번호 0건. 422/500 응답의 입력값 에코 제거(`test_m0_security.py`), 샌드박스 stderr 폐기. E2E 서버 로그(API·워커·웹)도 0건 |
| 2 | DB를 덤프해도 이름/연락처/이메일/주소/생년월일이 평문이 아니다 | ✅ | `test_m2_data.py::test_db_dump_contains_no_plaintext_pii`, `test_m1_auth.py::test_user_email_encrypted_at_rest` |
| 3 | 다른 사용자의 `resume_id`로 요청하면 403/404 (IDOR) | ✅ | `test_m3_upload.py::test_status_idor`, `test_m4_extraction.py::test_review_permissions`, `test_m6_retention.py::test_delete_request_permissions`. RLS 2차 방어는 `test_m2_data.py::test_rls_*` |
| 4 | `viewer`가 마스킹 해제 API를 호출하면 거부된다 | ✅ | `test_m5_search.py::test_viewer_cannot_reveal_or_see_photo` (+ `test_m7` 흐름 안의 403) |
| 5 | 마스킹 해제·원본 다운로드·검색이 모두 감사 로그에 남는다 | ✅ | `test_reveal_flow_with_reason_and_expiry`, `test_source_download_rules`, `test_search_audit_hashes_identity_terms` |
| 6 | 감사 로그를 변조하면 해시 체인 검증이 실패한다 | ✅ | `test_m1_auth.py::test_audit_chain_verifies_and_detects_tampering`. 전체 흐름 뒤 체인이 온전한지도 확인(`test_m7`) |
| 7 | 버킷/파일 URL에 직접 접근하면 거부된다 | ✅ (설계) | 파일은 DB 안에 DEK 암호문으로만 존재하고 버킷이 없다. 사진은 유효한 열람 허가가 있는 세션만 받을 수 있다(`test_reveal_grant_is_per_session`) |
| 8 | 악성 PDF/DOCX, 확장자 위조 파일, 압축폭탄이 거부된다 | ✅ | `test_m3_upload.py::test_worker_pipeline` (12종), `test_upload_rejects_spoofed_or_oversized`, `test_malware_rejected_and_deleted` |
| 9 | 주민등록번호 패턴이 저장되지 않는다 | ✅ | `test_m4_extraction.py::test_rrn_never_stored_*` (DB 전체 덤프 검사), `test_manual_rrn_entry_rejected` |
| 10 | 보존기간이 지난 데이터가 자동 파기되고 키가 폐기된다 | ✅ | `test_m6_retention.py::test_retention_expiry_*`, `test_purge_after_grace_is_unrecoverable` |
| 11 | MFA 없이는 어떤 기능에도 접근할 수 없다 | ✅ | `test_m1_auth.py::test_every_route_requires_mfa`: **등록된 모든 라우트를 자동 순회**하므로 새 엔드포인트도 검사된다 |
| 12 | 보안 헤더·CSP·CORS 설정이 점검 도구에서 통과한다 | ✅ 자동 / ⏳ 외부 도구 | 모든 응답(200/4xx/500)의 헤더를 검사(`test_security_headers`, `test_m7` 흐름 전체). CORS 비활성(`test_cors_not_enabled`). 웹은 요청별 nonce CSP를 E2E에서 확인. **운영 도메인에 배포한 뒤 OWASP ZAP baseline과 Mozilla Observatory로 다시 점검해야 한다** |
| 13 | 의존성 취약점 스캔 결과 High 이상 없음 | ✅ | `pip-audit -r requirements.txt`: 0건. `npm audit --audit-level=high`: 0건. CI와 Dependabot이 매주 점검 |
| 14 | 운영 데이터가 개발/스테이징 환경에 없다 | ✅ 절차 | 테스트·픽스처는 합성 생성기(`tests/synthetic.py`, `tests/samples.py`)만 쓴다. `.gitignore`가 `*.pdf`·`*.docx`·`*.hwp`를 막고 CI gitleaks가 검사한다. 운영 DB를 복사하지 않는 규칙은 CLAUDE.md 1번과 SECURITY.md에 있다. **분기별 접근권한 리뷰 때 실제로 확인해야 한다** |

## 모의 공격 시나리오 (`test_m7_attacks.py` 외)
| 시나리오 | 결과 |
|---|---|
| SQL 인젝션 (검색 필드 5종 × 페이로드 5종) | 무해. 결과 없음 또는 422, 스키마 그대로 |
| text/plain 본문을 이용한 로그인 CSRF | Origin 검사에서 403, JSON 파싱에서 422 |
| 다른 세션의 CSRF 토큰 재사용 / 위조 세션 쿠키 | 403 / 401 |
| 요청 본문에 role을 넣어 권한 상승 | 무시됨 |
| 다른 세션으로 step-up·열람 허가 재사용 | 불가 |
| MFA 코드 무차별 대입 | 5회 실패 시 429와 계정 잠금 |
| TOTP 코드 재사용 | 거부 |
| 경로 조작(`..`, 인코딩) | 401/404/422 |
| 압축 객체 스트림에 숨긴 PDF Launch, `#4A` 이름 이스케이프, 끊어진 참조로 검사 중단 유도 | 모두 탐지 |
| DB 쓰기 권한으로 암호문을 다른 행에 붙여넣기 | 복호화 실패(AAD) |
| 감사 로그 UPDATE/DELETE (앱 계정, 슈퍼유저) | 권한 없음 / 트리거로 차단 |
| 레이트 리미터 메모리 고갈(키 회전) | 오래된 키 정리 |

## 남은 위험 (수용 또는 운영 단계에서 처리)
1. **샌드박스 네트워크 네임스페이스**: 파서 프로세스는 워커 컨테이너와 네트워크를 공유한다. 외부망은 없고 자격증명도 없다. 더 강하게 막으려면 gVisor나 `network_mode: none` 전용 파서 컨테이너를 쓴다.
2. **로컬 KMS 모의**: KEK가 환경변수에 있다. 운영 전에 클라우드 KMS나 HSM으로 바꿔야 한다(OPEN_QUESTIONS #4).
3. **블라인드 인덱스 키 로테이션**: KEK 로테이션은 구현했다. BIDX_KEY를 바꾸려면 모든 인덱스를 다시 계산하는 배치가 필요한데 아직 없다.
4. **레이트 리밋이 프로세스 메모리 기반**: API 인스턴스를 여러 개 띄우면 DB나 Redis 기반으로 바꿔야 한다.
5. **백업 속 DEK**: 백업에는 wrapped DEK도 함께 들어 있다. 백업 보존기간이 끝나는 시점이 최종 파기 시점이다.
6. **GeoIP 미적용**: 신규 국가 로그인은 탐지하지 않는다(신규 IP만 탐지).
7. **법무 검토 필요**: 보존기간, 접근기록 보관기간, 정보주체 요청 처리 기한, 침해 통지 기한(OPEN_QUESTIONS #5·#6).
