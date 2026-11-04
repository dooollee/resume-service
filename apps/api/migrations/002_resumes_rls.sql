-- M2: 이력서 데이터 모델 + Row Level Security (애플리케이션 권한 검사에 대한 2차 방어)
-- RLS 컨텍스트는 요청마다 트랜잭션 로컬로 설정된다: app.user_id, app.role (admin|recruiter|viewer|system|anonymous)

CREATE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('app.role', true), '') $$;
CREATE FUNCTION app_user() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

CREATE TABLE resumes (
    id uuid PRIMARY KEY,
    status text NOT NULL DEFAULT 'UPLOADED'
        CHECK (status IN ('UPLOADED', 'SCANNING', 'EXTRACTING', 'REVIEW', 'CONFIRMED', 'FAILED')),
    failure_code text,                          -- 'malware', 'invalid_file' 등 코드만 (개인정보 없음)
    warnings text[] NOT NULL DEFAULT '{}',      -- 'rrn_removed' 등
    uploaded_by uuid NOT NULL REFERENCES users (id),
    dek_wrapped bytea NOT NULL,                 -- 이력서별 DEK (KEK로 감쌈). 파기 = 이 행 삭제(crypto-shredding)
    key_version int NOT NULL,
    consent_at timestamptz NOT NULL,
    consent_version text NOT NULL,
    retention_until timestamptz NOT NULL,
    source_sha256 bytea NOT NULL,
    source_mime text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    confirmed_at timestamptz,
    deleted_at timestamptz,                     -- 삭제 요청 = 즉시 비활성화
    purge_after timestamptz                     -- 유예기간 후 영구 파기
);
CREATE INDEX ON resumes (status) WHERE deleted_at IS NULL;
CREATE INDEX ON resumes (retention_until);

-- 파일 원문·사진: 이력서 DEK로 앱 레벨 암호화한 암호문만 저장 (공개 버킷이 존재하지 않음)
CREATE TABLE resume_files (
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('source', 'photo')),
    ciphertext bytea NOT NULL,
    original_name_enc bytea,
    size int NOT NULL,
    PRIMARY KEY (resume_id, kind)
);

-- 식별 정보: 전부 AES-256-GCM 암호문 + 정확 일치 검색용 블라인드 인덱스
CREATE TABLE resume_identity (
    resume_id uuid PRIMARY KEY REFERENCES resumes (id) ON DELETE CASCADE,
    name_enc bytea, name_bidx bytea,
    phone_enc bytea, phone_bidx bytea,
    email_enc bytea, email_bidx bytea,
    birth_enc bytea,
    gender_enc bytea,
    address_enc bytea,
    intro_enc bytea                             -- 자기소개(자유 서술은 개인정보를 포함할 수 있어 암호화)
);
CREATE INDEX ON resume_identity (name_bidx);
CREATE INDEX ON resume_identity (phone_bidx);
CREATE INDEX ON resume_identity (email_bidx);

-- 검색용 비식별 정보: 평문 + 인덱스
CREATE TABLE resume_education (
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    pos int NOT NULL,
    school text, major text, degree text,
    start_ym text CHECK (start_ym ~ '^\d{4}-\d{2}$'),
    end_ym text CHECK (end_ym ~ '^\d{4}-\d{2}$'),
    PRIMARY KEY (resume_id, pos)
);
CREATE TABLE resume_career (
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    pos int NOT NULL,
    company text, title text,
    start_ym text CHECK (start_ym ~ '^\d{4}-\d{2}$'),
    end_ym text CHECK (end_ym ~ '^\d{4}-\d{2}$'),
    description_enc bytea,                      -- 담당업무(자유 서술) 암호화
    PRIMARY KEY (resume_id, pos)
);
CREATE TABLE resume_skills (
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    name text NOT NULL,                         -- 정규화된 표준명 (별칭 사전 적용)
    level text CHECK (level IN ('초급', '중급', '고급', '전문가')),
    years numeric(4, 1) CHECK (years >= 0 AND years <= 60),
    PRIMARY KEY (resume_id, name)
);
CREATE INDEX ON resume_skills (name);
CREATE TABLE resume_certs (
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    pos int NOT NULL,
    name text, issuer text,
    acquired_ym text CHECK (acquired_ym ~ '^\d{4}-\d{2}$'),
    PRIMARY KEY (resume_id, pos)
);

CREATE TABLE consents (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    version text NOT NULL,
    agreed_at timestamptz NOT NULL,
    purpose text NOT NULL,
    items text[] NOT NULL,
    retention_months int NOT NULL CHECK (retention_months BETWEEN 1 AND 60),
    recorded_by uuid NOT NULL REFERENCES users (id),
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- 마스킹 해제 허가: 세션 단위, 짧은 만료
CREATE TABLE reveal_grants (
    session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    resume_id uuid NOT NULL REFERENCES resumes (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (session_id, resume_id)
);

-- ---------------- RLS ----------------
CREATE FUNCTION resume_writable(rid uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM resumes r WHERE r.id = rid
          AND (app_role() IN ('admin', 'system') OR (app_role() = 'recruiter' AND r.uploaded_by = app_user()))
    )
$$;
GRANT EXECUTE ON FUNCTION app_role(), app_user(), resume_writable(uuid) TO resume_app;

ALTER TABLE resumes ENABLE ROW LEVEL SECURITY;
CREATE POLICY resumes_select ON resumes FOR SELECT USING (
    app_role() IN ('admin', 'system')
    OR (app_role() = 'recruiter' AND deleted_at IS NULL)
    OR (app_role() = 'viewer' AND deleted_at IS NULL AND status = 'CONFIRMED')
);
CREATE POLICY resumes_insert ON resumes FOR INSERT WITH CHECK (
    app_role() = 'system' OR (app_role() IN ('admin', 'recruiter') AND uploaded_by = app_user())
);
CREATE POLICY resumes_update ON resumes FOR UPDATE USING (
    app_role() IN ('admin', 'system') OR (app_role() = 'recruiter' AND uploaded_by = app_user() AND deleted_at IS NULL)
);

-- 삭제 요청(즉시 비활성화): 갱신 후 행이 recruiter에게 안 보이게 되므로 RLS UPDATE로는 불가 →
-- 권한을 함수 안에서 직접 검사하는 SECURITY DEFINER 함수로만 허용한다.
CREATE FUNCTION request_resume_deletion(rid uuid, grace interval) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    UPDATE resumes SET deleted_at = now(), purge_after = now() + grace
     WHERE id = rid AND deleted_at IS NULL
       AND (app_role() = 'admin' OR (app_role() = 'recruiter' AND uploaded_by = app_user()))
    RETURNING true
$$;
GRANT EXECUTE ON FUNCTION request_resume_deletion(uuid, interval) TO resume_app;
CREATE POLICY resumes_delete ON resumes FOR DELETE USING (app_role() = 'system');  -- 영구 파기는 배치만

-- 민감 테이블: viewer는 읽기 불가
ALTER TABLE resume_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE resume_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE consents ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_select ON resume_identity FOR SELECT USING (
    app_role() IN ('admin', 'recruiter', 'system') AND EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY identity_write ON resume_identity FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
CREATE POLICY files_select ON resume_files FOR SELECT USING (
    app_role() IN ('admin', 'recruiter', 'system') AND EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY files_write ON resume_files FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
CREATE POLICY consents_select ON consents FOR SELECT USING (
    app_role() IN ('admin', 'recruiter', 'system') AND EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY consents_write ON consents FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));

-- 검색용 테이블: 부모 이력서가 보이면 읽기 가능
ALTER TABLE resume_education ENABLE ROW LEVEL SECURITY;
ALTER TABLE resume_career ENABLE ROW LEVEL SECURITY;
ALTER TABLE resume_skills ENABLE ROW LEVEL SECURITY;
ALTER TABLE resume_certs ENABLE ROW LEVEL SECURITY;
CREATE POLICY edu_select ON resume_education FOR SELECT USING (EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY edu_write ON resume_education FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
CREATE POLICY career_select ON resume_career FOR SELECT USING (EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY career_write ON resume_career FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
CREATE POLICY skills_select ON resume_skills FOR SELECT USING (EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY skills_write ON resume_skills FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
CREATE POLICY certs_select ON resume_certs FOR SELECT USING (EXISTS (SELECT 1 FROM resumes r WHERE r.id = resume_id));
CREATE POLICY certs_write ON resume_certs FOR ALL
    USING (resume_writable(resume_id)) WITH CHECK (resume_writable(resume_id));
