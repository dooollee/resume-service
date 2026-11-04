-- M1: 사용자, 세션, 감사 로그
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email_bidx bytea NOT NULL UNIQUE,          -- 로그인 조회용 블라인드 인덱스
    email_enc bytea NOT NULL,
    dek_wrapped bytea NOT NULL,
    key_version int NOT NULL,
    password_hash text NOT NULL,               -- argon2id
    role text NOT NULL CHECK (role IN ('admin', 'recruiter', 'viewer')),
    mfa_secret_enc bytea,
    mfa_enabled boolean NOT NULL DEFAULT false,
    mfa_last_step bigint NOT NULL DEFAULT 0,   -- TOTP 재사용 방지
    recovery_codes bytea[] NOT NULL DEFAULT '{}',  -- SHA-256 해시
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until timestamptz,
    must_change_password boolean NOT NULL DEFAULT true,
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,          -- 토큰 원문은 저장하지 않음
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mfa_ok boolean NOT NULL DEFAULT false,
    csrf_token text NOT NULL,
    ip text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    stepup_at timestamptz
);
CREATE INDEX ON sessions (user_id);

CREATE TABLE audit_logs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts timestamptz NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    ip text,
    user_agent text,
    reason text,
    detail jsonb,
    prev_hash bytea NOT NULL,
    hash bytea NOT NULL
);
CREATE INDEX ON audit_logs (actor_id, ts);
CREATE INDEX ON audit_logs (action, ts);

-- append-only: 앱 계정 권한 회수 + 소유자라도 트리거로 차단
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM resume_app;
CREATE FUNCTION audit_logs_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END $$;
CREATE TRIGGER audit_logs_no_modify BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();
