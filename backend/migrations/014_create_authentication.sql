-- IntelSOC Authentication and User Management.
-- Additive migration: existing security tables remain unchanged.

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash TEXT,

    role VARCHAR(20) NOT NULL
        CHECK (role IN ('viewer', 'analyst', 'administrator')),

    status VARCHAR(20) NOT NULL DEFAULT 'invited'
        CHECK (status IN (
            'invited', 'active', 'suspended', 'deactivated'
        )),

    created_by UUID REFERENCES users(user_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,

    CONSTRAINT users_username_not_empty
        CHECK (LENGTH(TRIM(username)) > 0),

    CONSTRAINT users_email_not_empty
        CHECK (LENGTH(TRIM(email)) > 0),

    CONSTRAINT users_active_password_required
        CHECK (
            status <> 'active'
            OR (
                password_hash IS NOT NULL
                AND LENGTH(password_hash) > 0
            )
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique
    ON users (LOWER(TRIM(username)));

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
    ON users (LOWER(TRIM(email)));

CREATE INDEX IF NOT EXISTS idx_users_role_status
    ON users (role, status);


CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES users(user_id),

    token_hash CHAR(64) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT auth_sessions_token_hash_format
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT auth_sessions_valid_expiration
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
    ON auth_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiration
    ON auth_sessions (expires_at);


CREATE TABLE IF NOT EXISTS auth_tokens (
    token_id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES users(user_id),

    token_hash CHAR(64) NOT NULL UNIQUE,

    purpose VARCHAR(20) NOT NULL
        CHECK (purpose IN ('invitation', 'password_reset')),

    created_by UUID REFERENCES users(user_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT auth_tokens_hash_format
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT auth_tokens_valid_expiration
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_purpose
    ON auth_tokens (user_id, purpose);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_expiration
    ON auth_tokens (expires_at);


CREATE TABLE IF NOT EXISTS auth_audit_logs (
    audit_id UUID PRIMARY KEY,

    actor_user_id UUID REFERENCES users(user_id),
    target_user_id UUID REFERENCES users(user_id),

    event_type VARCHAR(64) NOT NULL,

    outcome VARCHAR(10) NOT NULL
        CHECK (outcome IN ('success', 'failure')),

    source_ip INET,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_created
    ON auth_audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_audit_actor
    ON auth_audit_logs (actor_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_audit_target
    ON auth_audit_logs (target_user_id, created_at DESC);
