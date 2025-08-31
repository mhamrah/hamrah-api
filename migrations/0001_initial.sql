CREATE TABLE IF NOT EXISTS migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT,
    picture TEXT,
    email_verified INTEGER,
    auth_method TEXT,
    provider TEXT,
    provider_id TEXT,
    last_login_platform TEXT,
    last_login_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    aaguid TEXT,
    credential_type TEXT NOT NULL DEFAULT 'public-key',
    user_verified INTEGER NOT NULL DEFAULT 0,
    credential_device_type TEXT,
    credential_backed_up INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    last_used INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE webauthn_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    user_id TEXT,
    type TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE auth_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    platform TEXT NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX auth_tokens_user_revoked_expires_idx ON auth_tokens(user_id, revoked, access_expires_at);
CREATE INDEX auth_tokens_expiration_idx ON auth_tokens(access_expires_at);
CREATE INDEX auth_tokens_refresh_expiration_idx ON auth_tokens(refresh_expires_at);
CREATE INDEX auth_tokens_user_platform_idx ON auth_tokens(user_id, platform);
