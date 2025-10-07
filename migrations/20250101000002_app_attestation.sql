-- App Attestation tables migration
-- Creates tables for iOS App Attestation challenge/verify flow

CREATE TABLE IF NOT EXISTS app_attest_challenges (
    id UUID PRIMARY KEY,
    challenge TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_attest_keys (
    key_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_app_attest_challenges_expires ON app_attest_challenges(expires_at);
CREATE INDEX idx_app_attest_keys_bundle ON app_attest_keys(bundle_id);
