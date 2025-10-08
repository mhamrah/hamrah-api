-- WebAuthn support migration
-- Creates tables for passkey credentials and challenge storage

-- WebAuthn credentials (passkeys)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,  -- base64url credential ID
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,  -- COSE public key bytes
    counter BIGINT NOT NULL DEFAULT 0,
    name TEXT,  -- User-friendly device name
    transports TEXT[],  -- Array of transport types (usb, nfc, ble, internal)
    aaguid BYTEA,  -- Authenticator AAGUID
    credential_type TEXT DEFAULT 'public-key',
    user_verified BOOLEAN DEFAULT false,
    credential_device_type TEXT,  -- singleDevice or multiDevice
    credential_backed_up BOOLEAN DEFAULT false,
    last_used TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credentials_last_used ON webauthn_credentials(last_used DESC);

-- WebAuthn challenges (temporary storage for registration/authentication)
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,  -- opaque challenge ID
    challenge TEXT NOT NULL,  -- base64url challenge
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,  -- NULL for discoverable auth
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication', 'discoverable_authentication')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_challenges_expires_at ON webauthn_challenges(expires_at);
CREATE INDEX idx_webauthn_challenges_user_id ON webauthn_challenges(user_id) WHERE user_id IS NOT NULL;
