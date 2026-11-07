-- Two-step sign-in: a second step when signing in on a new device. It protects
-- access to the ciphertext and is not part of the encryption.

-- One row while two-step sign-in is on. The authenticator secret is sealed
-- under a key derived from the server secret (XChaCha20-Poly1305, the account
-- id as associated data), so a database copy alone doesn't reveal it.
-- totp_last_step is the last accepted 30-second step: codes can't be replayed.
CREATE TABLE two_step (
    account_id     TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    totp_secret    TEXT NOT NULL,
    totp_last_step BIGINT NOT NULL,
    enabled_at     BIGINT NOT NULL
);

-- WebAuthn credentials. public_key is the raw key (an uncompressed P-256 point
-- for ES256, 32 bytes for Ed25519), base64url.
CREATE TABLE security_keys (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    algorithm     BIGINT NOT NULL,
    public_key    TEXT NOT NULL,
    sign_count    BIGINT NOT NULL,
    name          TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    last_used_at  BIGINT,
    UNIQUE (account_id, credential_id)
);

-- Single-use recovery codes, stored as HMACs under the server secret.
CREATE TABLE recovery_codes (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    PRIMARY KEY (account_id, code_hash)
);

-- A method being added: an authenticator secret waiting for its first code
-- (sealed like totp_secret), or a WebAuthn registration challenge.
CREATE TABLE two_step_setups (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    secret     TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX two_step_setups_account ON two_step_setups (account_id);

-- Devices that finished signing in. A device that sends its token with a later
-- login skips the second step. device_id is the device the token was last
-- issued to; signing that device out forgets the token.
CREATE TABLE trusted_devices (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX trusted_devices_account ON trusted_devices (account_id);
CREATE INDEX trusted_devices_device ON trusted_devices (device_id);
