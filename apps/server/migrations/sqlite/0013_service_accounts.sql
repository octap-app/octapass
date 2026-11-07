-- Service accounts (plan 03, "Non-human access"): a vault member that isn't a person. The token
-- never reaches the server: it keeps the public keys, the grant exactly as the creator's device
-- signed it, and a name only the creator can open. revoked_at keeps the row so the security log
-- can still name it.
CREATE TABLE service_accounts (
    id                TEXT PRIMARY KEY,
    vault_id          TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    created_by        TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role              TEXT NOT NULL,
    public_enc_key    TEXT NOT NULL,
    public_sign_key   TEXT NOT NULL,
    encrypted_name    TEXT NOT NULL,
    wrapped_vault_key TEXT NOT NULL,
    granted_by        TEXT NOT NULL,
    granter_sign_key  TEXT NOT NULL,
    granted_at        BIGINT NOT NULL,
    signature         TEXT NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT,
    last_used_at      BIGINT,
    revoked_at        BIGINT
);
CREATE INDEX service_accounts_vault ON service_accounts (vault_id);
CREATE INDEX service_accounts_created_by ON service_accounts (created_by);

-- Tokens are stored only as hashes, like device sessions.
CREATE TABLE service_account_sessions (
    token_hash         TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    expires_at         BIGINT NOT NULL
);
CREATE INDEX service_account_sessions_account ON service_account_sessions (service_account_id);
CREATE INDEX service_account_sessions_expires ON service_account_sessions (expires_at);

-- Security log: which service account, and a blob only the account can open (what Octa Pass
-- Connect handed out, and to which client).
ALTER TABLE audit_events ADD COLUMN service_account_id TEXT;
ALTER TABLE audit_events ADD COLUMN sealed_detail TEXT;
