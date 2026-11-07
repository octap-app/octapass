-- Octa Pass sync server schema, version 1.
-- Kept to portable SQL (TEXT, BIGINT, INTEGER) so a Postgres migration can mirror it.
-- Times are Unix milliseconds. Binary values are stored as the base64url text clients send.

CREATE TABLE accounts (
    id                   TEXT PRIMARY KEY,
    email                TEXT NOT NULL UNIQUE,
    kdf_memory_kib       INTEGER NOT NULL,
    kdf_iterations       INTEGER NOT NULL,
    kdf_parallelism      INTEGER NOT NULL,
    account_salt         TEXT NOT NULL,
    opaque_record        TEXT NOT NULL,
    wrapped_ask          TEXT NOT NULL,
    public_enc_key       TEXT NOT NULL,
    public_sign_key      TEXT NOT NULL,
    wrapped_private_keys TEXT NOT NULL,
    recovery_wrapped_ask TEXT NOT NULL,
    email_verified_at    BIGINT NOT NULL,
    created_at           BIGINT NOT NULL
);

-- One outstanding sign-up per email. The code is stored as an HMAC under the server secret.
CREATE TABLE pending_registrations (
    email      TEXT PRIMARY KEY,
    code_hash  TEXT NOT NULL,
    attempts   INTEGER NOT NULL,
    expires_at BIGINT NOT NULL
);

-- Emails allowed to sign up when OCTAPASS_SIGNUPS=invite.
CREATE TABLE invites (
    email      TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL
);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    revoked_at   BIGINT
);
CREATE INDEX devices_account ON devices (account_id);

-- Tokens are stored only as SHA-256 hashes.
CREATE TABLE sessions (
    id                          TEXT PRIMARY KEY,
    account_id                  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id                   TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    access_token_hash           TEXT NOT NULL UNIQUE,
    access_expires_at           BIGINT NOT NULL,
    refresh_token_hash          TEXT NOT NULL UNIQUE,
    previous_refresh_token_hash TEXT UNIQUE,
    refresh_expires_at          BIGINT NOT NULL,
    created_at                  BIGINT NOT NULL
);
CREATE INDEX sessions_device ON sessions (device_id);

CREATE TABLE vaults (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    revision   BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE vault_members (
    vault_id          TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    account_id        TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role              TEXT NOT NULL,
    wrapped_vault_key TEXT NOT NULL,
    added_at          BIGINT NOT NULL,
    PRIMARY KEY (vault_id, account_id)
);
CREATE INDEX vault_members_account ON vault_members (account_id);

-- revision is the vault revision of the item's last change.
CREATE TABLE items (
    vault_id           TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    id                 TEXT NOT NULL,
    revision           BIGINT NOT NULL,
    encrypted_item_key TEXT NOT NULL,
    overview           TEXT NOT NULL,
    details            TEXT NOT NULL,
    updated_at         BIGINT NOT NULL,
    deleted_at         BIGINT,
    PRIMARY KEY (vault_id, id)
);
CREATE INDEX items_vault_revision ON items (vault_id, revision);
CREATE INDEX items_deleted_at ON items (deleted_at);

-- Items purged from the trash, kept 90 days so other devices learn about them.
CREATE TABLE tombstones (
    vault_id  TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    item_id   TEXT NOT NULL,
    revision  BIGINT NOT NULL,
    purged_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, item_id)
);
CREATE INDEX tombstones_vault_revision ON tombstones (vault_id, revision);

-- Proof of a fresh master-password login, required for dangerous actions. Single use.
CREATE TABLE reauth_tokens (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX reauth_tokens_account ON reauth_tokens (account_id);

-- Hashes of the tokens a deleted account still had out, so its other devices
-- get "account deleted" instead of a generic 401. Holds no account id, email
-- or device data, and each row expires with its token.
CREATE TABLE deleted_account_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

-- The only trace a deleted account leaves: an anonymous count per UTC day.
CREATE TABLE account_deletions_daily (
    day   TEXT PRIMARY KEY,
    count BIGINT NOT NULL
);
