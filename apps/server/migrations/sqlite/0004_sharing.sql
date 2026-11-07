-- Sharing: shared and family vaults, families, one-time share links, emergency
-- access and the account's own security log.

-- Shared and family vaults. key_id identifies the current vault key (item keys
-- wrapped under any other key are refused). Grants are made and signed on the
-- granter's device; the server keeps them exactly as sent, plus the granter's
-- signing key at the time, so members can verify them later.
ALTER TABLE vaults ADD COLUMN key_id TEXT;
ALTER TABLE vault_members ADD COLUMN granted_by TEXT;
ALTER TABLE vault_members ADD COLUMN granter_sign_key TEXT;
ALTER TABLE vault_members ADD COLUMN granted_at BIGINT;
ALTER TABLE vault_members ADD COLUMN signature TEXT;

-- One family per account. The organiser is also a member.
CREATE TABLE families (
    id           TEXT PRIMARY KEY,
    organiser_id TEXT NOT NULL UNIQUE REFERENCES accounts (id) ON DELETE CASCADE,
    vault_id     TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    created_at   BIGINT NOT NULL
);

CREATE TABLE family_members (
    family_id  TEXT NOT NULL REFERENCES families (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL UNIQUE REFERENCES accounts (id) ON DELETE CASCADE,
    joined_at  BIGINT NOT NULL,
    PRIMARY KEY (family_id, account_id)
);

-- An invite carries the invitee's grant to the Family vault, so accepting
-- needs nothing more from the organiser.
CREATE TABLE family_invites (
    family_id         TEXT NOT NULL REFERENCES families (id) ON DELETE CASCADE,
    account_id        TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role              TEXT NOT NULL,
    wrapped_vault_key TEXT NOT NULL,
    granted_by        TEXT NOT NULL,
    granter_sign_key  TEXT NOT NULL,
    granted_at        BIGINT NOT NULL,
    signature         TEXT NOT NULL,
    invited_at        BIGINT NOT NULL,
    PRIMARY KEY (family_id, account_id)
);
CREATE INDEX family_invites_account ON family_invites (account_id);

-- The key that opens the ciphertext lives only in the link's fragment.
-- passphrase_required is 0 or 1.
CREATE TABLE share_links (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    ciphertext          TEXT NOT NULL,
    passphrase_required BIGINT NOT NULL,
    max_views           BIGINT NOT NULL,
    views               BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    created_at          BIGINT NOT NULL
);
CREATE INDEX share_links_account ON share_links (account_id);
CREATE INDEX share_links_expires_at ON share_links (expires_at);

-- scope_vault_id is NULL when the sealed key is the grantor's account key.
-- status: idle, requested or released.
CREATE TABLE emergency_contacts (
    id               TEXT PRIMARY KEY,
    grantor_id       TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    contact_id       TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    scope_vault_id   TEXT REFERENCES vaults (id) ON DELETE CASCADE,
    access_level     TEXT NOT NULL,
    wait_days        BIGINT NOT NULL,
    sealed_key       TEXT NOT NULL,
    status           TEXT NOT NULL,
    requested_at     BIGINT,
    releases_at      BIGINT,
    released_at      BIGINT,
    last_reminded_at BIGINT,
    created_at       BIGINT NOT NULL,
    UNIQUE (grantor_id, contact_id)
);
CREATE INDEX emergency_contacts_contact ON emergency_contacts (contact_id);
CREATE INDEX emergency_contacts_status ON emergency_contacts (status, releases_at);

-- The account's own security log. other_account_id is cleared when that
-- account is deleted.
CREATE TABLE audit_events (
    id                   TEXT PRIMARY KEY,
    account_id           TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    event_type           TEXT NOT NULL,
    other_account_id     TEXT,
    emergency_contact_id TEXT,
    created_at           BIGINT NOT NULL
);
CREATE INDEX audit_events_account ON audit_events (account_id, created_at);
CREATE INDEX audit_events_other ON audit_events (other_account_id);
