-- Organisations: teams built on shared vaults (plan 03, "Organisations and single sign-on").
-- Nothing here is a key. An organisation vault is a shared vault with org_id set, and
-- vault keys still reach people only through the signed grants in vault_members.

-- One row per organisation. The policy columns are 0 or 1 unless noted.
-- sso_max_age_hours: how long a sign-in with SSO lasts; 0 checks only at sign-in.
-- max_auto_lock_minutes and min_password_length are applied by clients and can be NULL.
CREATE TABLE organisations (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    require_two_step         BIGINT NOT NULL DEFAULT 0,
    require_sso              BIGINT NOT NULL DEFAULT 0,
    sso_max_age_hours        BIGINT NOT NULL DEFAULT 168,
    disable_share_links      BIGINT NOT NULL DEFAULT 0,
    disable_emergency_access BIGINT NOT NULL DEFAULT 0,
    disable_export           BIGINT NOT NULL DEFAULT 0,
    max_auto_lock_minutes    BIGINT,
    min_password_length      BIGINT,
    created_at               BIGINT NOT NULL
);

-- One organisation per account, as with families. role: owner, admin or member.
CREATE TABLE org_members (
    org_id     TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL UNIQUE REFERENCES accounts (id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    joined_at  BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);

-- Invites hold no key, so they can name an email with no account yet. role: admin or member.
CREATE TABLE org_invites (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    role       TEXT NOT NULL,
    invited_by TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    invited_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    UNIQUE (org_id, email)
);
CREATE INDEX org_invites_email ON org_invites (email);

-- Groups are lists of people, not key holders.
CREATE TABLE org_groups (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (org_id, name)
);

CREATE TABLE org_group_members (
    group_id   TEXT NOT NULL REFERENCES org_groups (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, account_id)
);
CREATE INDEX org_group_members_account ON org_group_members (account_id);

ALTER TABLE vaults ADD COLUMN org_id TEXT REFERENCES organisations (id);
CREATE INDEX vaults_org ON vaults (org_id);

-- Who should have a vault: its linked groups, people added to it directly and the
-- organisation owners. Only a key holder can turn that into a grant.
CREATE TABLE org_vault_groups (
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES org_groups (id) ON DELETE CASCADE,
    role     TEXT NOT NULL,
    PRIMARY KEY (vault_id, group_id)
);
CREATE INDEX org_vault_groups_group ON org_vault_groups (group_id);

CREATE TABLE org_vault_direct (
    vault_id   TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    PRIMARY KEY (vault_id, account_id)
);
CREATE INDEX org_vault_direct_account ON org_vault_direct (account_id);

-- Vaults someone lost access to, until a key holder rotates the key.
CREATE TABLE org_rotations (
    vault_id TEXT PRIMARY KEY REFERENCES vaults (id) ON DELETE CASCADE,
    since    BIGINT NOT NULL
);

-- The OpenID Connect client. client_secret is sealed under the server secret, and NULL for a
-- public client. tested_at is set by a finished test sign-in, and cleared by any change.
CREATE TABLE org_sso (
    org_id        TEXT PRIMARY KEY REFERENCES organisations (id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT,
    tested_at     BIGINT,
    updated_at    BIGINT NOT NULL
);

-- Which IdP subject is which member. It only ever satisfies the SSO step for that account.
CREATE TABLE org_sso_identities (
    org_id     TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    linked_at  BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id),
    UNIQUE (org_id, subject)
);
CREATE INDEX org_sso_identities_account ON org_sso_identities (account_id);

-- The admin activity log. actor_id is cleared when that account is deleted.
CREATE TABLE org_events (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    actor_id   TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    subject    TEXT,
    created_at BIGINT NOT NULL
);
CREATE INDEX org_events_org ON org_events (org_id, created_at);

-- When SSO last passed for this session. NULL: never.
ALTER TABLE sessions ADD COLUMN sso_at BIGINT;

-- Memberships the server may serve: all of them, except organisation vaults while the member
-- breaks the two-step policy. Reads and writes of vault contents go through this view.
CREATE VIEW vault_access AS
SELECT m.vault_id, m.account_id, m.role, m.wrapped_vault_key, m.added_at, m.granted_by,
       m.granter_sign_key, m.granted_at, m.signature
FROM vault_members m
JOIN vaults v ON v.id = m.vault_id
WHERE v.org_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM organisations o
    WHERE o.id = v.org_id AND o.require_two_step = 1
      AND NOT EXISTS (SELECT 1 FROM two_step t WHERE t.account_id = m.account_id)
);
