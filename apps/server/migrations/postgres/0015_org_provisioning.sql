-- Organisations, round two (plan 03, "SAML" and "SCIM provisioning"). Nothing here is a key either:
-- SCIM says who should be a member and in which groups, and SAML is one more way to pass the SSO
-- step after the master password. Vault keys still reach people only through signed grants.

-- SAML 2.0 beside OpenID Connect. protocol: oidc or saml. For saml, issuer is the IdP's entity id,
-- client_id is unused (''), saml_sso_url is its HTTP-Redirect SingleSignOnService, and
-- saml_certificates its signing certificates, base64 DER, one per line.
ALTER TABLE org_sso ADD COLUMN protocol TEXT NOT NULL DEFAULT 'oidc';
ALTER TABLE org_sso ADD COLUMN saml_sso_url TEXT;
ALTER TABLE org_sso ADD COLUMN saml_certificates TEXT;

-- SCIM bearer tokens, stored only as hashes. Each one can provision and deprovision members of one
-- organisation, and nothing else.
CREATE TABLE org_scim_tokens (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    created_by   TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX org_scim_tokens_org ON org_scim_tokens (org_id);

-- Users as the identity provider describes them. user_key is user_name lowercased (SCIM user
-- names don't depend on case); email is who gets the invite. account_id is set once that person is
-- a member, by email: provisioning invites, and only the person accepting makes them a member.
CREATE TABLE org_scim_users (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    user_name    TEXT NOT NULL,
    user_key     TEXT NOT NULL,
    email        TEXT NOT NULL,
    external_id  TEXT,
    display_name TEXT,
    active       BIGINT NOT NULL DEFAULT 1,
    account_id   TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL,
    UNIQUE (org_id, user_key)
);
CREATE INDEX org_scim_users_email ON org_scim_users (org_id, email);
CREATE INDEX org_scim_users_account ON org_scim_users (account_id);

-- Groups the identity provider manages. Their members follow the provider's list.
ALTER TABLE org_groups ADD COLUMN scim_managed BIGINT NOT NULL DEFAULT 0;
ALTER TABLE org_groups ADD COLUMN scim_external_id TEXT;

-- Who the provider put in each group, joined or not yet. Applied to org_group_members for those
-- who are members.
CREATE TABLE org_scim_group_members (
    group_id     TEXT NOT NULL REFERENCES org_groups (id) ON DELETE CASCADE,
    scim_user_id TEXT NOT NULL REFERENCES org_scim_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, scim_user_id)
);
CREATE INDEX org_scim_group_members_user ON org_scim_group_members (scim_user_id);
