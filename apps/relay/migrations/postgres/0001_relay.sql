-- Who an alias forwards to and how it is doing. No subject, body, site or description is ever
-- stored: those stay in the user's encrypted vault or never arrive at all.
CREATE TABLE relay_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    -- The account's verified email, sealed with a key from the relay secret.
    destination_sealed TEXT NOT NULL,
    -- HMAC of the address, to recognise it as a sender without opening it.
    destination_hash TEXT NOT NULL,
    paused_at BIGINT,
    hard_bounces BIGINT NOT NULL DEFAULT 0,
    soft_bounces BIGINT NOT NULL DEFAULT 0,
    complaints BIGINT NOT NULL DEFAULT 0,
    window_started_at BIGINT NOT NULL,
    aliases_today BIGINT NOT NULL DEFAULT 0,
    aliases_day TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE TABLE relay_aliases (
    local TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES relay_accounts (id) ON DELETE CASCADE,
    enabled BIGINT NOT NULL DEFAULT 1,
    paused_at BIGINT,
    forwarded BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    replied BIGINT NOT NULL DEFAULT 0,
    hard_bounces BIGINT NOT NULL DEFAULT 0,
    soft_bounces BIGINT NOT NULL DEFAULT 0,
    complaints BIGINT NOT NULL DEFAULT 0,
    window_started_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX relay_aliases_account ON relay_aliases (account_id);

-- One reverse alias per (alias, external sender), for reply-through.
CREATE TABLE relay_contacts (
    reverse_local TEXT PRIMARY KEY NOT NULL,
    alias_local TEXT NOT NULL REFERENCES relay_aliases (local) ON DELETE CASCADE,
    sender_hash TEXT NOT NULL,
    sender_sealed TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (alias_local, sender_hash)
);

CREATE TABLE relay_blocked_senders (
    alias_local TEXT NOT NULL REFERENCES relay_aliases (local) ON DELETE CASCADE,
    sender_hash TEXT NOT NULL,
    PRIMARY KEY (alias_local, sender_hash)
);
