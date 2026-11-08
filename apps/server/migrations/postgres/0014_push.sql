-- Push sync (plan 04, "Push relay"). Where each signed-in device can be woken up: one token per
-- device, and a token belongs to the device that registered it last. A push carries nothing but
-- "sync" or "alert", so this table is the only thing push adds about a device.
CREATE TABLE push_tokens (
    device_id  TEXT PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- apns or fcm
    platform   TEXT NOT NULL,
    token      TEXT NOT NULL UNIQUE,
    -- 1 for an APNs development build (Apple's sandbox), else 0.
    sandbox    BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX push_tokens_account ON push_tokens (account_id);

-- This server's registration with a push relay, made once per relay address. The key lets the
-- server send wakeups through the relay and nothing else.
CREATE TABLE push_relay_installations (
    relay_url        TEXT PRIMARY KEY,
    installation_id  TEXT NOT NULL,
    installation_key TEXT NOT NULL,
    created_at       BIGINT NOT NULL
);
