-- Octa Pass servers that may send wakeups through this relay. An installation is a server, not a
-- person: nothing here names an account, a device or a push token. Tokens pass through in memory
-- and are never stored.
CREATE TABLE installations (
    id TEXT PRIMARY KEY NOT NULL,
    -- SHA-256 of the installation key; the key itself is only ever with the server.
    key_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT,
    -- Set by `octapass-push-relay admin revoke`; the server is then refused.
    revoked_at BIGINT
);
