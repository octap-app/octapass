-- Trust can't outlive its device: a trusted device whose device row is
-- purged (signed out, or its session lapsed) or revoked is forgotten, so
-- every trusted device shows in the account's device list. Tokens are capped
-- at 30 days, like refresh tokens.
CREATE TABLE trusted_devices_new (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
INSERT INTO trusted_devices_new (token_hash, account_id, device_id, created_at, expires_at)
    SELECT t.token_hash, t.account_id, t.device_id, t.created_at,
           MIN(t.expires_at, t.created_at + 2592000000)
    FROM trusted_devices t
    WHERE EXISTS (SELECT 1 FROM devices d WHERE d.id = t.device_id AND d.revoked_at IS NULL);
DROP TABLE trusted_devices;
ALTER TABLE trusted_devices_new RENAME TO trusted_devices;
CREATE INDEX trusted_devices_account ON trusted_devices (account_id);
CREATE INDEX trusted_devices_device ON trusted_devices (device_id);
