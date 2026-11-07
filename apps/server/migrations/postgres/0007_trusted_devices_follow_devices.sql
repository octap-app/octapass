-- Trust can't outlive its device: a trusted device whose device row is
-- purged (signed out, or its session lapsed) or revoked is forgotten, so
-- every trusted device shows in the account's device list. Tokens are capped
-- at 30 days, like refresh tokens.
DELETE FROM trusted_devices t
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.id = t.device_id AND d.revoked_at IS NULL);
UPDATE trusted_devices SET expires_at = created_at + 2592000000
    WHERE expires_at > created_at + 2592000000;
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_device_fkey
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE;
