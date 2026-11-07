-- Emergency access: a rotation leaves a vault-scoped contact's sealed key on the
-- old vault key until the grantor renews it (key_stale is 0 or 1), and organiser
-- recovery is an emergency record the family's organiser holds (organiser_recovery
-- is 0 or 1): it allows the reset and no reading.
ALTER TABLE emergency_contacts ADD COLUMN key_stale BIGINT NOT NULL DEFAULT 0;
ALTER TABLE emergency_contacts ADD COLUMN organiser_recovery BIGINT NOT NULL DEFAULT 0;
