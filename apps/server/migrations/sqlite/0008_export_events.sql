-- "Vault exported" in the security log: the device's name and platform as they were when it
-- exported (its device row goes when it signs out), the format, and whether the file holds the
-- attachments (0 or 1). Nothing from the vault itself.
ALTER TABLE audit_events ADD COLUMN device_name TEXT;
ALTER TABLE audit_events ADD COLUMN device_platform TEXT;
ALTER TABLE audit_events ADD COLUMN export_format TEXT;
ALTER TABLE audit_events ADD COLUMN export_attachments BIGINT;
