-- Running totals per vault for storage quotas: items stored (trash included)
-- and the bytes of their ciphertext as stored (base64url text).
ALTER TABLE vaults ADD COLUMN item_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN item_bytes BIGINT NOT NULL DEFAULT 0;
UPDATE vaults SET
    item_count = (SELECT COUNT(*) FROM items WHERE items.vault_id = vaults.id),
    item_bytes = (SELECT COALESCE(SUM(LENGTH(encrypted_item_key) + LENGTH(overview) + LENGTH(details)), 0)
                  FROM items WHERE items.vault_id = vaults.id);
