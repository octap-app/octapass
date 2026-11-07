-- Attachments: encrypted files kept with items. The server knows only each
-- file's stored size; its name, type and key are in the item's encrypted
-- details. object_key names the file in storage and is random, unrelated to
-- any id. Rows must go before their item (no cascade), so that every path that
-- removes items also queues their files for deletion.
CREATE TABLE attachments (
    vault_id   TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    id         TEXT NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    size       BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, item_id, id),
    FOREIGN KEY (vault_id, item_id) REFERENCES items (vault_id, id)
);

-- Files to delete from storage, retried with backoff until storage confirms.
-- Holds object keys only, nothing that links them to an account.
CREATE TABLE attachment_deletions (
    object_key      TEXT PRIMARY KEY,
    attempts        BIGINT NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL
);
CREATE INDEX attachment_deletions_due ON attachment_deletions (next_attempt_at);

-- Running total per vault for the attachment quota, counted like item_bytes.
ALTER TABLE vaults ADD COLUMN attachment_bytes BIGINT NOT NULL DEFAULT 0;
