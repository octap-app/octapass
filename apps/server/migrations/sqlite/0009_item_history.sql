-- Past versions of an item (plan 01): the last 10, as ciphertext, under the item's own key, which
-- doesn't change when the item is edited. They go with their item, and with its vault.
CREATE TABLE item_history (
    vault_id   TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    revision   BIGINT NOT NULL,
    overview   TEXT NOT NULL,
    details    TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, item_id, revision),
    FOREIGN KEY (vault_id, item_id) REFERENCES items (vault_id, id) ON DELETE CASCADE
);
