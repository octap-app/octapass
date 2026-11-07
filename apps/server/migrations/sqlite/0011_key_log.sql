-- The key log (plan 03): an append-only Merkle tree of account public keys, with each account's
-- ML-KEM key and key record. Text columns hold base64url. A leaf is two hashes and stays when its
-- account is deleted; the record behind it goes.
ALTER TABLE accounts ADD COLUMN wrapped_pq_private_key TEXT;
ALTER TABLE accounts ADD COLUMN key_record TEXT;

CREATE TABLE key_log_state (
    id        BIGINT PRIMARY KEY,
    tree_size BIGINT NOT NULL
);
INSERT INTO key_log_state (id, tree_size) VALUES (1, 0);

CREATE TABLE key_log_leaves (
    leaf_index  BIGINT PRIMARY KEY,
    label       TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    record      TEXT,
    account_id  TEXT
);
CREATE INDEX key_log_leaves_label ON key_log_leaves (label, leaf_index);
CREATE INDEX key_log_leaves_account ON key_log_leaves (account_id);

-- Every perfect subtree the tree has completed: proofs are built from these.
CREATE TABLE key_log_nodes (
    level BIGINT NOT NULL,
    idx   BIGINT NOT NULL,
    hash  TEXT NOT NULL,
    PRIMARY KEY (level, idx)
);
