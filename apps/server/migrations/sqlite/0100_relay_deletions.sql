-- Accounts the masked email relay still has to forget. A row is written in the transaction that
-- deletes the account, and removed once the relay has confirmed. Only used with a relay configured.
-- Numbered 0100 so it can't collide with another branch's next migration.
CREATE TABLE relay_deletions (
    account_id TEXT PRIMARY KEY NOT NULL,
    attempts BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL
);
