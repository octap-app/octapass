-- Witnesses for the key log (plan 03, "Witnesses"): the tree size each witness last cosigned, so
-- the next checkpoint goes with the right consistency proof, and the newest checkpoint enough of
-- them cosigned, which clients get with every head. Both are rebuilt by the next round if lost.
CREATE TABLE key_log_witness_sizes (
    vkey      TEXT PRIMARY KEY,
    tree_size BIGINT NOT NULL
);

CREATE TABLE key_log_witnessed (
    id         BIGINT PRIMARY KEY,
    tree_size  BIGINT NOT NULL,
    checkpoint TEXT NOT NULL
);
