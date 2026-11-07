-- Daily sign-up counters per email: verification codes sent and wrong codes
-- tried. Keyed by an HMAC of the email under the server secret, so the table
-- holds no addresses. Rows are purged once their UTC day is over.
CREATE TABLE signup_counters (
    email_key  TEXT NOT NULL,
    day        TEXT NOT NULL,
    codes_sent BIGINT NOT NULL,
    failures   BIGINT NOT NULL,
    PRIMARY KEY (email_key, day)
);
