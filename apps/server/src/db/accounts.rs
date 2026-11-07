//! Accounts, pending sign-ups and invites.

use octapass_api::{AccountBundle, CredentialsUpdate, KdfAlgorithm, KdfParams, KeyRecord};
use sqlx::FromRow;

use super::{Conn, Db};

#[derive(FromRow)]
pub struct AccountRow {
    pub id: String,
    pub email: String,
    kdf_memory_kib: i64,
    kdf_iterations: i64,
    kdf_parallelism: i64,
    pub account_salt: String,
    pub opaque_record: String,
    wrapped_ask: String,
    public_enc_key: String,
    pub public_sign_key: String,
    wrapped_private_keys: String,
    recovery_wrapped_ask: String,
    wrapped_pq_private_key: Option<String>,
    key_record: Option<String>,
}

impl AccountRow {
    pub fn kdf(&self) -> KdfParams {
        // Values were range-checked on the way in, so they fit in u32.
        let to_u32 = |v: i64| u32::try_from(v).expect("stored KDF parameter fits in u32");
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: to_u32(self.kdf_memory_kib),
            iterations: to_u32(self.kdf_iterations),
            parallelism: to_u32(self.kdf_parallelism),
        }
    }

    pub fn into_bundle(self) -> AccountBundle {
        AccountBundle {
            kdf: self.kdf(),
            account_id: Some(self.id),
            email: self.email,
            account_salt: self.account_salt,
            wrapped_ask: self.wrapped_ask,
            public_enc_key: self.public_enc_key,
            public_sign_key: self.public_sign_key,
            wrapped_private_keys: self.wrapped_private_keys,
            recovery_wrapped_ask: self.recovery_wrapped_ask,
            wrapped_pq_private_key: self.wrapped_pq_private_key,
            key_record: self.key_record.as_deref().map(key_record),
        }
    }
}

/// A stored key record. Only `POST /v1/transparency/publish` writes them.
pub fn key_record(json: &str) -> KeyRecord {
    serde_json::from_str(json).expect("stored key records are valid JSON")
}

macro_rules! select_account {
    ($filter:literal) => {
        concat!(
            "SELECT id, email, kdf_memory_kib, kdf_iterations, kdf_parallelism, account_salt, opaque_record, ",
            "wrapped_ask, public_enc_key, public_sign_key, wrapped_private_keys, recovery_wrapped_ask, ",
            "wrapped_pq_private_key, key_record ",
            "FROM accounts WHERE ",
            $filter
        )
    };
}

pub async fn find_by_email(db: &Db, email: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    sqlx::query_as(select_account!("email = $1"))
        .bind(email)
        .fetch_optional(db)
        .await
}

pub async fn find_by_id(db: &Db, id: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    sqlx::query_as(select_account!("id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn email_for(conn: &mut Conn, id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_optional(conn)
        .await
}

pub async fn email_exists<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    email: &str,
) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = $1")
        .bind(email)
        .fetch_optional(executor)
        .await?;
    Ok(found.is_some())
}

/// A validated sign-up, ready to store.
pub struct NewAccount<'a> {
    pub id: &'a str,
    /// Normalised; `bundle.email` is whatever the client sent.
    pub email: &'a str,
    pub bundle: &'a AccountBundle,
    pub opaque_record: &'a str,
    pub now: i64,
}

pub async fn insert(conn: &mut Conn, account: NewAccount<'_>) -> Result<(), sqlx::Error> {
    let NewAccount {
        id,
        email,
        bundle,
        opaque_record,
        now,
    } = account;
    sqlx::query(
        "INSERT INTO accounts (id, email, kdf_memory_kib, kdf_iterations, kdf_parallelism, account_salt, \
         opaque_record, wrapped_ask, public_enc_key, public_sign_key, wrapped_private_keys, recovery_wrapped_ask, \
         email_verified_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)",
    )
    .bind(id)
    .bind(email)
    .bind(i64::from(bundle.kdf.memory_kib))
    .bind(i64::from(bundle.kdf.iterations))
    .bind(i64::from(bundle.kdf.parallelism))
    .bind(&bundle.account_salt)
    .bind(opaque_record)
    .bind(&bundle.wrapped_ask)
    .bind(&bundle.public_enc_key)
    .bind(&bundle.public_sign_key)
    .bind(&bundle.wrapped_private_keys)
    .bind(&bundle.recovery_wrapped_ask)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Stores a new code for this email. Wrong guesses at an unexpired earlier
/// code still count, so asking for a new code doesn't buy more guesses.
pub async fn upsert_pending(
    db: &Db,
    email: &str,
    code_hash: &str,
    now: i64,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pending_registrations (email, code_hash, attempts, expires_at) VALUES ($1, $2, 0, $3) \
         ON CONFLICT (email) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, \
         attempts = CASE WHEN pending_registrations.expires_at > $4 THEN pending_registrations.attempts ELSE 0 END",
    )
    .bind(email)
    .bind(code_hash)
    .bind(expires_at)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

/// Uses up one attempt at the email's code and returns its hash, or `None`
/// if there's no unexpired code with attempts left. A single statement, so
/// concurrent guesses can't share an attempt.
pub async fn take_attempt(
    db: &Db,
    email: &str,
    max_attempts: i64,
    now: i64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE pending_registrations SET attempts = attempts + 1 \
         WHERE email = $1 AND attempts < $2 AND expires_at > $3 RETURNING code_hash",
    )
    .bind(email)
    .bind(max_attempts)
    .bind(now)
    .fetch_optional(db)
    .await
}

/// The stored salt and public signing key, read inside a transaction that's about to replace
/// them, so a signature is checked against what's really being replaced.
pub async fn signing_state(
    conn: &mut Conn,
    id: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT account_salt, public_sign_key FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_optional(conn)
        .await
}

/// Replaces what depends on the master password: the OPAQUE record and the
/// AUK-wrapped ASK, and the recovery-wrapped ASK when the update has one.
pub async fn replace_credentials(
    conn: &mut Conn,
    id: &str,
    opaque_record: &str,
    update: &CredentialsUpdate,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE accounts SET opaque_record = $1, kdf_memory_kib = $2, kdf_iterations = $3, \
         kdf_parallelism = $4, account_salt = $5, wrapped_ask = $6, \
         recovery_wrapped_ask = COALESCE($7, recovery_wrapped_ask) WHERE id = $8",
    )
    .bind(opaque_record)
    .bind(i64::from(update.kdf.memory_kib))
    .bind(i64::from(update.kdf.iterations))
    .bind(i64::from(update.kdf.parallelism))
    .bind(&update.account_salt)
    .bind(&update.wrapped_ask)
    .bind(update.recovery_wrapped_ask.as_deref())
    .bind(id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Counts a verification code sent today. Returns `false`, counting
/// nothing, once `cap` codes went out.
pub async fn count_code_sent(
    db: &Db,
    email_key: &str,
    day: &str,
    cap: i64,
) -> Result<bool, sqlx::Error> {
    let sent: Option<i64> = sqlx::query_scalar(
        "INSERT INTO signup_counters (email_key, day, codes_sent, failures) VALUES ($1, $2, 1, 0) \
         ON CONFLICT (email_key, day) DO UPDATE SET codes_sent = signup_counters.codes_sent + 1 \
         WHERE signup_counters.codes_sent < $3 RETURNING codes_sent",
    )
    .bind(email_key)
    .bind(day)
    .bind(cap)
    .fetch_optional(db)
    .await?;
    Ok(sent.is_some())
}

pub async fn failures_today(db: &Db, email_key: &str, day: &str) -> Result<i64, sqlx::Error> {
    let failures: Option<i64> = sqlx::query_scalar(
        "SELECT failures FROM signup_counters WHERE email_key = $1 AND day = $2",
    )
    .bind(email_key)
    .bind(day)
    .fetch_optional(db)
    .await?;
    Ok(failures.unwrap_or(0))
}

pub async fn count_failure(db: &Db, email_key: &str, day: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO signup_counters (email_key, day, codes_sent, failures) VALUES ($1, $2, 0, 1) \
         ON CONFLICT (email_key, day) DO UPDATE SET failures = signup_counters.failures + 1",
    )
    .bind(email_key)
    .bind(day)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_counters(conn: &mut Conn, email_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM signup_counters WHERE email_key = $1")
        .bind(email_key)
        .execute(conn)
        .await?;
    Ok(())
}

/// Drops counters from before `today` (a `YYYY-MM-DD` UTC day).
pub async fn purge_old_counters(db: &Db, today: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM signup_counters WHERE day < $1")
        .bind(today)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_pending(conn: &mut Conn, email: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_registrations WHERE email = $1")
        .bind(email)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn is_invited(db: &Db, email: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM invites WHERE email = $1")
        .bind(email)
        .fetch_optional(db)
        .await?;
    Ok(found.is_some())
}

pub async fn add_invite(db: &Db, email: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invites (email, created_at) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
    )
    .bind(email)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_invite(conn: &mut Conn, email: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM invites WHERE email = $1")
        .bind(email)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn purge_expired_pending(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_registrations WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}
