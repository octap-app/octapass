//! Two-step sign-in: the authenticator secret, security keys, recovery codes,
//! methods being set up and trusted devices. Secrets arrive here already
//! sealed or hashed.

use sqlx::FromRow;

use octapass_api::SecurityKeyRecord;

use super::{Conn, Db, days, rfc3339};
use crate::crypto::{random_token, token_hash};

/// At most this long after its sign-in, and only while the device itself
/// exists (signed in, not revoked): never longer than its session.
const TRUSTED_DEVICE_TTL: i64 = days(30);

#[derive(FromRow)]
pub struct TotpRow {
    pub totp_secret: String,
    pub totp_last_step: i64,
}

pub async fn totp(conn: &mut Conn, account_id: &str) -> Result<Option<TotpRow>, sqlx::Error> {
    sqlx::query_as("SELECT totp_secret, totp_last_step FROM two_step WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(conn)
        .await
}

pub async fn is_enabled(db: &Db, account_id: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM two_step WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(db)
        .await?;
    Ok(found.is_some())
}

/// Turns two-step sign-in on with this authenticator secret, or replaces the
/// secret. Returns whether it was off before.
pub async fn set_totp(
    conn: &mut Conn,
    account_id: &str,
    sealed_secret: &str,
    last_step: i64,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let replaced = sqlx::query(
        "UPDATE two_step SET totp_secret = $1, totp_last_step = $2 WHERE account_id = $3",
    )
    .bind(sealed_secret)
    .bind(last_step)
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    if replaced.rows_affected() == 1 {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO two_step (account_id, totp_secret, totp_last_step, enabled_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(sealed_secret)
    .bind(last_step)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(true)
}

/// Records the step of an accepted code. Fails (returns `false`) if another
/// request already used this step or a later one.
pub async fn use_totp_step(
    conn: &mut Conn,
    account_id: &str,
    step: i64,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE two_step SET totp_last_step = $1 WHERE account_id = $2 AND totp_last_step < $1",
    )
    .bind(step)
    .bind(account_id)
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() == 1)
}

/// Turns two-step sign-in off: every method and recovery code goes. Returns
/// whether it was on.
pub async fn disable(conn: &mut Conn, account_id: &str) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM two_step WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    for statement in [
        "DELETE FROM security_keys WHERE account_id = $1",
        "DELETE FROM recovery_codes WHERE account_id = $1",
        "DELETE FROM two_step_setups WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(account_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(removed.rows_affected() == 1)
}

// ---------- Recovery codes ----------

pub async fn replace_recovery_codes(
    conn: &mut Conn,
    account_id: &str,
    code_hashes: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM recovery_codes WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    for hash in code_hashes {
        sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES ($1, $2)")
            .bind(account_id)
            .bind(hash)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Uses up a recovery code. Returns `false` if it isn't one of the account's.
pub async fn use_recovery_code(
    conn: &mut Conn,
    account_id: &str,
    code_hash: &str,
) -> Result<bool, sqlx::Error> {
    let used = sqlx::query("DELETE FROM recovery_codes WHERE account_id = $1 AND code_hash = $2")
        .bind(account_id)
        .bind(code_hash)
        .execute(conn)
        .await?;
    Ok(used.rows_affected() == 1)
}

pub async fn recovery_codes_left(db: &Db, account_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM recovery_codes WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(db)
        .await
}

// ---------- Security keys ----------

#[derive(FromRow)]
pub struct SecurityKeyRow {
    pub id: String,
    pub credential_id: String,
    pub algorithm: i64,
    pub public_key: String,
    pub sign_count: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl SecurityKeyRow {
    pub fn record(&self) -> SecurityKeyRecord {
        SecurityKeyRecord {
            id: self.id.clone(),
            name: self.name.clone(),
            created_at: rfc3339(self.created_at),
            last_used_at: self.last_used_at.map(rfc3339),
        }
    }
}

/// Oldest first.
pub async fn security_keys<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    account_id: &str,
) -> Result<Vec<SecurityKeyRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, credential_id, algorithm, public_key, sign_count, name, created_at, last_used_at \
         FROM security_keys WHERE account_id = $1 ORDER BY created_at, id",
    )
    .bind(account_id)
    .fetch_all(executor)
    .await
}

pub struct NewSecurityKey<'a> {
    pub account_id: &'a str,
    pub credential_id: &'a str,
    pub algorithm: i64,
    pub public_key: &'a str,
    pub sign_count: i64,
    pub name: &'a str,
    pub now: i64,
}

pub async fn insert_security_key(
    conn: &mut Conn,
    key: NewSecurityKey<'_>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO security_keys (id, account_id, credential_id, algorithm, public_key, sign_count, name, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(key.account_id)
    .bind(key.credential_id)
    .bind(key.algorithm)
    .bind(key.public_key)
    .bind(key.sign_count)
    .bind(key.name)
    .bind(key.now)
    .execute(conn)
    .await?;
    Ok(id)
}

/// Records a sign-in with the key. Fails (returns `false`) if a concurrent
/// sign-in already moved the counter to or past `sign_count`.
pub async fn use_security_key(
    conn: &mut Conn,
    id: &str,
    previous_count: i64,
    sign_count: i64,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let used = sqlx::query(
        "UPDATE security_keys SET sign_count = $1, last_used_at = $2 WHERE id = $3 AND sign_count = $4",
    )
    .bind(sign_count)
    .bind(now)
    .bind(id)
    .bind(previous_count)
    .execute(conn)
    .await?;
    Ok(used.rows_affected() == 1)
}

pub async fn delete_security_key(
    conn: &mut Conn,
    account_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let deleted = sqlx::query("DELETE FROM security_keys WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(deleted.rows_affected() == 1)
}

// ---------- Methods being set up ----------

pub async fn insert_setup(
    db: &Db,
    account_id: &str,
    kind: &str,
    secret: &str,
    expires_at: i64,
) -> Result<String, sqlx::Error> {
    let id = random_token();
    sqlx::query(
        "INSERT INTO two_step_setups (id, account_id, kind, secret, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_hash(&id))
    .bind(account_id)
    .bind(kind)
    .bind(secret)
    .bind(expires_at)
    .execute(db)
    .await?;
    Ok(id)
}

/// A setup's secret. `None` if it's unknown, expired, another account's or of
/// another kind.
pub async fn find_setup(
    conn: &mut Conn,
    id: &str,
    account_id: &str,
    kind: &str,
    now: i64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT secret FROM two_step_setups WHERE id = $1 AND account_id = $2 AND kind = $3 AND expires_at > $4",
    )
    .bind(token_hash(id))
    .bind(account_id)
    .bind(kind)
    .bind(now)
    .fetch_optional(conn)
    .await
}

/// Uses up a setup. Returns `false` if another request already did.
pub async fn delete_setup(conn: &mut Conn, id: &str) -> Result<bool, sqlx::Error> {
    let deleted = sqlx::query("DELETE FROM two_step_setups WHERE id = $1")
        .bind(token_hash(id))
        .execute(conn)
        .await?;
    Ok(deleted.rows_affected() == 1)
}

pub async fn purge_expired_setups(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM two_step_setups WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

// ---------- Trusted devices ----------
//
// Trust belongs to a device row (deleted with it, see migration 0007), so it
// never outlives the device in the account's device list.

/// The device just signed in: trust it for its next sign-in.
pub async fn trust_device(
    conn: &mut Conn,
    account_id: &str,
    device_id: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    let token = random_token();
    sqlx::query(
        "INSERT INTO trusted_devices (token_hash, account_id, device_id, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_hash(&token))
    .bind(account_id)
    .bind(device_id)
    .bind(now)
    .bind(now + TRUSTED_DEVICE_TTL)
    .execute(conn)
    .await?;
    Ok(token)
}

const VALID_TRUST: &str = "token_hash = $1 AND account_id = $2 AND expires_at > $3 AND device_id IN \
     (SELECT id FROM devices WHERE revoked_at IS NULL)";

pub async fn is_trusted(
    db: &Db,
    account_id: &str,
    token: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT 1 FROM trusted_devices WHERE {VALID_TRUST}"
    )))
    .bind(token_hash(token))
    .bind(account_id)
    .bind(now)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// Uses up a trusted-device token, so it works for one sign-in. Returns
/// `false` if it isn't valid, or another sign-in used it first.
pub async fn use_trust(
    conn: &mut Conn,
    account_id: &str,
    token: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let used = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM trusted_devices WHERE {VALID_TRUST}"
    )))
    .bind(token_hash(token))
    .bind(account_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(used.rows_affected() == 1)
}

/// A signed-out device has to do the second step again.
pub async fn forget_device<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    device_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM trusted_devices WHERE device_id = $1")
        .bind(device_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Every device of the account but `keep` has to do the second step on its
/// next sign-in.
pub async fn forget_devices<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    account_id: &str,
    keep: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM trusted_devices WHERE account_id = $1 AND device_id <> $2")
        .bind(account_id)
        .bind(keep.unwrap_or_default())
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn purge_expired_trust(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM trusted_devices WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}
