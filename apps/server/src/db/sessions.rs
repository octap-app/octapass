//! Devices and token sessions. Tokens are random; only their SHA-256 hashes
//! are stored.

use sqlx::FromRow;

use octapass_api::DeviceRecord;

use super::{Conn, Db, days, rfc3339};
use crate::crypto::{random_token, token_hash};

pub const ACCESS_TOKEN_TTL_SECS: u64 = 15 * 60;
const ACCESS_TOKEN_TTL: i64 = 15 * 60 * 1000;
const REFRESH_TOKEN_TTL: i64 = days(30);

pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl Tokens {
    fn generate() -> Self {
        Self {
            access_token: random_token(),
            refresh_token: random_token(),
        }
    }
}

#[derive(FromRow)]
pub struct Session {
    pub account_id: String,
    pub device_id: String,
    pub access_expires_at: i64,
}

pub async fn insert_device(
    conn: &mut Conn,
    account_id: &str,
    name: &str,
    platform: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, platform, created_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(&id)
    .bind(account_id)
    .bind(name)
    .bind(platform)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(id)
}

pub async fn insert(
    conn: &mut Conn,
    account_id: &str,
    device_id: &str,
    now: i64,
    sso_at: Option<i64>,
) -> Result<Tokens, sqlx::Error> {
    let tokens = Tokens::generate();
    sqlx::query(
        "INSERT INTO sessions (id, account_id, device_id, access_token_hash, access_expires_at, \
         refresh_token_hash, refresh_expires_at, created_at, sso_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(account_id)
    .bind(device_id)
    .bind(token_hash(&tokens.access_token))
    .bind(now + ACCESS_TOKEN_TTL)
    .bind(token_hash(&tokens.refresh_token))
    .bind(now + REFRESH_TOKEN_TTL)
    .bind(now)
    .bind(sso_at)
    .execute(conn)
    .await?;
    Ok(tokens)
}

/// The account behind a current refresh token, and when SSO last passed for that session.
/// When SSO last passed for this device's session, so a session made from it ([`insert`]) keeps
/// the same age.
pub async fn device_sso_at(
    db: &Db,
    account_id: &str,
    device_id: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT sso_at FROM sessions WHERE account_id = $1 AND device_id = $2")
            .bind(account_id)
            .bind(device_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(sso_at,)| sso_at))
}

pub async fn sso_state(
    db: &Db,
    refresh_token: &str,
) -> Result<Option<(String, Option<i64>)>, sqlx::Error> {
    sqlx::query_as("SELECT account_id, sso_at FROM sessions WHERE refresh_token_hash = $1")
        .bind(token_hash(refresh_token))
        .fetch_optional(db)
        .await
}

pub async fn find_by_access_token(
    db: &Db,
    access_token: &str,
    now: i64,
) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as(
        "SELECT account_id, device_id, access_expires_at FROM sessions WHERE access_token_hash = $1 AND access_expires_at > $2",
    )
    .bind(token_hash(access_token))
    .bind(now)
    .fetch_optional(db)
    .await
}

pub enum Refresh {
    Rotated(Tokens),
    /// A refresh token that was already rotated came back: someone copied it.
    /// The whole session has been revoked.
    Reused(Session),
    Invalid,
}

pub async fn refresh(db: &Db, refresh_token: &str, now: i64) -> Result<Refresh, sqlx::Error> {
    let presented = token_hash(refresh_token);
    let tokens = Tokens::generate();
    // A single conditional UPDATE, so two concurrent refreshes with the same
    // token can't both succeed.
    let rotated = sqlx::query(
        "UPDATE sessions SET access_token_hash = $1, access_expires_at = $2, refresh_token_hash = $3, \
         previous_refresh_token_hash = refresh_token_hash, refresh_expires_at = $4 \
         WHERE refresh_token_hash = $5 AND refresh_expires_at > $6",
    )
    .bind(token_hash(&tokens.access_token))
    .bind(now + ACCESS_TOKEN_TTL)
    .bind(token_hash(&tokens.refresh_token))
    .bind(now + REFRESH_TOKEN_TTL)
    .bind(&presented)
    .bind(now)
    .execute(db)
    .await?;
    if rotated.rows_affected() == 1 {
        sqlx::query(
            "UPDATE devices SET last_seen_at = $1 WHERE id = (SELECT device_id FROM sessions WHERE refresh_token_hash = $2)",
        )
        .bind(now)
        .bind(token_hash(&tokens.refresh_token))
        .execute(db)
        .await?;
        return Ok(Refresh::Rotated(tokens));
    }

    let reused: Option<Session> = sqlx::query_as(
        "DELETE FROM sessions WHERE previous_refresh_token_hash = $1 \
         RETURNING account_id, device_id, access_expires_at",
    )
    .bind(&presented)
    .fetch_optional(db)
    .await?;
    Ok(reused.map_or(Refresh::Invalid, Refresh::Reused))
}

/// Signs a device out: its sessions are deleted, the device is marked
/// revoked and no longer skips two-step sign-in. Returns `false` if the account has no such signed-in device.
pub async fn revoke_device(
    db: &Db,
    account_id: &str,
    device_id: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    let revoked = sqlx::query(
        "UPDATE devices SET revoked_at = $1 WHERE id = $2 AND account_id = $3 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(device_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE device_id = $1 AND account_id = $2")
        .bind(device_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    if revoked.rows_affected() == 1 {
        super::two_step::forget_device(&mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(revoked.rows_affected() == 1)
}

/// Signs out every device of the account but `keep`, inside `conn`'s
/// transaction, the way [`revoke_device`] signs out one. Returns the ids of
/// the devices it signed out.
pub async fn revoke_other_devices(
    conn: &mut Conn,
    account_id: &str,
    keep: Option<&str>,
    now: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let keep_id = keep.unwrap_or_default();
    let revoked: Vec<String> = sqlx::query_scalar(
        "UPDATE devices SET revoked_at = $1 WHERE account_id = $2 AND id <> $3 AND revoked_at IS NULL \
         RETURNING id",
    )
    .bind(now)
    .bind(account_id)
    .bind(keep_id)
    .fetch_all(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE account_id = $1 AND device_id <> $2")
        .bind(account_id)
        .bind(keep_id)
        .execute(&mut *conn)
        .await?;
    super::two_step::forget_devices(&mut *conn, account_id, keep).await?;
    Ok(revoked)
}

#[derive(FromRow)]
struct DeviceRow {
    id: String,
    name: String,
    platform: String,
    created_at: i64,
    last_seen_at: i64,
}

/// The account's devices that are still signed in, most recently seen first.
pub async fn devices(
    db: &Db,
    account_id: &str,
    current_device_id: &str,
    now: i64,
) -> Result<Vec<DeviceRecord>, sqlx::Error> {
    let rows: Vec<DeviceRow> = sqlx::query_as(
        "SELECT d.id, d.name, d.platform, d.created_at, d.last_seen_at FROM devices d \
         WHERE d.account_id = $1 AND d.revoked_at IS NULL AND EXISTS \
         (SELECT 1 FROM sessions s WHERE s.device_id = d.id AND s.refresh_expires_at > $2) \
         ORDER BY d.last_seen_at DESC, d.id",
    )
    .bind(account_id)
    .bind(now)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| DeviceRecord {
            current: row.id == current_device_id,
            id: row.id,
            name: row.name,
            platform: row.platform,
            created_at: rfc3339(row.created_at),
            last_seen_at: rfc3339(row.last_seen_at),
        })
        .collect())
}

/// Whether `device_id` came from the sign-in that finished sign-up: the
/// account's only device ever, added within ten minutes of creating it.
pub async fn is_first_device(
    db: &Db,
    account_id: &str,
    device_id: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let first: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM accounts a WHERE a.id = $1 AND a.created_at > $3 \
         AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.account_id = a.id AND d.id <> $2)",
    )
    .bind(account_id)
    .bind(device_id)
    .bind(now - 10 * 60 * 1000)
    .fetch_one(db)
    .await?;
    Ok(first == 1)
}

pub async fn rename_device(db: &Db, device_id: &str, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET name = $1 WHERE id = $2")
        .bind(name)
        .bind(device_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn touch_device(db: &Db, device_id: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
        .bind(now)
        .bind(device_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Forgets devices that have no session left: signed out, revoked or expired.
pub async fn purge_signed_out_devices(db: &Db) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM devices WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = devices.id)",
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn purge_expired(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE refresh_expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

pub const REAUTH_TOKEN_TTL_SECS: u64 = 5 * 60;
const REAUTH_TOKEN_TTL: i64 = 5 * 60 * 1000;

/// Issues a single-use token proving a fresh master-password login.
pub async fn insert_reauth_token(
    db: &Db,
    account_id: &str,
    purpose: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    let token = random_token();
    sqlx::query("INSERT INTO reauth_tokens (token_hash, account_id, purpose, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(token_hash(&token))
        .bind(account_id)
        .bind(purpose)
        .bind(now + REAUTH_TOKEN_TTL)
        .execute(db)
        .await?;
    Ok(token)
}

/// Uses up a reauth token. Returns `false` if it's unknown, expired, already
/// used, or was issued to another account or for another purpose.
pub async fn consume_reauth_token(
    conn: &mut Conn,
    token: &str,
    account_id: &str,
    purpose: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let consumed = sqlx::query(
        "DELETE FROM reauth_tokens WHERE token_hash = $1 AND account_id = $2 AND purpose = $3 AND expires_at > $4",
    )
    .bind(token_hash(token))
    .bind(account_id)
    .bind(purpose)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(consumed.rows_affected() == 1)
}

pub async fn purge_expired_reauth_tokens(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM reauth_tokens WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}
