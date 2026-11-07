//! One-time share links. The server holds ciphertext whose key is in the
//! link's fragment; it counts views and forgets the link at its limit or
//! expiry.

use octapass_api::{ShareLinkRecord, ShareLinkResponse};
use sqlx::FromRow;

use super::{Db, rfc3339};

pub struct NewShareLink<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub ciphertext: &'a str,
    pub passphrase_required: bool,
    pub max_views: u32,
    pub expires_at: i64,
    pub now: i64,
}

pub async fn insert(db: &Db, link: NewShareLink<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO share_links (id, account_id, ciphertext, passphrase_required, max_views, views, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 0, $6, $7)",
    )
    .bind(link.id)
    .bind(link.account_id)
    .bind(link.ciphertext)
    .bind(i64::from(link.passphrase_required))
    .bind(i64::from(link.max_views))
    .bind(link.expires_at)
    .bind(link.now)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn count_active(db: &Db, account_id: &str, now: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM share_links WHERE account_id = $1 AND expires_at > $2",
    )
    .bind(account_id)
    .bind(now)
    .fetch_one(db)
    .await
}

#[derive(FromRow)]
struct ViewRow {
    ciphertext: String,
    passphrase_required: i64,
    expires_at: i64,
    views: i64,
    max_views: i64,
}

/// Counts a view and returns the link, deleting it if that was the last
/// view. `None` for unknown and expired links. A single conditional update,
/// so concurrent viewers can't get more views than the limit between them.
pub async fn view(db: &Db, id: &str, now: i64) -> Result<Option<ShareLinkResponse>, sqlx::Error> {
    let row: Option<ViewRow> = sqlx::query_as(
        "UPDATE share_links SET views = views + 1 WHERE id = $1 AND expires_at > $2 AND views < max_views \
         RETURNING ciphertext, passphrase_required, expires_at, views, max_views",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        // Expired (or already used up): forget it now rather than at the next purge.
        sqlx::query("DELETE FROM share_links WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;
        return Ok(None);
    };
    if row.views >= row.max_views {
        sqlx::query("DELETE FROM share_links WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(Some(ShareLinkResponse {
        ciphertext: row.ciphertext,
        passphrase_required: row.passphrase_required != 0,
        expires_at: rfc3339(row.expires_at),
        views_left: u32::try_from(row.max_views - row.views).unwrap_or_default(),
    }))
}

pub async fn delete(db: &Db, id: &str, account_id: &str) -> Result<bool, sqlx::Error> {
    let deleted = sqlx::query("DELETE FROM share_links WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(db)
        .await?;
    Ok(deleted.rows_affected() > 0)
}

#[derive(FromRow)]
struct LinkRow {
    id: String,
    passphrase_required: i64,
    max_views: i64,
    views: i64,
    expires_at: i64,
    created_at: i64,
}

/// The account's links that can still be viewed, newest first.
pub async fn list(
    db: &Db,
    account_id: &str,
    now: i64,
) -> Result<Vec<ShareLinkRecord>, sqlx::Error> {
    let rows: Vec<LinkRow> = sqlx::query_as(
        "SELECT id, passphrase_required, max_views, views, expires_at, created_at FROM share_links \
         WHERE account_id = $1 AND expires_at > $2 ORDER BY created_at DESC, id",
    )
    .bind(account_id)
    .bind(now)
    .fetch_all(db)
    .await?;
    let count = |n: i64| u32::try_from(n).unwrap_or_default();
    Ok(rows
        .into_iter()
        .map(|row| ShareLinkRecord {
            id: row.id,
            expires_at: rfc3339(row.expires_at),
            max_views: count(row.max_views),
            views: count(row.views),
            passphrase_required: row.passphrase_required != 0,
            created_at: rfc3339(row.created_at),
        })
        .collect())
}

pub async fn purge_expired(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM share_links WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}
