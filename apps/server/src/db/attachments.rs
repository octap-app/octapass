//! Attachment records, the per-owner attachment quota and the queue of files
//! to delete from storage.

use octapass_api::AttachmentRecord;
use sqlx::FromRow;

use super::{Conn, Db, rfc3339};
use crate::db::items::to_u64;

#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// The vault, item or attachment doesn't exist, or the account can't see it.
    #[error("not found")]
    NotFound,
    #[error("read-only vault")]
    ReadOnly,
    #[error("an attachment with this id already exists")]
    Exists,
    /// The vault's owner would go over their attachment quota.
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(FromRow)]
struct Row {
    vault_id: String,
    item_id: String,
    id: String,
    size: i64,
    created_at: i64,
}

impl Row {
    fn into_record(self) -> AttachmentRecord {
        AttachmentRecord {
            id: self.id,
            vault_id: self.vault_id,
            item_id: self.item_id,
            size: to_u64(self.size),
            created_at: rfc3339(self.created_at),
        }
    }
}

/// Where an attachment goes, and its stored size.
pub struct NewAttachment<'a> {
    pub vault_id: &'a str,
    pub item_id: &'a str,
    pub id: &'a str,
    pub size: u64,
}

fn size(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

async fn role(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT role FROM vault_access WHERE vault_id = $1 AND account_id = $2")
        .bind(vault_id)
        .bind(account_id)
        .fetch_optional(conn)
        .await
}

fn can_write(role: &str) -> bool {
    matches!(role, "owner" | "manage" | "write")
}

/// Whether the item exists and isn't in the trash.
async fn live_item(conn: &mut Conn, vault_id: &str, item_id: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM items WHERE vault_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(vault_id)
    .bind(item_id)
    .fetch_optional(conn)
    .await?;
    Ok(found.is_some())
}

/// The largest attachment total of the vault's owners, over every vault each owns.
async fn owners_usage(conn: &mut Conn, vault_id: &str) -> Result<i64, sqlx::Error> {
    let totals: Vec<i64> = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(v.attachment_bytes), 0) AS BIGINT) \
         FROM vault_members o \
         JOIN vault_members m ON m.account_id = o.account_id AND m.role = 'owner' \
         JOIN vaults v ON v.id = m.vault_id \
         WHERE o.vault_id = $1 AND o.role = 'owner' GROUP BY o.account_id",
    )
    .bind(vault_id)
    .fetch_all(conn)
    .await?;
    Ok(totals.into_iter().max().unwrap_or(0))
}

/// The checks an upload must pass, made before its body is read so a refused
/// upload costs no bandwidth. [`insert`] makes them again, atomically.
pub async fn check_upload(
    db: &Db,
    account_id: &str,
    new: &NewAttachment<'_>,
    quota_bytes: u64,
) -> Result<(), AttachmentError> {
    let mut conn = db.acquire().await?;
    match role(&mut conn, new.vault_id, account_id).await? {
        None => return Err(AttachmentError::NotFound),
        Some(role) if !can_write(&role) => return Err(AttachmentError::ReadOnly),
        Some(_) => {}
    }
    if !live_item(&mut conn, new.vault_id, new.item_id).await? {
        return Err(AttachmentError::NotFound);
    }
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM attachments WHERE vault_id = $1 AND item_id = $2 AND id = $3",
    )
    .bind(new.vault_id)
    .bind(new.item_id)
    .bind(new.id)
    .fetch_optional(&mut *conn)
    .await?;
    if exists.is_some() {
        return Err(AttachmentError::Exists);
    }
    if owners_usage(&mut conn, new.vault_id)
        .await?
        .saturating_add(size(new.size))
        > size(quota_bytes)
    {
        return Err(AttachmentError::QuotaExceeded);
    }
    Ok(())
}

/// Records a stored file. On an error nothing changed, and the caller must
/// queue the stored object for deletion.
pub async fn insert(
    db: &Db,
    account_id: &str,
    new: &NewAttachment<'_>,
    object_key: &str,
    quota_bytes: u64,
    now: i64,
) -> Result<AttachmentRecord, AttachmentError> {
    let mut tx = db.begin().await?;
    // Writing first takes the write lock (SQLite) or locks the vault row
    // (PostgreSQL), so concurrent uploads can't both slip under the quota.
    let counted = sqlx::query(
        "UPDATE vaults SET attachment_bytes = attachment_bytes + $3 WHERE id = $1 AND id IN \
         (SELECT vault_id FROM vault_access WHERE account_id = $2 AND role IN ('owner', 'manage', 'write'))",
    )
    .bind(new.vault_id)
    .bind(account_id)
    .bind(size(new.size))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if counted == 0 {
        return Err(match role(&mut tx, new.vault_id, account_id).await? {
            Some(_) => AttachmentError::ReadOnly,
            None => AttachmentError::NotFound,
        });
    }
    if !live_item(&mut tx, new.vault_id, new.item_id).await? {
        return Err(AttachmentError::NotFound);
    }
    let inserted = sqlx::query(
        "INSERT INTO attachments (vault_id, item_id, id, object_key, size, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (vault_id, item_id, id) DO NOTHING",
    )
    .bind(new.vault_id)
    .bind(new.item_id)
    .bind(new.id)
    .bind(object_key)
    .bind(size(new.size))
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AttachmentError::Exists);
    }
    if owners_usage(&mut tx, new.vault_id).await? > size(quota_bytes) {
        return Err(AttachmentError::QuotaExceeded);
    }
    tx.commit().await?;
    Ok(AttachmentRecord {
        id: new.id.to_owned(),
        vault_id: new.vault_id.to_owned(),
        item_id: new.item_id.to_owned(),
        size: new.size,
        created_at: rfc3339(now),
    })
}

/// The object key and stored size of an attachment any member of the vault
/// can read, trash included.
pub async fn find(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    id: &str,
) -> Result<(String, u64), AttachmentError> {
    let found: Option<(String, i64)> = sqlx::query_as(
        "SELECT a.object_key, a.size FROM attachments a \
         JOIN vault_access m ON m.vault_id = a.vault_id AND m.account_id = $1 \
         WHERE a.vault_id = $2 AND a.item_id = $3 AND a.id = $4",
    )
    .bind(account_id)
    .bind(vault_id)
    .bind(item_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    let (key, size) = found.ok_or(AttachmentError::NotFound)?;
    Ok((key, to_u64(size)))
}

/// An item's attachments, oldest first.
pub async fn list(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
) -> Result<Vec<AttachmentRecord>, AttachmentError> {
    let mut conn = db.acquire().await?;
    if role(&mut conn, vault_id, account_id).await?.is_none() {
        return Err(AttachmentError::NotFound);
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT vault_id, item_id, id, size, created_at FROM attachments \
         WHERE vault_id = $1 AND item_id = $2 ORDER BY created_at, id",
    )
    .bind(vault_id)
    .bind(item_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(Row::into_record).collect())
}

/// Removes an attachment and queues its file for deletion.
pub async fn delete(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    id: &str,
    now: i64,
) -> Result<(), AttachmentError> {
    let mut tx = db.begin().await?;
    let removed: Option<(String, i64)> = sqlx::query_as(
        "DELETE FROM attachments WHERE vault_id = $1 AND item_id = $2 AND id = $3 AND vault_id IN \
         (SELECT vault_id FROM vault_access WHERE account_id = $4 AND role IN ('owner', 'manage', 'write')) \
         RETURNING object_key, size",
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((object_key, size)) = removed else {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM attachments WHERE vault_id = $1 AND item_id = $2 AND id = $3",
        )
        .bind(vault_id)
        .bind(item_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let readable = role(&mut tx, vault_id, account_id).await?.is_some();
        return Err(if readable && exists.is_some() {
            AttachmentError::ReadOnly
        } else {
            AttachmentError::NotFound
        });
    };
    sqlx::query("UPDATE vaults SET attachment_bytes = attachment_bytes - $2 WHERE id = $1")
        .bind(vault_id)
        .bind(size)
        .execute(&mut *tx)
        .await?;
    queue_deletion(&mut tx, &object_key, now).await?;
    tx.commit().await?;
    Ok(())
}

/// Queues an object for deletion from storage, due at once.
pub async fn queue_deletion(
    conn: &mut Conn,
    object_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO attachment_deletions (object_key, attempts, next_attempt_at) VALUES ($1, 0, $2) \
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(object_key)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Removes the attachments of the vault's items matching `items` (a condition
/// on `items` with the vault id as `$1` and `extra` as `$2`), queues their
/// files and takes them off the vault's total. Runs inside the caller's
/// transaction, before the items go.
async fn remove_where(
    conn: &mut Conn,
    vault_id: &str,
    items: &str,
    extra: i64,
    now: i64,
) -> Result<(), sqlx::Error> {
    let matching = format!(
        "FROM attachments WHERE vault_id = $1 AND item_id IN (SELECT id FROM items WHERE vault_id = $1 AND {items})"
    );
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO attachment_deletions (object_key, attempts, next_attempt_at) \
         SELECT object_key, 0, $3 {matching} ON CONFLICT (object_key) DO NOTHING"
    )))
    .bind(vault_id)
    .bind(extra)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE vaults SET attachment_bytes = attachment_bytes - \
         (SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) {matching}) WHERE id = $1"
    )))
    .bind(vault_id)
    .bind(extra)
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!("DELETE {matching}")))
        .bind(vault_id)
        .bind(extra)
        .execute(conn)
        .await?;
    Ok(())
}

/// Before purging the vault's items trashed at or before `cutoff`.
pub(super) async fn remove_purged(
    conn: &mut Conn,
    vault_id: &str,
    cutoff: i64,
    now: i64,
) -> Result<(), sqlx::Error> {
    remove_where(
        conn,
        vault_id,
        "deleted_at IS NOT NULL AND deleted_at <= $2",
        cutoff,
        now,
    )
    .await
}

/// Before deleting a whole vault.
pub(super) async fn remove_vault(
    conn: &mut Conn,
    vault_id: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    // `$2` is unused but bound, so both callers share the statements.
    remove_where(conn, vault_id, "$2 = $2", 0, now).await
}

/// Up to `limit` queued deletions that are due, with their failed attempts so far.
pub async fn due_deletions(
    db: &Db,
    now: i64,
    limit: i64,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT object_key, attempts FROM attachment_deletions WHERE next_attempt_at <= $1 \
         ORDER BY next_attempt_at LIMIT $2",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(db)
    .await
}

pub async fn deletion_done(db: &Db, object_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM attachment_deletions WHERE object_key = $1")
        .bind(object_key)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn deletion_failed(
    db: &Db,
    object_key: &str,
    next_attempt_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE attachment_deletions SET attempts = attempts + 1, next_attempt_at = $2 WHERE object_key = $1",
    )
    .bind(object_key)
    .bind(next_attempt_at)
    .execute(db)
    .await?;
    Ok(())
}

/// What the vaults the account owns hold: items, item bytes and attachment bytes.
pub async fn account_usage(db: &Db, account_id: &str) -> Result<(u64, u64, u64), sqlx::Error> {
    let (items, item_bytes, attachment_bytes): (i64, i64, i64) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(v.item_count), 0) AS BIGINT), CAST(COALESCE(SUM(v.item_bytes), 0) AS BIGINT), \
         CAST(COALESCE(SUM(v.attachment_bytes), 0) AS BIGINT) FROM vaults v \
         JOIN vault_members m ON m.vault_id = v.id WHERE m.account_id = $1 AND m.role = 'owner'",
    )
    .bind(account_id)
    .fetch_one(db)
    .await?;
    let count = |n: i64| to_u64(n.max(0));
    Ok((count(items), count(item_bytes), count(attachment_bytes)))
}
