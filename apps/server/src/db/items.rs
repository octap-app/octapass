//! Vaults and items: revisions, sync, writes with preconditions, trash and
//! tombstones.
//!
//! Every write transaction starts by bumping the vault revision. That takes the
//! write lock first (SQLite) or locks the vault row (Postgres), so concurrent
//! writes to one vault are serialised and revisions never repeat.

use std::collections::HashMap;

use octapass_api::{
    DeletedItem, ItemRecord, ItemRevision, PutItemRequest, SyncResponse, VaultGrant, VaultRecord,
    VaultRole, VaultType,
};
use sqlx::FromRow;

use super::{Conn, Db, days, rfc3339};
use crate::validate;

/// Items stay in the trash this long before they're purged.
const TRASH_RETENTION: i64 = days(30);
/// Purged items leave a tombstone for this long.
const TOMBSTONE_RETENTION: i64 = days(90);
/// Past versions kept per item (plan 01).
const HISTORY_LIMIT: usize = 10;

pub async fn insert_personal_vault(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
    wrapped_vault_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vaults (id, type, revision, created_at) VALUES ($1, 'personal', 0, $2)",
    )
    .bind(vault_id)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO vault_members (vault_id, account_id, role, wrapped_vault_key, added_at) \
         VALUES ($1, $2, 'owner', $3, $4)",
    )
    .bind(vault_id)
    .bind(account_id)
    .bind(wrapped_vault_key)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn vault_exists(conn: &mut Conn, vault_id: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_optional(conn)
        .await?;
    Ok(found.is_some())
}

#[derive(FromRow)]
struct VaultRow {
    id: String,
    #[sqlx(rename = "type")]
    vault_type: String,
    revision: i64,
    key_id: Option<String>,
    org_id: Option<String>,
    wrapped_vault_key: String,
    role: String,
    granted_by: Option<String>,
    granter_sign_key: Option<String>,
    granted_at: Option<i64>,
    signature: Option<String>,
}

const SELECT_VAULTS: &str = "SELECT v.id, v.type, v.revision, v.key_id, v.org_id, m.wrapped_vault_key, m.role, \
     m.granted_by, m.granter_sign_key, m.granted_at, m.signature \
     FROM vaults v JOIN vault_access m ON m.vault_id = v.id";

impl VaultRow {
    fn into_record(self) -> VaultRecord {
        let grant = match (
            self.granted_by,
            self.granter_sign_key,
            self.granted_at,
            self.signature,
        ) {
            (
                Some(granted_by),
                Some(granter_public_sign_key),
                Some(granted_at),
                Some(signature),
            ) => Some(VaultGrant {
                granted_by,
                granter_public_sign_key,
                granted_at: to_u64(granted_at),
                signature,
            }),
            _ => None,
        };
        VaultRecord {
            id: self.id,
            vault_type: parse_vault_type(&self.vault_type),
            revision: to_u64(self.revision),
            wrapped_vault_key: self.wrapped_vault_key,
            role: parse_role(&self.role),
            key_id: self.key_id,
            grant,
            org_id: self.org_id,
        }
    }
}

pub fn parse_vault_type(vault_type: &str) -> VaultType {
    match vault_type {
        "shared" => VaultType::Shared,
        "family" => VaultType::Family,
        _ => VaultType::Personal,
    }
}

/// Stored roles were checked on the way in; an unknown one grants the least.
pub fn parse_role(role: &str) -> VaultRole {
    VaultRole::parse(role).unwrap_or(VaultRole::Read)
}

#[derive(FromRow)]
struct ItemRow {
    vault_id: String,
    id: String,
    revision: i64,
    encrypted_item_key: String,
    overview: String,
    details: String,
    updated_at: i64,
    deleted_at: Option<i64>,
}

impl ItemRow {
    /// Stored ciphertext bytes, as counted against the quota.
    fn size(&self) -> i64 {
        stored_size(&self.encrypted_item_key, &self.overview, &self.details)
    }

    fn into_record(self) -> ItemRecord {
        ItemRecord {
            id: self.id,
            vault_id: self.vault_id,
            revision: to_u64(self.revision),
            encrypted_item_key: self.encrypted_item_key,
            overview: self.overview,
            details: self.details,
            updated_at: rfc3339(self.updated_at),
            deleted_at: self.deleted_at.map(rfc3339),
        }
    }
}

const SELECT_ITEMS: &str = "SELECT vault_id, id, revision, encrypted_item_key, overview, details, updated_at, deleted_at FROM items";

pub(super) fn stored_size(encrypted_item_key: &str, overview: &str, details: &str) -> i64 {
    let len = encrypted_item_key.len() + overview.len() + details.len();
    i64::try_from(len).expect("bodies are far below i64::MAX")
}

/// How much one sync response may hold, so responses stay bounded however
/// large the vaults are.
#[derive(Clone, Copy, Debug)]
pub struct PageSize {
    pub items: usize,
    pub bytes: i64,
}

pub const PAGE: PageSize = PageSize {
    items: 1000,
    bytes: 8 * 1024 * 1024,
};
/// Rows read per query while filling a page.
const CHUNK: usize = 100;

/// Every vault the account can access (or just `only_vault`, if it can),
/// plus the items and tombstones newer than the client's revision for each
/// vault (all of them for vaults missing from `since`), up to `page`.
/// `without_org_vaults` leaves organisation vaults out, for an emergency contact their policy
/// keeps out.
///
/// A page only ends between two revisions, never inside one, and each vault
/// comes back with the revision the response is complete up to. So a client
/// stores those revisions and asks again while `has_more` is set.
pub async fn sync(
    db: &Db,
    account_id: &str,
    since: &HashMap<String, u64>,
    only_vault: Option<&str>,
    without_org_vaults: bool,
    page: PageSize,
) -> Result<SyncResponse, sqlx::Error> {
    // One read transaction gives a consistent snapshot: no item can be newer
    // than the vault revision returned with it.
    let mut tx = db.begin().await?;
    let vaults: Vec<VaultRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_VAULTS} WHERE m.account_id = $1 AND ($2 IS NULL OR v.id = $2) \
         AND ($3 = 0 OR v.org_id IS NULL) ORDER BY v.id"
    )))
    .bind(account_id)
    .bind(only_vault)
    .bind(i64::from(without_org_vaults))
    .fetch_all(&mut *tx)
    .await?;
    sync_vaults(tx, vaults, since, page).await
}

/// A service account's one vault, as a sync: its grant takes the place of a member's. A revoked or
/// expired one has been refused before it gets here.
pub async fn sync_service_account(
    db: &Db,
    service_account_id: &str,
    since: &HashMap<String, u64>,
    page: PageSize,
) -> Result<SyncResponse, sqlx::Error> {
    let mut tx = db.begin().await?;
    let vaults: Vec<VaultRow> = sqlx::query_as(
        "SELECT v.id, v.type, v.revision, v.key_id, v.org_id, s.wrapped_vault_key, s.role, \
         s.granted_by, s.granter_sign_key, s.granted_at, s.signature \
         FROM vaults v JOIN service_accounts s ON s.vault_id = v.id WHERE s.id = $1",
    )
    .bind(service_account_id)
    .fetch_all(&mut *tx)
    .await?;
    sync_vaults(tx, vaults, since, page).await
}

async fn sync_vaults(
    mut tx: sqlx::Transaction<'_, sqlx::Any>,
    vaults: Vec<VaultRow>,
    since: &HashMap<String, u64>,
    page: PageSize,
) -> Result<SyncResponse, sqlx::Error> {
    let mut filled = Page {
        size: page,
        items: Vec::new(),
        bytes: 0,
    };
    let mut has_more = false;
    let mut deleted = Vec::new();
    let mut records = Vec::with_capacity(vaults.len());
    for mut vault in vaults {
        let after = since
            .get(&vault.id)
            .map_or(0, |&rev| i64::try_from(rev).unwrap_or(i64::MAX));
        let complete_to = if vault.revision <= after {
            vault.revision
        } else if filled.is_full() {
            has_more = true;
            after
        } else {
            match filled.fill(&mut tx, &vault.id, after).await? {
                None => vault.revision,
                Some(revision) => {
                    has_more = true;
                    revision
                }
            }
        };

        let purged: Vec<(String, i64)> = sqlx::query_as(
            "SELECT item_id, revision FROM tombstones WHERE vault_id = $1 AND revision > $2 AND revision <= $3 \
             ORDER BY revision",
        )
        .bind(&vault.id)
        .bind(after)
        .bind(complete_to)
        .fetch_all(&mut *tx)
        .await?;
        deleted.extend(purged.into_iter().map(|(item_id, revision)| DeletedItem {
            vault_id: vault.id.clone(),
            item_id,
            revision: to_u64(revision),
        }));
        vault.revision = complete_to;
        records.push(vault.into_record());
    }
    tx.commit().await?;

    Ok(SyncResponse {
        vaults: records,
        items: filled.items,
        deleted,
        has_more,
    })
}

struct Page {
    size: PageSize,
    items: Vec<ItemRecord>,
    bytes: i64,
}

impl Page {
    fn is_full(&self) -> bool {
        self.items.len() >= self.size.items || self.bytes >= self.size.bytes
    }

    /// Adds the vault's items newer than `after`, in revision order. Returns
    /// `None` if they all fit, or the last revision that fit whole.
    async fn fill(
        &mut self,
        conn: &mut Conn,
        vault_id: &str,
        after: i64,
    ) -> Result<Option<i64>, sqlx::Error> {
        let mut full_at = None;
        let mut last: (i64, Option<String>) = (after, None);
        loop {
            let rows: Vec<ItemRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "{SELECT_ITEMS} WHERE vault_id = $1 AND (revision > $2 OR (revision = $2 AND $3 IS NOT NULL AND id > $3)) \
                 ORDER BY revision, id LIMIT $4"
            )))
            .bind(vault_id)
            .bind(last.0)
            .bind(&last.1)
            .bind(CHUNK as i64)
            .fetch_all(&mut *conn)
            .await?;
            let fetched = rows.len();
            for row in rows {
                if full_at.is_some_and(|revision| revision != row.revision) {
                    return Ok(full_at);
                }
                last = (row.revision, Some(row.id.clone()));
                self.bytes += row.size();
                self.items.push(row.into_record());
                if full_at.is_none() && self.is_full() {
                    full_at = Some(last.0);
                }
            }
            if fetched < CHUNK {
                return Ok(None);
            }
        }
    }
}

pub enum Precondition {
    /// `If-None-Match: *`
    Create,
    /// `If-Match: "<revision>"`
    Revision(u64),
    /// Whatever revision is stored, as long as the item exists.
    Any,
}

pub enum ItemWrite<'a> {
    Put(Precondition, &'a PutItemRequest),
    /// The expected revision, or `None` for whatever is stored.
    Delete(Option<u64>),
    Restore,
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The vault or item doesn't exist, or the account can't see it.
    #[error("not found")]
    NotFound,
    #[error("read-only vault")]
    ReadOnly,
    /// The item key isn't wrapped under the vault's current key.
    #[error("stale vault key")]
    StaleVaultKey,
    #[error("conflict")]
    Conflict(Box<ItemRecord>),
    /// The vault's owner would go over their item count or storage quota.
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The item's revision after the write.
    pub revision: u64,
    /// `false` when the write was a no-op, like deleting an item already in the trash.
    pub changed: bool,
}

/// How the vault's stored items changed: their count and ciphertext bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Usage {
    pub items: i64,
    pub bytes: i64,
    /// `bytes` without the item's history: an edit that shrinks an item keeps the old version too,
    /// and an account over quota must still be able to clean up.
    pub history_bytes: i64,
}

impl std::ops::AddAssign for Usage {
    fn add_assign(&mut self, other: Self) {
        self.items += other.items;
        self.bytes += other.bytes;
        self.history_bytes += other.history_bytes;
    }
}

/// Applies one item write.
pub async fn write(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    write: ItemWrite<'_>,
    quota: Quota,
    now: i64,
) -> Result<Written, WriteError> {
    write_all(db, account_id, vault_id, vec![(item_id, write)], quota, now)
        .await?
        .pop()
        .expect("one result per write")
}

/// Applies writes to one vault atomically, in order: either all of them or,
/// if any fails, none. Every change gets the same new vault revision.
///
/// The outer error covers the whole vault (no access, read-only, over quota,
/// database); the inner results are per write. If one of them is an error,
/// nothing was committed.
pub async fn write_all(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    writes: Vec<(&str, ItemWrite<'_>)>,
    quota: Quota,
    now: i64,
) -> Result<Vec<Result<Written, WriteError>>, WriteError> {
    let mut tx = db.begin().await?;
    let bumped: Option<(i64, Option<String>)> = sqlx::query_as(
        "UPDATE vaults SET revision = revision + 1 WHERE id = $1 AND id IN \
         (SELECT vault_id FROM vault_access WHERE account_id = $2 AND role IN ('owner', 'manage', 'write')) \
         RETURNING revision, key_id",
    )
    .bind(vault_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((revision, key_id)) = bumped else {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM vault_access WHERE vault_id = $1 AND account_id = $2",
        )
        .bind(vault_id)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
        return Err(if role.is_some() {
            WriteError::ReadOnly
        } else {
            WriteError::NotFound
        });
    };
    apply_writes(tx, vault_id, key_id, revision, writes, quota, now).await
}

/// One write by a service account with the `write` role, in the same way as a member's.
pub async fn write_as_service_account(
    db: &Db,
    service_account_id: &str,
    vault_id: &str,
    item_id: &str,
    write: ItemWrite<'_>,
    quota: Quota,
    now: i64,
) -> Result<Written, WriteError> {
    let mut tx = db.begin().await?;
    let bumped: Option<(i64, Option<String>)> = sqlx::query_as(
        "UPDATE vaults SET revision = revision + 1 WHERE id = $1 AND id IN \
         (SELECT vault_id FROM service_accounts WHERE id = $2 AND role = 'write' AND revoked_at IS NULL) \
         RETURNING revision, key_id",
    )
    .bind(vault_id)
    .bind(service_account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((revision, key_id)) = bumped else {
        return Err(WriteError::ReadOnly);
    };
    apply_writes(
        tx,
        vault_id,
        key_id,
        revision,
        vec![(item_id, write)],
        quota,
        now,
    )
    .await?
    .pop()
    .expect("one result per write")
}

async fn apply_writes(
    mut tx: sqlx::Transaction<'_, sqlx::Any>,
    vault_id: &str,
    key_id: Option<String>,
    revision: i64,
    writes: Vec<(&str, ItemWrite<'_>)>,
    quota: Quota,
    now: i64,
) -> Result<Vec<Result<Written, WriteError>>, WriteError> {
    let mut results = Vec::with_capacity(writes.len());
    let mut usage = Usage::default();
    for (item_id, write) in writes {
        let target = Target {
            vault_id,
            item_id,
            key_id: key_id.as_deref(),
        };
        match apply(&mut tx, target, write, revision, now).await {
            Err(WriteError::Db(error)) => return Err(error.into()),
            Ok((written, delta)) => {
                usage += delta;
                results.push(Ok(written));
            }
            Err(error) => results.push(Err(error)),
        }
    }
    let failed = results.iter().any(Result::is_err);
    let changed = results.iter().any(|r| matches!(r, Ok(w) if w.changed));
    // Not committing drops `tx`, which rolls back the revision bump too.
    if changed && !failed {
        add_usage(&mut tx, vault_id, usage).await?;
        // Only growth is checked, so an account over quota can still clean up.
        let grew = usage.bytes - usage.history_bytes > 0;
        if (usage.items > 0 || grew) && over_quota(&mut tx, vault_id, quota).await? {
            return Err(WriteError::QuotaExceeded);
        }
        tx.commit().await?;
    }
    Ok(results)
}

/// Per-account storage limits, counted over the vaults the account owns,
/// trash included.
#[derive(Clone, Copy, Debug)]
pub struct Quota {
    pub items: u64,
    pub bytes: u64,
}

pub(super) async fn add_usage(
    conn: &mut Conn,
    vault_id: &str,
    usage: Usage,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE vaults SET item_count = item_count + $2, item_bytes = item_bytes + $3 WHERE id = $1",
    )
    .bind(vault_id)
    .bind(usage.items)
    .bind(usage.bytes)
    .execute(conn)
    .await?;
    Ok(())
}

/// Whether any owner of the vault now stores more than the quota allows.
async fn over_quota(conn: &mut Conn, vault_id: &str, quota: Quota) -> Result<bool, sqlx::Error> {
    let owners: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(v.item_count), 0) AS BIGINT), CAST(COALESCE(SUM(v.item_bytes), 0) AS BIGINT) \
         FROM vault_members o \
         JOIN vault_members m ON m.account_id = o.account_id AND m.role = 'owner' \
         JOIN vaults v ON v.id = m.vault_id \
         WHERE o.vault_id = $1 AND o.role = 'owner' GROUP BY o.account_id",
    )
    .bind(vault_id)
    .fetch_all(conn)
    .await?;
    let limit = |max: u64| i64::try_from(max).unwrap_or(i64::MAX);
    Ok(owners
        .iter()
        .any(|&(items, bytes)| items > limit(quota.items) || bytes > limit(quota.bytes)))
}

/// The item a write goes to, and the vault's current key id when it has one.
#[derive(Clone, Copy)]
struct Target<'a> {
    vault_id: &'a str,
    item_id: &'a str,
    key_id: Option<&'a str>,
}

/// One write inside `write_all`'s transaction, at the already bumped
/// `revision`. Also returns how it changed the vault's storage use.
async fn apply(
    conn: &mut Conn,
    target: Target<'_>,
    write: ItemWrite<'_>,
    revision: i64,
    now: i64,
) -> Result<(Written, Usage), WriteError> {
    let Target {
        vault_id,
        item_id,
        key_id,
    } = target;
    // After a key rotation, a member still on the old key must not store item
    // keys the other members can't open.
    if let (ItemWrite::Put(_, body), Some(key_id)) = (&write, key_id)
        && validate::envelope_key_id(&body.encrypted_item_key).as_deref() != Some(key_id)
    {
        return Err(WriteError::StaleVaultKey);
    }
    let current: Option<ItemRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_ITEMS} WHERE vault_id = $1 AND id = $2"
    )))
    .bind(vault_id)
    .bind(item_id)
    .fetch_optional(&mut *conn)
    .await?;

    let unchanged = |current: &ItemRow| {
        let written = Written {
            revision: to_u64(current.revision),
            changed: false,
        };
        (written, Usage::default())
    };
    let size = |body: &PutItemRequest| {
        stored_size(&body.encrypted_item_key, &body.overview, &body.details)
    };
    let mut usage = Usage::default();
    // Every statement takes the vault id, item id and new revision as $1..$3.
    let keyed = |sql: &'static str| sqlx::query(sql).bind(vault_id).bind(item_id).bind(revision);
    let statement = match (write, current) {
        (ItemWrite::Put(Precondition::Create, _), Some(current)) => {
            return Err(WriteError::Conflict(Box::new(current.into_record())));
        }
        (ItemWrite::Put(Precondition::Create, body), None) => {
            usage = Usage {
                items: 1,
                bytes: size(body),
                history_bytes: 0,
            };
            sqlx::query("DELETE FROM tombstones WHERE vault_id = $1 AND item_id = $2")
                .bind(vault_id)
                .bind(item_id)
                .execute(&mut *conn)
                .await?;
            keyed(
                "INSERT INTO items (vault_id, id, revision, encrypted_item_key, overview, details, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&body.encrypted_item_key)
            .bind(&body.overview)
            .bind(&body.details)
            .bind(now)
        }
        (_, None) => return Err(WriteError::NotFound),
        (ItemWrite::Put(Precondition::Revision(expected), _) | ItemWrite::Delete(Some(expected)), Some(current))
            if to_u64(current.revision) != expected =>
        {
            return Err(WriteError::Conflict(Box::new(current.into_record())));
        }
        (ItemWrite::Put(_, body), Some(current)) => {
            usage.bytes = size(body) - current.size();
            if !body.skip_history {
                usage.history_bytes = keep_version(&mut *conn, &current).await?;
                usage.bytes += usage.history_bytes;
            }
            keyed(
                "UPDATE items SET revision = $3, encrypted_item_key = $4, overview = $5, details = $6, updated_at = $7 \
                 WHERE vault_id = $1 AND id = $2",
            )
            .bind(&body.encrypted_item_key)
            .bind(&body.overview)
            .bind(&body.details)
            .bind(now)
        }
        (ItemWrite::Delete(_), Some(current)) if current.deleted_at.is_some() => return Ok(unchanged(&current)),
        (ItemWrite::Delete(_), Some(_)) => keyed(
            "UPDATE items SET revision = $3, deleted_at = $4, updated_at = $4 WHERE vault_id = $1 AND id = $2",
        )
        .bind(now),
        (ItemWrite::Restore, Some(current)) if current.deleted_at.is_none() => return Ok(unchanged(&current)),
        (ItemWrite::Restore, Some(_)) => keyed(
            "UPDATE items SET revision = $3, deleted_at = NULL, updated_at = $4 WHERE vault_id = $1 AND id = $2",
        )
        .bind(now),
    };
    statement.execute(&mut *conn).await?;
    let written = Written {
        revision: to_u64(revision),
        changed: true,
    };
    Ok((written, usage))
}

/// Adds the version an edit is about to replace to the item's history and drops what falls off the
/// end. Returns how the history's size changed: it counts against the quota like any stored
/// ciphertext.
async fn keep_version(conn: &mut Conn, current: &ItemRow) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO item_history (vault_id, item_id, revision, overview, details, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (vault_id, item_id, revision) DO NOTHING",
    )
    .bind(&current.vault_id)
    .bind(&current.id)
    .bind(current.revision)
    .bind(&current.overview)
    .bind(&current.details)
    .bind(current.updated_at)
    .execute(&mut *conn)
    .await?;
    let kept: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT revision, CAST(LENGTH(overview) + LENGTH(details) AS BIGINT) FROM item_history \
         WHERE vault_id = $1 AND item_id = $2 ORDER BY revision DESC",
    )
    .bind(&current.vault_id)
    .bind(&current.id)
    .fetch_all(&mut *conn)
    .await?;
    let added = stored_size("", &current.overview, &current.details);
    let Some(&(newest_dropped, _)) = kept.get(HISTORY_LIMIT) else {
        return Ok(added);
    };
    sqlx::query("DELETE FROM item_history WHERE vault_id = $1 AND item_id = $2 AND revision <= $3")
        .bind(&current.vault_id)
        .bind(&current.id)
        .bind(newest_dropped)
        .execute(conn)
        .await?;
    let dropped: i64 = kept[HISTORY_LIMIT..].iter().map(|(_, size)| size).sum();
    Ok(added - dropped)
}

#[derive(FromRow)]
struct RevisionRow {
    revision: i64,
    overview: String,
    details: String,
    updated_at: i64,
}

/// The item's past versions, newest first, or `None` when the account can't see the item.
pub async fn history(
    db: &Db,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
) -> Result<Option<Vec<ItemRevision>>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let visible: Option<i64> = sqlx::query_scalar(
        // `vault_access`, not `vault_members`: past versions are vault contents, which an
        // organisation's two-step policy can withhold (plan 04 History, m25-teams).
        "SELECT 1 FROM items i JOIN vault_access m ON m.vault_id = i.vault_id \
         WHERE i.vault_id = $1 AND i.id = $2 AND m.account_id = $3",
    )
    .bind(vault_id)
    .bind(item_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    if visible.is_none() {
        return Ok(None);
    }
    let rows: Vec<RevisionRow> = sqlx::query_as(
        "SELECT revision, overview, details, updated_at FROM item_history \
         WHERE vault_id = $1 AND item_id = $2 ORDER BY revision DESC",
    )
    .bind(vault_id)
    .bind(item_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(
        rows.into_iter()
            .map(|row| ItemRevision {
                revision: to_u64(row.revision),
                overview: row.overview,
                details: row.details,
                updated_at: rfc3339(row.updated_at),
            })
            .collect(),
    ))
}

/// The accounts that can see a vault, and so hear about its changes.
pub async fn members(db: &Db, vault_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT account_id FROM vault_members WHERE vault_id = $1")
        .bind(vault_id)
        .fetch_all(db)
        .await
}

/// Every vault the account can access, with its current revision.
pub async fn revisions(db: &Db, account_id: &str) -> Result<Vec<(String, u64)>, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT v.id, v.revision FROM vaults v JOIN vault_access m ON m.vault_id = v.id \
         WHERE m.account_id = $1 ORDER BY v.id",
    )
    .bind(account_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, revision)| (id, to_u64(revision)))
        .collect())
}

/// Moves items that sat in the trash for 30 days to tombstones, and drops
/// tombstones older than 90 days. Returns each vault that changed, with its
/// new revision.
pub async fn purge(db: &Db, now: i64) -> Result<Vec<(String, u64)>, sqlx::Error> {
    let trash_cutoff = now - TRASH_RETENTION;
    let vaults: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT vault_id FROM items WHERE deleted_at IS NOT NULL AND deleted_at <= $1",
    )
    .bind(trash_cutoff)
    .fetch_all(db)
    .await?;

    let mut changed = Vec::with_capacity(vaults.len());
    for vault_id in vaults {
        let mut tx = db.begin().await?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(&vault_id)
        .fetch_one(&mut *tx)
        .await?;
        super::attachments::remove_purged(&mut tx, &vault_id, trash_cutoff, now).await?;
        sqlx::query(
            "INSERT INTO tombstones (vault_id, item_id, revision, purged_at) \
             SELECT vault_id, id, $2, $3 FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at <= $4 \
             ON CONFLICT (vault_id, item_id) DO UPDATE SET revision = excluded.revision, purged_at = excluded.purged_at",
        )
        .bind(&vault_id)
        .bind(revision)
        .bind(now)
        .bind(trash_cutoff)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE vaults SET item_count = item_count - purged.n, item_bytes = item_bytes - purged.bytes \
             FROM (SELECT COUNT(*) AS n, \
                   CAST(COALESCE(SUM(LENGTH(encrypted_item_key) + LENGTH(overview) + LENGTH(details)), 0) AS BIGINT) \
                   + (SELECT CAST(COALESCE(SUM(LENGTH(h.overview) + LENGTH(h.details)), 0) AS BIGINT) \
                      FROM item_history h JOIN items i ON i.vault_id = h.vault_id AND i.id = h.item_id \
                      WHERE i.vault_id = $1 AND i.deleted_at IS NOT NULL AND i.deleted_at <= $2) AS bytes \
                   FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at <= $2) AS purged \
             WHERE vaults.id = $1",
        )
        .bind(&vault_id)
        .bind(trash_cutoff)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM items WHERE vault_id = $1 AND deleted_at IS NOT NULL AND deleted_at <= $2",
        )
        .bind(&vault_id)
        .bind(trash_cutoff)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        changed.push((vault_id, to_u64(revision)));
    }

    sqlx::query("DELETE FROM tombstones WHERE purged_at <= $1")
        .bind(now - TOMBSTONE_RETENTION)
        .execute(db)
        .await?;
    Ok(changed)
}

pub(super) fn to_u64(value: i64) -> u64 {
    u64::try_from(value).expect("revisions are never negative")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{connect, now};

    const UNLIMITED: Quota = Quota {
        items: u64::MAX,
        bytes: u64::MAX,
    };

    async fn vault_with_item() -> (tempfile::TempDir, Db, PutItemRequest) {
        let dir = tempfile::tempdir().unwrap();
        let db = connect(&format!("sqlite://{}/test.db", dir.path().display()))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, email, kdf_memory_kib, kdf_iterations, kdf_parallelism, account_salt, opaque_record, \
             wrapped_ask, public_enc_key, public_sign_key, wrapped_private_keys, recovery_wrapped_ask, email_verified_at, created_at) \
             VALUES ('a', 'a@example.com', 65536, 3, 1, '', '', '', '', '', '', '', 0, 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        insert_personal_vault(&mut db.acquire().await.unwrap(), "v", "a", "key", 0)
            .await
            .unwrap();
        let body = PutItemRequest {
            encrypted_item_key: "k".into(),
            overview: "o".into(),
            details: "d".into(),
            skip_history: false,
        };
        (dir, db, body)
    }

    async fn create(db: &Db, item_id: &str, body: &PutItemRequest, now: i64) -> Written {
        let write = ItemWrite::Put(Precondition::Create, body);
        super::write(db, "a", "v", item_id, write, UNLIMITED, now)
            .await
            .unwrap()
    }

    async fn usage(db: &Db) -> (i64, i64) {
        sqlx::query_as("SELECT item_count, item_bytes FROM vaults WHERE id = 'v'")
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn purges_old_trash_into_tombstones() {
        let (_dir, db, body) = vault_with_item().await;
        let start = now();
        create(&db, "old", &body, start).await;
        write(
            &db,
            "a",
            "v",
            "old",
            ItemWrite::Delete(Some(1)),
            UNLIMITED,
            start,
        )
        .await
        .unwrap();
        create(&db, "kept", &body, start).await;
        assert_eq!(usage(&db).await, (2, 6));

        assert_eq!(
            purge(&db, start + days(29)).await.unwrap(),
            vec![],
            "still in the trash"
        );
        assert_eq!(
            purge(&db, start + days(31)).await.unwrap(),
            vec![("v".to_owned(), 4)]
        );
        assert_eq!(usage(&db).await, (1, 3));

        let since = HashMap::from([("v".to_owned(), 3)]);
        let synced = sync(&db, "a", &since, None, false, PAGE).await.unwrap();
        assert_eq!(synced.vaults[0].revision, 4);
        assert!(synced.items.is_empty());
        assert_eq!(
            synced.deleted,
            vec![DeletedItem {
                vault_id: "v".into(),
                item_id: "old".into(),
                revision: 4
            }]
        );

        // Tombstones age out after 90 days.
        purge(&db, start + days(31) + days(91)).await.unwrap();
        assert!(
            sync(&db, "a", &since, None, false, PAGE)
                .await
                .unwrap()
                .deleted
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_failed_precondition_does_not_bump_the_revision() {
        let (_dir, db, body) = vault_with_item().await;
        create(&db, "i", &body, 0).await;
        let stale = ItemWrite::Put(Precondition::Revision(7), &body);
        let conflict = write(&db, "a", "v", "i", stale, UNLIMITED, 0).await;
        assert!(matches!(conflict, Err(WriteError::Conflict(current)) if current.revision == 1));
        let noop = write(&db, "a", "v", "i", ItemWrite::Restore, UNLIMITED, 0)
            .await
            .unwrap();
        assert_eq!(
            noop,
            Written {
                revision: 1,
                changed: false
            }
        );
        let synced = sync(&db, "a", &HashMap::new(), None, false, PAGE)
            .await
            .unwrap();
        assert_eq!(synced.vaults[0].revision, 1);
        assert!(matches!(
            write(&db, "b", "v", "i", ItemWrite::Restore, UNLIMITED, 0).await,
            Err(WriteError::NotFound)
        ));
    }

    #[tokio::test]
    async fn quotas_limit_growth_but_not_cleanup() {
        let (_dir, db, body) = vault_with_item().await;
        let quota = Quota { items: 2, bytes: 8 };
        let db = &db;
        let put = |id: &'static str, precondition, body| async move {
            let write = ItemWrite::Put(precondition, body);
            super::write(db, "a", "v", id, write, quota, 0).await
        };
        put("one", Precondition::Create, &body).await.unwrap();
        put("two", Precondition::Create, &body).await.unwrap();
        assert!(matches!(
            put("three", Precondition::Create, &body).await,
            Err(WriteError::QuotaExceeded)
        ));
        assert_eq!(usage(db).await, (2, 6), "the refused write left no trace");

        let big = PutItemRequest {
            details: "dddd".into(),
            ..body.clone()
        };
        assert!(matches!(
            put("one", Precondition::Any, &big).await,
            Err(WriteError::QuotaExceeded)
        ));
        // Over quota after the operator lowers it, shrinking still works.
        sqlx::query("UPDATE vaults SET item_bytes = 100")
            .execute(db)
            .await
            .unwrap();
        let small = PutItemRequest {
            details: String::new(),
            ..body.clone()
        };
        put("one", Precondition::Any, &small).await.unwrap();
        // One byte less on the item, and the two-byte version it replaced joins the history.
        assert_eq!(usage(db).await, (2, 101));
    }

    #[tokio::test]
    async fn pages_end_between_revisions() {
        let (_dir, db, body) = vault_with_item().await;
        // Revisions 1 and 2 hold three items each, revision 3 holds one.
        for (revision, ids) in [
            (1, ["a1", "a2", "a3"].as_slice()),
            (2, &["b1", "b2", "b3"]),
            (3, &["c1"]),
        ] {
            let writes = ids
                .iter()
                .map(|id| (*id, ItemWrite::Put(Precondition::Create, &body)))
                .collect();
            let results = write_all(&db, "a", "v", writes, UNLIMITED, 0)
                .await
                .unwrap();
            assert!(
                results
                    .iter()
                    .all(|r| r.as_ref().unwrap().revision == revision)
            );
        }
        let page = PageSize {
            items: 4,
            bytes: i64::MAX,
        };

        let first = sync(&db, "a", &HashMap::new(), None, false, page)
            .await
            .unwrap();
        assert!(first.has_more);
        assert_eq!(first.items.len(), 6, "revision 2 is never split");
        assert_eq!(first.vaults[0].revision, 2);

        let since = HashMap::from([("v".to_owned(), 2)]);
        let last = sync(&db, "a", &since, None, false, page).await.unwrap();
        assert!(!last.has_more);
        assert_eq!(last.items.len(), 1);
        assert_eq!(last.vaults[0].revision, 3);

        // A byte budget ends pages the same way.
        let tiny = PageSize {
            items: 1000,
            bytes: 1,
        };
        let first = sync(&db, "a", &HashMap::new(), None, false, tiny)
            .await
            .unwrap();
        assert_eq!((first.items.len(), first.vaults[0].revision), (3, 1));
    }
}
