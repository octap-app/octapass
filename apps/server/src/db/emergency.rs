//! Emergency contacts and the request → wait → release timeline. Every
//! status change is a conditional update, so two racing requests (or the
//! maintenance task and a request) can't both apply the same transition.

use octapass_api::{EmergencyAccessLevel, EmergencyContactRecord, EmergencyScope, EmergencyStatus};
use sqlx::FromRow;

use super::{Conn, Db, days, rfc3339};

#[derive(Clone, FromRow)]
pub struct ContactRow {
    pub id: String,
    pub grantor_id: String,
    pub grantor_email: String,
    pub contact_id: String,
    pub contact_email: String,
    pub scope_vault_id: Option<String>,
    pub access_level: String,
    pub wait_days: i64,
    pub sealed_key: String,
    pub status: String,
    pub requested_at: Option<i64>,
    pub releases_at: Option<i64>,
    pub released_at: Option<i64>,
    pub created_at: i64,
    pub key_stale: i64,
    pub organiser_recovery: i64,
}

impl ContactRow {
    pub fn status(&self) -> EmergencyStatus {
        match self.status.as_str() {
            "requested" => EmergencyStatus::Requested,
            "released" => EmergencyStatus::Released,
            _ => EmergencyStatus::Idle,
        }
    }

    pub fn is_organiser_recovery(&self) -> bool {
        self.organiser_recovery != 0
    }

    /// Whether a released record may replace the grantor's credentials.
    pub fn allows_takeover(&self) -> bool {
        self.access_level == "takeover" && self.scope_vault_id.is_none()
    }

    pub fn into_record(self) -> EmergencyContactRecord {
        EmergencyContactRecord {
            key_stale: self.key_stale != 0,
            organiser_recovery: self.is_organiser_recovery(),
            status: self.status(),
            scope: match self.scope_vault_id {
                Some(vault_id) => EmergencyScope::Vault { vault_id },
                None => EmergencyScope::Account,
            },
            access_level: if self.access_level == "takeover" {
                EmergencyAccessLevel::Takeover
            } else {
                EmergencyAccessLevel::View
            },
            wait_days: u32::try_from(self.wait_days).unwrap_or_default(),
            requested_at: self.requested_at.map(rfc3339),
            releases_at: self.releases_at.map(rfc3339),
            released_at: self.released_at.map(rfc3339),
            created_at: rfc3339(self.created_at),
            id: self.id,
            grantor_id: self.grantor_id,
            grantor_email: self.grantor_email,
            contact_id: self.contact_id,
            contact_email: self.contact_email,
        }
    }
}

const SELECT_CONTACTS: &str = "SELECT e.id, e.grantor_id, g.email AS grantor_email, e.contact_id, \
     c.email AS contact_email, e.scope_vault_id, e.access_level, e.wait_days, e.sealed_key, e.status, \
     e.requested_at, e.releases_at, e.released_at, e.created_at, e.key_stale, e.organiser_recovery \
     FROM emergency_contacts e JOIN accounts g ON g.id = e.grantor_id JOIN accounts c ON c.id = e.contact_id";

pub struct NewContact<'a> {
    pub id: &'a str,
    pub grantor_id: &'a str,
    pub contact_id: &'a str,
    pub scope_vault_id: Option<&'a str>,
    pub access_level: &'static str,
    pub wait_days: u32,
    pub sealed_key: &'a str,
    pub organiser_recovery: bool,
    pub now: i64,
}

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    contact: NewContact<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO emergency_contacts (id, grantor_id, contact_id, scope_vault_id, access_level, wait_days, \
         sealed_key, status, created_at, organiser_recovery) VALUES ($1, $2, $3, $4, $5, $6, $7, 'idle', $8, $9)",
    )
    .bind(contact.id)
    .bind(contact.grantor_id)
    .bind(contact.contact_id)
    .bind(contact.scope_vault_id)
    .bind(contact.access_level)
    .bind(i64::from(contact.wait_days))
    .bind(contact.sealed_key)
    .bind(contact.now)
    .bind(i64::from(contact.organiser_recovery))
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn find(db: &Db, id: &str) -> Result<Option<ContactRow>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_CONTACTS} WHERE e.id = $1"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// (as grantor, as contact), oldest first.
pub async fn list_for(
    db: &Db,
    account_id: &str,
) -> Result<(Vec<ContactRow>, Vec<ContactRow>), sqlx::Error> {
    let rows: Vec<ContactRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_CONTACTS} WHERE e.grantor_id = $1 OR e.contact_id = $1 ORDER BY e.created_at, e.id"
    )))
    .bind(account_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .partition(|row| row.grantor_id == account_id))
}

pub async fn delete(conn: &mut Conn, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM emergency_contacts WHERE id = $1")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

/// The contact's sealed copy no longer opens the vault's items: a rotation replaced the key.
pub async fn mark_vault_keys_stale(conn: &mut Conn, vault_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE emergency_contacts SET key_stale = 1 WHERE scope_vault_id = $1")
        .bind(vault_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// The grantor sealed the vault's current key to the contact again.
pub async fn renew_key(conn: &mut Conn, id: &str, sealed_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE emergency_contacts SET sealed_key = $2, key_stale = 0 WHERE id = $1")
        .bind(id)
        .bind(sealed_key)
        .execute(conn)
        .await?;
    Ok(())
}

/// Takes a released record that allows a takeover, inside the takeover's transaction, as its first
/// write: a denial that landed first wins, and nothing can use the record twice.
pub async fn take_for_takeover(conn: &mut Conn, id: &str) -> Result<bool, sqlx::Error> {
    let taken = sqlx::query(
        "DELETE FROM emergency_contacts WHERE id = $1 AND status = 'released' \
         AND access_level = 'takeover' AND scope_vault_id IS NULL",
    )
    .bind(id)
    .execute(conn)
    .await?;
    Ok(taken.rows_affected() > 0)
}

/// Ends the organiser recovery a member gave, if any, when they leave the family. Returns the
/// record's id.
pub async fn remove_organiser_recovery(
    conn: &mut Conn,
    grantor_id: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM emergency_contacts WHERE grantor_id = $1 AND organiser_recovery = 1 \
         RETURNING id, contact_id",
    )
    .bind(grantor_id)
    .fetch_optional(conn)
    .await
}

/// Ends every organiser recovery an organiser holds, when the family is deleted. Returns
/// (record id, member) for each.
pub async fn remove_organiser_recoveries_to(
    conn: &mut Conn,
    organiser_id: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM emergency_contacts WHERE contact_id = $1 AND organiser_recovery = 1 \
         RETURNING id, grantor_id",
    )
    .bind(organiser_id)
    .fetch_all(conn)
    .await
}

/// Idle → requested. The key is released at `releases_at` unless denied.
pub async fn request(
    conn: &mut Conn,
    id: &str,
    now: i64,
    wait_days: i64,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE emergency_contacts SET status = 'requested', requested_at = $2, releases_at = $3, \
         last_reminded_at = $2 WHERE id = $1 AND status = 'idle'",
    )
    .bind(id)
    .bind(now)
    .bind(now + days(wait_days))
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() > 0)
}

/// Requested or released → idle: the grantor denied, or took a release back.
pub async fn deny(conn: &mut Conn, id: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE emergency_contacts SET status = 'idle', requested_at = NULL, releases_at = NULL, \
         released_at = NULL, last_reminded_at = NULL WHERE id = $1 AND status IN ('requested', 'released')",
    )
    .bind(id)
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() > 0)
}

/// Requested → released. With `due_only`, only once the waiting period is over: an automatic
/// release must not act on a request that was denied and made again in the meantime.
pub async fn release(
    conn: &mut Conn,
    id: &str,
    now: i64,
    due_only: bool,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE emergency_contacts SET status = 'released', released_at = $2 WHERE id = $1 AND status = 'requested' \
         AND ($3 = 0 OR releases_at <= $2)",
    )
    .bind(id)
    .bind(now)
    .bind(i64::from(due_only))
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() > 0)
}

/// Requests whose waiting period is over.
pub async fn due(db: &Db, now: i64) -> Result<Vec<ContactRow>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_CONTACTS} WHERE e.status = 'requested' AND e.releases_at <= $1 ORDER BY e.releases_at"
    )))
    .bind(now)
    .fetch_all(db)
    .await
}

/// Pending requests whose grantor hasn't been reminded for a day. Marks them
/// reminded.
pub async fn take_reminders(db: &Db, now: i64) -> Result<Vec<ContactRow>, sqlx::Error> {
    let rows: Vec<ContactRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_CONTACTS} WHERE e.status = 'requested' AND e.last_reminded_at <= $1 ORDER BY e.releases_at"
    )))
    .bind(now - days(1))
    .fetch_all(db)
    .await?;
    let mut taken = Vec::with_capacity(rows.len());
    for row in rows {
        let updated = sqlx::query(
            "UPDATE emergency_contacts SET last_reminded_at = $2 WHERE id = $1 AND status = 'requested' \
             AND last_reminded_at <= $3",
        )
        .bind(&row.id)
        .bind(now)
        .bind(now - days(1))
        .execute(db)
        .await?;
        if updated.rows_affected() > 0 {
            taken.push(row);
        }
    }
    Ok(taken)
}
