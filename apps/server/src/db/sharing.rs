//! Shared and family vaults: members, their grants and key rotation. Grants
//! are stored as the granter's device sent them, next to the granter's signing
//! key at that time.

use std::collections::{HashMap, HashSet};

use octapass_api::{Grant, RotateVaultRequest, SecurityEventType, VaultRole};
use sqlx::FromRow;

use super::items::{Usage, add_usage, parse_role, stored_size, to_u64};
use super::{Conn, Db};

pub async fn create_vault(
    conn: &mut Conn,
    vault_type: &'static str,
    key_id: &str,
    grant: &Grant,
    granter_sign_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vaults (id, type, revision, key_id, created_at) VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(&grant.vault_id)
    .bind(vault_type)
    .bind(key_id)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    put_member(conn, grant, granter_sign_key, now).await
}

/// Adds the grant's recipient to the vault, or replaces their grant.
pub async fn put_member(
    conn: &mut Conn,
    grant: &Grant,
    granter_sign_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vault_members (vault_id, account_id, role, wrapped_vault_key, added_at, \
         granted_by, granter_sign_key, granted_at, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (vault_id, account_id) DO UPDATE SET role = excluded.role, \
         wrapped_vault_key = excluded.wrapped_vault_key, granted_by = excluded.granted_by, \
         granter_sign_key = excluded.granter_sign_key, granted_at = excluded.granted_at, \
         signature = excluded.signature",
    )
    .bind(&grant.vault_id)
    .bind(&grant.recipient_account_id)
    .bind(grant.role.as_str())
    .bind(&grant.wrapped_vault_key)
    .bind(now)
    .bind(&grant.granted_by)
    .bind(granter_sign_key)
    .bind(i64::try_from(grant.granted_at).unwrap_or(i64::MAX))
    .bind(&grant.signature)
    .execute(conn)
    .await?;
    Ok(())
}

/// Takes the vault's write lock (on SQLite, the database's) before a
/// transaction reads what its change depends on, so a concurrent change can't
/// slip in between the check and the write.
pub async fn lock_vault(conn: &mut Conn, vault_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE vaults SET revision = revision WHERE id = $1")
        .bind(vault_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// The id of the vault's current key. Personal vaults have none until their first rotation.
pub async fn key_id(conn: &mut Conn, vault_id: &str) -> Result<Option<String>, sqlx::Error> {
    let key_id: Option<Option<String>> =
        sqlx::query_scalar("SELECT key_id FROM vaults WHERE id = $1")
            .bind(vault_id)
            .fetch_optional(conn)
            .await?;
    Ok(key_id.flatten())
}

/// A vault as one of its members sees it.
pub struct Membership {
    pub vault_type: String,
    pub role: VaultRole,
    pub org_id: Option<String>,
}

pub async fn membership(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
) -> Result<Option<Membership>, sqlx::Error> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT v.type, m.role, v.org_id FROM vaults v JOIN vault_access m ON m.vault_id = v.id \
         WHERE v.id = $1 AND m.account_id = $2",
    )
    .bind(vault_id)
    .bind(account_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(vault_type, role, org_id)| Membership {
        vault_type,
        role: parse_role(&role),
        org_id,
    }))
}

#[derive(FromRow)]
pub struct MemberRow {
    pub account_id: String,
    pub email: String,
    pub role: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    pub key_record: Option<String>,
    pub granted_by: Option<String>,
    pub added_at: i64,
}

pub async fn members(db: &Db, vault_id: &str) -> Result<Vec<MemberRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT m.account_id, a.email, m.role, a.public_enc_key, a.public_sign_key, a.key_record, m.granted_by, m.added_at \
         FROM vault_members m JOIN accounts a ON a.id = m.account_id WHERE m.vault_id = $1 \
         ORDER BY m.added_at, m.account_id",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await
}

pub async fn remove_member(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND account_id = $2")
        .bind(vault_id)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(removed.rows_affected() > 0)
}

pub async fn owner_count(conn: &mut Conn, vault_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM vault_members WHERE vault_id = $1 AND role = 'owner'",
    )
    .bind(vault_id)
    .fetch_one(conn)
    .await
}

/// Deletes a vault and everything in it.
pub async fn delete_vault(conn: &mut Conn, vault_id: &str) -> Result<(), sqlx::Error> {
    super::attachments::remove_vault(conn, vault_id, super::now()).await?;
    for statement in [
        "DELETE FROM emergency_contacts WHERE scope_vault_id = $1",
        "DELETE FROM items WHERE vault_id = $1",
        "DELETE FROM tombstones WHERE vault_id = $1",
        "DELETE FROM vault_members WHERE vault_id = $1",
        "DELETE FROM vaults WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(vault_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    #[error("the vault changed since that revision")]
    VaultChanged,
    #[error("the caller may no longer manage this vault")]
    Forbidden,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Swaps in a new vault key in one transaction: every member's grant and
/// every item key, at a new revision so every member syncs the items again.
/// Fails unless the vault is still at `request.revision`, the grants cover
/// exactly the current members with their current roles, and the items are
/// exactly the vault's items. A family vault's pending invites take the new
/// grants in `request.invites`; the ones it leaves out are cancelled, so no
/// invite keeps the old key. A personal vault has no grants or invites: its
/// owner's wrapped key takes `request.wrapped_vault_key`. Vault-scoped emergency
/// contacts are left on the old key, marked stale until the grantor renews them.
/// Returns the new revision.
pub async fn rotate(
    db: &Db,
    vault_id: &str,
    caller: &str,
    request: &RotateVaultRequest,
    granter_sign_key: &str,
    now: i64,
) -> Result<u64, RotateError> {
    let mut tx = db.begin().await?;
    let expected = i64::try_from(request.revision).unwrap_or(i64::MAX);
    let revision: Option<i64> = sqlx::query_scalar(
        "UPDATE vaults SET revision = revision + 1, key_id = $3 WHERE id = $1 AND revision = $2 \
         RETURNING revision",
    )
    .bind(vault_id)
    .bind(expected)
    .bind(&request.key_id)
    .fetch_optional(&mut *tx)
    .await?;
    let revision = revision.ok_or(RotateError::VaultChanged)?;

    let members: HashMap<String, String> =
        sqlx::query_as("SELECT account_id, role FROM vault_members WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    // Checked again inside the transaction: a manager removed while rotating must not get the new key.
    if !members
        .get(caller)
        .is_some_and(|role| parse_role(role) >= VaultRole::Manage)
    {
        return Err(RotateError::Forbidden);
    }
    let vault_type: String = sqlx::query_scalar("SELECT type FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_one(&mut *tx)
        .await?;
    let personal = vault_type == "personal";
    if personal != request.wrapped_vault_key.is_some() {
        return Err(RotateError::Invalid(
            "wrappedVaultKey is for personal vaults, and they need it".into(),
        ));
    }
    if personal && !(request.grants.is_empty() && request.invites.is_empty()) {
        return Err(RotateError::Invalid(
            "a personal vault has no grants or invites".into(),
        ));
    }
    let mut granted = HashSet::new();
    for grant in &request.grants {
        let role = members.get(&grant.recipient_account_id);
        if role.map(|role| parse_role(role)) != Some(grant.role) {
            return Err(RotateError::Invalid(
                "every grant must be for a current member, with their current role".into(),
            ));
        }
        if !granted.insert(grant.recipient_account_id.as_str()) {
            return Err(RotateError::Invalid("one grant per member".into()));
        }
    }
    if !personal && granted.len() != members.len() {
        return Err(RotateError::Invalid(
            "every member needs a new grant".into(),
        ));
    }

    let stored: HashMap<String, String> =
        sqlx::query_as("SELECT id, encrypted_item_key FROM items WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    let mut usage = Usage::default();
    let mut rewrapped = HashSet::new();
    for item in &request.items {
        let Some(old) = stored.get(&item.item_id) else {
            return Err(RotateError::Invalid(format!(
                "item {} isn't in this vault",
                item.item_id
            )));
        };
        if !rewrapped.insert(item.item_id.as_str()) {
            return Err(RotateError::Invalid(format!(
                "item {} appears twice",
                item.item_id
            )));
        }
        usage.bytes += stored_size(&item.encrypted_item_key, "", "") - stored_size(old, "", "");
    }
    if rewrapped.len() != stored.len() {
        return Err(RotateError::Invalid(
            "every item in the vault, trash included, needs its re-wrapped key".into(),
        ));
    }

    let pending = pending_invites(&mut tx, vault_id).await?;
    let mut reissued = HashSet::new();
    for grant in &request.invites {
        let Some((_, role)) = pending
            .iter()
            .find(|(account_id, _)| *account_id == grant.recipient_account_id)
        else {
            return Err(RotateError::Invalid(
                "every invite grant must be for a pending invite".into(),
            ));
        };
        if parse_role(role) != grant.role {
            return Err(RotateError::Invalid(
                "an invite grant must keep the invite's role".into(),
            ));
        }
        if !reissued.insert(grant.recipient_account_id.as_str()) {
            return Err(RotateError::Invalid("one grant per invite".into()));
        }
    }

    // Left out, a service account keeps a key that no longer opens the vault: it fails closed.
    let active = super::service_accounts::active_in(&mut tx, vault_id).await?;
    let mut service_granted = HashSet::new();
    for grant in &request.service_grants {
        crate::routes::service_accounts::check_service_grant(&active, grant)
            .map_err(RotateError::Invalid)?;
        if !service_granted.insert(grant.recipient_account_id.as_str()) {
            return Err(RotateError::Invalid("one grant per service account".into()));
        }
    }

    if let Some(wrapped_vault_key) = &request.wrapped_vault_key {
        sqlx::query("UPDATE vault_members SET wrapped_vault_key = $2 WHERE vault_id = $1")
            .bind(vault_id)
            .bind(wrapped_vault_key)
            .execute(&mut *tx)
            .await?;
    }
    for grant in &request.grants {
        put_member(&mut tx, grant, granter_sign_key, now).await?;
    }
    for grant in &request.service_grants {
        super::service_accounts::put_grant(&mut tx, grant, granter_sign_key).await?;
    }
    for grant in &request.invites {
        sqlx::query(
            "UPDATE family_invites SET wrapped_vault_key = $3, granted_by = $4, granter_sign_key = $5, \
             granted_at = $6, signature = $7 WHERE account_id = $2 \
             AND family_id = (SELECT id FROM families WHERE vault_id = $1)",
        )
        .bind(vault_id)
        .bind(&grant.recipient_account_id)
        .bind(&grant.wrapped_vault_key)
        .bind(&grant.granted_by)
        .bind(granter_sign_key)
        .bind(i64::try_from(grant.granted_at).unwrap_or(i64::MAX))
        .bind(&grant.signature)
        .execute(&mut *tx)
        .await?;
    }
    for (account_id, _) in &pending {
        if !reissued.contains(account_id.as_str()) {
            sqlx::query(
                "DELETE FROM family_invites WHERE account_id = $2 \
                 AND family_id = (SELECT id FROM families WHERE vault_id = $1)",
            )
            .bind(vault_id)
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    for item in &request.items {
        sqlx::query(
            "UPDATE items SET encrypted_item_key = $3, revision = $4 WHERE vault_id = $1 AND id = $2",
        )
        .bind(vault_id)
        .bind(&item.item_id)
        .bind(&item.encrypted_item_key)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
    }
    add_usage(&mut tx, vault_id, usage).await?;
    super::emergency::mark_vault_keys_stale(&mut tx, vault_id).await?;
    let event = SecurityEventType::VaultKeyRotated;
    super::audit::record(&mut *tx, caller, event, None, None, now).await?;
    tx.commit().await?;
    Ok(to_u64(revision))
}

/// (account id, role) of each pending invite to the family whose vault this is.
async fn pending_invites(
    conn: &mut Conn,
    vault_id: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT i.account_id, i.role FROM family_invites i JOIN families f ON f.id = i.family_id \
         WHERE f.vault_id = $1",
    )
    .bind(vault_id)
    .fetch_all(conn)
    .await
}
