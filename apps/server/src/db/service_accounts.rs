//! Service accounts: vault members that aren't people (plan 03, "Non-human access"). Grants are
//! stored as the creator's device signed them, and the name is ciphertext.

use octapass_api::{CreateServiceAccountRequest, Grant, ServiceAccountRecord, VaultRole};
use sqlx::FromRow;

use super::items::parse_role;
use super::{Conn, Db, rfc3339};
use crate::crypto::token_hash;

#[derive(FromRow)]
pub struct ServiceAccountRow {
    pub id: String,
    pub vault_id: String,
    pub created_by: String,
    pub role: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    pub encrypted_name: String,
    pub granted_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

const SELECT: &str = "SELECT id, vault_id, created_by, role, public_enc_key, public_sign_key, \
     encrypted_name, granted_by, created_at, expires_at, last_used_at, revoked_at FROM service_accounts";

impl ServiceAccountRow {
    pub fn into_record(self) -> ServiceAccountRecord {
        ServiceAccountRecord {
            role: parse_role(&self.role),
            created_at: rfc3339(self.created_at),
            expires_at: self.expires_at.map(rfc3339),
            last_used_at: self.last_used_at.map(rfc3339),
            revoked_at: self.revoked_at.map(rfc3339),
            id: self.id,
            vault_id: self.vault_id,
            created_by: self.created_by,
            public_enc_key: self.public_enc_key,
            encrypted_name: self.encrypted_name,
            granted_by: self.granted_by,
        }
    }

    /// Whether it may still act. `expires_at` is checked here, not in SQL, so every path agrees.
    pub fn is_active(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|at| at > now)
    }
}

pub async fn insert(
    conn: &mut Conn,
    request: &CreateServiceAccountRequest,
    expires_at: Option<i64>,
    created_by: &str,
    granter_sign_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    let grant = &request.grant;
    sqlx::query(
        "INSERT INTO service_accounts (id, vault_id, created_by, role, public_enc_key, public_sign_key, \
         encrypted_name, wrapped_vault_key, granted_by, granter_sign_key, granted_at, signature, \
         created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(&request.id)
    .bind(&grant.vault_id)
    .bind(created_by)
    .bind(grant.role.as_str())
    .bind(&request.public_enc_key)
    .bind(&request.public_sign_key)
    .bind(&request.encrypted_name)
    .bind(&grant.wrapped_vault_key)
    .bind(&grant.granted_by)
    .bind(granter_sign_key)
    .bind(i64::try_from(grant.granted_at).unwrap_or(i64::MAX))
    .bind(&grant.signature)
    .bind(now)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn find(db: &Db, id: &str) -> Result<Option<ServiceAccountRow>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn list(db: &Db, vault_id: &str) -> Result<Vec<ServiceAccountRow>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE vault_id = $1 ORDER BY created_at, id"
    )))
    .bind(vault_id)
    .fetch_all(db)
    .await
}

/// The ids and roles of a vault's accounts that aren't revoked. Expired ones keep getting new keys
/// (they may be extended by a person later, and a key to nobody harms nothing).
pub async fn active_in(
    conn: &mut Conn,
    vault_id: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, role FROM service_accounts WHERE vault_id = $1 AND revoked_at IS NULL",
    )
    .bind(vault_id)
    .fetch_all(conn)
    .await
}

/// A rotation's new grant for a service account.
pub async fn put_grant(
    conn: &mut Conn,
    grant: &Grant,
    granter_sign_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE service_accounts SET wrapped_vault_key = $2, granted_by = $3, granter_sign_key = $4, \
         granted_at = $5, signature = $6 WHERE id = $1",
    )
    .bind(&grant.recipient_account_id)
    .bind(&grant.wrapped_vault_key)
    .bind(&grant.granted_by)
    .bind(granter_sign_key)
    .bind(i64::try_from(grant.granted_at).unwrap_or(i64::MAX))
    .bind(&grant.signature)
    .execute(conn)
    .await?;
    Ok(())
}

/// Ends it now: no new sessions, and the live ones go. The row stays so the log can name it.
/// `false` if it was already revoked.
pub async fn revoke(conn: &mut Conn, id: &str, now: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE service_accounts SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;
    sqlx::query("DELETE FROM service_account_sessions WHERE service_account_id = $1")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(done)
}

pub async fn insert_session(
    db: &Db,
    token: &str,
    id: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO service_account_sessions (token_hash, service_account_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash(token))
    .bind(id)
    .bind(expires_at)
    .execute(db)
    .await?;
    Ok(())
}

/// The service account behind an access token, while the token and the account are both good.
pub async fn find_by_token(
    db: &Db,
    token: &str,
    now: i64,
) -> Result<Option<ServiceAccountRow>, sqlx::Error> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT service_account_id FROM service_account_sessions WHERE token_hash = $1 AND expires_at > $2",
    )
    .bind(token_hash(token))
    .bind(now)
    .fetch_optional(db)
    .await?;
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(find(db, &id).await?.filter(|row| row.is_active(now)))
}

pub async fn touch(db: &Db, id: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE service_accounts SET last_used_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn purge_expired_sessions(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM service_account_sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

/// Roles a service account can hold.
pub fn allowed_role(role: VaultRole) -> bool {
    matches!(role, VaultRole::Read | VaultRole::Write)
}
