//! Families: an organiser, members, pending invites and the shared Family
//! vault. Each account belongs to at most one family.

use octapass_api::{FamilyInvite, Grant, VaultRole};
use sqlx::FromRow;

use super::{Conn, Db, rfc3339};

#[derive(Clone, FromRow)]
pub struct FamilyRow {
    pub id: String,
    pub organiser_id: String,
    pub vault_id: String,
    pub created_at: i64,
}

pub async fn of_account(
    conn: &mut Conn,
    account_id: &str,
) -> Result<Option<FamilyRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT f.id, f.organiser_id, f.vault_id, f.created_at FROM families f \
         JOIN family_members m ON m.family_id = f.id WHERE m.account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(conn)
    .await
}

pub async fn find(conn: &mut Conn, family_id: &str) -> Result<Option<FamilyRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, organiser_id, vault_id, created_at FROM families WHERE id = $1")
        .bind(family_id)
        .fetch_optional(conn)
        .await
}

pub async fn create(conn: &mut Conn, family: &FamilyRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO families (id, organiser_id, vault_id, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&family.id)
    .bind(&family.organiser_id)
    .bind(&family.vault_id)
    .bind(family.created_at)
    .execute(&mut *conn)
    .await?;
    add_member(conn, &family.id, &family.organiser_id, family.created_at).await
}

pub async fn add_member(
    conn: &mut Conn,
    family_id: &str,
    account_id: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO family_members (family_id, account_id, joined_at) VALUES ($1, $2, $3)",
    )
    .bind(family_id)
    .bind(account_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn remove_member(
    conn: &mut Conn,
    family_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed =
        sqlx::query("DELETE FROM family_members WHERE family_id = $1 AND account_id = $2")
            .bind(family_id)
            .bind(account_id)
            .execute(conn)
            .await?;
    Ok(removed.rows_affected() > 0)
}

/// (account id, email, joined at), organiser first.
pub async fn members(
    db: &Db,
    family: &FamilyRow,
) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT m.account_id, a.email, m.joined_at FROM family_members m JOIN accounts a ON a.id = m.account_id \
         WHERE m.family_id = $1 ORDER BY CASE WHEN m.account_id = $2 THEN 0 ELSE 1 END, m.joined_at, m.account_id",
    )
    .bind(&family.id)
    .bind(&family.organiser_id)
    .fetch_all(db)
    .await
}

/// Members plus pending invites: what counts against the family size.
pub async fn size(conn: &mut Conn, family_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT CAST((SELECT COUNT(*) FROM family_members WHERE family_id = $1) + \
         (SELECT COUNT(*) FROM family_invites WHERE family_id = $1) AS BIGINT)",
    )
    .bind(family_id)
    .fetch_one(conn)
    .await
}

pub async fn put_invite(
    conn: &mut Conn,
    family_id: &str,
    grant: &Grant,
    granter_sign_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO family_invites (family_id, account_id, role, wrapped_vault_key, granted_by, granter_sign_key, \
         granted_at, signature, invited_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (family_id, account_id) DO UPDATE SET role = excluded.role, \
         wrapped_vault_key = excluded.wrapped_vault_key, granted_by = excluded.granted_by, \
         granter_sign_key = excluded.granter_sign_key, granted_at = excluded.granted_at, \
         signature = excluded.signature, invited_at = excluded.invited_at",
    )
    .bind(family_id)
    .bind(&grant.recipient_account_id)
    .bind(grant.role.as_str())
    .bind(&grant.wrapped_vault_key)
    .bind(&grant.granted_by)
    .bind(granter_sign_key)
    .bind(i64::try_from(grant.granted_at).unwrap_or(i64::MAX))
    .bind(&grant.signature)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct InviteGrantRow {
    role: String,
    wrapped_vault_key: String,
    granted_by: String,
    granter_sign_key: String,
    granted_at: i64,
    signature: String,
}

/// Removes the account's invite and returns its grant and the granter's
/// signing key, ready to become a vault membership.
pub async fn take_invite(
    conn: &mut Conn,
    family: &FamilyRow,
    account_id: &str,
) -> Result<Option<(Grant, String)>, sqlx::Error> {
    let row: Option<InviteGrantRow> = sqlx::query_as(
        "DELETE FROM family_invites WHERE family_id = $1 AND account_id = $2 \
         RETURNING role, wrapped_vault_key, granted_by, granter_sign_key, granted_at, signature",
    )
    .bind(&family.id)
    .bind(account_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| {
        let grant = Grant {
            vault_id: family.vault_id.clone(),
            recipient_account_id: account_id.to_owned(),
            role: VaultRole::parse(&row.role).unwrap_or(VaultRole::Read),
            wrapped_vault_key: row.wrapped_vault_key,
            granted_by: row.granted_by,
            granted_at: u64::try_from(row.granted_at).unwrap_or_default(),
            signature: row.signature,
        };
        (grant, row.granter_sign_key)
    }))
}

pub async fn delete_invite(
    conn: &mut Conn,
    family_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed =
        sqlx::query("DELETE FROM family_invites WHERE family_id = $1 AND account_id = $2")
            .bind(family_id)
            .bind(account_id)
            .execute(conn)
            .await?;
    Ok(removed.rows_affected() > 0)
}

#[derive(FromRow)]
struct InviteRow {
    family_id: String,
    account_id: String,
    email: String,
    organiser_email: String,
    invited_at: i64,
}

impl InviteRow {
    fn into_record(self) -> FamilyInvite {
        FamilyInvite {
            family_id: self.family_id,
            account_id: self.account_id,
            email: self.email,
            organiser_email: self.organiser_email,
            invited_at: rfc3339(self.invited_at),
        }
    }
}

const SELECT_INVITES: &str = "SELECT i.family_id, i.account_id, a.email, o.email AS organiser_email, i.invited_at \
     FROM family_invites i JOIN accounts a ON a.id = i.account_id JOIN families f ON f.id = i.family_id \
     JOIN accounts o ON o.id = f.organiser_id";

/// The family's pending invites.
pub async fn invites(db: &Db, family_id: &str) -> Result<Vec<FamilyInvite>, sqlx::Error> {
    let rows: Vec<InviteRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_INVITES} WHERE i.family_id = $1 ORDER BY i.invited_at, i.account_id"
    )))
    .bind(family_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(InviteRow::into_record).collect())
}

/// Invitations the account has received.
pub async fn invitations_for(db: &Db, account_id: &str) -> Result<Vec<FamilyInvite>, sqlx::Error> {
    let rows: Vec<InviteRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_INVITES} WHERE i.account_id = $1 ORDER BY i.invited_at, i.family_id"
    )))
    .bind(account_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(InviteRow::into_record).collect())
}

/// Deletes the family, its members and invites. The Family vault is the
/// caller's to delete.
pub async fn delete(conn: &mut Conn, family_id: &str) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM family_invites WHERE family_id = $1",
        "DELETE FROM family_members WHERE family_id = $1",
        "DELETE FROM families WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(family_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
