//! Organisations: members, invites, groups, the vaults they reach, policies and SSO settings.
//!
//! Nothing here is a key. An organisation vault is a shared vault with `org_id` set, and its key
//! reaches people only through grants made on a key holder's device. This module works out who
//! *should* have each vault; [`reconcile`] takes access away from anyone who no longer should, at
//! once, while adding someone always waits for a key holder.

use std::collections::{HashMap, HashSet};

use octapass_api::{
    Grant, OrgEvent, OrgGroupRecord, OrgInvitation, OrgInviteRecord, OrgMemberRecord,
    OrgPendingGrant, OrgPolicies, OrgRole, OrgVaultAccessPlan, OrgVaultGroup, OrgVaultRecord,
    VaultRole,
};
use sqlx::FromRow;

use super::items::parse_role;
use super::{Conn, Db, days, rfc3339, sharing};

/// Events are kept as long as the security log.
const EVENT_RETENTION: i64 = days(365);

const ORG_COLUMNS: &str = "o.id, o.name, o.require_two_step, o.require_sso, o.sso_max_age_hours, \
     o.disable_share_links, o.disable_emergency_access, o.disable_export, \
     o.max_auto_lock_minutes, o.min_password_length, o.created_at";

#[derive(Clone, FromRow)]
pub struct OrgRow {
    pub id: String,
    pub name: String,
    require_two_step: i64,
    require_sso: i64,
    sso_max_age_hours: i64,
    disable_share_links: i64,
    disable_emergency_access: i64,
    disable_export: i64,
    max_auto_lock_minutes: Option<i64>,
    min_password_length: Option<i64>,
    pub created_at: i64,
}

impl OrgRow {
    pub fn policies(&self) -> OrgPolicies {
        OrgPolicies {
            require_two_step: self.require_two_step != 0,
            require_sso: self.require_sso != 0,
            sso_max_age_hours: u32::try_from(self.sso_max_age_hours).unwrap_or_default(),
            disable_share_links: self.disable_share_links != 0,
            disable_emergency_access: self.disable_emergency_access != 0,
            disable_export: self.disable_export != 0,
            max_auto_lock_minutes: self
                .max_auto_lock_minutes
                .and_then(|minutes| u32::try_from(minutes).ok()),
            min_password_length: self
                .min_password_length
                .and_then(|length| u32::try_from(length).ok()),
        }
    }
}

pub fn parse_org_role(role: &str) -> OrgRole {
    OrgRole::parse(role).unwrap_or(OrgRole::Member)
}

pub async fn create(
    conn: &mut Conn,
    id: &str,
    name: &str,
    owner: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO organisations (id, name, created_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(name)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    add_member(conn, id, owner, OrgRole::Owner, now).await
}

/// Takes the organisation's write lock (on SQLite, the database's) before a transaction reads
/// what its change depends on. Returns whether the organisation exists.
pub async fn lock(conn: &mut Conn, org_id: &str) -> Result<bool, sqlx::Error> {
    let locked = sqlx::query("UPDATE organisations SET name = name WHERE id = $1")
        .bind(org_id)
        .execute(conn)
        .await?;
    Ok(locked.rows_affected() > 0)
}

pub async fn find(conn: &mut Conn, org_id: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ORG_COLUMNS} FROM organisations o WHERE o.id = $1"
    )))
    .bind(org_id)
    .fetch_optional(conn)
    .await
}

/// The account's organisation and its role there.
pub async fn of_account(
    conn: &mut Conn,
    account_id: &str,
) -> Result<Option<(OrgRow, OrgRole)>, sqlx::Error> {
    let org: Option<OrgRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ORG_COLUMNS} FROM organisations o JOIN org_members m ON m.org_id = o.id \
         WHERE m.account_id = $1"
    )))
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(org) = org else {
        return Ok(None);
    };
    Ok(member_role(conn, &org.id, account_id)
        .await?
        .map(|role| (org, role)))
}

pub async fn rename(conn: &mut Conn, org_id: &str, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE organisations SET name = $2 WHERE id = $1")
        .bind(org_id)
        .bind(name)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn set_policies(
    conn: &mut Conn,
    org_id: &str,
    policies: &OrgPolicies,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE organisations SET require_two_step = $2, require_sso = $3, sso_max_age_hours = $4, \
         disable_share_links = $5, disable_emergency_access = $6, disable_export = $7, \
         max_auto_lock_minutes = $8, min_password_length = $9 WHERE id = $1",
    )
    .bind(org_id)
    .bind(i64::from(policies.require_two_step))
    .bind(i64::from(policies.require_sso))
    .bind(i64::from(policies.sso_max_age_hours))
    .bind(i64::from(policies.disable_share_links))
    .bind(i64::from(policies.disable_emergency_access))
    .bind(i64::from(policies.disable_export))
    .bind(policies.max_auto_lock_minutes.map(i64::from))
    .bind(policies.min_password_length.map(i64::from))
    .execute(conn)
    .await?;
    Ok(())
}

/// Deletes the organisation and its vaults. Returns each vault with the members it had, so they
/// can be told.
pub async fn delete(
    conn: &mut Conn,
    org_id: &str,
) -> Result<Vec<(String, Vec<String>)>, sqlx::Error> {
    let vault_ids = vaults_of(conn, org_id).await?;
    let mut gone = Vec::with_capacity(vault_ids.len());
    for vault_id in vault_ids {
        let members: Vec<String> =
            sqlx::query_scalar("SELECT account_id FROM vault_members WHERE vault_id = $1")
                .bind(&vault_id)
                .fetch_all(&mut *conn)
                .await?;
        sharing::delete_vault(conn, &vault_id).await?;
        gone.push((vault_id, members));
    }
    sqlx::query("DELETE FROM organisations WHERE id = $1")
        .bind(org_id)
        .execute(conn)
        .await?;
    Ok(gone)
}

// Members.

pub async fn add_member(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
    role: OrgRole,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_members (org_id, account_id, role, joined_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(account_id)
    .bind(role.as_str())
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn member_role(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
) -> Result<Option<OrgRole>, sqlx::Error> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND account_id = $2")
            .bind(org_id)
            .bind(account_id)
            .fetch_optional(conn)
            .await?;
    Ok(role.as_deref().map(parse_org_role))
}

pub async fn set_member_role(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
    role: OrgRole,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE org_members SET role = $3 WHERE org_id = $1 AND account_id = $2")
        .bind(org_id)
        .bind(account_id)
        .bind(role.as_str())
        .execute(conn)
        .await?;
    Ok(())
}

/// Takes the member out of the organisation, its groups and its vault lists. Their vault access
/// goes in [`reconcile`]. Returns whether they were a member.
pub async fn remove_member(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "DELETE FROM org_group_members WHERE account_id = $2 AND group_id IN \
         (SELECT id FROM org_groups WHERE org_id = $1)",
    )
    .bind(org_id)
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM org_vault_direct WHERE account_id = $2 AND vault_id IN \
         (SELECT id FROM vaults WHERE org_id = $1)",
    )
    .bind(org_id)
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM org_sso_identities WHERE org_id = $1 AND account_id = $2")
        .bind(org_id)
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    let removed = sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND account_id = $2")
        .bind(org_id)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(removed.rows_affected() > 0)
}

pub async fn owner_count(conn: &mut Conn, org_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM org_members WHERE org_id = $1 AND role = 'owner'",
    )
    .bind(org_id)
    .fetch_one(conn)
    .await
}

pub async fn member_count(db: &Db, org_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM org_members WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(db)
        .await
}

#[derive(FromRow)]
struct MemberRow {
    account_id: String,
    email: String,
    role: String,
    two_step: i64,
    sso_linked: i64,
    joined_at: i64,
}

pub async fn members(db: &Db, org_id: &str) -> Result<Vec<OrgMemberRecord>, sqlx::Error> {
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT m.account_id, a.email, m.role, m.joined_at, \
         CAST(CASE WHEN t.account_id IS NULL THEN 0 ELSE 1 END AS BIGINT) AS two_step, \
         CAST(CASE WHEN i.account_id IS NULL THEN 0 ELSE 1 END AS BIGINT) AS sso_linked \
         FROM org_members m JOIN accounts a ON a.id = m.account_id \
         LEFT JOIN two_step t ON t.account_id = m.account_id \
         LEFT JOIN org_sso_identities i ON i.org_id = m.org_id AND i.account_id = m.account_id \
         WHERE m.org_id = $1 ORDER BY a.email",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| OrgMemberRecord {
            role: parse_org_role(&row.role),
            account_id: row.account_id,
            email: row.email,
            two_step: row.two_step != 0,
            sso_linked: row.sso_linked != 0,
            joined_at: rfc3339(row.joined_at),
        })
        .collect())
}

/// Who takes over as owner when the only owner's account is deleted: the longest-serving admin,
/// else the longest-serving member. `None` when nobody else is left.
pub async fn successor(
    conn: &mut Conn,
    org_id: &str,
    leaving: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account_id FROM org_members WHERE org_id = $1 AND account_id <> $2 \
         ORDER BY CASE WHEN role = 'admin' THEN 0 ELSE 1 END, joined_at, account_id LIMIT 1",
    )
    .bind(org_id)
    .bind(leaving)
    .fetch_optional(conn)
    .await
}

// Invites.

pub struct NewInvite<'a> {
    pub id: &'a str,
    pub org_id: &'a str,
    pub email: &'a str,
    pub role: OrgRole,
    pub invited_by: &'a str,
    pub now: i64,
    pub expires_at: i64,
}

/// Stores an invite, or renews the one this email already has.
pub async fn put_invite(conn: &mut Conn, invite: NewInvite<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_invites (id, org_id, email, role, invited_by, invited_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (org_id, email) DO UPDATE SET role = excluded.role, \
         invited_by = excluded.invited_by, invited_at = excluded.invited_at, \
         expires_at = excluded.expires_at",
    )
    .bind(invite.id)
    .bind(invite.org_id)
    .bind(invite.email)
    .bind(invite.role.as_str())
    .bind(invite.invited_by)
    .bind(invite.now)
    .bind(invite.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct InviteRow {
    id: String,
    email: String,
    role: String,
    invited_at: i64,
    expires_at: i64,
}

pub async fn invites(db: &Db, org_id: &str, now: i64) -> Result<Vec<OrgInviteRecord>, sqlx::Error> {
    let rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT id, email, role, invited_at, expires_at FROM org_invites \
         WHERE org_id = $1 AND expires_at > $2 ORDER BY invited_at, id",
    )
    .bind(org_id)
    .bind(now)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| OrgInviteRecord {
            role: parse_org_role(&row.role),
            id: row.id,
            email: row.email,
            invited_at: rfc3339(row.invited_at),
            expires_at: rfc3339(row.expires_at),
        })
        .collect())
}

/// Invitations to this email. They carry the policies, because joining agrees to them.
pub async fn invitations_for(
    conn: &mut Conn,
    email: &str,
    now: i64,
) -> Result<Vec<OrgInvitation>, sqlx::Error> {
    let rows: Vec<(String, String, String, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT i.id, i.org_id, i.role, a.email, i.invited_at, i.expires_at FROM org_invites i \
         LEFT JOIN accounts a ON a.id = i.invited_by \
         WHERE i.email = $1 AND i.expires_at > $2 ORDER BY i.invited_at, i.id",
    )
    .bind(email)
    .bind(now)
    .fetch_all(&mut *conn)
    .await?;
    let mut invitations = Vec::with_capacity(rows.len());
    for (id, org_id, role, invited_by, invited_at, expires_at) in rows {
        let Some(org) = find(conn, &org_id).await? else {
            continue;
        };
        invitations.push(OrgInvitation {
            id,
            org_id,
            org_name: org.name.clone(),
            role: parse_org_role(&role),
            invited_by,
            policies: org.policies(),
            invited_at: rfc3339(invited_at),
            expires_at: rfc3339(expires_at),
        });
    }
    Ok(invitations)
}

/// An unexpired invite: (email, role).
pub async fn find_invite(
    conn: &mut Conn,
    org_id: &str,
    invite_id: &str,
    now: i64,
) -> Result<Option<(String, OrgRole)>, sqlx::Error> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT email, role FROM org_invites WHERE id = $1 AND org_id = $2 AND expires_at > $3",
    )
    .bind(invite_id)
    .bind(org_id)
    .bind(now)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(email, role)| (email, parse_org_role(&role))))
}

pub async fn delete_invite(
    conn: &mut Conn,
    org_id: &str,
    invite_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM org_invites WHERE id = $1 AND org_id = $2")
        .bind(invite_id)
        .bind(org_id)
        .execute(conn)
        .await?;
    Ok(removed.rows_affected() > 0)
}

// Groups.

pub async fn create_group(
    conn: &mut Conn,
    org_id: &str,
    group_id: &str,
    name: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO org_groups (id, org_id, name, created_at) VALUES ($1, $2, $3, $4)")
        .bind(group_id)
        .bind(org_id)
        .bind(name)
        .bind(now)
        .execute(conn)
        .await?;
    Ok(())
}

/// The group's name, if it belongs to this organisation.
pub async fn group_name(
    conn: &mut Conn,
    org_id: &str,
    group_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT name FROM org_groups WHERE id = $1 AND org_id = $2")
        .bind(group_id)
        .bind(org_id)
        .fetch_optional(conn)
        .await
}

pub async fn rename_group(
    conn: &mut Conn,
    org_id: &str,
    group_id: &str,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let renamed = sqlx::query("UPDATE org_groups SET name = $3 WHERE id = $1 AND org_id = $2")
        .bind(group_id)
        .bind(org_id)
        .bind(name)
        .execute(conn)
        .await?;
    Ok(renamed.rows_affected() > 0)
}

pub async fn delete_group(conn: &mut Conn, group_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_groups WHERE id = $1")
        .bind(group_id)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn add_to_group(
    conn: &mut Conn,
    group_id: &str,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_group_members (group_id, account_id) VALUES ($1, $2) \
         ON CONFLICT (group_id, account_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(account_id)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn remove_from_group(
    conn: &mut Conn,
    group_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed =
        sqlx::query("DELETE FROM org_group_members WHERE group_id = $1 AND account_id = $2")
            .bind(group_id)
            .bind(account_id)
            .execute(conn)
            .await?;
    Ok(removed.rows_affected() > 0)
}

pub async fn groups(db: &Db, org_id: &str) -> Result<Vec<OrgGroupRecord>, sqlx::Error> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, name, created_at FROM org_groups WHERE org_id = $1 ORDER BY name, id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    let pairs: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.group_id, m.account_id FROM org_group_members m \
         JOIN org_groups g ON g.id = m.group_id WHERE g.org_id = $1 ORDER BY m.account_id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    let mut members: HashMap<String, Vec<String>> = HashMap::new();
    for (group_id, account_id) in pairs {
        members.entry(group_id).or_default().push(account_id);
    }
    Ok(rows
        .into_iter()
        .map(|(id, name, created_at)| OrgGroupRecord {
            members: members.remove(&id).unwrap_or_default(),
            id,
            name,
            created_at: rfc3339(created_at),
        })
        .collect())
}

// Vaults.

pub async fn vaults_of(conn: &mut Conn, org_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM vaults WHERE org_id = $1 ORDER BY id")
        .bind(org_id)
        .fetch_all(conn)
        .await
}

/// Files a new vault under the organisation, with its creator as a direct member.
pub async fn adopt_vault(
    conn: &mut Conn,
    org_id: &str,
    vault_id: &str,
    creator: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE vaults SET org_id = $2 WHERE id = $1")
        .bind(vault_id)
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    set_direct(conn, vault_id, creator, VaultRole::Owner).await
}

/// Whether the vault belongs to this organisation.
pub async fn has_vault(conn: &mut Conn, org_id: &str, vault_id: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM vaults WHERE id = $1 AND org_id = $2")
            .bind(vault_id)
            .bind(org_id)
            .fetch_optional(conn)
            .await?;
    Ok(found.is_some())
}

pub async fn set_direct(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
    role: VaultRole,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_vault_direct (vault_id, account_id, role) VALUES ($1, $2, $3) \
         ON CONFLICT (vault_id, account_id) DO UPDATE SET role = excluded.role",
    )
    .bind(vault_id)
    .bind(account_id)
    .bind(role.as_str())
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn clear_direct(
    conn: &mut Conn,
    vault_id: &str,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_vault_direct WHERE vault_id = $1 AND account_id = $2")
        .bind(vault_id)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn link_group(
    conn: &mut Conn,
    vault_id: &str,
    group_id: &str,
    role: VaultRole,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_vault_groups (vault_id, group_id, role) VALUES ($1, $2, $3) \
         ON CONFLICT (vault_id, group_id) DO UPDATE SET role = excluded.role",
    )
    .bind(vault_id)
    .bind(group_id)
    .bind(role.as_str())
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn unlink_group(
    conn: &mut Conn,
    vault_id: &str,
    group_id: &str,
) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM org_vault_groups WHERE vault_id = $1 AND group_id = $2")
        .bind(vault_id)
        .bind(group_id)
        .execute(conn)
        .await?;
    Ok(removed.rows_affected() > 0)
}

/// Marks a vault for rotation: someone who had its key lost access.
pub async fn mark_rotation(conn: &mut Conn, vault_id: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_rotations (vault_id, since) VALUES ($1, $2) \
         ON CONFLICT (vault_id) DO NOTHING",
    )
    .bind(vault_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// The key was rotated. Nothing waits on this, so a failure only means one rotation too many.
pub async fn rotation_done(db: &Db, vault_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_rotations WHERE vault_id = $1")
        .bind(vault_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Who should have this vault, and with what role: the organisation's owners, as vault owners;
/// the people added to it directly; and everyone in a linked group. The highest role wins.
pub async fn entitlements(
    conn: &mut Conn,
    org_id: &str,
    vault_id: &str,
) -> Result<HashMap<String, VaultRole>, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT account_id, 'owner' FROM org_members WHERE org_id = $1 AND role = 'owner' \
         UNION ALL SELECT account_id, role FROM org_vault_direct WHERE vault_id = $2 \
         UNION ALL SELECT m.account_id, l.role FROM org_vault_groups l \
         JOIN org_group_members m ON m.group_id = l.group_id WHERE l.vault_id = $2",
    )
    .bind(org_id)
    .bind(vault_id)
    .fetch_all(conn)
    .await?;
    let mut entitled: HashMap<String, VaultRole> = HashMap::new();
    for (account_id, role) in rows {
        let role = parse_role(&role);
        entitled
            .entry(account_id)
            .and_modify(|held| *held = (*held).max(role))
            .or_insert(role);
    }
    Ok(entitled)
}

async fn current_members(
    conn: &mut Conn,
    vault_id: &str,
) -> Result<Vec<(String, VaultRole)>, sqlx::Error> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT account_id, role FROM vault_members WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(conn)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(account_id, role)| (account_id, parse_role(&role)))
        .collect())
}

/// What [`reconcile`] changed.
#[derive(Default)]
pub struct Reconciled {
    /// Vaults that lost members, with those members.
    pub lost: Vec<(String, Vec<String>)>,
    /// Vaults left with nobody who can manage them.
    pub orphaned: Vec<String>,
}

/// Brings every organisation vault in line with who should have it. Anyone with no entitlement
/// loses the vault and the vault is marked for rotation. Anyone whose role went down loses it too,
/// until a key holder grants the lower role: a role is part of the signed grant, which the server
/// can't rewrite. They keep nothing they didn't have, so that needs no rotation.
pub async fn reconcile(conn: &mut Conn, org_id: &str, now: i64) -> Result<Reconciled, sqlx::Error> {
    let mut result = Reconciled::default();
    for vault_id in vaults_of(conn, org_id).await? {
        let entitled = entitlements(conn, org_id, &vault_id).await?;
        let current = current_members(conn, &vault_id).await?;
        let managed = current.iter().any(|(_, role)| *role >= VaultRole::Manage);
        let mut lost = Vec::new();
        let mut remaining_manager = false;
        let mut rotate = false;
        for (account_id, role) in current {
            match entitled.get(&account_id) {
                Some(wanted) if *wanted >= role => remaining_manager |= role >= VaultRole::Manage,
                wanted => {
                    rotate |= wanted.is_none();
                    sharing::remove_member(conn, &vault_id, &account_id).await?;
                    lost.push(account_id);
                }
            }
        }
        if rotate {
            mark_rotation(conn, &vault_id, now).await?;
        }
        if managed && !remaining_manager {
            result.orphaned.push(vault_id.clone());
        }
        if !lost.is_empty() {
            result.lost.push((vault_id, lost));
        }
    }
    Ok(result)
}

#[derive(FromRow)]
struct OrgVaultRow {
    id: String,
    created_at: i64,
    rotation_since: Option<i64>,
}

pub async fn vaults(
    db: &Db,
    org_id: &str,
    viewer: &str,
) -> Result<Vec<OrgVaultRecord>, sqlx::Error> {
    let rows: Vec<OrgVaultRow> = sqlx::query_as(
        "SELECT v.id, v.created_at, r.since AS rotation_since FROM vaults v \
         LEFT JOIN org_rotations r ON r.vault_id = v.id WHERE v.org_id = $1 ORDER BY v.id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    let mut conn = db.acquire().await?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let members = current_members(&mut conn, &row.id).await?;
        let links: Vec<(String, String)> = sqlx::query_as(
            "SELECT group_id, role FROM org_vault_groups WHERE vault_id = $1 ORDER BY group_id",
        )
        .bind(&row.id)
        .fetch_all(&mut *conn)
        .await?;
        records.push(OrgVaultRecord {
            member_count: members.len() as u64,
            manager_count: members
                .iter()
                .filter(|(_, role)| *role >= VaultRole::Manage)
                .count() as u64,
            role: members
                .iter()
                .find(|(account_id, _)| account_id == viewer)
                .map(|(_, role)| *role),
            groups: links
                .into_iter()
                .map(|(group_id, role)| OrgVaultGroup {
                    group_id,
                    role: parse_role(&role),
                })
                .collect(),
            rotation_pending: row.rotation_since.is_some(),
            id: row.id,
            created_at: rfc3339(row.created_at),
        });
    }
    Ok(records)
}

#[derive(FromRow)]
struct PublicKeys {
    id: String,
    email: String,
    public_enc_key: String,
    public_sign_key: String,
    key_record: Option<String>,
}

/// What each organisation vault is waiting for from a key holder. A vault the viewer can apply
/// shows who it's waiting for; other vaults show only to admins, who can chase a vault's managers.
pub async fn access_plan(
    db: &Db,
    org_id: &str,
    viewer: &str,
    admin: bool,
) -> Result<Vec<OrgVaultAccessPlan>, sqlx::Error> {
    let mut conn = db.acquire().await?;
    let mut plans = Vec::new();
    for vault_id in vaults_of(&mut conn, org_id).await? {
        let entitled = entitlements(&mut conn, org_id, &vault_id).await?;
        let current: HashMap<String, VaultRole> = current_members(&mut conn, &vault_id)
            .await?
            .into_iter()
            .collect();
        let mine: Option<VaultRole> = sqlx::query_scalar::<_, String>(
            "SELECT role FROM vault_access WHERE vault_id = $1 AND account_id = $2",
        )
        .bind(&vault_id)
        .bind(viewer)
        .fetch_optional(&mut *conn)
        .await?
        .as_deref()
        .map(parse_role);
        let can_apply = mine.is_some_and(|role| role >= VaultRole::Manage);
        let rotate: Option<i64> =
            sqlx::query_scalar("SELECT since FROM org_rotations WHERE vault_id = $1")
                .bind(&vault_id)
                .fetch_optional(&mut *conn)
                .await?;

        let mut grants = Vec::new();
        for (account_id, role) in &entitled {
            let held = current.get(account_id);
            if held.is_some_and(|held| held >= role) {
                continue;
            }
            // Only an owner may grant owner (plan 15).
            if can_apply && *role == VaultRole::Owner && mine != Some(VaultRole::Owner) {
                continue;
            }
            let keys: Option<PublicKeys> = sqlx::query_as(
                "SELECT id, email, public_enc_key, public_sign_key, key_record FROM accounts WHERE id = $1",
            )
            .bind(account_id)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(keys) = keys {
                grants.push(OrgPendingGrant {
                    account_id: keys.id,
                    email: keys.email,
                    role: *role,
                    public_enc_key: keys.public_enc_key,
                    public_sign_key: keys.public_sign_key,
                    key_record: keys.key_record.as_deref().map(super::accounts::key_record),
                    upgrade: held.is_some(),
                });
            }
        }
        grants.sort_by(|a, b| a.email.cmp(&b.email));
        if (grants.is_empty() && rotate.is_none()) || !(can_apply || admin) {
            continue;
        }
        plans.push(OrgVaultAccessPlan {
            key_id: if can_apply {
                sharing::key_id(&mut conn, &vault_id).await?
            } else {
                None
            },
            vault_id,
            can_apply,
            grants,
            rotate: rotate.is_some(),
        });
    }
    Ok(plans)
}

/// Stores grants a key holder made, each already checked against [`entitlements`].
pub async fn store_grants(
    conn: &mut Conn,
    grants: &[Grant],
    sign_key: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    for grant in grants {
        sharing::put_member(conn, grant, sign_key, now).await?;
    }
    Ok(())
}

// Enforcement.

/// The account's organisation policies, if it's in one.
pub async fn policies_of(db: &Db, account_id: &str) -> Result<Option<OrgPolicies>, sqlx::Error> {
    let mut conn = db.acquire().await?;
    Ok(of_account(&mut conn, account_id)
        .await?
        .map(|(org, _)| org.policies()))
}

/// Whether organisation vaults are being withheld from this member.
pub async fn access_withheld(db: &Db, account_id: &str) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM org_members m JOIN organisations o ON o.id = m.org_id \
         WHERE m.account_id = $1 AND o.require_two_step = 1 \
         AND NOT EXISTS (SELECT 1 FROM two_step t WHERE t.account_id = m.account_id)",
    )
    .bind(account_id)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// Whether this account's emergency contacts are kept out of the vault by its organisation.
pub async fn hides_from_emergency(
    db: &Db,
    grantor: &str,
    vault_id: &str,
) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM vaults v JOIN organisations o ON o.id = v.org_id \
         WHERE v.id = $1 AND o.disable_emergency_access = 1 \
         AND EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = o.id AND m.account_id = $2)",
    )
    .bind(vault_id)
    .bind(grantor)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// What the SSO step needs, for an account it applies to.
#[derive(Clone, FromRow)]
pub struct SsoRule {
    pub org_id: String,
    pub org_name: String,
    pub issuer: String,
    pub client_id: String,
    /// Sealed; `None` for a public client.
    pub client_secret: Option<String>,
    pub max_age_hours: i64,
    pub updated_at: i64,
    /// `oidc` or `saml`. For SAML, `issuer` is the IdP's entity id and `client_id` is unused.
    pub protocol: String,
    pub saml_sso_url: Option<String>,
    /// Base64 DER, one per line.
    pub saml_certificates: Option<String>,
}

impl SsoRule {
    pub fn is_saml(&self) -> bool {
        self.protocol == "saml"
    }
}

const SELECT_SSO: &str = "SELECT o.id AS org_id, o.name AS org_name, s.issuer, s.client_id, s.client_secret, \
     o.sso_max_age_hours AS max_age_hours, s.updated_at, s.protocol, s.saml_sso_url, \
     s.saml_certificates \
     FROM organisations o JOIN org_sso s ON s.org_id = o.id";

/// The SSO step this account must pass, if any. Owners are exempt.
pub async fn sso_rule(db: &Db, account_id: &str) -> Result<Option<SsoRule>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_SSO} JOIN org_members m ON m.org_id = o.id \
         WHERE m.account_id = $1 AND m.role <> 'owner' AND o.require_sso = 1"
    )))
    .bind(account_id)
    .fetch_optional(db)
    .await
}

/// The organisation's SSO settings, whatever its policy says.
pub async fn sso_settings(db: &Db, org_id: &str) -> Result<Option<SsoRule>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT_SSO} WHERE o.id = $1")))
        .bind(org_id)
        .fetch_optional(db)
        .await
}

pub async fn tested_at(conn: &mut Conn, org_id: &str) -> Result<Option<i64>, sqlx::Error> {
    let tested: Option<Option<i64>> =
        sqlx::query_scalar("SELECT tested_at FROM org_sso WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(conn)
            .await?;
    Ok(tested.flatten())
}

/// The settings to store, for either protocol.
pub enum SsoSettings<'a> {
    Oidc {
        issuer: &'a str,
        client_id: &'a str,
        client_secret: Option<&'a str>,
    },
    Saml {
        entity_id: &'a str,
        sso_url: &'a str,
        certificates: &'a str,
    },
}

/// Saves the settings and clears the test sign-in. Members' links to IdP subjects go too when the
/// provider changed (another protocol, issuer or entity id): a subject means something only to
/// the provider that issued it.
pub async fn put_sso(
    conn: &mut Conn,
    org_id: &str,
    settings: SsoSettings<'_>,
    now: i64,
) -> Result<(), sqlx::Error> {
    let (protocol, issuer, client_id, client_secret, sso_url, certificates) = match settings {
        SsoSettings::Oidc {
            issuer,
            client_id,
            client_secret,
        } => ("oidc", issuer, client_id, client_secret, None, None),
        SsoSettings::Saml {
            entity_id,
            sso_url,
            certificates,
        } => (
            "saml",
            entity_id,
            "",
            None,
            Some(sso_url),
            Some(certificates),
        ),
    };
    let previous: Option<(String, String)> =
        sqlx::query_as("SELECT protocol, issuer FROM org_sso WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(&mut *conn)
            .await?;
    if previous.is_some_and(|(was, from)| was != protocol || from != issuer) {
        sqlx::query("DELETE FROM org_sso_identities WHERE org_id = $1")
            .bind(org_id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query(
        "INSERT INTO org_sso (org_id, issuer, client_id, client_secret, tested_at, updated_at, \
         protocol, saml_sso_url, saml_certificates) \
         VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8) \
         ON CONFLICT (org_id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id, \
         client_secret = excluded.client_secret, tested_at = NULL, updated_at = excluded.updated_at, \
         protocol = excluded.protocol, saml_sso_url = excluded.saml_sso_url, \
         saml_certificates = excluded.saml_certificates",
    )
    .bind(org_id)
    .bind(issuer)
    .bind(client_id)
    .bind(client_secret)
    .bind(now)
    .bind(protocol)
    .bind(sso_url)
    .bind(certificates)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_sso(conn: &mut Conn, org_id: &str) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM org_sso WHERE org_id = $1",
        "DELETE FROM org_sso_identities WHERE org_id = $1",
    ] {
        sqlx::query(statement)
            .bind(org_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// A test sign-in finished with these settings. Settings changed since don't count.
pub async fn sso_tested(
    db: &Db,
    org_id: &str,
    updated_at: i64,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let tested =
        sqlx::query("UPDATE org_sso SET tested_at = $3 WHERE org_id = $1 AND updated_at = $2")
            .bind(org_id)
            .bind(updated_at)
            .bind(now)
            .execute(db)
            .await?;
    Ok(tested.rows_affected() > 0)
}

pub async fn sso_subject(
    db: &Db,
    org_id: &str,
    account_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT subject FROM org_sso_identities WHERE org_id = $1 AND account_id = $2",
    )
    .bind(org_id)
    .bind(account_id)
    .fetch_optional(db)
    .await
}

/// Links an IdP subject to a member. `false` if another member already has that subject.
pub async fn link_sso(
    db: &Db,
    org_id: &str,
    account_id: &str,
    subject: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let linked = sqlx::query(
        "INSERT INTO org_sso_identities (org_id, account_id, subject, linked_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(org_id)
    .bind(account_id)
    .bind(subject)
    .bind(now)
    .execute(db)
    .await?;
    Ok(linked.rows_affected() > 0)
}

// The activity log.

pub async fn record_event(
    conn: &mut Conn,
    org_id: &str,
    actor: &str,
    event_type: &str,
    subject: Option<&str>,
    now: i64,
) -> Result<(), sqlx::Error> {
    record_event_by(conn, org_id, Some(actor), event_type, subject, now).await
}

/// An event with no person behind it, such as the identity provider's (SCIM) changes, has no
/// actor.
pub async fn record_event_by(
    conn: &mut Conn,
    org_id: &str,
    actor: Option<&str>,
    event_type: &str,
    subject: Option<&str>,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_events (id, org_id, actor_id, event_type, subject, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(org_id)
    .bind(actor)
    .bind(event_type)
    .bind(subject)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// An `org_events` row with its actor's email: id, type, email, subject, time.
type EventRow = (String, String, Option<String>, Option<String>, i64);

pub async fn events(db: &Db, org_id: &str) -> Result<Vec<OrgEvent>, sqlx::Error> {
    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT e.id, e.event_type, a.email, e.subject, e.created_at FROM org_events e \
         LEFT JOIN accounts a ON a.id = e.actor_id WHERE e.org_id = $1 \
         ORDER BY e.created_at DESC, e.id DESC LIMIT 500",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, event_type, actor, subject, created_at)| OrgEvent {
            id,
            event_type,
            actor,
            subject,
            created_at: rfc3339(created_at),
        })
        .collect())
}

/// Expired invites and events past their year.
pub async fn purge(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_invites WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM org_events WHERE created_at <= $1")
        .bind(now - EVENT_RETENTION)
        .execute(db)
        .await?;
    Ok(())
}

/// Makes way for an account's deletion: its organisation keeps an owner, or goes with its last
/// member, and the vaults it was in are marked for rotation. Returns the vaults deleted with the
/// organisation.
pub async fn account_leaving(
    conn: &mut Conn,
    account_id: &str,
    now: i64,
) -> Result<Vec<(String, Vec<String>)>, sqlx::Error> {
    let Some((org, role)) = of_account(conn, account_id).await? else {
        return Ok(Vec::new());
    };
    let successor = successor(conn, &org.id, account_id).await?;
    let Some(successor) = successor else {
        return delete(conn, &org.id).await;
    };
    if role == OrgRole::Owner && owner_count(conn, &org.id).await? == 1 {
        set_member_role(conn, &org.id, &successor, OrgRole::Owner).await?;
    }
    let vaults: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT m.vault_id FROM vault_members m JOIN vaults v ON v.id = m.vault_id \
         WHERE m.account_id = $1 AND v.org_id = $2",
    )
    .bind(account_id)
    .bind(&org.id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    for vault_id in vaults {
        mark_rotation(conn, &vault_id, now).await?;
    }
    Ok(Vec::new())
}
