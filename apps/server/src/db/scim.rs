//! SCIM provisioning (plan 03, "SCIM provisioning"): who the identity provider says should be in
//! the organisation and its groups, and how that becomes invites, memberships and group lists.
//!
//! The provider can't make anyone a member. Provisioning invites; the person accepts on their own
//! device. Deprovisioning removes at once, and [`super::orgs::reconcile`] then takes the
//! organisation's vaults away and marks them for rotation, exactly as an admin's removal does.
//! Owners are never removed this way, so a provider can't lock the organisation out.

use octapass_api::{OrgRole, OrgScimTokenRecord};
use sqlx::FromRow;

use super::orgs::{self, record_event_by};
use super::{Conn, Db, days, rfc3339};

/// How long a provisioned invite lasts before the provider's next update renews it.
pub const INVITE_LIFETIME: i64 = days(14);
/// A token's last use is written at most this often.
const TOUCH_EVERY: i64 = 60 * 1000;

// Tokens.

pub async fn create_token(
    conn: &mut Conn,
    id: &str,
    org_id: &str,
    token_hash: &str,
    name: &str,
    created_by: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_scim_tokens (id, org_id, token_hash, name, created_by, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(org_id)
    .bind(token_hash)
    .bind(name)
    .bind(created_by)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn token_count(conn: &mut Conn, org_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM org_scim_tokens WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(conn)
        .await
}

/// id, name, creator's email, created, last used.
type TokenRow = (String, String, Option<String>, i64, Option<i64>);

pub async fn tokens(db: &Db, org_id: &str) -> Result<Vec<OrgScimTokenRecord>, sqlx::Error> {
    let rows: Vec<TokenRow> = sqlx::query_as(
        "SELECT t.id, t.name, a.email, t.created_at, t.last_used_at FROM org_scim_tokens t \
         LEFT JOIN accounts a ON a.id = t.created_by WHERE t.org_id = $1 ORDER BY t.created_at, t.id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, created_by, created_at, last_used_at)| OrgScimTokenRecord {
                id,
                name,
                created_by,
                created_at: rfc3339(created_at),
                last_used_at: last_used_at.map(rfc3339),
            },
        )
        .collect())
}

/// The token's name, if it was this organisation's and is now gone.
pub async fn delete_token(
    conn: &mut Conn,
    org_id: &str,
    token_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM org_scim_tokens WHERE id = $1 AND org_id = $2")
            .bind(token_id)
            .bind(org_id)
            .fetch_optional(&mut *conn)
            .await?;
    if name.is_some() {
        sqlx::query("DELETE FROM org_scim_tokens WHERE id = $1")
            .bind(token_id)
            .execute(conn)
            .await?;
    }
    Ok(name)
}

/// The organisation a token belongs to. Records its use, at most once a minute.
pub async fn org_for_token(
    db: &Db,
    token_hash: &str,
    now: i64,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, org_id, last_used_at FROM org_scim_tokens WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await?;
    let Some((id, org_id, last_used)) = row else {
        return Ok(None);
    };
    if last_used.is_none_or(|at| now - at >= TOUCH_EVERY) {
        sqlx::query("UPDATE org_scim_tokens SET last_used_at = $2 WHERE id = $1")
            .bind(&id)
            .bind(now)
            .execute(db)
            .await?;
    }
    Ok(Some(org_id))
}

// Users.

#[derive(Clone, Debug, FromRow)]
pub struct ScimUser {
    pub id: String,
    pub org_id: String,
    pub user_name: String,
    pub email: String,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    active: i64,
    pub account_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ScimUser {
    pub fn new(id: String, org_id: String, user_name: String, email: String, now: i64) -> Self {
        Self {
            id,
            org_id,
            user_name,
            email,
            external_id: None,
            display_name: None,
            active: 1,
            account_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn active(&self) -> bool {
        self.active != 0
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = i64::from(active);
    }
}

const USER_COLUMNS: &str = "id, org_id, user_name, email, external_id, display_name, active, \
     account_id, created_at, updated_at";

/// What a list may be filtered by: SCIM's `eq` on one attribute.
pub enum Filter {
    None,
    Id(String),
    UserName(String),
    ExternalId(String),
    Email(String),
    DisplayName(String),
}

pub async fn find_user(
    conn: &mut Conn,
    org_id: &str,
    id: &str,
) -> Result<Option<ScimUser>, sqlx::Error> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {USER_COLUMNS} FROM org_scim_users WHERE org_id = $1 AND id = $2"
    )))
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await
}

/// One page of users, 0-based `offset`, and how many match in all.
pub async fn list_users(
    conn: &mut Conn,
    org_id: &str,
    filter: &Filter,
    offset: i64,
    limit: i64,
) -> Result<(i64, Vec<ScimUser>), sqlx::Error> {
    let (clause, value) = match filter {
        Filter::None => ("", None),
        Filter::Id(value) => (" AND id = $2", Some(value.clone())),
        Filter::UserName(value) => (" AND user_key = $2", Some(value.to_lowercase())),
        Filter::ExternalId(value) => (" AND external_id = $2", Some(value.clone())),
        Filter::Email(value) => (" AND email = $2", Some(value.to_lowercase())),
        Filter::DisplayName(value) => (" AND display_name = $2", Some(value.clone())),
    };
    let (limit_at, offset_at) = if value.is_some() { (3, 4) } else { (2, 3) };
    let count =
        format!("SELECT CAST(COUNT(*) AS BIGINT) FROM org_scim_users WHERE org_id = $1{clause}");
    let page = format!(
        "SELECT {USER_COLUMNS} FROM org_scim_users WHERE org_id = $1{clause} \
         ORDER BY created_at, id LIMIT ${limit_at} OFFSET ${offset_at}"
    );
    let mut total = sqlx::query_scalar(sqlx::AssertSqlSafe(count)).bind(org_id);
    let mut rows = sqlx::query_as(sqlx::AssertSqlSafe(page)).bind(org_id);
    if let Some(value) = value {
        total = total.bind(value.clone());
        rows = rows.bind(value);
    }
    let total: i64 = total.fetch_one(&mut *conn).await?;
    let rows: Vec<ScimUser> = rows.bind(limit).bind(offset).fetch_all(conn).await?;
    Ok((total, rows))
}

/// Stores a new user or the changes to one. A user name another user has is a unique violation.
pub async fn put_user(conn: &mut Conn, user: &ScimUser) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_scim_users (id, org_id, user_name, user_key, email, external_id, \
         display_name, active, account_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (id) DO UPDATE SET user_name = excluded.user_name, user_key = excluded.user_key, \
         email = excluded.email, external_id = excluded.external_id, \
         display_name = excluded.display_name, active = excluded.active, \
         account_id = excluded.account_id, updated_at = excluded.updated_at",
    )
    .bind(&user.id)
    .bind(&user.org_id)
    .bind(&user.user_name)
    .bind(user.user_name.to_lowercase())
    .bind(&user.email)
    .bind(&user.external_id)
    .bind(&user.display_name)
    .bind(user.active)
    .bind(&user.account_id)
    .bind(user.created_at)
    .bind(user.updated_at)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_user(conn: &mut Conn, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_scim_users WHERE id = $1")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

async fn groups_of_user(conn: &mut Conn, user_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT group_id FROM org_scim_group_members WHERE scim_user_id = $1")
        .bind(user_id)
        .fetch_all(conn)
        .await
}

// Groups.

#[derive(Clone, Debug)]
pub struct ScimGroup {
    pub id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub created_at: i64,
    /// (SCIM user id, user name).
    pub members: Vec<(String, String)>,
}

type GroupRow = (String, String, Option<String>, i64);

async fn with_members(conn: &mut Conn, rows: Vec<GroupRow>) -> Result<Vec<ScimGroup>, sqlx::Error> {
    let mut groups = Vec::with_capacity(rows.len());
    for (id, name, external_id, created_at) in rows {
        let members = group_members(conn, &id).await?;
        groups.push(ScimGroup {
            id,
            name,
            external_id,
            created_at,
            members,
        });
    }
    Ok(groups)
}

pub async fn find_group(
    conn: &mut Conn,
    org_id: &str,
    id: &str,
) -> Result<Option<ScimGroup>, sqlx::Error> {
    let row: Option<GroupRow> = sqlx::query_as(
        "SELECT id, name, scim_external_id, created_at FROM org_groups \
         WHERE org_id = $1 AND id = $2 AND scim_managed = 1",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(with_members(conn, row.into_iter().collect()).await?.pop())
}

/// One page of the groups the provider manages, and how many match. Groups made by hand in Open
/// Pass aren't the provider's to see or change.
pub async fn list_groups(
    conn: &mut Conn,
    org_id: &str,
    filter: &Filter,
    offset: i64,
    limit: i64,
    members: bool,
) -> Result<(i64, Vec<ScimGroup>), sqlx::Error> {
    let (clause, value) = match filter {
        Filter::None => ("", None),
        Filter::Id(value) => (" AND id = $2", Some(value.clone())),
        Filter::DisplayName(value) => (" AND name = $2", Some(value.clone())),
        Filter::ExternalId(value) => (" AND scim_external_id = $2", Some(value.clone())),
        Filter::UserName(_) | Filter::Email(_) => (" AND 1 = 0", None),
    };
    let (limit_at, offset_at) = if value.is_some() { (3, 4) } else { (2, 3) };
    let base = format!("FROM org_groups WHERE org_id = $1 AND scim_managed = 1{clause}");
    let count = format!("SELECT CAST(COUNT(*) AS BIGINT) {base}");
    let page = format!(
        "SELECT id, name, scim_external_id, created_at {base} ORDER BY created_at, id \
         LIMIT ${limit_at} OFFSET ${offset_at}"
    );
    let mut total = sqlx::query_scalar(sqlx::AssertSqlSafe(count)).bind(org_id);
    let mut rows = sqlx::query_as(sqlx::AssertSqlSafe(page)).bind(org_id);
    if let Some(value) = value {
        total = total.bind(value.clone());
        rows = rows.bind(value);
    }
    let total: i64 = total.fetch_one(&mut *conn).await?;
    let rows: Vec<GroupRow> = rows.bind(limit).bind(offset).fetch_all(&mut *conn).await?;
    let groups = if members {
        with_members(conn, rows).await?
    } else {
        rows.into_iter()
            .map(|(id, name, external_id, created_at)| ScimGroup {
                id,
                name,
                external_id,
                created_at,
                members: Vec::new(),
            })
            .collect()
    };
    Ok((total, groups))
}

pub async fn create_group(
    conn: &mut Conn,
    org_id: &str,
    id: &str,
    name: &str,
    external_id: Option<&str>,
    now: i64,
) -> Result<(), sqlx::Error> {
    orgs::create_group(conn, org_id, id, name, now).await?;
    sqlx::query("UPDATE org_groups SET scim_managed = 1, scim_external_id = $2 WHERE id = $1")
        .bind(id)
        .bind(external_id)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn update_group(
    conn: &mut Conn,
    id: &str,
    name: &str,
    external_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE org_groups SET name = $2, scim_external_id = $3 WHERE id = $1")
        .bind(id)
        .bind(name)
        .bind(external_id)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn group_members(
    conn: &mut Conn,
    group_id: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT u.id, u.user_name FROM org_scim_group_members m \
         JOIN org_scim_users u ON u.id = m.scim_user_id WHERE m.group_id = $1 ORDER BY u.user_key",
    )
    .bind(group_id)
    .fetch_all(conn)
    .await
}

/// The SCIM users of this organisation among `ids`, so a group can't name another's.
pub async fn known_users(
    conn: &mut Conn,
    org_id: &str,
    ids: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    let mut known = Vec::with_capacity(ids.len());
    for id in ids {
        if find_user(conn, org_id, id).await?.is_some() && !known.contains(id) {
            known.push(id.clone());
        }
    }
    Ok(known)
}

pub async fn add_group_member(
    conn: &mut Conn,
    group_id: &str,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_scim_group_members (group_id, scim_user_id) VALUES ($1, $2) \
         ON CONFLICT (group_id, scim_user_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn clear_group_members(conn: &mut Conn, group_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_scim_group_members WHERE group_id = $1")
        .bind(group_id)
        .execute(conn)
        .await?;
    Ok(())
}

// Applying the provider's view.

/// What applying a change did, for the emails and notifications after it commits.
#[derive(Default)]
pub struct Applied {
    /// New invites, to email.
    pub invited: Vec<String>,
    /// Members removed, to email.
    pub removed: Vec<String>,
}

async fn account_by_email(conn: &mut Conn, email: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
        .bind(email)
        .fetch_optional(conn)
        .await
}

/// Invites the email, or renews its invite, keeping the role an admin may have chosen. Returns
/// whether there was no live invite before, so one should be emailed.
async fn invite(conn: &mut Conn, org_id: &str, email: &str, now: i64) -> Result<bool, sqlx::Error> {
    let live: Option<i64> = sqlx::query_scalar(
        "SELECT expires_at FROM org_invites WHERE org_id = $1 AND email = $2 AND expires_at > $3",
    )
    .bind(org_id)
    .bind(email)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO org_invites (id, org_id, email, role, invited_by, invited_at, expires_at) \
         VALUES ($1, $2, $3, $4, NULL, $5, $6) \
         ON CONFLICT (org_id, email) DO UPDATE SET expires_at = excluded.expires_at",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(org_id)
    .bind(email)
    .bind(OrgRole::Member.as_str())
    .bind(now)
    .bind(now + INVITE_LIFETIME)
    .execute(conn)
    .await?;
    Ok(live.is_none())
}

async fn cancel_invite(conn: &mut Conn, org_id: &str, email: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM org_invites WHERE org_id = $1 AND email = $2")
        .bind(org_id)
        .bind(email)
        .execute(conn)
        .await?;
    Ok(())
}

/// Makes a group's member list what the provider says, for those of its users who are members.
/// Returns whether anyone was taken out, so the caller reconciles vault access.
pub async fn apply_group(
    conn: &mut Conn,
    org_id: &str,
    group_id: &str,
) -> Result<bool, sqlx::Error> {
    let wanted: Vec<String> = sqlx::query_scalar(
        "SELECT u.account_id FROM org_scim_group_members m \
         JOIN org_scim_users u ON u.id = m.scim_user_id \
         JOIN org_members o ON o.account_id = u.account_id AND o.org_id = u.org_id \
         WHERE m.group_id = $1 AND u.org_id = $2 AND u.active = 1",
    )
    .bind(group_id)
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    let current: Vec<String> =
        sqlx::query_scalar("SELECT account_id FROM org_group_members WHERE group_id = $1")
            .bind(group_id)
            .fetch_all(&mut *conn)
            .await?;
    for account in wanted.iter().filter(|account| !current.contains(account)) {
        orgs::add_to_group(conn, group_id, account).await?;
    }
    let mut removed = false;
    for account in current.iter().filter(|account| !wanted.contains(account)) {
        removed |= orgs::remove_from_group(conn, group_id, account).await?;
    }
    Ok(removed)
}

/// Brings Octa Pass in line with one provisioned user, and stores it. An active user who isn't a
/// member yet is invited; one who is gets the provider's groups. An inactive one loses their invite
/// and, unless they're an owner, their membership. The caller reconciles vault access after.
pub async fn apply_user(
    conn: &mut Conn,
    user: &mut ScimUser,
    now: i64,
    applied: &mut Applied,
) -> Result<(), sqlx::Error> {
    let org_id = user.org_id.clone();
    let account = account_by_email(conn, &user.email).await?;
    let role = match &account {
        Some(account) => orgs::member_role(conn, &org_id, account).await?,
        None => None,
    };
    let email = user.email.clone();
    if user.active() {
        match (account, role) {
            (Some(account), Some(_)) => {
                cancel_invite(conn, &org_id, &email).await?;
                user.account_id = Some(account);
            }
            _ => {
                user.account_id = None;
                if invite(conn, &org_id, &email, now).await? {
                    record_event_by(conn, &org_id, None, "scim-user-invited", Some(&email), now)
                        .await?;
                    applied.invited.push(email.clone());
                }
            }
        }
        put_user(conn, user).await?;
        for group in groups_of_user(conn, &user.id).await? {
            apply_group(conn, &org_id, &group).await?;
        }
        return Ok(());
    }

    cancel_invite(conn, &org_id, &email).await?;
    user.account_id = None;
    put_user(conn, user).await?;
    if let (Some(account), Some(role)) = (account, role) {
        if role == OrgRole::Owner {
            // Owners leave by hand: a provider must not be able to lock the organisation out.
            let event = "scim-owner-kept";
            record_event_by(conn, &org_id, None, event, Some(&email), now).await?;
        } else {
            orgs::remove_member(conn, &org_id, &account).await?;
            let event = "scim-user-deprovisioned";
            record_event_by(conn, &org_id, None, event, Some(&email), now).await?;
            applied.removed.push(email);
        }
    }
    Ok(())
}

/// Someone accepted an invite: if the provider provisioned them, link them and give them the
/// provider's groups.
pub async fn member_joined(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
    email: &str,
) -> Result<(), sqlx::Error> {
    let users: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM org_scim_users WHERE org_id = $1 AND email = $2 AND active = 1",
    )
    .bind(org_id)
    .bind(email)
    .fetch_all(&mut *conn)
    .await?;
    for user in users {
        sqlx::query("UPDATE org_scim_users SET account_id = $2 WHERE id = $1")
            .bind(&user)
            .bind(account_id)
            .execute(&mut *conn)
            .await?;
        for group in groups_of_user(conn, &user).await? {
            apply_group(conn, org_id, &group).await?;
        }
    }
    Ok(())
}
