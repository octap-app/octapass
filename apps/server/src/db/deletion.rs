//! Account deletion: everything linked to the account goes, in one transaction.

use super::{Conn, Db, audit, families, orgs, sharing, utc_day};

pub struct DeletedAccount {
    /// For the confirmation email, sent after commit.
    pub email: String,
    /// Every shared or family vault the account was in, with its other
    /// members, who should hear that its membership changed.
    pub vault_members: Vec<(String, Vec<String>)>,
}

/// Deletes the account and everything linked to it, or returns `None` if
/// there was no such account.
///
/// Leaves behind an anonymous daily counter, the hashes of the account's
/// outstanding tokens (no account id), so its other devices can be told the
/// account is gone, its key log leaf (two hashes, which an append-only log can't give back: the
/// record behind it goes), and in grants the account gave to members of vaults that
/// live on, its id and public signing key: they are part of what it signed.
pub async fn delete_account(
    conn: &mut Conn,
    account_id: &str,
    now: i64,
) -> Result<Option<DeletedAccount>, sqlx::Error> {
    let Some(email) = super::accounts::email_for(conn, account_id).await? else {
        return Ok(None);
    };

    for (column, expires) in [
        ("access_token_hash", "access_expires_at"),
        ("refresh_token_hash", "refresh_expires_at"),
        ("previous_refresh_token_hash", "refresh_expires_at"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO deleted_account_tokens (token_hash, expires_at) \
             SELECT {column}, {expires} FROM sessions WHERE account_id = $1 AND {column} IS NOT NULL \
             ON CONFLICT (token_hash) DO NOTHING"
        )))
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    }

    super::key_log::forget_records(conn, account_id).await?;

    let pairs: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.vault_id, o.account_id FROM vault_members m \
         JOIN vault_members o ON o.vault_id = m.vault_id AND o.account_id <> m.account_id \
         WHERE m.account_id = $1 ORDER BY m.vault_id, o.account_id",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut vault_members: Vec<(String, Vec<String>)> = Vec::new();
    for (vault_id, member) in pairs {
        match vault_members.last_mut() {
            Some((last, members)) if *last == vault_id => members.push(member),
            _ => vault_members.push((vault_id, vec![member])),
        }
    }

    // A family goes with its organiser (its vault, solely owned, goes below).
    let organised: Vec<String> =
        sqlx::query_scalar("SELECT id FROM families WHERE organiser_id = $1")
            .bind(account_id)
            .fetch_all(&mut *conn)
            .await?;
    for family_id in &organised {
        families::delete(conn, family_id).await?;
    }

    // An organisation keeps an owner, or goes with its last member.
    for (vault_id, members) in orgs::account_leaving(conn, account_id, now).await? {
        if !vault_members.iter().any(|(known, _)| *known == vault_id) {
            vault_members.push((vault_id, members));
        }
    }

    // Vaults with no other owner disappear with all their contents: every
    // personal vault, and shared and family vaults the account solely owns.
    // An organisation vault others are in outlives them: those people hold its
    // key, and the organisation's owners can still be given it.
    let doomed_vaults: Vec<String> = sqlx::query_scalar(
        "SELECT m.vault_id FROM vault_members m WHERE m.account_id = $1 AND m.role = 'owner' AND NOT EXISTS \
         (SELECT 1 FROM vault_members o WHERE o.vault_id = m.vault_id AND o.role = 'owner' AND o.account_id <> $1) \
         AND NOT EXISTS (SELECT 1 FROM vaults v JOIN vault_members o ON o.vault_id = v.id \
         WHERE v.id = m.vault_id AND v.org_id IS NOT NULL AND o.account_id <> $1)",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    for vault_id in &doomed_vaults {
        sharing::delete_vault(conn, vault_id).await?;
    }

    audit::forget_account(conn, account_id).await?;
    for statement in [
        "DELETE FROM family_members WHERE account_id = $1",
        "DELETE FROM family_invites WHERE account_id = $1",
        "DELETE FROM share_links WHERE account_id = $1",
        "DELETE FROM emergency_contacts WHERE grantor_id = $1 OR contact_id = $1",
        "DELETE FROM vault_members WHERE account_id = $1",
        "DELETE FROM reauth_tokens WHERE account_id = $1",
        "DELETE FROM two_step WHERE account_id = $1",
        "DELETE FROM security_keys WHERE account_id = $1",
        "DELETE FROM recovery_codes WHERE account_id = $1",
        "DELETE FROM two_step_setups WHERE account_id = $1",
        "DELETE FROM trusted_devices WHERE account_id = $1",
        "DELETE FROM sessions WHERE account_id = $1",
        "DELETE FROM devices WHERE account_id = $1",
        "DELETE FROM accounts WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(account_id)
            .execute(&mut *conn)
            .await?;
    }
    for statement in [
        "DELETE FROM pending_registrations WHERE email = $1",
        "DELETE FROM invites WHERE email = $1",
    ] {
        sqlx::query(statement)
            .bind(&email)
            .execute(&mut *conn)
            .await?;
    }

    sqlx::query(
        "INSERT INTO account_deletions_daily (day, count) VALUES ($1, 1) \
         ON CONFLICT (day) DO UPDATE SET count = account_deletions_daily.count + 1",
    )
    .bind(utc_day(now))
    .execute(&mut *conn)
    .await?;

    Ok(Some(DeletedAccount {
        email,
        vault_members,
    }))
}

pub async fn is_deleted_account_token(
    db: &Db,
    token_hash: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM deleted_account_tokens WHERE token_hash = $1 AND expires_at > $2",
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

pub async fn purge_expired_tokens(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM deleted_account_tokens WHERE expires_at <= $1")
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}
