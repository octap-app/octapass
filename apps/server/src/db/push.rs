//! Push tokens and this server's registration with the push relay (migration 0014).

use crate::db::{Conn, Db};

/// Where one device is woken up.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct PushTarget {
    pub account_id: String,
    pub device_id: String,
    pub platform: String,
    pub token: String,
    pub sandbox: i64,
}

/// Saves the device's token, taking it from any other device that had it: the system gives a
/// token to one app install, so it can only reach the device that registered it last.
pub async fn set_token(
    conn: &mut Conn,
    account_id: &str,
    device_id: &str,
    platform: &str,
    token: &str,
    sandbox: bool,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM push_tokens WHERE token = $1 AND device_id <> $2")
        .bind(token)
        .bind(device_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO push_tokens (device_id, account_id, platform, token, sandbox, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (device_id) DO UPDATE SET platform = $3, token = $4, sandbox = $5, \
         updated_at = $6",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(platform)
    .bind(token)
    .bind(i64::from(sandbox))
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn delete_device_token(db: &Db, device_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Tokens the relay said are dead.
pub async fn delete_tokens(db: &Db, tokens: &[String]) -> Result<(), sqlx::Error> {
    for token in tokens {
        sqlx::query("DELETE FROM push_tokens WHERE token = $1")
            .bind(token)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// The signed-in devices of these accounts that can be woken up. A signed-out device's token
/// stays until the device row goes, but nothing is sent to it.
pub async fn targets(db: &Db, account_ids: &[String]) -> Result<Vec<PushTarget>, sqlx::Error> {
    let mut found = Vec::new();
    for chunk in account_ids.chunks(100) {
        let placeholders: Vec<String> = (1..=chunk.len()).map(|n| format!("${n}")).collect();
        let sql = format!(
            "SELECT p.account_id, p.device_id, p.platform, p.token, p.sandbox FROM push_tokens p \
             JOIN devices d ON d.id = p.device_id \
             WHERE d.revoked_at IS NULL AND p.account_id IN ({}) ORDER BY p.device_id",
            placeholders.join(", ")
        );
        let mut query = sqlx::query_as::<_, PushTarget>(sqlx::AssertSqlSafe(sql));
        for account_id in chunk {
            query = query.bind(account_id);
        }
        found.extend(query.fetch_all(db).await?);
    }
    Ok(found)
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Installation {
    pub installation_id: String,
    pub installation_key: String,
}

pub async fn installation(db: &Db, relay_url: &str) -> Result<Option<Installation>, sqlx::Error> {
    sqlx::query_as(
        "SELECT installation_id, installation_key FROM push_relay_installations \
         WHERE relay_url = $1",
    )
    .bind(relay_url)
    .fetch_optional(db)
    .await
}

pub async fn save_installation(
    db: &Db,
    relay_url: &str,
    installation: &Installation,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO push_relay_installations \
         (relay_url, installation_id, installation_key, created_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (relay_url) DO UPDATE SET installation_id = $2, installation_key = $3, \
         created_at = $4",
    )
    .bind(relay_url)
    .bind(&installation.installation_id)
    .bind(&installation.installation_key)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn forget_installation(db: &Db, relay_url: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM push_relay_installations WHERE relay_url = $1")
        .bind(relay_url)
        .execute(db)
        .await?;
    Ok(())
}
