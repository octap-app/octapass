//! Installations, on SQLite or PostgreSQL through sqlx's `Any` driver, as the vault server and
//! the masked email relay do. Nothing else is stored.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::Executor;
use sqlx::any::AnyPoolOptions;

pub type Db = sqlx::AnyPool;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

const SQLITE_PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; \
     PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;";

pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    sqlx::any::install_default_drivers();
    let sqlite = url.starts_with("sqlite:");
    if !sqlite && !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
        return Err(sqlx::Error::Configuration(
            "the database URL must start with sqlite: or postgres://".into(),
        ));
    }
    let url = if sqlite && !url.contains("mode=") {
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{url}{separator}mode=rwc")
    } else {
        url.to_owned()
    };
    let pool = AnyPoolOptions::new()
        .max_connections(if sqlite { 4 } else { 8 })
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if sqlite {
                    conn.execute(SQLITE_PRAGMAS).await?;
                }
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    if sqlite {
        SQLITE_MIGRATOR.run(&pool).await?;
    } else {
        POSTGRES_MIGRATOR.run(&pool).await?;
    }
    Ok(pool)
}

pub fn now() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970");
    i64::try_from(elapsed.as_millis()).expect("timestamp fits in i64")
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Installation {
    pub id: String,
    pub key_hash: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub async fn insert(db: &Db, id: &str, key_hash: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO installations (id, key_hash, created_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(key_hash)
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn find(db: &Db, id: &str) -> Result<Option<Installation>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, key_hash, created_at, last_used_at, revoked_at FROM installations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// Recorded at most once an hour per installation, so busy servers don't write on every push.
pub async fn touch(db: &Db, id: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE installations SET last_used_at = $2 \
         WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $3)",
    )
    .bind(id)
    .bind(now)
    .bind(now - 60 * 60 * 1000)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list(db: &Db) -> Result<Vec<Installation>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, key_hash, created_at, last_used_at, revoked_at FROM installations \
         ORDER BY created_at",
    )
    .fetch_all(db)
    .await
}

/// Returns whether there was such an installation still allowed to send.
pub async fn revoke(db: &Db, id: &str, now: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE installations SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(db)
    .await?;
    Ok(done.rows_affected() > 0)
}
