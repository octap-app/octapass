//! Storage, on SQLite or PostgreSQL through sqlx's `Any` driver. Every query
//! uses `$n` placeholders and SQL both backends accept; each backend has its
//! own migrations directory, kept statement for statement in step.

pub mod accounts;
pub mod attachments;
pub mod audit;
pub mod deletion;
pub mod emergency;
pub mod families;
pub mod items;
pub mod key_log;
pub mod orgs;
pub mod scim;
pub mod service_accounts;
pub mod sessions;
pub mod share_links;
pub mod sharing;
pub mod two_step;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::Executor;
use sqlx::any::AnyPoolOptions;

pub type Db = sqlx::AnyPool;
pub type Conn = sqlx::AnyConnection;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    pub fn of_url(url: &str) -> Option<Self> {
        if url.starts_with("sqlite:") {
            Some(Self::Sqlite)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Some(Self::Postgres)
        } else {
            None
        }
    }

    pub fn of(db: &Db) -> Self {
        let url = db.connect_options().database_url.to_string();
        Self::of_url(&url).expect("connect only accepts known backends")
    }
}

/// Settings every SQLite connection needs. Deleted rows are overwritten with
/// zeros (`secure_delete`), so a deleted account can't be read back from free
/// pages of the file.
const SQLITE_PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; \
     PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;";

pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    sqlx::any::install_default_drivers();
    let backend = Backend::of_url(url).ok_or_else(|| {
        sqlx::Error::Configuration("the database URL must start with sqlite: or postgres://".into())
    })?;
    let url = match backend {
        // Create the file on first start.
        Backend::Sqlite if !url.contains("mode=") => {
            let separator = if url.contains('?') { '&' } else { '?' };
            format!("{url}{separator}mode=rwc")
        }
        _ => url.to_owned(),
    };
    let pool = AnyPoolOptions::new()
        .max_connections(if backend == Backend::Sqlite { 8 } else { 16 })
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if backend == Backend::Sqlite {
                    conn.execute(SQLITE_PRAGMAS).await?;
                }
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    match backend {
        Backend::Sqlite => SQLITE_MIGRATOR.run(&pool).await?,
        Backend::Postgres => POSTGRES_MIGRATOR.run(&pool).await?,
    }
    Ok(pool)
}

/// SQLite: copies the write-ahead log into the database and empties it, so
/// deleted data doesn't linger in old WAL frames. Readers holding an old
/// snapshot can keep it from finishing; the next checkpoint then catches up.
/// PostgreSQL reuses the space of deleted rows through autovacuum.
pub async fn checkpoint(db: &Db) -> Result<(), sqlx::Error> {
    if Backend::of(db) == Backend::Sqlite {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(db)
            .await?;
    }
    Ok(())
}

/// Unix time in milliseconds, the unit every timestamp column uses.
pub fn now() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970");
    i64::try_from(elapsed.as_millis()).expect("timestamp fits in i64")
}

pub const fn days(n: i64) -> i64 {
    n * 24 * 60 * 60 * 1000
}

/// The UTC day of a timestamp, as `YYYY-MM-DD`.
pub fn utc_day(millis: i64) -> String {
    rfc3339(millis)[..10].to_owned()
}

/// RFC 3339, as the API returns timestamps.
pub fn rfc3339(millis: i64) -> String {
    let nanos = i128::from(millis) * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .expect("stored timestamps are in range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_761_177_600_123), "2025-10-23T00:00:00.123Z");
    }
}
