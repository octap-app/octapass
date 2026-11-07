//! The relay's own database, on SQLite or PostgreSQL through sqlx's `Any` driver, as the vault
//! server does: `$n` placeholders, SQL both accept, one migrations folder each.
//!
//! Addresses are sealed; lookups go through keyed hashes. Nothing about a message is stored but
//! the counters.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::any::AnyPoolOptions;
use sqlx::{AssertSqlSafe, Executor};

use crate::address;
use crate::config::Limits;
use crate::keys::Keys;

pub type Db = sqlx::AnyPool;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

const SQLITE_PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; \
     PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;";

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
        .max_connections(if sqlite { 8 } else { 16 })
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

/// Unix time in milliseconds, the unit every timestamp column uses.
pub fn now() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970");
    i64::try_from(elapsed.as_millis()).expect("timestamp fits in i64")
}

fn utc_day(millis: i64) -> String {
    let date = time::OffsetDateTime::from_unix_timestamp(millis / 1000)
        .expect("stored timestamps are in range")
        .date();
    date.to_string()
}

const DAY: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    pub local: String,
    pub account_id: String,
    pub enabled: bool,
    /// Stopped by the relay itself after bounces or complaints.
    pub paused: bool,
    pub account_paused: bool,
    pub forwarded: i64,
    pub blocked: i64,
    pub replied: i64,
    pub created_at: i64,
}

impl Alias {
    pub fn forwards(&self) -> bool {
        self.enabled && !self.paused && !self.account_paused
    }
}

const ALIAS_COLUMNS: &str = "a.local, a.account_id, a.enabled, a.paused_at, c.paused_at, \
     a.forwarded, a.blocked, a.replied, a.created_at";
type AliasRow = (
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    i64,
    i64,
);

fn alias_of(row: AliasRow) -> Alias {
    let (
        local,
        account_id,
        enabled,
        paused,
        account_paused,
        forwarded,
        blocked,
        replied,
        created_at,
    ) = row;
    Alias {
        local,
        account_id,
        enabled: enabled != 0,
        paused: paused.is_some(),
        account_paused: account_paused.is_some(),
        forwarded,
        blocked,
        replied,
        created_at,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("the account has as many aliases as it may")]
    TooMany,
    #[error("the account made as many aliases as it may today")]
    TooManyToday,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// What a report changed, so the caller can send its one notice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Paused {
    pub alias: bool,
    pub account: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Hard,
    Soft,
    Complaint,
}

impl Report {
    fn column(self) -> &'static str {
        match self {
            Self::Hard => "hard_bounces",
            Self::Soft => "soft_bounces",
            Self::Complaint => "complaints",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    Forwarded,
    Blocked,
    Replied,
}

impl Counter {
    fn column(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Blocked => "blocked",
            Self::Replied => "replied",
        }
    }
}

fn destination_context(account_id: &str) -> String {
    format!("destination:{account_id}")
}

fn contact_context(reverse: &str) -> String {
    format!("contact:{reverse}")
}

/// Hashed destinations share one scope: an incoming envelope sender is compared to them.
const DESTINATION_SCOPE: &str = "destination";

// Every `AssertSqlSafe` below formats only table and column names from constants in this file;
// values always go through `bind`.

/// The database with the keys that open it.
pub struct Store<'a> {
    pub db: &'a Db,
    pub keys: &'a Keys,
}

impl Store<'_> {
    /// Creates the account or brings its forwarding address up to date, and returns whether it's
    /// paused. The vault server sends the verified email with every call that needs one, so an
    /// email change reaches the relay without its own message.
    pub async fn sync_account(&self, id: &str, email: &str) -> Result<(), sqlx::Error> {
        let now = now();
        let sealed = self.keys.seal(&destination_context(id), email);
        let hash = self.keys.lookup(DESTINATION_SCOPE, email);
        sqlx::query(
            "INSERT INTO relay_accounts (id, destination_sealed, destination_hash, window_started_at, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET destination_sealed = $2, destination_hash = $3",
        )
        .bind(id)
        .bind(&sealed)
        .bind(&hash)
        .bind(now)
        .bind(now)
        .execute(self.db)
        .await?;
        Ok(())
    }

    pub async fn destination(&self, account_id: &str) -> Result<Option<String>, sqlx::Error> {
        let sealed: Option<(String,)> =
            sqlx::query_as("SELECT destination_sealed FROM relay_accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(self.db)
                .await?;
        Ok(sealed.and_then(|(sealed,)| self.keys.open(&destination_context(account_id), &sealed)))
    }

    pub async fn sender_is_destination(
        &self,
        account_id: &str,
        sender: &str,
    ) -> Result<bool, sqlx::Error> {
        let hash = self.keys.lookup(DESTINATION_SCOPE, sender);
        let found: Option<(String,)> =
            sqlx::query_as("SELECT id FROM relay_accounts WHERE id = $1 AND destination_hash = $2")
                .bind(account_id)
                .bind(&hash)
                .fetch_optional(self.db)
                .await?;
        Ok(found.is_some())
    }

    pub async fn delete_account(&self, id: &str) -> Result<(), sqlx::Error> {
        // Aliases, contacts and blocks go with it (`ON DELETE CASCADE`).
        sqlx::query("DELETE FROM relay_accounts WHERE id = $1")
            .bind(id)
            .execute(self.db)
            .await?;
        Ok(())
    }

    pub async fn create_alias(
        &self,
        account_id: &str,
        limits: &Limits,
    ) -> Result<Alias, CreateError> {
        let now = now();
        let day = utc_day(now);
        // One statement, so concurrent creations can't both pass the daily cap.
        let taken = sqlx::query(
            "UPDATE relay_accounts SET \
               aliases_today = CASE WHEN aliases_day = $1 THEN aliases_today + 1 ELSE 1 END, \
               aliases_day = $1 \
             WHERE id = $2 AND (aliases_day <> $1 OR aliases_today < $3) \
               AND (SELECT COUNT(*) FROM relay_aliases WHERE account_id = $2) < $4",
        )
        .bind(&day)
        .bind(account_id)
        .bind(limits.aliases_per_day)
        .bind(limits.aliases_per_account)
        .execute(self.db)
        .await?;
        if taken.rows_affected() == 0 {
            let (count,): (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM relay_aliases WHERE account_id = $1")
                    .bind(account_id)
                    .fetch_one(self.db)
                    .await?;
            return Err(if count >= limits.aliases_per_account {
                CreateError::TooMany
            } else {
                CreateError::TooManyToday
            });
        }
        let local = address::new_alias();
        sqlx::query(
            "INSERT INTO relay_aliases (local, account_id, window_started_at, created_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&local)
        .bind(account_id)
        .bind(now)
        .bind(now)
        .execute(self.db)
        .await?;
        Ok(self.alias(&local).await?.ok_or(sqlx::Error::RowNotFound)?)
    }

    pub async fn alias(&self, local: &str) -> Result<Option<Alias>, sqlx::Error> {
        let row: Option<AliasRow> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT {ALIAS_COLUMNS} FROM relay_aliases a \
             JOIN relay_accounts c ON c.id = a.account_id WHERE a.local = $1"
        )))
        .bind(local)
        .fetch_optional(self.db)
        .await?;
        Ok(row.map(alias_of))
    }

    pub async fn aliases(&self, account_id: &str) -> Result<Vec<Alias>, sqlx::Error> {
        let rows: Vec<AliasRow> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT {ALIAS_COLUMNS} FROM relay_aliases a \
             JOIN relay_accounts c ON c.id = a.account_id \
             WHERE a.account_id = $1 ORDER BY a.created_at DESC, a.local"
        )))
        .bind(account_id)
        .fetch_all(self.db)
        .await?;
        Ok(rows.into_iter().map(alias_of).collect())
    }

    /// Turning an alias on is the user saying they've dealt with whatever paused it, so it clears
    /// the relay's pauses and counts too. Returns false when the alias isn't this account's.
    pub async fn set_enabled(
        &self,
        account_id: &str,
        local: &str,
        enabled: bool,
    ) -> Result<bool, sqlx::Error> {
        let now = now();
        let changed = sqlx::query(
            "UPDATE relay_aliases SET enabled = $1 WHERE local = $2 AND account_id = $3",
        )
        .bind(i64::from(enabled))
        .bind(local)
        .bind(account_id)
        .execute(self.db)
        .await?
        .rows_affected()
            == 1;
        if changed && enabled {
            let clear = "paused_at = NULL, hard_bounces = 0, soft_bounces = 0, complaints = 0, \
                         window_started_at = $1";
            sqlx::query(AssertSqlSafe(format!(
                "UPDATE relay_aliases SET {clear} WHERE local = $2"
            )))
            .bind(now)
            .bind(local)
            .execute(self.db)
            .await?;
            sqlx::query(AssertSqlSafe(format!(
                "UPDATE relay_accounts SET {clear} WHERE id = $2"
            )))
            .bind(now)
            .bind(account_id)
            .execute(self.db)
            .await?;
        }
        Ok(changed)
    }

    pub async fn delete_alias(&self, account_id: &str, local: &str) -> Result<bool, sqlx::Error> {
        let deleted = sqlx::query("DELETE FROM relay_aliases WHERE local = $1 AND account_id = $2")
            .bind(local)
            .bind(account_id)
            .execute(self.db)
            .await?;
        Ok(deleted.rows_affected() == 1)
    }

    pub async fn set_blocked(
        &self,
        account_id: &str,
        local: &str,
        sender: &str,
        blocked: bool,
    ) -> Result<bool, sqlx::Error> {
        let owned: Option<(String,)> =
            sqlx::query_as("SELECT local FROM relay_aliases WHERE local = $1 AND account_id = $2")
                .bind(local)
                .bind(account_id)
                .fetch_optional(self.db)
                .await?;
        if owned.is_none() {
            return Ok(false);
        }
        let hash = self.keys.lookup(local, sender);
        let query = if blocked {
            "INSERT INTO relay_blocked_senders (alias_local, sender_hash) VALUES ($1, $2) \
             ON CONFLICT (alias_local, sender_hash) DO NOTHING"
        } else {
            "DELETE FROM relay_blocked_senders WHERE alias_local = $1 AND sender_hash = $2"
        };
        sqlx::query(query)
            .bind(local)
            .bind(&hash)
            .execute(self.db)
            .await?;
        Ok(true)
    }

    pub async fn is_blocked(&self, local: &str, sender: &str) -> Result<bool, sqlx::Error> {
        let hash = self.keys.lookup(local, sender);
        let found: Option<(String,)> = sqlx::query_as(
            "SELECT alias_local FROM relay_blocked_senders WHERE alias_local = $1 AND sender_hash = $2",
        )
        .bind(local)
        .bind(&hash)
        .fetch_optional(self.db)
        .await?;
        Ok(found.is_some())
    }

    /// The reverse alias for a sender on this alias, made on first contact. `None` when the alias
    /// is at its contact limit.
    pub async fn contact(
        &self,
        alias: &str,
        sender: &str,
        max: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        let hash = self.keys.lookup(alias, sender);
        let find = || async {
            let row: Option<(String,)> = sqlx::query_as(
                "SELECT reverse_local FROM relay_contacts WHERE alias_local = $1 AND sender_hash = $2",
            )
            .bind(alias)
            .bind(&hash)
            .fetch_optional(self.db)
            .await?;
            Ok::<_, sqlx::Error>(row.map(|(reverse,)| reverse))
        };
        if let Some(reverse) = find().await? {
            return Ok(Some(reverse));
        }
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM relay_contacts WHERE alias_local = $1")
                .bind(alias)
                .fetch_one(self.db)
                .await?;
        if count >= max {
            return Ok(None);
        }
        let reverse = address::new_reverse();
        // Two messages from a new sender at once: the second keeps the first's row.
        sqlx::query(
            "INSERT INTO relay_contacts (reverse_local, alias_local, sender_hash, sender_sealed, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (alias_local, sender_hash) DO NOTHING",
        )
        .bind(&reverse)
        .bind(alias)
        .bind(&hash)
        .bind(self.keys.seal(&contact_context(&reverse), sender))
        .bind(now())
        .execute(self.db)
        .await?;
        find().await
    }

    /// The alias and the external address behind a reverse alias.
    pub async fn reverse(&self, reverse: &str) -> Result<Option<(String, String)>, sqlx::Error> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT alias_local, sender_sealed FROM relay_contacts WHERE reverse_local = $1",
        )
        .bind(reverse)
        .fetch_optional(self.db)
        .await?;
        Ok(row.and_then(|(alias, sealed)| {
            let sender = self.keys.open(&contact_context(reverse), &sealed)?;
            Some((alias, sender))
        }))
    }

    pub async fn count(&self, local: &str, counter: Counter) -> Result<(), sqlx::Error> {
        let column = counter.column();
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE relay_aliases SET {column} = {column} + 1 WHERE local = $1"
        )))
        .bind(local)
        .execute(self.db)
        .await?;
        Ok(())
    }

    /// Counts a bounce or complaint against the alias and its account, and pauses whichever went
    /// over its limit. `paused_at` is set once, so each pause reports true exactly once, even
    /// when reports race, and that one true is the one notice.
    pub async fn report(
        &self,
        alias: &Alias,
        report: Report,
        limits: &Limits,
    ) -> Result<Paused, sqlx::Error> {
        let (alias_limit, account_limit) = match report {
            Report::Hard => (limits.alias_hard_bounces, limits.account_hard_bounces),
            Report::Complaint => (limits.alias_complaints, limits.account_complaints),
            Report::Soft => (i64::MAX, i64::MAX),
        };
        let cutoff = now() - limits.feedback_window_days * DAY;
        let alias_count = self
            .bump("relay_aliases", "local", &alias.local, report, cutoff)
            .await?;
        let account_count = self
            .bump("relay_accounts", "id", &alias.account_id, report, cutoff)
            .await?;
        Ok(Paused {
            alias: alias_count >= alias_limit
                && self.pause("relay_aliases", "local", &alias.local).await?,
            account: account_count >= account_limit
                && self
                    .pause("relay_accounts", "id", &alias.account_id)
                    .await?,
        })
    }

    async fn bump(
        &self,
        table: &str,
        key: &str,
        id: &str,
        report: Report,
        cutoff: i64,
    ) -> Result<i64, sqlx::Error> {
        let column = report.column();
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE {table} SET hard_bounces = 0, soft_bounces = 0, complaints = 0, \
             window_started_at = $1 WHERE {key} = $2 AND window_started_at < $3"
        )))
        .bind(now())
        .bind(id)
        .bind(cutoff)
        .execute(self.db)
        .await?;
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE {table} SET {column} = {column} + 1 WHERE {key} = $1"
        )))
        .bind(id)
        .execute(self.db)
        .await?;
        let (count,): (i64,) = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT {column} FROM {table} WHERE {key} = $1"
        )))
        .bind(id)
        .fetch_one(self.db)
        .await?;
        Ok(count)
    }

    async fn pause(&self, table: &str, key: &str, id: &str) -> Result<bool, sqlx::Error> {
        let paused = sqlx::query(AssertSqlSafe(format!(
            "UPDATE {table} SET paused_at = $1 WHERE {key} = $2 AND paused_at IS NULL"
        )))
        .bind(now())
        .bind(id)
        .execute(self.db)
        .await?;
        Ok(paused.rows_affected() == 1)
    }
}
