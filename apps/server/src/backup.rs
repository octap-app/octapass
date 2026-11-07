//! Online backups of a SQLite server, and restoring one.
//!
//! A backup is a folder `octapass-YYYYMMDD-HHMMSS` holding the database (`VACUUM INTO`, a
//! consistent copy while the server keeps running), the two secret files and the `attachments`
//! folder. Attachment files never change once written, so a file the previous backup already
//! has is hard-linked rather than copied. The folder is written under a temporary name and
//! renamed when complete. The database is copied first: a file deleted between the two steps
//! belonged to something already deleted, and a file added after it is just unused.

use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{Backups, Config};
use crate::db::{self, Backend};
use crate::secrets::{OPAQUE_SETUP_FILE, SERVER_SECRET_FILE};
use crate::state::AppState;
use crate::storage::StorageConfig;

const PREFIX: &str = "octapass-";
const PARTIAL: &str = ".partial-";
const DATABASE_FILE: &str = "octapass.db";
const ATTACHMENTS: &str = "attachments";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backups only work with SQLite; back up PostgreSQL with pg_dump")]
    NotSqlite,
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0} is not an Octa Pass backup (no {DATABASE_FILE} or secret files)")]
    NotABackup(PathBuf),
}

/// Writes a new backup into `dir` and returns its folder.
pub async fn create(state: &AppState, dir: &Path) -> Result<PathBuf, BackupError> {
    if Backend::of(&state.db) != Backend::Sqlite {
        return Err(BackupError::NotSqlite);
    }
    tokio::fs::create_dir_all(dir).await?;
    let name = folder_name(db::now());
    let partial = dir.join(format!("{PARTIAL}{name}"));
    let done = dir.join(&name);
    if tokio::fs::try_exists(&done).await? {
        return Ok(done);
    }
    let _ = tokio::fs::remove_dir_all(&partial).await;
    // Only the server's user can read a backup: it holds the server's secrets.
    tokio::fs::DirBuilder::new()
        .mode(0o700)
        .create(&partial)
        .await?;

    let database = partial.join(DATABASE_FILE);
    sqlx::query("VACUUM INTO $1")
        .bind(database.to_string_lossy().into_owned())
        .execute(&state.db)
        .await?;
    tokio::fs::set_permissions(&database, Permissions::from_mode(0o600)).await?;

    let data_dir = state.config.data_dir.clone();
    let attachments = match &state.config.attachments.storage {
        StorageConfig::Local { dir } => Some(dir.clone()),
        // A bucket is backed up by its provider's own means.
        StorageConfig::S3(_) => None,
    };
    let previous = latest(dir)?.map(|(_, path)| path.join(ATTACHMENTS));
    let target = partial.clone();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        for file in [OPAQUE_SETUP_FILE, SERVER_SECRET_FILE] {
            std::fs::copy(data_dir.join(file), target.join(file))?;
        }
        if let Some(source) = attachments {
            copy_attachments(&source, &target.join(ATTACHMENTS), previous.as_deref())?;
        }
        Ok(())
    })
    .await
    .map_err(io::Error::other)??;
    tokio::fs::rename(&partial, &done).await?;
    Ok(done)
}

/// Copies each file, or hard-links it from `previous` when that has the same file.
fn copy_attachments(source: &Path, target: &Path, previous: Option<&Path>) -> io::Result<()> {
    std::fs::create_dir_all(target)?;
    let entries = match std::fs::read_dir(source) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        let to = target.join(entry.file_name());
        let linked = previous.is_some_and(|previous| {
            let earlier = previous.join(entry.file_name());
            std::fs::metadata(&earlier).is_ok_and(|m| m.len() == metadata.len())
                && std::fs::hard_link(&earlier, &to).is_ok()
        });
        if !linked {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Deletes all but the newest `keep` backups, and leftovers of interrupted ones.
pub fn prune(dir: &Path, keep: usize) -> io::Result<()> {
    let mut backups = list(dir)?;
    backups.sort();
    let excess = backups.len().saturating_sub(keep);
    for (_, path) in backups.into_iter().take(excess) {
        std::fs::remove_dir_all(path)?;
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(PARTIAL) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

/// Finished backups in `dir`, as (folder name, path).
fn list(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut backups = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(PREFIX) && entry.file_type()?.is_dir() {
            backups.push((name, entry.path()));
        }
    }
    Ok(backups)
}

fn latest(dir: &Path) -> io::Result<Option<(String, PathBuf)>> {
    Ok(list(dir)?.into_iter().max())
}

/// `octapass-20261024-153000`, in UTC, so names sort by time.
fn folder_name(millis: i64) -> String {
    let rfc3339 = db::rfc3339(millis);
    let digits: String = rfc3339[..19].chars().filter(char::is_ascii_digit).collect();
    format!("{PREFIX}{}-{}", &digits[..8], &digits[8..14])
}

/// When the newest backup was made, in Unix milliseconds.
fn made_at(name: &str) -> Option<i64> {
    let stamp = name.strip_prefix(PREFIX)?;
    let format = time::macros::format_description!("[year][month][day]-[hour][minute][second]");
    let at = time::PrimitiveDateTime::parse(stamp, &format).ok()?;
    i64::try_from(at.assume_utc().unix_timestamp_nanos() / 1_000_000).ok()
}

/// Makes a backup whenever the newest one is older than `backups.every`, checking every few
/// minutes, so restarts neither skip nor repeat one.
pub fn spawn_schedule(state: AppState, backups: Backups) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            let due = match latest(&backups.dir) {
                Ok(newest) => newest
                    .and_then(|(name, _)| made_at(&name))
                    .is_none_or(|at| {
                        db::now() - at
                            >= i64::try_from(backups.every.as_millis()).unwrap_or(i64::MAX)
                    }),
                Err(error) => {
                    tracing::error!(%error, "can't read the backup folder");
                    continue;
                }
            };
            if !due {
                continue;
            }
            match create(&state, &backups.dir).await {
                Ok(path) => {
                    tracing::info!(path = %path.display(), "backup written");
                    if let Err(error) = prune(&backups.dir, backups.keep) {
                        tracing::error!(%error, "deleting old backups failed");
                    }
                }
                Err(error) => tracing::error!(%error, "backup failed"),
            }
        }
    });
}

/// Puts a backup in place of the server's data. The server must be stopped. What was there is
/// moved to `<data dir>/before-restore-<time>` rather than deleted.
pub fn restore(config: &Config, backup: &Path) -> Result<PathBuf, BackupError> {
    let database = sqlite_path(&config.database_url).ok_or(BackupError::NotSqlite)?;
    let has = |file: &str| backup.join(file).is_file();
    if !(has(DATABASE_FILE) && has(OPAQUE_SETUP_FILE) && has(SERVER_SECRET_FILE)) {
        return Err(BackupError::NotABackup(backup.to_owned()));
    }
    let aside = config.data_dir.join(format!(
        "before-restore-{}",
        &folder_name(db::now())[PREFIX.len()..]
    ));
    std::fs::create_dir_all(&aside)?;
    let move_aside = |path: &Path| -> io::Result<()> {
        match std::fs::rename(path, aside.join(path.file_name().unwrap_or_default())) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    };
    let database_name = database.file_name().unwrap_or_default().to_string_lossy();
    for suffix in ["", "-wal", "-shm"] {
        move_aside(&database.with_file_name(format!("{database_name}{suffix}")))?;
    }
    for file in [OPAQUE_SETUP_FILE, SERVER_SECRET_FILE] {
        move_aside(&config.data_dir.join(file))?;
        std::fs::copy(backup.join(file), config.data_dir.join(file))?;
    }
    std::fs::copy(backup.join(DATABASE_FILE), &database)?;
    if let StorageConfig::Local { dir } = &config.attachments.storage {
        move_aside(dir)?;
        std::fs::create_dir_all(dir)?;
        if let Ok(entries) = std::fs::read_dir(backup.join(ATTACHMENTS)) {
            for entry in entries {
                let entry = entry?;
                std::fs::copy(entry.path(), dir.join(entry.file_name()))?;
            }
        }
    }
    Ok(aside)
}

/// The file behind a `sqlite:` URL.
fn sqlite_path(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("sqlite:")?;
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let path = rest.split('?').next()?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sort_by_time_and_parse_back() {
        let millis = 1_761_177_600_123 + 3_723_000; // 2025-10-23 01:02:03 UTC
        let name = folder_name(millis);
        assert_eq!(name, "octapass-20251023-010203");
        assert_eq!(made_at(&name), Some(millis - 123));
        assert!(folder_name(millis) < folder_name(millis + 1000));
        assert_eq!(made_at("octapass-nonsense"), None);
    }

    #[test]
    fn finds_the_sqlite_file() {
        assert_eq!(
            sqlite_path("sqlite:///data/octapass.db"),
            Some(PathBuf::from("/data/octapass.db"))
        );
        assert_eq!(
            sqlite_path("sqlite://./data/octapass.db?mode=rwc"),
            Some(PathBuf::from("./data/octapass.db"))
        );
        assert_eq!(sqlite_path("postgres://db/octapass"), None);
    }

    #[test]
    fn prune_keeps_the_newest_and_drops_partial_ones() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "octapass-20261001-000000",
            "octapass-20261003-000000",
            "octapass-20261002-000000",
            ".partial-octapass-20261004-000000",
            "notes",
        ] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }
        prune(dir.path(), 2).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "notes",
                "octapass-20261002-000000",
                "octapass-20261003-000000"
            ]
        );
    }

    #[test]
    fn unchanged_attachments_are_linked_not_copied() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("attachments");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("aa"), b"first").unwrap();
        let first = dir.path().join("one");
        copy_attachments(&source, &first, None).unwrap();
        std::fs::write(source.join("bb"), b"second").unwrap();
        let second = dir.path().join("two");
        copy_attachments(&source, &second, Some(&first)).unwrap();
        assert_eq!(std::fs::read(second.join("bb")).unwrap(), b"second");
        let ino = |path: PathBuf| std::fs::metadata(path).unwrap().ino();
        assert_eq!(ino(first.join("aa")), ino(second.join("aa")));
        assert_ne!(ino(source.join("aa")), ino(first.join("aa")));
    }
}
