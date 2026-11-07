//! Where attachment files live: a directory (the default) or an S3-compatible
//! bucket. Files are ciphertext the server can't read; their names, types and
//! keys are inside the item's encrypted details.
//!
//! An upload is first written to a spool file in the data directory, so it is
//! checked (size, envelope version) and hashed before the backend sees it, and
//! a cut-off upload never leaves a partial object behind.
//!
//! Objects are deleted through the `attachment_deletions` queue: the row that
//! names an object and the queue entry change in the same transaction, then
//! [`drain`] deletes the objects and retries failures with backoff, so an
//! unreachable bucket can't make an account or item deletion fail or leave
//! files behind.

mod local;
mod s3;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub use local::LocalStorage;
pub use s3::{S3Config, S3Storage};

use crate::db;
use crate::state::AppState;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("object storage: {0}")]
    Remote(String),
}

/// A finished upload in the spool directory. Dropping it removes the file.
pub struct Upload {
    path: PathBuf,
    pub len: u64,
    /// Hex SHA-256 of the contents, for S3's signed payload hash.
    pub sha256: String,
    /// The envelope version, for a quick check of what was sent.
    pub first_byte: Option<u8>,
}

impl Upload {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        // Already gone when a backend moved it into place.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A stored file, ready to stream to a client.
pub struct Object {
    pub len: u64,
    pub body: Body,
}

/// An attachment storage backend. Keys are random and opaque.
pub trait ObjectStorage: Send + Sync {
    /// Stores the upload under `key`.
    fn put<'a>(&'a self, key: &'a str, upload: Upload) -> BoxFuture<'a, Result<(), StorageError>>;
    /// The object, or `None` if there's none under `key`.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StorageError>>;
    /// Deletes the object. Deleting a missing object succeeds.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>>;
    /// Whether the backend is reachable, for `/readyz`.
    fn check(&self) -> BoxFuture<'_, Result<(), StorageError>>;
}

/// Where attachments go, from `OCTAPASS_S3_*` or the data directory.
#[derive(Clone, Debug)]
pub enum StorageConfig {
    Local { dir: PathBuf },
    S3(S3Config),
}

pub fn open(config: &StorageConfig) -> Result<Arc<dyn ObjectStorage>, StorageError> {
    Ok(match config {
        StorageConfig::Local { dir } => Arc::new(LocalStorage::new(dir.clone())?),
        StorageConfig::S3(s3) => Arc::new(S3Storage::new(s3.clone())?),
    })
}

/// A new random object key: 16 random bytes, hex. Unrelated to any id, so the
/// bucket listing says nothing about accounts, vaults or items.
pub fn new_object_key() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// The body had more or fewer bytes than its `Content-Length`.
    #[error("the body doesn't match its Content-Length")]
    LengthMismatch,
    #[error("the client stopped sending")]
    Stalled,
    #[error("reading the body: {0}")]
    Body(axum::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// How long an upload may go without sending anything.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Writes a request body of exactly `len` bytes to a new file in `dir`.
pub async fn spool(dir: &Path, body: Body, len: u64) -> Result<Upload, SpoolError> {
    let path = dir.join(new_object_key());
    // From here on, dropping `upload` removes the file, whatever goes wrong.
    let mut upload = Upload {
        path,
        len,
        sha256: String::new(),
        first_byte: None,
    };
    let mut file = tokio::fs::File::create(&upload.path).await?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut body = body;
    loop {
        let frame = tokio::time::timeout(IDLE_TIMEOUT, body.frame())
            .await
            .map_err(|_| SpoolError::Stalled)?;
        let Some(frame) = frame else { break };
        let Ok(data) = frame.map_err(SpoolError::Body)?.into_data() else {
            continue; // trailers
        };
        written += data.len() as u64;
        if written > len {
            return Err(SpoolError::LengthMismatch);
        }
        if upload.first_byte.is_none() {
            upload.first_byte = data.first().copied();
        }
        hasher.update(&data);
        file.write_all(&data).await?;
    }
    if written != len {
        return Err(SpoolError::LengthMismatch);
    }
    file.sync_all().await?;
    upload.sha256 = hex(&hasher.finalize());
    Ok(upload)
}

/// Spool files older than this are from uploads cut off by a crash or restart.
const SPOOL_MAX_AGE: Duration = Duration::from_secs(2 * 60 * 60);

/// Removes stale spool files. Recent ones may belong to uploads still running,
/// here or on another server sharing the data directory.
pub fn clean_spool(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > SPOOL_MAX_AGE);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Objects deleted per round of [`drain`].
const DRAIN_BATCH: i64 = 100;

/// Deletes the queued objects that are due, retrying failures later.
pub async fn drain(state: &AppState) -> Result<(), sqlx::Error> {
    loop {
        let now = db::now();
        let due = db::attachments::due_deletions(&state.db, now, DRAIN_BATCH).await?;
        let mut deleted = 0;
        for (key, attempts) in &due {
            match state.storage.delete(key).await {
                Ok(()) => {
                    db::attachments::deletion_done(&state.db, key).await?;
                    deleted += 1;
                }
                Err(error) => {
                    tracing::warn!(%error, attempts, "deleting an attachment failed; will retry");
                    let next = now + retry_delay(*attempts);
                    db::attachments::deletion_failed(&state.db, key, next).await?;
                }
            }
        }
        // Stop when nothing is due, or when everything due failed (it waits now).
        if (due.len() as i64) < DRAIN_BATCH || deleted == 0 {
            return Ok(());
        }
    }
}

/// One minute after the first failure, doubling up to a day.
fn retry_delay(attempts: i64) -> i64 {
    let minutes = 1i64 << attempts.clamp(0, 11);
    (minutes * 60 * 1000).min(db::days(1))
}

/// Runs [`drain`] in the background, after a commit that queued deletions.
pub fn drain_soon(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = drain(&state).await {
            tracing::error!(%error, "deleting attachments failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_to_a_day() {
        assert_eq!(retry_delay(0), 60_000);
        assert_eq!(retry_delay(1), 120_000);
        assert_eq!(retry_delay(10), 1024 * 60_000);
        assert_eq!(retry_delay(11), db::days(1));
        assert_eq!(retry_delay(500), db::days(1));
    }

    #[tokio::test]
    async fn spooling_checks_the_length_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let upload = spool(dir.path(), Body::from("hello"), 5).await.unwrap();
        assert_eq!(std::fs::read(upload.path()).unwrap(), b"hello");
        assert_eq!(
            upload.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        drop(upload);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        for len in [4, 6] {
            let result = spool(dir.path(), Body::from("hello"), len).await;
            assert!(matches!(result, Err(SpoolError::LengthMismatch)), "{len}");
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "no partial files"
        );
    }
}
