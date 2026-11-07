//! The website icon proxy (plan 04): clients ask the server for a site's icon, so their
//! browsing never reaches an icon service. The server fetches from the site itself, keeps the
//! result in the data directory for a while, and never ties a request to an account.

mod domain;
mod fetch;
mod html;
mod image;
pub(crate) mod net;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

pub use domain::normalise as normalise_domain;
pub use fetch::Limits;
pub use net::TestNetwork;

use crate::db::days;

/// How long a found icon is kept, here and by clients.
pub const ICON_TTL_MS: i64 = days(7);
/// How long "this site has no icon" is kept: sites add icons, and fetches fail now and then.
pub const MISS_TTL_MS: i64 = days(1);
/// Sites fetched at the same time, across all clients.
const CONCURRENT_FETCHES: usize = 8;

pub struct Icons {
    fetcher: fetch::Fetcher,
    dir: PathBuf,
    /// Keys the cache file names, so the directory isn't a readable list of sites.
    name_key: [u8; 32],
    fetches: Semaphore,
    /// One fetch per site at a time; later askers wait for it and read the cache.
    in_flight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Icons {
    pub fn new(
        dir: PathBuf,
        name_key: [u8; 32],
        test: Option<Arc<TestNetwork>>,
        limits: Limits,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            fetcher: fetch::Fetcher::new(test, limits),
            dir,
            name_key,
            fetches: Semaphore::new(CONCURRENT_FETCHES),
            in_flight: Mutex::default(),
        })
    }

    /// The PNG icon for a normalised domain, from the cache or the site; `None` when it has none.
    pub async fn get(&self, domain: &str, now: i64) -> Option<Vec<u8>> {
        if let Some(cached) = self.cached(domain, now).await {
            return cached;
        }
        let lock = {
            let mut in_flight = self.in_flight.lock().expect("icon lock poisoned");
            in_flight.entry(domain.to_owned()).or_default().clone()
        };
        let guard = lock.lock().await;
        // Someone else may have fetched it while this request waited.
        let icon = match self.cached(domain, now).await {
            Some(cached) => cached,
            None => {
                let _permit = self
                    .fetches
                    .acquire()
                    .await
                    .expect("the semaphore is never closed");
                let icon = self.fetcher.icon(domain).await;
                self.store(domain, icon.as_deref(), now).await;
                icon
            }
        };
        drop(guard);
        let mut in_flight = self.in_flight.lock().expect("icon lock poisoned");
        if Arc::strong_count(&lock) <= 2 {
            in_flight.remove(domain);
        }
        icon
    }

    fn path(&self, domain: &str) -> PathBuf {
        let name =
            crate::crypto::keyed_hash(&self.name_key, "octapass/icon-cache", domain.as_bytes());
        let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.icon"))
    }

    /// `Some(None)` is a remembered miss. Files are the expiry (8 bytes, big-endian Unix ms),
    /// then the PNG, if any.
    async fn cached(&self, domain: &str, now: i64) -> Option<Option<Vec<u8>>> {
        let bytes = tokio::fs::read(self.path(domain)).await.ok()?;
        let (expires, png) = parse_entry(&bytes)?;
        (expires > now).then(|| (!png.is_empty()).then(|| png.to_vec()))
    }

    async fn store(&self, domain: &str, icon: Option<&[u8]>, now: i64) {
        let ttl = if icon.is_some() {
            ICON_TTL_MS
        } else {
            MISS_TTL_MS
        };
        let mut bytes = (now + ttl).to_be_bytes().to_vec();
        bytes.extend_from_slice(icon.unwrap_or_default());
        let path = self.path(domain);
        let temp = path.with_extension("tmp");
        let written = async {
            tokio::fs::write(&temp, &bytes).await?;
            tokio::fs::rename(&temp, &path).await
        };
        if let Err(error) = written.await {
            tracing::warn!(%error, "couldn't cache an icon");
        }
    }

    /// Deletes expired entries and leftovers of interrupted writes.
    pub fn purge(&self, now: i64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let expired = match path.extension().and_then(|e| e.to_str()) {
                Some("icon") => std::fs::read(&path)
                    .ok()
                    .and_then(|bytes| parse_entry(&bytes).map(|(expires, _)| expires <= now))
                    .unwrap_or(true),
                _ => true,
            };
            if expired {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn parse_entry(bytes: &[u8]) -> Option<(i64, &[u8])> {
    let (expires, png) = bytes.split_first_chunk::<8>()?;
    Some((i64::from_be_bytes(*expires), png))
}
