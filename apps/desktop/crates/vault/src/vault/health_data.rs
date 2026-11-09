//! The health report's site lists (plan 06): the bundled ones, or a newer signed file from the
//! account's server, fetched at most once a day and kept in the data folder. The file is public,
//! so it isn't encrypted; it's checked against the pinned key whenever it's read.

use std::path::PathBuf;

use octapass_core::health_data;
use serde::{Deserialize, Serialize};

use super::Vault;
use crate::error::Result;
use crate::model::unix_ms;
use time::OffsetDateTime;

const FILE: &str = "health-data.json";

/// The lists the web view's health report uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthDataLists {
    pub version: u64,
    pub passkey_domains: Vec<String>,
    pub two_factor_domains: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    /// The newest file accepted, as downloaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    /// When the server was last asked, in Unix milliseconds.
    #[serde(default)]
    checked_at: u64,
}

impl Vault {
    fn health_data_path(&self) -> PathBuf {
        self.config.data_dir.join(FILE)
    }

    fn stored_health_data(&self) -> Stored {
        std::fs::read_to_string(self.health_data_path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// The newest lists on this device. Asks the account's server for a newer file when a day
    /// has passed; a server that doesn't answer, or answers with a file that isn't signed and
    /// newer, leaves them as they were. Local vaults keep the bundled lists.
    pub async fn health_data(&self) -> Result<HealthDataLists> {
        let mut stored = self.stored_health_data();
        let server = self
            .with_unlocked(|unlocked| Ok(unlocked.key.clone()))
            .ok()
            .filter(|key| !key.is_local())
            .map(|key| key.server_url);
        let now = unix_ms(OffsetDateTime::now_utc());
        if let Some(server) = server
            && now.saturating_sub(stored.checked_at) >= health_data::CHECK_HOURS as u64 * 3_600_000
            && let Ok(text) = self.api(&server).health_data().await
        {
            let in_use = health_data::newest(stored.file.as_deref()).version;
            if health_data::verify(&text, in_use).is_ok() {
                stored.file = Some(text);
            }
            stored.checked_at = now;
            if let Ok(json) = serde_json::to_string(&stored) {
                // Best effort: without the file, the next report asks again.
                let _ = std::fs::write(self.health_data_path(), json);
            }
        }
        let data = health_data::newest(stored.file.as_deref());
        Ok(HealthDataLists {
            version: data.version,
            passkey_domains: data.passkey_domains.into_iter().collect(),
            two_factor_domains: data.two_factor_domains.into_iter().collect(),
        })
    }
}
