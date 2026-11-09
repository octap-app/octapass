//! The health report's signed site lists (plan 06), served at `GET /v1/health/data`.
//!
//! The server starts with the file its build bundled. With `OCTAPASS_HEALTH_DATA_URL` set (the
//! project's site publishes it at `/data/health-data.json`) it also fetches that file once a day
//! and serves it when it's signed by the pinned key and newer. Clients check the signature and
//! version again themselves: the server is a mirror, not trusted, and it can't change the lists.
//! The file is public and the same for everyone, so serving it learns nothing about an account.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use octapass_core::health_data::{self, Rejected};

use crate::config::HealthDataSource;
use crate::state::AppState;

const TIMEOUT: Duration = Duration::from_secs(15);

/// The file the server hands out, and its version.
pub struct HealthDataMirror {
    served: RwLock<(Arc<str>, u64)>,
    key: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("couldn't reach the health data URL: {0}")]
    Http(#[from] reqwest::Error),
    #[error("the health data URL answered {0}")]
    Status(u16),
    #[error("the health data file is larger than {} bytes", health_data::MAX_BYTES)]
    TooLarge,
    #[error("the health data file isn't valid UTF-8")]
    NotText,
    #[error("{0}")]
    Rejected(#[from] Rejected),
}

impl HealthDataMirror {
    pub fn new(source: &HealthDataSource) -> Self {
        Self {
            served: RwLock::new((
                Arc::from(health_data::BUNDLED),
                health_data::bundled().version,
            )),
            key: source.key,
        }
    }

    pub fn file(&self) -> Arc<str> {
        self.served.read().expect("health data lock").0.clone()
    }

    pub fn version(&self) -> u64 {
        self.served.read().expect("health data lock").1
    }

    /// Serves `text` from now on when it's signed and newer. `Ok(false)`: the same version or an
    /// older one, which is the usual answer.
    pub fn offer(&self, text: &str) -> Result<bool, Rejected> {
        let mut served = self.served.write().expect("health data lock");
        match health_data::verify_with_key(text, served.1, &self.key) {
            Ok(data) => {
                *served = (Arc::from(text), data.version);
                Ok(true)
            }
            Err(Rejected::Rollback) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Fetches the file once from `OCTAPASS_HEALTH_DATA_URL`. No cookies, no redirects, no more than
/// `MAX_BYTES`.
pub async fn fetch(state: &AppState) -> Result<bool, FetchError> {
    let Some(url) = state.config.health_data.url.as_deref() else {
        return Ok(false);
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()?;
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(FetchError::Status(response.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > health_data::MAX_BYTES {
            return Err(FetchError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body).map_err(|_| FetchError::NotText)?;
    Ok(state.health_data.offer(text)?)
}

/// Fetches at start and then every `interval`, when a URL is set.
pub fn spawn(state: AppState) {
    if state.config.health_data.url.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(state.config.health_data.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match fetch(&state).await {
                Ok(true) => {
                    tracing::info!(version = state.health_data.version(), "health data updated")
                }
                Ok(false) => {}
                Err(error) => tracing::warn!(%error, "health data not updated"),
            }
        }
    });
}
