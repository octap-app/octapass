//! Push sync through the push relay (plan 04, "Push relay"; the relay is `apps/push-relay`).
//!
//! Phones register a push token for their device. When something an account can see changes,
//! the server sends the relay, for each of that account's signed-in devices, the token and one
//! word: `sync` (a vault changed) or `alert` (sharing, a family invite, emergency access). No
//! account, vault, item, email or name ever goes to the relay, and the relay never learns which
//! tokens belong together beyond one request.
//!
//! Changes gather for a moment (`batch_delay`), so an import wakes each phone once. Pushes are
//! best effort: phones still sync when opened, so a lost push only delays a sync.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::PushRelay;
use crate::db::push::Installation;
use crate::db::{self, Db};
use crate::state::AppState;

const TIMEOUT: Duration = Duration::from_secs(15);
/// What the relay takes in one request.
const BATCH: usize = 100;

/// What a push asks a phone to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PushKind {
    /// A vault changed: sync silently.
    Sync,
    /// Something to show: the phone shows its own generic notice and syncs.
    Alert,
}

pub struct Push {
    url: String,
    batch_delay: Duration,
    http: Client,
    installation: Mutex<Option<Installation>>,
    /// One registration at a time.
    registering: tokio::sync::Mutex<()>,
    pending: Mutex<Pending>,
    /// The relay's operator revoked this server: nothing more is sent until a restart, and the
    /// server doesn't register again by itself.
    revoked: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct Pending {
    accounts: HashMap<String, PushKind>,
    scheduled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Message<'a> {
    platform: &'a str,
    token: &'a str,
    sandbox: bool,
    kind: PushKind,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PushRequest<'a> {
    installation_id: &'a str,
    messages: &'a [Message<'a>],
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Sent,
    Unregistered,
    Failed,
}

#[derive(Deserialize)]
struct PushResults {
    results: Vec<Outcome>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registered {
    installation_id: String,
    installation_key: String,
}

impl Push {
    pub async fn new(config: &PushRelay, db: &Db) -> Result<Self, sqlx::Error> {
        let http = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("the HTTP client's settings are valid");
        Ok(Self {
            installation: Mutex::new(db::push::installation(db, &config.url).await?),
            url: config.url.clone(),
            batch_delay: config.batch_delay,
            http,
            registering: tokio::sync::Mutex::new(()),
            pending: Mutex::default(),
            revoked: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Registered with the relay, so pushes can go out.
    pub fn ready(&self) -> bool {
        self.installation_guard().is_some() && !self.is_revoked()
    }

    fn is_revoked(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn installation_guard(&self) -> std::sync::MutexGuard<'_, Option<Installation>> {
        self.installation.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn pending_guard(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The installation, registering first if this server has none with this relay.
    async fn installation(&self, db: &Db) -> Option<Installation> {
        if let Some(installation) = self.installation_guard().clone() {
            return Some(installation);
        }
        let _one = self.registering.lock().await;
        if let Some(installation) = self.installation_guard().clone() {
            return Some(installation);
        }
        let response = self
            .http
            .post(format!("{}/v1/installations", self.url))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await;
        let registered: Registered = match response {
            Ok(response) if response.status() == StatusCode::CREATED => {
                match response.bytes().await.map(|b| serde_json::from_slice(&b)) {
                    Ok(Ok(registered)) => registered,
                    _ => {
                        tracing::error!("the push relay's registration answer is unreadable");
                        return None;
                    }
                }
            }
            Ok(response) => {
                tracing::warn!(status = %response.status(), "the push relay refused to register this server");
                return None;
            }
            Err(error) => {
                tracing::warn!(%error, "the push relay can't be reached");
                return None;
            }
        };
        let installation = Installation {
            installation_id: registered.installation_id,
            installation_key: registered.installation_key,
        };
        if let Err(error) =
            db::push::save_installation(db, &self.url, &installation, db::now()).await
        {
            tracing::error!(%error, "couldn't keep the push relay installation");
            return None;
        }
        tracing::info!("registered with the push relay");
        *self.installation_guard() = Some(installation.clone());
        Some(installation)
    }

    /// The relay no longer knows this installation (its data was lost, or it moved): forget it,
    /// so the next maintenance round registers again. A revoked one is `403` instead, and stays.
    async fn forget(&self, db: &Db) {
        *self.installation_guard() = None;
        if let Err(error) = db::push::forget_installation(db, &self.url).await {
            tracing::error!(%error, "couldn't forget the push relay installation");
        }
    }
}

/// Registers in the background if this server has no installation yet. At startup and from
/// maintenance, so a relay that was down at startup is tried again.
pub fn register_soon(state: &AppState) {
    if let Some(push) = &state.push
        && !push.ready()
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Some(push) = &state.push {
                push.installation(&state.db).await;
            }
        });
    }
}

/// Wakes the account's devices soon. An alert wins over a sync in the same round.
pub fn wake(state: &AppState, account_id: &str, kind: PushKind) {
    let Some(push) = &state.push else { return };
    let schedule = {
        let mut pending = push.pending_guard();
        let entry = pending
            .accounts
            .entry(account_id.to_owned())
            .or_insert(kind);
        *entry = (*entry).max(kind);
        !std::mem::replace(&mut pending.scheduled, true)
    };
    if schedule {
        let state = state.clone();
        let delay = push.batch_delay;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            flush(&state).await;
        });
    }
}

async fn flush(state: &AppState) {
    let Some(push) = &state.push else { return };
    if push.is_revoked() {
        push.pending_guard().scheduled = false;
        push.pending_guard().accounts.clear();
        return;
    }
    let accounts = {
        let mut pending = push.pending_guard();
        pending.scheduled = false;
        std::mem::take(&mut pending.accounts)
    };
    if accounts.is_empty() {
        return;
    }
    let ids: Vec<String> = accounts.keys().cloned().collect();
    let targets = match db::push::targets(&state.db, &ids).await {
        Ok(targets) => targets,
        Err(error) => {
            tracing::error!(%error, "couldn't read push tokens");
            return;
        }
    };
    if targets.is_empty() {
        return;
    }
    let Some(installation) = push.installation(&state.db).await else {
        return;
    };
    let messages: Vec<Message<'_>> = targets
        .iter()
        .map(|target| Message {
            platform: &target.platform,
            token: &target.token,
            sandbox: target.sandbox == 1,
            kind: accounts[&target.account_id],
        })
        .collect();
    let mut dead = Vec::new();
    for batch in messages.chunks(BATCH) {
        let body = PushRequest {
            installation_id: &installation.installation_id,
            messages: batch,
        };
        let response = push
            .http
            .post(format!("{}/v1/push", push.url))
            .bearer_auth(&installation.installation_key)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).expect("push requests serialize"))
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(error = %error.without_url(), "the push relay can't be reached");
                break;
            }
        };
        match response.status() {
            StatusCode::OK => {
                let results = response
                    .bytes()
                    .await
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<PushResults>(&bytes).ok());
                let Some(results) = results else {
                    tracing::warn!("the push relay's answer is unreadable");
                    continue;
                };
                for (message, outcome) in batch.iter().zip(results.results) {
                    match outcome {
                        Outcome::Unregistered => dead.push(message.token.to_owned()),
                        Outcome::Sent | Outcome::Failed => {}
                    }
                }
            }
            StatusCode::UNAUTHORIZED => {
                tracing::error!(
                    "the push relay doesn't know this server's installation; it registers again later"
                );
                push.forget(&state.db).await;
                break;
            }
            StatusCode::FORBIDDEN => {
                tracing::error!(
                    "the push relay's operator revoked this server: no more pushes until the \
                     revocation is lifted and the server restarts"
                );
                push.revoked
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                tracing::warn!("the push relay is limiting this server; pushes were dropped");
                break;
            }
            status => {
                tracing::warn!(%status, "the push relay didn't take the pushes");
                break;
            }
        }
    }
    if !dead.is_empty()
        && let Err(error) = db::push::delete_tokens(&state.db, &dead).await
    {
        tracing::error!(%error, "couldn't forget dead push tokens");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alert_outranks_a_sync() {
        assert!(PushKind::Alert > PushKind::Sync);
        assert_eq!(PushKind::Sync.max(PushKind::Alert), PushKind::Alert);
        assert_eq!(
            serde_json::to_string(&PushKind::Alert).unwrap(),
            "\"alert\""
        );
    }
}
