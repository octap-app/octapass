//! A thin client for the masked email relay (`apps/relay`), which is a service of its own with its
//! own database. This server only vouches for who's asking: it passes on the signed-in account's
//! id and verified email. No mail, and nothing from the vault, passes through here.

use std::time::Duration;

use axum::http::{Method, StatusCode};
use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::Relay;
use crate::db;
use crate::db::Conn;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const TIMEOUT: Duration = Duration::from_secs(10);
/// The relay's day-long cap on new aliases; the exact moment it lifts isn't known here.
const DAILY_LIMIT_WAIT: Duration = Duration::from_secs(60 * 60);

pub struct RelayClient {
    url: String,
    token: String,
    http: Client,
}

impl RelayClient {
    pub fn new(config: &Relay) -> Self {
        let http = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("the HTTP client's settings are valid");
        Self {
            url: config.url.clone(),
            token: config.token.clone(),
            http,
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.url))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(serde_json::to_vec(body).expect("request bodies serialize"));
        }
        request.send().await
    }

    /// A call whose reply a user is waiting for. The relay's refusals become this API's errors;
    /// anything else means it can't be reached, which says nothing to the user but "later".
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> ApiResult<T> {
        let response = self.checked(method, path, body).await?;
        let bytes = response.bytes().await.map_err(|error| {
            tracing::warn!(%error, "the masked email relay's reply was cut off");
            ApiError::Unavailable
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            tracing::error!(%error, "the masked email relay sent an unreadable reply");
            ApiError::Unavailable
        })
    }

    /// `call` for replies with no body.
    pub async fn call_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> ApiResult<()> {
        self.checked(method, path, body).await.map(|_| ())
    }

    async fn checked(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> ApiResult<reqwest::Response> {
        let response = self.send(method, path, body).await.map_err(|error| {
            tracing::warn!(%error, "the masked email relay can't be reached");
            ApiError::Unavailable
        })?;
        match response.status() {
            status if status.is_success() => Ok(response),
            StatusCode::NOT_FOUND => Err(ApiError::NotFound),
            StatusCode::CONFLICT => Err(ApiError::MaskedEmailLimit),
            StatusCode::TOO_MANY_REQUESTS => Err(ApiError::RateLimited(DAILY_LIMIT_WAIT)),
            StatusCode::BAD_REQUEST => {
                let bytes = response.bytes().await.unwrap_or_default();
                let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                Err(ApiError::BadRequest(
                    match body["error"].as_str() {
                        Some("bad-sender") => "that isn't an email address",
                        _ => "this account's email can't receive forwarded mail",
                    }
                    .into(),
                ))
            }
            status => {
                tracing::error!(%status, "the masked email relay refused a call");
                Err(ApiError::Unavailable)
            }
        }
    }

    async fn delete_account(&self, account_id: &str) -> bool {
        let path = format!("/internal/accounts/{account_id}");
        matches!(
            self.send(Method::DELETE, &path, None::<&()>).await,
            Ok(response) if response.status().is_success()
        )
    }
}

/// Remembers, in the transaction that deletes the account, that the relay must forget it too. The
/// relay holds the account's email and contacts, so its deletion has to survive the relay being
/// down at that moment.
pub async fn queue_deletion(
    state: &AppState,
    conn: &mut Conn,
    account_id: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    if state.relay.is_some() {
        sqlx::query(
            "INSERT INTO relay_deletions (account_id, attempts, next_attempt_at) VALUES ($1, 0, $2) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(now)
        .execute(conn)
        .await?;
    }
    Ok(())
}

/// One minute after the first failure, doubling up to a day.
fn retry_delay(attempts: i64) -> i64 {
    let minutes = 1i64 << attempts.clamp(0, 11);
    (minutes * 60 * 1000).min(db::days(1))
}

/// Tells the relay about every deletion that's due. Failures wait for a later round.
pub async fn drain(state: &AppState) {
    let Some(relay) = &state.relay else { return };
    let now = db::now();
    let due: Result<Vec<(String, i64)>, sqlx::Error> = sqlx::query_as(
        "SELECT account_id, attempts FROM relay_deletions WHERE next_attempt_at <= $1",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await;
    let due = match due {
        Ok(due) => due,
        Err(error) => {
            tracing::error!(%error, "reading the relay's deletions failed");
            return;
        }
    };
    for (account_id, attempts) in due {
        let query = if relay.delete_account(&account_id).await {
            sqlx::query("DELETE FROM relay_deletions WHERE account_id = $1").bind(account_id)
        } else {
            tracing::warn!("the masked email relay didn't take a deletion; it will be tried again");
            sqlx::query(
                "UPDATE relay_deletions SET attempts = attempts + 1, next_attempt_at = $2 \
                 WHERE account_id = $1",
            )
            .bind(account_id)
            .bind(now + retry_delay(attempts))
        };
        if let Err(error) = query.execute(&state.db).await {
            tracing::error!(%error, "updating the relay's deletions failed");
        }
    }
}

/// Runs [`drain`] in the background, after a commit that queued a deletion.
pub fn drain_soon(state: &AppState) {
    if state.relay.is_some() {
        let state = state.clone();
        tokio::spawn(async move { drain(&state).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_to_a_day() {
        assert_eq!(retry_delay(0), 60_000);
        assert_eq!(retry_delay(3), 480_000);
        assert_eq!(retry_delay(500), db::days(1));
    }
}
