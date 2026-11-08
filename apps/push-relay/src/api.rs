//! The relay's HTTP API, for Octa Pass servers only. Nothing here is meant for browsers.
//!
//! - `POST /v1/installations` registers a server: `201 {installationId, installationKey}`.
//! - `POST /v1/push` with `Authorization: Bearer <installationKey>` and
//!   `{installationId, messages: [{platform, token, sandbox, kind}]}` (at most 100) sends them and
//!   answers `{results: ["sent" | "unregistered" | "failed", …]}` in the same order. `401` for an
//!   unknown installation or a wrong key, `403` for a revoked one, `429` over the limit.
//! - `GET /healthz`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::task::JoinSet;

use crate::apns::Apns;
use crate::config::Config;
use crate::db::{self, Db};
use crate::fcm::Fcm;
use crate::jwt::KeyError;
use crate::limits::Buckets;
use crate::{Kind, Outcome};

/// Room for 100 messages with the longest tokens.
const MAX_BODY: usize = 256 * 1024;
const MAX_TOKEN: usize = 4096;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub db: Db,
    pub config: Config,
    apns: Option<Apns>,
    fcm: Option<Fcm>,
    pushes: Buckets,
    registrations: Buckets,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("APNs key: {0}")]
    Apns(KeyError),
    #[error("FCM service account key: {0}")]
    Fcm(KeyError),
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, StartupError> {
        let db = db::connect(&config.database_url).await?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("the HTTP client's settings are valid");
        let apns = config
            .apns
            .as_ref()
            .map(|apns| Apns::new(apns, http.clone()))
            .transpose()
            .map_err(StartupError::Apns)?;
        let fcm = config
            .fcm
            .as_ref()
            .map(|fcm| Fcm::new(fcm, http.clone()))
            .transpose()
            .map_err(StartupError::Fcm)?;
        let limits = config.limits;
        Ok(Self(Arc::new(Inner {
            db,
            apns,
            fcm,
            pushes: Buckets::new(limits.pushes_per_minute, limits.push_refill()),
            registrations: Buckets::new(
                limits.registrations_per_hour,
                limits.registration_refill(),
            ),
            config,
        })))
    }

    /// Housekeeping for the in-memory limits.
    pub fn prune(&self) {
        self.pushes.prune();
        self.registrations.prune();
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/v1/installations", post(register))
        .route("/v1/push", post(push))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

enum ApiError {
    BadRequest(&'static str),
    Unauthorized,
    /// The operator revoked this installation. Distinct from `Unauthorized`, so an honest server
    /// stops instead of registering again.
    Revoked,
    RateLimited(std::time::Duration),
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            ApiError::BadRequest(reason) => (StatusCode::BAD_REQUEST, reason),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unknown installation"),
            ApiError::Revoked => (StatusCode::FORBIDDEN, "revoked"),
            ApiError::RateLimited(wait) => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "rate-limited" })),
                )
                    .into_response();
                let seconds = wait.as_secs().max(1).to_string();
                response.headers_mut().insert(
                    "retry-after",
                    HeaderValue::from_str(&seconds).expect("digits are a valid header"),
                );
                return response;
            }
            ApiError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "try again later"),
        };
        (status, Json(json!({ "error": error }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database");
        ApiError::Unavailable
    }
}

fn client_ip(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if state.config.trust_proxy
        && let Some(last) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
    {
        return last.trim().to_owned();
    }
    peer.map(|addr| addr.ip().to_string()).unwrap_or_default()
}

fn key_hash(key: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Registered {
    installation_id: String,
    installation_key: String,
}

async fn register(
    State(state): State<AppState>,
    extensions: axum::http::Extensions,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Registered>), ApiError> {
    let peer = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let ip = client_ip(&state, &headers, peer);
    state
        .registrations
        .take(&ip, 1)
        .map_err(ApiError::RateLimited)?;
    let mut id = [0u8; 16];
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    OsRng.fill_bytes(&mut key);
    let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    let key = URL_SAFE_NO_PAD.encode(key);
    db::insert(&state.db, &id, &key_hash(&key), db::now()).await?;
    tracing::info!(installation = %id, "server registered");
    Ok((
        StatusCode::CREATED,
        Json(Registered {
            installation_id: id,
            installation_key: key,
        }),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Platform {
    Apns,
    Fcm,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    platform: Platform,
    token: String,
    #[serde(default)]
    sandbox: bool,
    kind: Kind,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRequest {
    installation_id: String,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct PushResults {
    results: Vec<Outcome>,
}

/// APNs device tokens are hex; FCM's are base64url with colons. Anything else could change the
/// URL it's sent to.
fn valid_token(platform: Platform, token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN
        && match platform {
            Platform::Apns => token.bytes().all(|b| b.is_ascii_hexdigit()),
            Platform::Fcm => token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':')),
        }
}

async fn push(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PushRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<PushResults>, ApiError> {
    let key = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let Json(request) = body.map_err(|_| ApiError::BadRequest("not a push request"))?;
    let installation = db::find(&state.db, &request.installation_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let matches: bool = key_hash(key)
        .as_bytes()
        .ct_eq(installation.key_hash.as_bytes())
        .into();
    if !matches {
        return Err(ApiError::Unauthorized);
    }
    if installation.revoked_at.is_some() {
        return Err(ApiError::Revoked);
    }
    let count = request.messages.len();
    if count == 0 || count > state.config.limits.max_batch {
        return Err(ApiError::BadRequest("send 1 to 100 messages"));
    }
    let count = u32::try_from(count).expect("at most 100");
    state
        .pushes
        .take(&installation.id, count)
        .map_err(ApiError::RateLimited)?;
    db::touch(&state.db, &installation.id, db::now()).await?;

    let mut tasks = JoinSet::new();
    for (index, message) in request.messages.into_iter().enumerate() {
        let state = state.clone();
        tasks.spawn(async move { (index, deliver(&state, message).await) });
    }
    let mut results = vec![Outcome::Failed; count as usize];
    while let Some(done) = tasks.join_next().await {
        if let Ok((index, outcome)) = done {
            results[index] = outcome;
        }
    }
    let sent = results.iter().filter(|o| **o == Outcome::Sent).count();
    let dead = results
        .iter()
        .filter(|o| **o == Outcome::Unregistered)
        .count();
    // Counts only: never a token.
    tracing::info!(installation = %installation.id, sent, dead, total = count, "pushes");
    Ok(Json(PushResults { results }))
}

async fn deliver(state: &AppState, message: Message) -> Outcome {
    if !valid_token(message.platform, &message.token) {
        return Outcome::Unregistered;
    }
    match message.platform {
        Platform::Apns => match &state.apns {
            Some(apns) => {
                apns.send(&message.token, message.sandbox, message.kind)
                    .await
            }
            None => Outcome::Failed,
        },
        Platform::Fcm => match &state.fcm {
            Some(fcm) => fcm.send(&message.token, message.kind).await,
            None => Outcome::Failed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_must_look_like_tokens() {
        assert!(valid_token(Platform::Apns, &"ab".repeat(32)));
        assert!(!valid_token(Platform::Apns, "ab/../x"));
        assert!(!valid_token(Platform::Apns, ""));
        assert!(valid_token(Platform::Fcm, "dGVzdA:APA91b-x_y"));
        assert!(!valid_token(Platform::Fcm, "a b"));
        assert!(!valid_token(Platform::Fcm, &"a".repeat(MAX_TOKEN + 1)));
    }
}
