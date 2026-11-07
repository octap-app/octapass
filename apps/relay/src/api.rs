//! The internal API the vault server calls. It speaks for every account, so it sits on loopback
//! behind a bearer token, and it trusts the account id and verified email the vault server sends:
//! the vault server is the one that checked the user's session.

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::address::Address;
use crate::db::{Alias, CreateError};
use crate::pipeline::{Relay, token_matches};

#[derive(Debug, Deserialize)]
pub struct AccountEmail {
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct SetEnabled {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct Sender {
    sender: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasView {
    id: String,
    address: String,
    enabled: bool,
    /// The relay stopped this alias, or the whole account, after bounces or complaints.
    paused: bool,
    forwarded: i64,
    blocked: i64,
    replied: i64,
    created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    aliases: Vec<AliasView>,
    max_aliases: i64,
    domain: String,
}

fn rfc3339(millis: i64) -> String {
    OffsetDateTime::from_unix_timestamp(millis / 1000)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .expect("stored timestamps are in range")
}

fn view(alias: Alias, domain: &str) -> AliasView {
    AliasView {
        address: format!("{}@{domain}", alias.local),
        enabled: alias.enabled,
        paused: alias.paused || alias.account_paused,
        forwarded: alias.forwarded,
        blocked: alias.blocked,
        replied: alias.replied,
        created_at: rfc3339(alias.created_at),
        id: alias.local,
    }
}

pub enum ApiError {
    Db(sqlx::Error),
    NotFound,
    /// The email can't take forwarded mail.
    BadDestination,
    BadSender,
    TooManyAliases,
    TooManyToday,
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(error)
    }
}

impl From<CreateError> for ApiError {
    fn from(error: CreateError) -> Self {
        match error {
            CreateError::TooMany => Self::TooManyAliases,
            CreateError::TooManyToday => Self::TooManyToday,
            CreateError::Db(error) => Self::Db(error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Db(error) => {
                tracing::error!(%error, "database error");
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
            }
            Self::NotFound => (StatusCode::NOT_FOUND, "not-found"),
            Self::BadDestination => (StatusCode::BAD_REQUEST, "bad-destination"),
            Self::BadSender => (StatusCode::BAD_REQUEST, "bad-sender"),
            Self::TooManyAliases => (StatusCode::CONFLICT, "alias-limit"),
            Self::TooManyToday => (StatusCode::TOO_MANY_REQUESTS, "alias-daily-limit"),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// A destination the relay can actually deliver to: a plain address, and not on its own domain,
/// where forwarding would feed itself.
fn destination(relay: &Relay, email: &str) -> ApiResult<String> {
    match Address::parse(email) {
        Ok(address) if address.domain != relay.config.domain => Ok(address.to_string()),
        _ => Err(ApiError::BadDestination),
    }
}

async fn authorize(State(relay): State<Arc<Relay>>, request: Request, next: Next) -> Response {
    let allowed = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token_matches(token, &relay.config.api_token));
    if allowed {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn put_account(
    State(relay): State<Arc<Relay>>,
    Path(account): Path<String>,
    Json(body): Json<AccountEmail>,
) -> ApiResult<Json<AccountView>> {
    let email = destination(&relay, &body.email)?;
    let store = relay.store();
    store.sync_account(&account, &email).await?;
    let domain = &relay.config.domain;
    let aliases = store.aliases(&account).await?;
    Ok(Json(AccountView {
        aliases: aliases.into_iter().map(|a| view(a, domain)).collect(),
        max_aliases: relay.config.limits.aliases_per_account,
        domain: domain.clone(),
    }))
}

async fn delete_account(
    State(relay): State<Arc<Relay>>,
    Path(account): Path<String>,
) -> ApiResult<StatusCode> {
    relay.store().delete_account(&account).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_alias(
    State(relay): State<Arc<Relay>>,
    Path(account): Path<String>,
    Json(body): Json<AccountEmail>,
) -> ApiResult<(StatusCode, Json<AliasView>)> {
    let email = destination(&relay, &body.email)?;
    let store = relay.store();
    store.sync_account(&account, &email).await?;
    let alias = store.create_alias(&account, &relay.config.limits).await?;
    Ok((StatusCode::CREATED, Json(view(alias, &relay.config.domain))))
}

async fn patch_alias(
    State(relay): State<Arc<Relay>>,
    Path((account, alias)): Path<(String, String)>,
    Json(body): Json<SetEnabled>,
) -> ApiResult<Json<AliasView>> {
    let store = relay.store();
    if !store.set_enabled(&account, &alias, body.enabled).await? {
        return Err(ApiError::NotFound);
    }
    let alias = store.alias(&alias).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(view(alias, &relay.config.domain)))
}

async fn delete_alias(
    State(relay): State<Arc<Relay>>,
    Path((account, alias)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    if relay.store().delete_alias(&account, &alias).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn set_blocked(
    relay: &Relay,
    account: &str,
    alias: &str,
    sender: &str,
    blocked: bool,
) -> ApiResult<StatusCode> {
    let sender = Address::parse(sender).map_err(|_| ApiError::BadSender)?;
    let store = relay.store();
    if store
        .set_blocked(account, alias, &sender.to_string(), blocked)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn block(
    State(relay): State<Arc<Relay>>,
    Path((account, alias)): Path<(String, String)>,
    Json(body): Json<Sender>,
) -> ApiResult<StatusCode> {
    set_blocked(&relay, &account, &alias, &body.sender, true).await
}

async fn unblock(
    State(relay): State<Arc<Relay>>,
    Path((account, alias)): Path<(String, String)>,
    Json(body): Json<Sender>,
) -> ApiResult<StatusCode> {
    set_blocked(&relay, &account, &alias, &body.sender, false).await
}

pub fn router(relay: Arc<Relay>) -> Router {
    let protected = Router::new()
        .route(
            "/internal/accounts/{account}",
            put(put_account).delete(delete_account),
        )
        .route("/internal/accounts/{account}/aliases", post(create_alias))
        .route(
            "/internal/accounts/{account}/aliases/{alias}",
            axum::routing::patch(patch_alias).delete(delete_alias),
        )
        .route(
            "/internal/accounts/{account}/aliases/{alias}/block",
            post(block),
        )
        .route(
            "/internal/accounts/{account}/aliases/{alias}/unblock",
            post(unblock),
        )
        .route_layer(middleware::from_fn_with_state(relay.clone(), authorize));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(relay)
}
