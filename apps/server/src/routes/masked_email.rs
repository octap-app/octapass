//! The server's own masked email service, proxied to the relay. Clients find out it exists from
//! `maskedEmailRelay` in server info; without a relay every route here answers 404.

use axum::Json;
use axum::extract::State;
use axum::http::{Method, StatusCode};
use octapass_api::problem::Problem;
use octapass_api::{
    MaskedEmailAlias, MaskedEmailAliases, MaskedEmailSender, SetMaskedEmailEnabled,
};
use serde::Serialize;

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated};
use crate::relay::RelayClient;
use crate::state::AppState;

#[derive(Serialize)]
struct AccountEmail {
    email: String,
}

fn relay(state: &AppState) -> ApiResult<&RelayClient> {
    state.relay.as_ref().ok_or(ApiError::MaskedEmailOff)
}

/// The signed-in account's verified email: the only place forwarded mail can go.
async fn account_email(state: &AppState, account_id: &str) -> ApiResult<AccountEmail> {
    let mut conn = state.db.acquire().await?;
    let email = db::accounts::email_for(&mut conn, account_id).await?;
    Ok(AccountEmail {
        email: email.ok_or(ApiError::Unauthorized)?,
    })
}

/// Alias ids go into the relay's URLs, so only ids shaped like the relay's get that far.
fn alias_path(account_id: &str, id: &str) -> ApiResult<String> {
    let issued = id.len() == 12
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    if issued {
        Ok(format!("/internal/accounts/{account_id}/aliases/{id}"))
    } else {
        Err(ApiError::NotFound)
    }
}

#[utoipa::path(
    get, path = "/v1/masked-email/aliases", tag = "masked-email",
    security(("bearer" = [])),
    responses(
        (status = 200, body = MaskedEmailAliases, description = "The account's aliases, newest first"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "This server has no masked email service"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<MaskedEmailAliases>> {
    let relay = relay(&state)?;
    let email = account_email(&state, &session.account_id).await?;
    let path = format!("/internal/accounts/{}", session.account_id);
    Ok(Json(relay.call(Method::PUT, &path, Some(&email)).await?))
}

#[utoipa::path(
    post, path = "/v1/masked-email/aliases", tag = "masked-email",
    security(("bearer" = [])),
    responses(
        (status = 201, body = MaskedEmailAlias, description = "A new random alias, forwarding to the account's email"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "This server has no masked email service"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "The account has as many aliases as the server allows"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "The account made as many aliases as it may today"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<(StatusCode, Json<MaskedEmailAlias>)> {
    let relay = relay(&state)?;
    let email = account_email(&state, &session.account_id).await?;
    let path = format!("/internal/accounts/{}/aliases", session.account_id);
    let alias = relay.call(Method::POST, &path, Some(&email)).await?;
    Ok((StatusCode::CREATED, Json(alias)))
}

#[utoipa::path(
    patch, path = "/v1/masked-email/aliases/{id}", tag = "masked-email",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "The alias id")),
    request_body = SetMaskedEmailEnabled,
    responses(
        (status = 200, body = MaskedEmailAlias, description = "The alias, turned on or off. Turning it on also ends a pause"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such alias on this account, or no masked email service"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn set_enabled(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<SetMaskedEmailEnabled>,
) -> ApiResult<Json<MaskedEmailAlias>> {
    let relay = relay(&state)?;
    let path = alias_path(&session.account_id, &id)?;
    Ok(Json(
        relay.call(Method::PATCH, &path, Some(&request)).await?,
    ))
}

#[utoipa::path(
    delete, path = "/v1/masked-email/aliases/{id}", tag = "masked-email",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "The alias id")),
    responses(
        (status = 204, description = "The alias and its contacts are gone. Mail to it is refused from now on"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such alias on this account, or no masked email service"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    let relay = relay(&state)?;
    let path = alias_path(&session.account_id, &id)?;
    relay.call_empty(Method::DELETE, &path, None::<&()>).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_blocked(
    state: &AppState,
    account_id: &str,
    id: &str,
    action: &str,
    request: &MaskedEmailSender,
) -> ApiResult<StatusCode> {
    let relay = relay(state)?;
    let path = format!("{}/{action}", alias_path(account_id, id)?);
    relay.call_empty(Method::POST, &path, Some(request)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/masked-email/aliases/{id}/block", tag = "masked-email",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "The alias id")),
    request_body = MaskedEmailSender,
    responses(
        (status = 204, description = "Mail from this sender to this alias is refused from now on"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such alias on this account, or no masked email service"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn block(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<MaskedEmailSender>,
) -> ApiResult<StatusCode> {
    set_blocked(&state, &session.account_id, &id, "block", &request).await
}

#[utoipa::path(
    post, path = "/v1/masked-email/aliases/{id}/unblock", tag = "masked-email",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "The alias id")),
    request_body = MaskedEmailSender,
    responses(
        (status = 204, description = "This sender can reach this alias again"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such alias on this account, or no masked email service"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn unblock(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<MaskedEmailSender>,
) -> ApiResult<StatusCode> {
    set_blocked(&state, &session.account_id, &id, "unblock", &request).await
}
