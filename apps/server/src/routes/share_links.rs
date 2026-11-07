//! One-time share links. The creator uploads ciphertext; the key that opens
//! it travels in the link's `#` fragment, which never reaches the server.
//! Viewing needs no account, so it has its own strict per-IP limit.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, HeaderValue};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{
    CreateShareLinkRequest, CreateShareLinkResponse, ShareLinkResponse, ShareLinksResponse,
};

use crate::crypto::{base64url, random_bytes};
use crate::db::{self, days, share_links};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated, ClientIp};
use crate::state::AppState;
use crate::validate;

/// An item snapshot: the largest item, plus the share link header.
pub const MAX_CIPHERTEXT: usize = 600 * 1024;
const MIN_CIPHERTEXT: usize = 2 + 24 + 16;
const MIN_LIFETIME: i64 = 60 * 60 * 1000;
const MAX_LIFETIME: i64 = days(30);
/// Clocks differ: a requested expiry this far outside the range still counts.
const CLOCK_SLACK: i64 = 5 * 60 * 1000;
const MAX_VIEWS: u32 = 100;
/// Links one account can have open at once.
const MAX_ACTIVE: i64 = 100;
/// Ids are 16 random bytes, base64url.
const ID_LEN: usize = 22;

#[utoipa::path(
    post, path = "/v1/share-links", tag = "share-links",
    security(("bearer" = [])),
    request_body = CreateShareLinkRequest,
    responses(
        (status = 201, body = CreateShareLinkResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "quota-exceeded: 100 open links; org-policy: the organisation doesn't allow them"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<CreateShareLinkRequest>,
) -> ApiResult<(StatusCode, Json<CreateShareLinkResponse>)> {
    let ciphertext = validate::base64url("ciphertext", &request.ciphertext, MAX_CIPHERTEXT)?;
    if ciphertext.len() < MIN_CIPHERTEXT || ciphertext[0] != 1 {
        return Err(ApiError::BadRequest(
            "ciphertext must be a version 1 share link".into(),
        ));
    }
    let policies = db::orgs::policies_of(&state.db, &session.account_id).await?;
    if policies.is_some_and(|policies| policies.disable_share_links) {
        return Err(ApiError::OrgPolicy(
            "your organisation doesn't allow share links",
        ));
    }
    let now = state.clock.now();
    let expires_at = validate::timestamp("expiresAt", &request.expires_at)?;
    let allowed = MIN_LIFETIME - CLOCK_SLACK..=MAX_LIFETIME + CLOCK_SLACK;
    if !allowed.contains(&(expires_at - now)) {
        return Err(ApiError::BadRequest(
            "expiresAt must be 1 hour to 30 days from now".into(),
        ));
    }
    if !(1..=MAX_VIEWS).contains(&request.max_views) {
        return Err(ApiError::BadRequest(format!(
            "maxViews must be 1 to {MAX_VIEWS}"
        )));
    }
    if share_links::count_active(&state.db, &session.account_id, now).await? >= MAX_ACTIVE {
        return Err(ApiError::QuotaExceeded);
    }
    let id = base64url(random_bytes::<16>());
    let link = share_links::NewShareLink {
        id: &id,
        account_id: &session.account_id,
        ciphertext: &request.ciphertext,
        passphrase_required: request.passphrase_required,
        max_views: request.max_views,
        expires_at,
        now,
    };
    share_links::insert(&state.db, link).await?;
    let response = CreateShareLinkResponse {
        id,
        expires_at: db::rfc3339(expires_at),
    };
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    get, path = "/v1/share-links/{id}", tag = "share-links",
    params(("id" = String, Path)),
    responses(
        (status = 200, body = ShareLinkResponse, description = "Counts a view. The last view deletes the link."),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "Unknown, used up or expired"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn view(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Response> {
    state
        .share_link_limiter
        .check(&ip)
        .map_err(ApiError::RateLimited)?;
    if !is_link_id(&id) {
        return Err(ApiError::NotFound);
    }
    let link = share_links::view(&state.db, &id, state.clock.now())
        .await?
        .ok_or(ApiError::NotFound)?;
    // The ciphertext is useless without the fragment, but there's no reason
    // for any cache to keep it.
    let no_store = [(CACHE_CONTROL, HeaderValue::from_static("no-store"))];
    Ok((no_store, Json(link)).into_response())
}

fn is_link_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[utoipa::path(
    get, path = "/v1/share-links", tag = "share-links",
    security(("bearer" = [])),
    responses(
        (status = 200, body = ShareLinksResponse, description = "The account's links that can still be viewed, newest first"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<ShareLinksResponse>> {
    let links = share_links::list(&state.db, &session.account_id, state.clock.now()).await?;
    Ok(Json(ShareLinksResponse { links }))
}

#[utoipa::path(
    delete, path = "/v1/share-links/{id}", tag = "share-links",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such link of this account"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    if is_link_id(&id) && share_links::delete(&state.db, &id, &session.account_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_ids_are_22_base64url_characters() {
        assert!(is_link_id(&base64url(random_bytes::<16>())));
        assert!(!is_link_id("short"));
        assert!(!is_link_id("aaaaaaaaaaaaaaaaaaaaa="));
        assert!(!is_link_id("../../../../etc/passwd!"));
    }
}
