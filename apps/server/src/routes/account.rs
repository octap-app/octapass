//! The signed-in account.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use octapass_api::problem::Problem;
use octapass_api::{
    AccountBundle, ConnectEventsRequest, DeleteAccountRequest, ExportFormat, REAUTH_TOKEN_HEADER,
    SecurityLogResponse, UsageResponse, VaultExportedRequest,
};

use crate::account_deletion::{self, Authorization};
use crate::db::{self, accounts, attachments, audit};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, Authenticated};
use crate::state::AppState;
use crate::validate;

const MAX_CONNECT_EVENTS: usize = 100;
const MAX_CONNECT_DETAIL: usize = 2048;

#[utoipa::path(
    get, path = "/v1/account", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, body = AccountBundle),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_account(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<AccountBundle>> {
    let account = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    Ok(Json(account.into_bundle()))
}

#[utoipa::path(
    delete, path = "/v1/account", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose delete-account")),
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "The account and everything linked to it were deleted"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "confirmEmail doesn't match"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn delete_account(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiJson(request): ApiJson<DeleteAccountRequest>,
) -> ApiResult<StatusCode> {
    let reauth_token = headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::ReauthRequired)?;
    let authorization = Authorization::User {
        reauth_token: reauth_token.trim(),
        confirm_email: &request.confirm_email,
    };
    account_deletion::delete_account(&state, &session.account_id, authorization).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/account/usage", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, body = UsageResponse, description = "What the vaults the account owns hold, and the limits"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn usage(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<UsageResponse>> {
    let (items, item_bytes, attachment_bytes) =
        attachments::account_usage(&state.db, &session.account_id).await?;
    let config = &state.config;
    Ok(Json(UsageResponse {
        items,
        max_items: config.quota.items,
        item_bytes,
        max_item_bytes: config.quota.bytes,
        attachment_bytes,
        max_attachment_bytes: config.attachments.quota_bytes,
        max_file_bytes: config.attachments.max_file_bytes,
    }))
}

#[utoipa::path(
    get, path = "/v1/security-log", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, body = SecurityLogResponse, description = "The account's own security log, newest first (kept a year)"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn security_log(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<SecurityLogResponse>> {
    let events = audit::list(&state.db, &session.account_id).await?;
    Ok(Json(SecurityLogResponse { events }))
}

#[utoipa::path(
    post, path = "/v1/security-log/connect", tag = "account",
    security(("bearer" = [])),
    request_body = ConnectEventsRequest,
    responses(
        (status = 204, description = "One `connect-secret-read` entry per blob. The server can't read them."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Over 100 blobs, or one isn't an envelope"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn connect_events(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<ConnectEventsRequest>,
) -> ApiResult<StatusCode> {
    if request.sealed_details.len() > MAX_CONNECT_EVENTS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_CONNECT_EVENTS} entries in one request"
        )));
    }
    for (i, sealed) in request.sealed_details.iter().enumerate() {
        validate::envelope(&format!("sealedDetails[{i}]"), sealed, MAX_CONNECT_DETAIL)?;
    }
    state
        .connect_log_limiter
        .check(&session.account_id)
        .map_err(ApiError::RateLimited)?;
    let mut tx = state.db.begin().await?;
    audit::record_connect(
        &mut tx,
        &session.account_id,
        &request.sealed_details,
        db::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/security-log/exports", tag = "account",
    security(("bearer" = [])),
    request_body = VaultExportedRequest,
    responses(
        (status = 204, description = "A \"vault exported\" entry naming this device was added to the security log"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Only the encrypted export holds attachments"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn vault_exported(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<VaultExportedRequest>,
) -> ApiResult<StatusCode> {
    if request.attachments && request.format != ExportFormat::Encrypted {
        return Err(ApiError::BadRequest(
            "only the encrypted export holds attachments".into(),
        ));
    }
    audit::record_export(
        &state.db,
        &session.account_id,
        &session.device_id,
        request.format,
        request.attachments,
        state.clock.now(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
