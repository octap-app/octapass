//! Health, server info and the OpenAPI document.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use octapass_api::problem::Problem;
use octapass_api::{API_VERSION, ServerInfo};
use utoipa::OpenApi;

use crate::error::{ApiError, ApiResult};
use crate::openapi::ApiDoc;
use crate::state::AppState;

#[utoipa::path(get, path = "/healthz", tag = "meta", responses((status = 200, description = "The process is up")))]
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(
    get, path = "/readyz", tag = "meta",
    responses(
        (status = 200, description = "The database and attachment storage are reachable"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn readyz(State(state): State<AppState>) -> ApiResult<StatusCode> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if let Err(error) = state.storage.check().await {
        tracing::warn!(%error, "attachment storage unreachable");
        return Err(ApiError::Unavailable);
    }
    Ok(StatusCode::OK)
}

#[utoipa::path(get, path = "/v1/server-info", tag = "meta", responses((status = 200, body = ServerInfo)))]
pub async fn server_info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "Octa Pass".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        api_version: API_VERSION,
        signups: state.config.signups,
        // True once the server is registered with its relay, so a phone's token can be used.
        push_relay: state.push.as_ref().is_some_and(|push| push.ready()),
        masked_email_relay: state.relay.is_some(),
        email_breach_checks: state.breach_client.is_some(),
    })
}

#[utoipa::path(get, path = "/v1/openapi.json", tag = "meta", responses((status = 200, description = "This OpenAPI 3.1 document")))]
pub async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
