//! `POST /v1/health/breach-email`: email breach alerts, opt-in on the client.

use axum::Json;
use axum::extract::State;
use octapass_api::problem::Problem;
use octapass_api::{BreachEmailRequest, BreachEmailResponse};

use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, Authenticated};
use crate::state::AppState;
use crate::validate;

#[utoipa::path(
    post, path = "/v1/health/breach-email", tag = "meta",
    security(("bearer" = [])),
    request_body = BreachEmailRequest,
    responses(
        (status = 200, body = BreachEmailResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "This server has no HIBP key"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "Per account, or the server's HIBP limit"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "HIBP didn't answer"),
    )
)]
pub async fn lookup(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<BreachEmailRequest>,
) -> ApiResult<Json<BreachEmailResponse>> {
    let client = state.breach_client.as_ref().ok_or(ApiError::NotFound)?;
    let email = validate::email(&request.email)?;
    state
        .breach_email_limiter
        .check(&session.account_id)
        .map_err(ApiError::RateLimited)?;
    Ok(Json(BreachEmailResponse {
        breaches: client.lookup(&email).await?,
    }))
}
