//! `GET /v1/health/data`: the health report's signed site lists (plan 06). Public: it's the
//! same file for everyone, and clients check its signature themselves.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::state::AppState;

#[utoipa::path(
    get, path = "/v1/health/data", tag = "meta",
    responses((
        status = 200, content_type = "application/json",
        description = "`{ payload, signature }`: the payload in base64, signed with the project's Ed25519 key over \
                       `openpass/v1/health-data ‖ 0x00 ‖ payload`. The newest file this server has: its bundled \
                       copy, or a newer one from `OCTAPASS_HEALTH_DATA_URL`.",
    ))
)]
pub async fn file(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.health_data.file().to_string(),
    )
}
