//! The account's signed-in devices: list, rename, remote sign-out.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use octapass_api::problem::Problem;
use octapass_api::{DeviceRecord, PushPlatform, PushTokenRequest, RenameDeviceRequest};

use crate::db::{self, sessions};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated};
use crate::state::AppState;
use crate::validate;

#[utoipa::path(
    get, path = "/v1/devices", tag = "devices",
    security(("bearer" = [])),
    responses(
        (status = 200, body = Vec<DeviceRecord>, description = "Signed-in devices, most recently seen first"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list_devices(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<Vec<DeviceRecord>>> {
    let devices = sessions::devices(
        &state.db,
        &session.account_id,
        &session.device_id,
        db::now(),
    )
    .await?;
    Ok(Json(devices))
}

#[utoipa::path(
    patch, path = "/v1/devices/current", tag = "devices",
    security(("bearer" = [])),
    request_body = RenameDeviceRequest,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn rename_current_device(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<RenameDeviceRequest>,
) -> ApiResult<StatusCode> {
    let name = validate::text("name", &request.name, 64)?;
    sessions::rename_device(&state.db, &session.device_id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/devices/{deviceId}", tag = "devices",
    security(("bearer" = [])),
    params(("deviceId" = String, Path)),
    responses(
        (status = 204, description = "The device was signed out and its live connections got session-revoked. \
            Deleting the current device is a sign-out."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such signed-in device on this account"),
    )
)]
pub async fn delete_device(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(device_id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    let device_id = validate::id("deviceId", &device_id)?;
    if state.revoke_device(&session.account_id, &device_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

/// The longest push token accepted. APNs tokens are 64 hex characters today and FCM tokens about
/// 160; both may grow.
const MAX_PUSH_TOKEN: usize = 4096;

#[utoipa::path(
    put, path = "/v1/devices/current/push", tag = "devices",
    security(("bearer" = [])),
    request_body = PushTokenRequest,
    responses(
        (status = 204, description = "Saved. When something this account can see changes, the server asks the \
            push relay to wake this device with `sync` or `alert`, and nothing more. A token another device had \
            moves to this one."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "`push-off`: this server sends no pushes"),
    )
)]
pub async fn put_push_token(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<PushTokenRequest>,
) -> ApiResult<StatusCode> {
    if state.push.is_none() {
        return Err(ApiError::PushOff);
    }
    let token = request.token.trim();
    let well_formed = !token.is_empty()
        && token.len() <= MAX_PUSH_TOKEN
        && match request.platform {
            PushPlatform::Apns => token.bytes().all(|b| b.is_ascii_hexdigit()),
            PushPlatform::Fcm => token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':')),
        };
    if !well_formed {
        return Err(ApiError::BadRequest("token isn't a push token".into()));
    }
    let (platform, token, sandbox) = match request.platform {
        PushPlatform::Apns => ("apns", token.to_ascii_lowercase(), request.sandbox),
        PushPlatform::Fcm => ("fcm", token.to_owned(), false),
    };
    let mut tx = state.db.begin().await?;
    db::push::set_token(
        &mut tx,
        &session.account_id,
        &session.device_id,
        platform,
        &token,
        sandbox,
        db::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/devices/current/push", tag = "devices",
    security(("bearer" = [])),
    responses(
        (status = 204, description = "This device gets no more pushes"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "`push-off`"),
    )
)]
pub async fn delete_push_token(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<StatusCode> {
    if state.push.is_none() {
        return Err(ApiError::PushOff);
    }
    db::push::delete_device_token(&state.db, &session.device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
