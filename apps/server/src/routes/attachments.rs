//! Attachments: encrypted files kept with items. The server stores each file's
//! ciphertext and size; its name, type and key are in the item's encrypted
//! details, so the server can't tell what a file is.

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{AttachmentRecord, AttachmentsResponse};

use crate::db;
use crate::db::attachments::{AttachmentError, NewAttachment};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiPath, Authenticated};
use crate::state::AppState;
use crate::storage::{self, SpoolError};
use crate::validate;

/// `header (36) ‖ tag (16)`: an encrypted empty file, the smallest there is.
const MIN_FILE_LEN: u64 = 52;
const FILE_VERSION: u8 = 0x01;

impl From<AttachmentError> for ApiError {
    fn from(error: AttachmentError) -> Self {
        match error {
            AttachmentError::NotFound => ApiError::NotFound,
            AttachmentError::ReadOnly => ApiError::Forbidden,
            AttachmentError::Exists => {
                ApiError::AlreadyExists("an attachment with this id already exists")
            }
            AttachmentError::QuotaExceeded => ApiError::QuotaExceeded,
            AttachmentError::Db(error) => error.into(),
        }
    }
}

impl From<SpoolError> for ApiError {
    fn from(error: SpoolError) -> Self {
        match error {
            SpoolError::Io(error) => ApiError::internal(error),
            other => ApiError::BadRequest(other.to_string()),
        }
    }
}

fn storage_unavailable(error: storage::StorageError) -> ApiError {
    tracing::error!(%error, "attachment storage failed");
    ApiError::Unavailable
}

fn ids(vault_id: &str, item_id: &str, attachment_id: Option<&str>) -> ApiResult<()> {
    validate::id("vaultId", vault_id)?;
    validate::id("itemId", item_id)?;
    if let Some(id) = attachment_id {
        validate::id("attachmentId", id)?;
    }
    Ok(())
}

#[utoipa::path(
    put, path = "/v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}", tag = "attachments",
    security(("bearer" = [])),
    params(
        ("vaultId" = String, Path), ("itemId" = String, Path), ("attachmentId" = String, Path),
        ("Content-Length" = u64, Header, description = "Required: the encrypted file's size"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The encrypted file"),
    responses(
        (status = 201, body = AttachmentRecord),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Not an encrypted attachment, or the body didn't match Content-Length"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Read-only vault, or quota-exceeded"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such vault or item, or the item is in the trash"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists"),
        (status = 411, body = Problem, content_type = "application/problem+json", description = "length-required"),
        (status = 413, body = Problem, content_type = "application/problem+json", description = "Larger than the server's file size limit"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "Storage unreachable"),
    )
)]
pub async fn upload(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id, attachment_id)): ApiPath<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    ids(&vault_id, &item_id, Some(&attachment_id))?;
    let len: u64 = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse().ok())
        .ok_or(ApiError::LengthRequired)?;
    let limits = &state.config.attachments;
    if len > limits.max_file_bytes {
        return Err(ApiError::PayloadTooLarge);
    }
    if len < MIN_FILE_LEN {
        return Err(ApiError::BadRequest(
            "the body must be an encrypted attachment".into(),
        ));
    }
    let new = NewAttachment {
        vault_id: &vault_id,
        item_id: &item_id,
        id: &attachment_id,
        size: len,
    };
    let account_id = &session.account_id;
    db::attachments::check_upload(&state.db, account_id, &new, limits.quota_bytes).await?;

    let upload = storage::spool(&state.uploads_dir, body, len).await?;
    if upload.first_byte != Some(FILE_VERSION) {
        return Err(ApiError::BadRequest(
            "the body must be an encrypted attachment".into(),
        ));
    }
    let object_key = storage::new_object_key();
    state
        .storage
        .put(&object_key, upload)
        .await
        .map_err(storage_unavailable)?;
    let now = db::now();
    match db::attachments::insert(
        &state.db,
        account_id,
        &new,
        &object_key,
        limits.quota_bytes,
        now,
    )
    .await
    {
        Ok(record) => Ok((StatusCode::CREATED, Json(record)).into_response()),
        Err(error) => {
            // Refused after all (a race with another upload or a removal): the
            // stored file has no record, so it goes.
            let mut conn = state.db.acquire().await?;
            db::attachments::queue_deletion(&mut conn, &object_key, now).await?;
            storage::drain_soon(&state);
            Err(error.into())
        }
    }
}

#[utoipa::path(
    get, path = "/v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}", tag = "attachments",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("itemId" = String, Path), ("attachmentId" = String, Path)),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/octet-stream", description = "The encrypted file"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "Storage unreachable"),
    )
)]
pub async fn download(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id, attachment_id)): ApiPath<(String, String, String)>,
) -> ApiResult<Response> {
    send_file(
        &state,
        &session.account_id,
        &vault_id,
        &item_id,
        &attachment_id,
    )
    .await
}

/// The encrypted file, if `account_id` is a member of its vault.
pub async fn send_file(
    state: &AppState,
    account_id: &str,
    vault_id: &str,
    item_id: &str,
    attachment_id: &str,
) -> ApiResult<Response> {
    ids(vault_id, item_id, Some(attachment_id))?;
    let (object_key, _) =
        db::attachments::find(&state.db, account_id, vault_id, item_id, attachment_id).await?;
    let object = state
        .storage
        .get(&object_key)
        .await
        .map_err(storage_unavailable)?
        .ok_or_else(|| {
            tracing::error!("an attachment's file is missing from storage");
            ApiError::NotFound
        })?;
    let headers = [
        (
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        ),
        (CONTENT_LENGTH, HeaderValue::from(object.len)),
    ];
    Ok((headers, object.body).into_response())
}

#[utoipa::path(
    delete, path = "/v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}", tag = "attachments",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("itemId" = String, Path), ("attachmentId" = String, Path)),
    responses(
        (status = 204, description = "Deleted; the file is removed from storage shortly"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Read-only vault"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id, attachment_id)): ApiPath<(String, String, String)>,
) -> ApiResult<StatusCode> {
    ids(&vault_id, &item_id, Some(&attachment_id))?;
    db::attachments::delete(
        &state.db,
        &session.account_id,
        &vault_id,
        &item_id,
        &attachment_id,
        db::now(),
    )
    .await?;
    storage::drain_soon(&state);
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/vaults/{vaultId}/items/{itemId}/attachments", tag = "attachments",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("itemId" = String, Path)),
    responses(
        (status = 200, body = AttachmentsResponse, description = "The item's attachments, oldest first"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id)): ApiPath<(String, String)>,
) -> ApiResult<Json<AttachmentsResponse>> {
    ids(&vault_id, &item_id, None)?;
    let attachments =
        db::attachments::list(&state.db, &session.account_id, &vault_id, &item_id).await?;
    Ok(Json(AttachmentsResponse { attachments }))
}
