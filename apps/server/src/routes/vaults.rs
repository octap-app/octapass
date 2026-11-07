//! Sync and item writes. Item contents are ciphertext the server can't read.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::header::{ETAG, IF_MATCH, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{ItemHistoryResponse, PutItemRequest, RevisionResponse, SyncResponse};
use serde::Deserialize;

use crate::db;
use crate::db::items::{self, ItemWrite, Precondition, WriteError};
use crate::db::sessions::Session;
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, Authenticated};
use crate::state::AppState;
use crate::validate;

pub const MAX_ITEM_KEY: usize = 1024;
const MAX_OVERVIEW: usize = 64 * 1024;
const MAX_DETAILS: usize = 512 * 1024;
const MAX_SINCE_ENTRIES: usize = 1000;

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SyncQuery {
    /// Comma-separated `<vaultId>:<revision>` pairs from the last sync. Vaults
    /// left out are returned in full.
    pub since: Option<String>,
}

#[utoipa::path(
    get, path = "/v1/sync", tag = "sync",
    security(("bearer" = [])),
    params(SyncQuery),
    responses(
        (status = 200, body = SyncResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "unauthorized, or account-deleted"),
    )
)]
pub async fn sync(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiQuery(query): ApiQuery<SyncQuery>,
) -> ApiResult<Json<SyncResponse>> {
    let since = parse_since(query.since.as_deref().unwrap_or(""))?;
    Ok(Json(
        items::sync(
            &state.db,
            &session.account_id,
            &since,
            None,
            false,
            items::PAGE,
        )
        .await?,
    ))
}

pub fn parse_since(raw: &str) -> ApiResult<HashMap<String, u64>> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.len() > MAX_SINCE_ENTRIES {
        return Err(ApiError::BadRequest("since has too many entries".into()));
    }
    entries
        .into_iter()
        .map(|entry| {
            entry
                .rsplit_once(':')
                .and_then(|(vault_id, revision)| {
                    Some((vault_id.to_owned(), revision.parse().ok()?))
                })
                .ok_or_else(|| {
                    ApiError::BadRequest(format!(
                        "since entry {entry:?} must be <vaultId>:<revision>"
                    ))
                })
        })
        .collect()
}

pub fn precondition(headers: &HeaderMap) -> ApiResult<Precondition> {
    match (headers.get(IF_MATCH), headers.get(IF_NONE_MATCH)) {
        (Some(_), Some(_)) => Err(ApiError::BadRequest(
            "send either If-Match or If-None-Match, not both".into(),
        )),
        (None, Some(value)) if value == "*" => Ok(Precondition::Create),
        (None, Some(_)) => Err(ApiError::BadRequest("If-None-Match must be *".into())),
        (Some(value), None) => Ok(Precondition::Revision(parse_revision_tag(value)?)),
        (None, None) => Err(ApiError::PreconditionRequired),
    }
}

/// Parses an `If-Match` value: a revision number as an entity tag, `"41"`.
fn parse_revision_tag(value: &HeaderValue) -> ApiResult<u64> {
    value
        .to_str()
        .ok()
        .map(str::trim)
        .and_then(|tag| tag.strip_prefix('"')?.strip_suffix('"'))
        .and_then(|revision| revision.parse().ok())
        .ok_or_else(|| {
            ApiError::BadRequest("If-Match must be a quoted revision, like \"41\"".into())
        })
}

fn ids(vault_id: &str, item_id: &str) -> ApiResult<()> {
    validate::id("vaultId", vault_id)?;
    validate::id("itemId", item_id)?;
    Ok(())
}

pub fn validate_item(body: &PutItemRequest) -> ApiResult<()> {
    validate::envelope("encryptedItemKey", &body.encrypted_item_key, MAX_ITEM_KEY)?;
    validate::envelope("overview", &body.overview, MAX_OVERVIEW)?;
    validate::envelope("details", &body.details, MAX_DETAILS)
}

/// Applies the write, tells live connections about it and answers with the
/// item's revision.
async fn write_item(
    state: &AppState,
    session: &Session,
    vault_id: &str,
    item_id: &str,
    write: ItemWrite<'_>,
) -> ApiResult<Response> {
    let written = items::write(
        &state.db,
        &session.account_id,
        vault_id,
        item_id,
        write,
        state.config.quota,
        db::now(),
    )
    .await?;
    if written.changed {
        state.vault_changed(vault_id, written.revision).await;
    }
    Ok(revision_response(written.revision))
}

pub fn revision_response(revision: u64) -> Response {
    let etag =
        HeaderValue::from_str(&format!("\"{revision}\"")).expect("digits are a valid header value");
    ([(ETAG, etag)], Json(RevisionResponse { revision })).into_response()
}

impl From<WriteError> for ApiError {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::NotFound => ApiError::NotFound,
            WriteError::ReadOnly => ApiError::Forbidden,
            WriteError::StaleVaultKey => ApiError::VaultKeyChanged(
                "this item key was wrapped under an old vault key: sync and encrypt it again",
            ),
            WriteError::Conflict(current) => ApiError::Conflict(current),
            WriteError::QuotaExceeded => ApiError::QuotaExceeded,
            WriteError::Db(error) => error.into(),
        }
    }
}

#[utoipa::path(
    put, path = "/v1/vaults/{vaultId}/items/{itemId}", tag = "sync",
    security(("bearer" = [])),
    params(
        ("vaultId" = String, Path), ("itemId" = String, Path),
        ("If-Match" = Option<String>, Header, description = "Quoted current revision, to update"),
        ("If-None-Match" = Option<String>, Header, description = "`*`, to create"),
    ),
    request_body = PutItemRequest,
    responses(
        (status = 200, body = RevisionResponse, headers(("ETag" = String))),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Read-only vault, or quota-exceeded"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "conflict; `current` holds the server's ItemRecord"),
        (status = 428, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn put_item(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id)): ApiPath<(String, String)>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PutItemRequest>,
) -> ApiResult<Response> {
    ids(&vault_id, &item_id)?;
    let precondition = precondition(&headers)?;
    validate_item(&body)?;
    let write = ItemWrite::Put(precondition, &body);
    write_item(&state, &session, &vault_id, &item_id, write).await
}

#[utoipa::path(
    delete, path = "/v1/vaults/{vaultId}/items/{itemId}", tag = "sync",
    security(("bearer" = [])),
    params(
        ("vaultId" = String, Path), ("itemId" = String, Path),
        ("If-Match" = String, Header, description = "Quoted current revision"),
    ),
    responses(
        (status = 200, body = RevisionResponse, description = "Moved to the trash"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 428, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_item(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id)): ApiPath<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    ids(&vault_id, &item_id)?;
    let expected = parse_revision_tag(
        headers
            .get(IF_MATCH)
            .ok_or(ApiError::PreconditionRequired)?,
    )?;
    let write = ItemWrite::Delete(Some(expected));
    write_item(&state, &session, &vault_id, &item_id, write).await
}

#[utoipa::path(
    post, path = "/v1/vaults/{vaultId}/items/{itemId}/restore", tag = "sync",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("itemId" = String, Path)),
    responses(
        (status = 200, body = RevisionResponse, description = "Restored from the trash"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn restore_item(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id)): ApiPath<(String, String)>,
) -> ApiResult<Response> {
    ids(&vault_id, &item_id)?;
    write_item(&state, &session, &vault_id, &item_id, ItemWrite::Restore).await
}

#[utoipa::path(
    get, path = "/v1/vaults/{vaultId}/items/{itemId}/history", tag = "sync",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("itemId" = String, Path)),
    responses(
        (status = 200, body = ItemHistoryResponse, description = "The item's last 10 past versions, newest first, as ciphertext"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn item_history(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, item_id)): ApiPath<(String, String)>,
) -> ApiResult<Json<ItemHistoryResponse>> {
    ids(&vault_id, &item_id)?;
    let revisions = items::history(&state.db, &session.account_id, &vault_id, &item_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(ItemHistoryResponse { revisions }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since() {
        let since = parse_since("a:3, b:0,").unwrap();
        assert_eq!(since.get("a"), Some(&3));
        assert_eq!(since.get("b"), Some(&0));
        assert!(parse_since("").unwrap().is_empty());
        assert!(parse_since("a").is_err());
        assert!(parse_since("a:-1").is_err());
    }

    #[test]
    fn parses_preconditions() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            precondition(&headers),
            Err(ApiError::PreconditionRequired)
        ));
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(matches!(precondition(&headers), Ok(Precondition::Create)));
        headers.insert(IF_MATCH, HeaderValue::from_static("\"4\""));
        assert!(precondition(&headers).is_err());
        headers.remove(IF_NONE_MATCH);
        assert!(matches!(
            precondition(&headers),
            Ok(Precondition::Revision(4))
        ));
        headers.insert(IF_MATCH, HeaderValue::from_static("4"));
        assert!(precondition(&headers).is_err());
    }
}
