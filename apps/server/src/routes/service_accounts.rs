//! Service accounts: non-human access to one shared vault (plan 03, "Non-human access").
//!
//! People make, list and revoke them with their own sessions. A service account signs in by
//! signing a single-use challenge with a key derived from its token, which never reaches the
//! server, and then fetches ciphertext it decrypts itself.

use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ed25519_dalek::{Signature, VerifyingKey};
use octapass_api::problem::Problem;
use octapass_api::{
    CreateServiceAccountRequest, Grant, PutItemRequest, SecurityEventType,
    ServiceAccountChallengeRequest, ServiceAccountChallengeResponse, ServiceAccountRecord,
    ServiceAccountSessionRequest, ServiceAccountSessionResponse, ServiceAccountsResponse,
    SyncResponse, VaultRole,
};

use super::auth::charge;
use super::sharing::{current_key, own_grant, public_sign_key, validate_key_id};
use super::vaults::{SyncQuery, parse_since, precondition, revision_response, validate_item};
use crate::crypto::{base64url, random_bytes, random_token};
use crate::db::items::{self, ItemWrite};
use crate::db::service_accounts::{self, ServiceAccountRow, allowed_role};
use crate::db::{audit, sharing};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, Authenticated, ClientIp};
use crate::state::AppState;
use crate::validate;

const AUTH_LABEL: &[u8] = b"octapass/v1/service-account-auth\0";
const MAX_NAME: usize = 1024;
const PUBLIC_KEY_LEN: usize = 32;
const SESSION_MS: i64 = 15 * 60 * 1000;
const CHALLENGE_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// The vault and its caller's role, for managers only.
async fn manage(
    state: &AppState,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<sharing::Membership> {
    let mut conn = state.db.acquire().await?;
    let mine = sharing::membership(&mut conn, vault_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if mine.role < VaultRole::Manage {
        return Err(ApiError::Forbidden);
    }
    Ok(mine)
}

fn validate_create(
    request: &CreateServiceAccountRequest,
    vault_id: &str,
    me: &str,
) -> ApiResult<()> {
    validate::id("id", &request.id)?;
    validate::exact_bytes("publicEncKey", &request.public_enc_key, PUBLIC_KEY_LEN)?;
    validate::exact_bytes("publicSignKey", &request.public_sign_key, PUBLIC_KEY_LEN)?;
    validate::envelope("encryptedName", &request.encrypted_name, MAX_NAME)?;
    validate_key_id(Some(&request.key_id))?;
    own_grant("grant", &request.grant, vault_id, me)?;
    if request.grant.recipient_account_id != request.id {
        return Err(ApiError::BadRequest(
            "grant.recipientAccountId must be the service account's id".into(),
        ));
    }
    if !allowed_role(request.grant.role) {
        return Err(ApiError::BadRequest(
            "a service account's role is read or write".into(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    post, path = "/v1/vaults/{vaultId}/service-accounts", tag = "service-accounts",
    security(("bearer" = [])),
    params(("vaultId" = String, Path)),
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, body = ServiceAccountRecord),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Shared vaults only, read or write only, or a bad field"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-key-changed: sync and make it again"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(vault_id): ApiPath<String>,
    ApiJson(request): ApiJson<CreateServiceAccountRequest>,
) -> ApiResult<(StatusCode, Json<ServiceAccountRecord>)> {
    let me = session.account_id.as_str();
    let vault_id = validate::id("vaultId", &vault_id)?;
    validate_create(&request, &vault_id, me)?;
    let now = state.clock.now();
    let expires_at = request
        .expires_at
        .as_deref()
        .map(|value| validate::timestamp("expiresAt", value))
        .transpose()?;
    if expires_at.is_some_and(|at| at <= now) {
        return Err(ApiError::BadRequest("expiresAt is in the past".into()));
    }
    let sign_key = public_sign_key(&state, me).await?;
    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &vault_id).await?;
    let mine = sharing::membership(&mut tx, &vault_id, me)
        .await?
        .ok_or(ApiError::NotFound)?;
    if mine.vault_type != "shared" {
        return Err(ApiError::BadRequest(
            "service accounts read shared vaults only: a personal vault's key can't be rotated"
                .into(),
        ));
    }
    if mine.role < VaultRole::Manage {
        return Err(ApiError::Forbidden);
    }
    current_key(&mut tx, &vault_id, Some(&request.key_id)).await?;
    service_accounts::insert(&mut tx, &request, expires_at, me, &sign_key, now).await?;
    audit::record_service_account(
        &mut *tx,
        me,
        SecurityEventType::ServiceAccountCreated,
        &request.id,
        now,
    )
    .await?;
    tx.commit().await?;
    let row = service_accounts::find(&state.db, &request.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::CREATED, Json(row.into_record())))
}

#[utoipa::path(
    get, path = "/v1/vaults/{vaultId}/service-accounts", tag = "service-accounts",
    security(("bearer" = [])),
    params(("vaultId" = String, Path)),
    responses(
        (status = 200, body = ServiceAccountsResponse, description = "Revoked ones too, so the log can name them"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(vault_id): ApiPath<String>,
) -> ApiResult<Json<ServiceAccountsResponse>> {
    let vault_id = validate::id("vaultId", &vault_id)?;
    manage(&state, &vault_id, &session.account_id).await?;
    let service_accounts = service_accounts::list(&state.db, &vault_id)
        .await?
        .into_iter()
        .map(ServiceAccountRow::into_record)
        .collect();
    Ok(Json(ServiceAccountsResponse { service_accounts }))
}

#[utoipa::path(
    delete, path = "/v1/vaults/{vaultId}/service-accounts/{serviceAccountId}", tag = "service-accounts",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("serviceAccountId" = String, Path)),
    responses(
        (status = 204, description = "Revoked: its sessions are gone and it can't sign in. Rotate the vault key next (`POST /v1/vaults/{vaultId}/rotate`)."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let vault_id = validate::id("vaultId", &vault_id)?;
    let id = validate::id("serviceAccountId", &id)?;
    manage(&state, &vault_id, me).await?;
    let row = service_accounts::find(&state.db, &id)
        .await?
        .filter(|row| row.vault_id == vault_id)
        .ok_or(ApiError::NotFound)?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    if service_accounts::revoke(&mut tx, &id, now).await? {
        let event = SecurityEventType::ServiceAccountRevoked;
        audit::record_service_account(&mut *tx, &row.created_by, event, &id, now).await?;
        if row.created_by != me {
            audit::record_service_account(&mut *tx, me, event, &id, now).await?;
        }
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/service-accounts/challenge", tag = "service-accounts",
    request_body = ServiceAccountChallengeRequest,
    responses(
        (status = 200, body = ServiceAccountChallengeResponse, description = "The same answer whether or not the id exists"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn challenge(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<ServiceAccountChallengeRequest>,
) -> ApiResult<Json<ServiceAccountChallengeResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let id = validate::id("serviceAccountId", &request.service_account_id)?;
    let challenge = base64url(random_bytes::<CHALLENGE_LEN>());
    state
        .pending_service_challenges
        .insert(challenge.clone(), &ip, id);
    Ok(Json(ServiceAccountChallengeResponse { challenge }))
}

fn signature_ok(public_sign_key: &str, id: &str, challenge: &str, signature: &[u8]) -> bool {
    let Ok(key) = validate::exact_bytes("key", public_sign_key, PUBLIC_KEY_LEN) else {
        return false;
    };
    let (Ok(key), Ok(signature)) = (
        <[u8; PUBLIC_KEY_LEN]>::try_from(key.as_slice()),
        <[u8; SIGNATURE_LEN]>::try_from(signature),
    ) else {
        return false;
    };
    let mut message = AUTH_LABEL.to_vec();
    for field in [id, challenge] {
        let len = u32::try_from(field.len()).expect("auth fields are short");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    // Strict verification also rejects small-order keys and non-canonical signatures.
    VerifyingKey::from_bytes(&key).is_ok_and(|key| {
        key.verify_strict(&message, &Signature::from_bytes(&signature))
            .is_ok()
    })
}

#[utoipa::path(
    post, path = "/v1/service-accounts/session", tag = "service-accounts",
    request_body = ServiceAccountSessionRequest,
    responses(
        (status = 200, body = ServiceAccountSessionResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "Wrong signature, used challenge, unknown id, revoked or expired"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn session(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<ServiceAccountSessionRequest>,
) -> ApiResult<Json<ServiceAccountSessionResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let id = validate::id("serviceAccountId", &request.service_account_id)?;
    let signature = validate::exact_bytes("signature", &request.signature, SIGNATURE_LEN)?;
    // Taken first, so a challenge can't be tried twice whatever happens next.
    let challenged = state
        .pending_service_challenges
        .take(&request.challenge)
        .ok_or(ApiError::Unauthorized)?;
    if challenged != id {
        return Err(ApiError::Unauthorized);
    }
    let row = service_accounts::find(&state.db, &id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if !signature_ok(&row.public_sign_key, &id, &request.challenge, &signature) {
        return Err(ApiError::Unauthorized);
    }
    let now = state.clock.now();
    if !row.is_active(now) {
        // Only a real token gets here: someone is still using one that was taken back.
        let event = SecurityEventType::ServiceAccountDenied;
        audit::record_service_account(&state.db, &row.created_by, event, &id, now).await?;
        return Err(ApiError::Unauthorized);
    }
    let access_token = random_token();
    let expires_at = row
        .expires_at
        .map_or(now + SESSION_MS, |at| at.min(now + SESSION_MS));
    service_accounts::insert_session(&state.db, &access_token, &id, expires_at).await?;
    Ok(Json(ServiceAccountSessionResponse {
        access_token,
        expires_in: u64::try_from((expires_at - now) / 1000).unwrap_or(0),
    }))
}

/// A service account's valid access token. People's tokens aren't accepted here, and these aren't
/// accepted anywhere else.
pub struct ServiceAccount(pub ServiceAccountRow);

impl FromRequestParts<AppState> for ServiceAccount {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        service_accounts::find_by_token(&state.db, token.trim(), state.clock.now())
            .await?
            .map(ServiceAccount)
            .ok_or(ApiError::Unauthorized)
    }
}

#[utoipa::path(
    get, path = "/v1/service-accounts/sync", tag = "service-accounts",
    security(("bearer" = [])),
    params(SyncQuery),
    responses(
        (status = 200, body = SyncResponse, description = "The service account's one vault, with its grant. Each first page is logged."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn sync(
    State(state): State<AppState>,
    ServiceAccount(account): ServiceAccount,
    ApiQuery(query): ApiQuery<SyncQuery>,
) -> ApiResult<Json<SyncResponse>> {
    let since = parse_since(query.since.as_deref().unwrap_or(""))?;
    let now = state.clock.now();
    // A fetch that continues an earlier page is the same read.
    if since.is_empty() {
        let event = SecurityEventType::ServiceAccountRead;
        audit::record_service_account(&state.db, &account.created_by, event, &account.id, now)
            .await?;
    }
    service_accounts::touch(&state.db, &account.id, now).await?;
    Ok(Json(
        items::sync_service_account(&state.db, &account.id, &since, items::PAGE).await?,
    ))
}

#[utoipa::path(
    put, path = "/v1/service-accounts/items/{itemId}", tag = "service-accounts",
    security(("bearer" = [])),
    params(
        ("itemId" = String, Path),
        ("If-Match" = Option<String>, Header, description = "Quoted current revision, to update"),
        ("If-None-Match" = Option<String>, Header, description = "`*`, to create"),
    ),
    request_body = PutItemRequest,
    responses(
        (status = 200, body = octapass_api::RevisionResponse, headers(("ETag" = String))),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Read-only service account, or quota-exceeded"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "conflict; `current` holds the server's ItemRecord"),
        (status = 428, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn put_item(
    State(state): State<AppState>,
    ServiceAccount(account): ServiceAccount,
    ApiPath(item_id): ApiPath<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PutItemRequest>,
) -> ApiResult<Response> {
    validate::id("itemId", &item_id)?;
    let precondition = precondition(&headers)?;
    validate_item(&body)?;
    let now = state.clock.now();
    let written = items::write_as_service_account(
        &state.db,
        &account.id,
        &account.vault_id,
        &item_id,
        ItemWrite::Put(precondition, &body),
        state.config.quota,
        now,
    )
    .await?;
    let event = SecurityEventType::ServiceAccountWrote;
    audit::record_service_account(&state.db, &account.created_by, event, &account.id, now).await?;
    if written.changed {
        state
            .vault_changed(&account.vault_id, written.revision)
            .await;
    }
    Ok(revision_response(written.revision).into_response())
}

/// Fails a rotation's service grant that isn't for an active service account with its role.
pub fn check_service_grant(active: &[(String, String)], grant: &Grant) -> Result<(), String> {
    let role = active
        .iter()
        .find(|(id, _)| *id == grant.recipient_account_id)
        .map(|(_, role)| items::parse_role(role));
    if role != Some(grant.role) {
        return Err(
            "every service grant must be for an active service account, with its role".into(),
        );
    }
    Ok(())
}
