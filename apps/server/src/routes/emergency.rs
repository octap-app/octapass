//! Emergency access. The grantor stores a key sealed to a trusted contact;
//! the contact can request it; unless the grantor denies the request within
//! the waiting period (1–30 days), the server releases the sealed key, and
//! with it read access to the vaults in scope. Every step is in the grantor's
//! security log and emailed to the other side.
//!
//! A released `takeover` record also lets the contact set a new master password
//! and Secret Key for the grantor (plan 06, "Takeover design"). Organiser
//! recovery is the same record held by the family's organiser, without the
//! read access.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use octapass_api::problem::Problem;
use octapass_api::{
    CreateEmergencyContactRequest, EmergencyAccessLevel, EmergencyContactRecord,
    EmergencyContactsResponse, EmergencyReleaseResponse, EmergencyScope, EmergencyStatus,
    EmergencyTakeoverRequest, PasswordRegistrationResponse, REAUTH_TOKEN_HEADER, ReauthPurpose,
    RenewEmergencyKeyRequest, SecurityEventType, SyncResponse, TakeoverRegistrationRequest,
    VaultRole,
};

use super::attachments::send_file;
use super::password::{new_credentials, registration_response, signature_matches};
use super::sharing::current_key;
use super::vaults::{SyncQuery, parse_since};
use crate::db::emergency::{self as contacts, ContactRow, NewContact};
use crate::db::{self, accounts, audit, items, sessions, sharing, two_step};
use crate::emergency::{self, requested_email};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, Authenticated};
use crate::mail::Email;
use crate::state::AppState;
use crate::validate;

pub const MAX_WAIT_DAYS: u32 = 30;
const TAKEOVER_LABEL: &[u8] = b"octapass/v1/emergency-takeover\0";

#[derive(PartialEq, Eq)]
enum Side {
    Grantor,
    Contact,
}

/// The record and which side of it the account is on. Records it isn't part
/// of don't exist for it. Requests whose waiting period is over are released
/// first, so the answer is never stale.
async fn load(state: &AppState, id: &str, account_id: &str) -> ApiResult<(ContactRow, Side)> {
    let id = validate::id("id", id)?;
    let now = state.clock.now();
    let mut row = contacts::find(&state.db, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.status() == EmergencyStatus::Requested && row.releases_at.is_some_and(|at| at <= now) {
        emergency::release(
            state,
            &row,
            SecurityEventType::EmergencyAccessReleased,
            now,
            true,
        )
        .await?;
        row = contacts::find(&state.db, &id)
            .await?
            .ok_or(ApiError::NotFound)?;
    }
    let side = if row.grantor_id == account_id {
        Side::Grantor
    } else if row.contact_id == account_id {
        Side::Contact
    } else {
        return Err(ApiError::NotFound);
    };
    Ok((row, side))
}

async fn reload(state: &AppState, id: &str) -> ApiResult<EmergencyContactRecord> {
    Ok(contacts::find(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound)?
        .into_record())
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts", tag = "emergency-access",
    security(("bearer" = [])),
    request_body = CreateEmergencyContactRequest,
    responses(
        (status = 201, body = EmergencyContactRecord),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such contact account"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "Too many contacts added, \
            by this account or for this contact"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<CreateEmergencyContactRequest>,
) -> ApiResult<(StatusCode, Json<EmergencyContactRecord>)> {
    let me = session.account_id.as_str();
    let policies = db::orgs::policies_of(&state.db, me).await?;
    if policies.is_some_and(|policies| policies.disable_emergency_access) {
        return Err(ApiError::OrgPolicy(
            "your organisation doesn't allow emergency access",
        ));
    }
    let contact_id = validate::id("contactAccountId", &request.contact_account_id)?;
    if contact_id == me {
        return Err(ApiError::BadRequest(
            "you can't be your own emergency contact".into(),
        ));
    }
    validate::sealed_key("sealedKey", &request.sealed_key)?;
    if !(1..=MAX_WAIT_DAYS).contains(&request.wait_days) {
        return Err(ApiError::BadRequest(format!(
            "waitDays must be 1 to {MAX_WAIT_DAYS}"
        )));
    }
    let scope_vault_id = match &request.scope {
        EmergencyScope::Account => None,
        EmergencyScope::Vault { vault_id } => {
            let vault_id = validate::id("scope.vaultId", vault_id)?;
            let mut conn = state.db.acquire().await?;
            let owned = sharing::membership(&mut conn, &vault_id, me)
                .await?
                .is_some_and(|membership| membership.role == VaultRole::Owner);
            if !owned {
                return Err(ApiError::BadRequest(
                    "scope.vaultId must be a vault you own".into(),
                ));
            }
            if request.access_level == EmergencyAccessLevel::Takeover {
                return Err(ApiError::BadRequest(
                    "takeover needs the account scope: a vault's key can't open an account".into(),
                ));
            }
            Some(vault_id)
        }
    };
    let contact = accounts::find_by_id(&state.db, &contact_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // Each new contact gets an email, so both sides of it have a budget.
    state
        .emergency_contact_limiter
        .check(me)
        .and_then(|()| state.emergency_recipient_limiter.check(&contact.email))
        .map_err(ApiError::RateLimited)?;

    let id = uuid::Uuid::now_v7().to_string();
    let now = state.clock.now();
    let new = NewContact {
        id: &id,
        grantor_id: me,
        contact_id: &contact_id,
        scope_vault_id: scope_vault_id.as_deref(),
        access_level: match request.access_level {
            EmergencyAccessLevel::View => "view",
            EmergencyAccessLevel::Takeover => "takeover",
        },
        wait_days: request.wait_days,
        sealed_key: &request.sealed_key,
        organiser_recovery: false,
        now,
    };
    contacts::insert(&state.db, new)
        .await
        .map_err(|error| match error.as_database_error() {
            Some(db_error) if db_error.is_unique_violation() => {
                ApiError::AlreadyExists("this account is already your emergency contact")
            }
            _ => error.into(),
        })?;
    let event = SecurityEventType::EmergencyContactAdded;
    audit::record(&state.db, me, event, Some(&contact_id), Some(&id), now).await?;
    let record = reload(&state, &id).await?;
    state.send_email(
        &contact.email,
        Email::EmergencyContactAdded {
            grantor: record.grantor_email.clone(),
        },
    );
    Ok((StatusCode::CREATED, Json(record)))
}

#[utoipa::path(
    get, path = "/v1/emergency-contacts", tag = "emergency-access",
    security(("bearer" = [])),
    responses(
        (status = 200, body = EmergencyContactsResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<EmergencyContactsResponse>> {
    emergency::release_due(&state, state.clock.now()).await?;
    let (granted, received) = contacts::list_for(&state.db, &session.account_id).await?;
    Ok(Json(EmergencyContactsResponse {
        granted: granted.into_iter().map(ContactRow::into_record).collect(),
        received: received.into_iter().map(ContactRow::into_record).collect(),
    }))
}

#[utoipa::path(
    delete, path = "/v1/emergency-contacts/{id}", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "The grantor removed the contact, or the contact stepped down"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    let (row, _) = load(&state, &id, &session.account_id).await?;
    let mut tx = state.db.begin().await?;
    contacts::delete(&mut tx, &row.id).await?;
    let event = if row.is_organiser_recovery() {
        SecurityEventType::OrganiserRecoveryDisabled
    } else {
        SecurityEventType::EmergencyContactRemoved
    };
    let now = state.clock.now();
    audit::record(
        &mut *tx,
        &row.grantor_id,
        event,
        Some(&row.contact_id),
        Some(&row.id),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts/{id}/request", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 200, body = EmergencyContactRecord, description = "Requested (or already requested or released). \
            The key is released at `releasesAt` unless the grantor denies it."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the contact can request"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn request(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<EmergencyContactRecord>> {
    let (row, side) = load(&state, &id, &session.account_id).await?;
    if side != Side::Contact {
        return Err(ApiError::Forbidden);
    }
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    if contacts::request(&mut tx, &row.id, now, row.wait_days).await? {
        let event = SecurityEventType::EmergencyAccessRequested;
        audit::record(
            &mut *tx,
            &row.grantor_id,
            event,
            Some(&row.contact_id),
            Some(&row.id),
            now,
        )
        .await?;
        tx.commit().await?;
        let requested = contacts::find(&state.db, &row.id)
            .await?
            .ok_or(ApiError::NotFound)?;
        state.send_email(&requested.grantor_email, requested_email(&requested, false));
        return Ok(Json(requested.into_record()));
    }
    Ok(Json(row.into_record()))
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts/{id}/deny", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 200, body = EmergencyContactRecord, description = "Back to idle. Works on a released key too, \
            which ends the contact's access through the server."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the grantor can deny"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn deny(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<EmergencyContactRecord>> {
    let (row, side) = load(&state, &id, &session.account_id).await?;
    if side != Side::Grantor {
        return Err(ApiError::Forbidden);
    }
    let mut tx = state.db.begin().await?;
    if contacts::deny(&mut tx, &row.id).await? {
        let event = SecurityEventType::EmergencyAccessDenied;
        let now = state.clock.now();
        audit::record(
            &mut *tx,
            &row.grantor_id,
            event,
            Some(&row.contact_id),
            Some(&row.id),
            now,
        )
        .await?;
        tx.commit().await?;
        state.send_email(
            &row.contact_email,
            Email::EmergencyAccessDenied {
                grantor: row.grantor_email.clone(),
            },
        );
    }
    Ok(Json(reload(&state, &row.id).await?))
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts/{id}/approve", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 200, body = EmergencyContactRecord, description = "Released now, without waiting"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Nothing requested"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the grantor can approve"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn approve(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<EmergencyContactRecord>> {
    let (row, side) = load(&state, &id, &session.account_id).await?;
    if side != Side::Grantor {
        return Err(ApiError::Forbidden);
    }
    let event = SecurityEventType::EmergencyAccessApproved;
    let released = row.status() == EmergencyStatus::Released
        || emergency::release(&state, &row, event, state.clock.now(), false).await?;
    if !released {
        return Err(ApiError::BadRequest("there's no request to approve".into()));
    }
    Ok(Json(reload(&state, &row.id).await?))
}

/// The released record, for its contact only.
async fn released(state: &AppState, id: &str, account_id: &str) -> ApiResult<ContactRow> {
    let (row, side) = load(state, id, account_id).await?;
    if side != Side::Contact || row.status() != EmergencyStatus::Released {
        return Err(ApiError::Forbidden);
    }
    Ok(row)
}

/// The released record, for a contact allowed to read. Organiser recovery allows the reset and
/// nothing else: any use of it signs the member out and tells them.
async fn released_to_read(state: &AppState, id: &str, account_id: &str) -> ApiResult<ContactRow> {
    let row = released(state, id, account_id).await?;
    if row.is_organiser_recovery() {
        return Err(ApiError::Forbidden);
    }
    Ok(row)
}

#[utoipa::path(
    get, path = "/v1/emergency-contacts/{id}/release", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    responses(
        (status = 200, body = EmergencyReleaseResponse, description = "The sealed key, and for an account scope the grantor's account bundle"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Not released, or not the contact"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_release(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<EmergencyReleaseResponse>> {
    let row = released(&state, &id, &session.account_id).await?;
    // The bundle's private keys open every vault shared with the grantor, and its wrapped
    // ASKs everything else: a vault scope only needs its sealed vault key.
    let grantor = match row.scope_vault_id {
        Some(_) => None,
        None => Some(
            accounts::find_by_id(&state.db, &row.grantor_id)
                .await?
                .ok_or(ApiError::NotFound)?
                .into_bundle(),
        ),
    };
    Ok(Json(EmergencyReleaseResponse {
        sealed_key: row.sealed_key.clone(),
        contact: row.into_record(),
        grantor,
    }))
}

#[utoipa::path(
    get, path = "/v1/emergency-contacts/{id}/sync", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path), SyncQuery),
    responses(
        (status = 200, body = SyncResponse, description = "The grantor's vaults in scope, read-only, paged like /v1/sync"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Not released, or not the contact"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn sync(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiQuery(query): ApiQuery<SyncQuery>,
) -> ApiResult<Json<SyncResponse>> {
    let row = released_to_read(&state, &id, &session.account_id).await?;
    let since = parse_since(query.since.as_deref().unwrap_or(""))?;
    let only_vault = row.scope_vault_id.as_deref();
    let keep_out = db::orgs::policies_of(&state.db, &row.grantor_id)
        .await?
        .is_some_and(|policies| policies.disable_emergency_access);
    let synced = items::sync(
        &state.db,
        &row.grantor_id,
        &since,
        only_vault,
        keep_out,
        items::PAGE,
    )
    .await?;
    Ok(Json(synced))
}

#[utoipa::path(
    get, path = "/v1/emergency-contacts/{id}/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path), ("vaultId" = String, Path), ("itemId" = String, Path), ("attachmentId" = String, Path)),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/octet-stream", description = "One of the grantor's encrypted files, from a vault in scope"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Not released, or not the contact"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such file, or its vault isn't in scope"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "Storage unreachable"),
    )
)]
pub async fn download_attachment(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((id, vault_id, item_id, attachment_id)): ApiPath<(String, String, String, String)>,
) -> ApiResult<Response> {
    let row = released_to_read(&state, &id, &session.account_id).await?;
    if row
        .scope_vault_id
        .as_deref()
        .is_some_and(|scope| scope != vault_id)
    {
        return Err(ApiError::NotFound);
    }
    if db::orgs::hides_from_emergency(&state.db, &row.grantor_id, &vault_id).await? {
        return Err(ApiError::NotFound);
    }
    // Read as the grantor: what the release opens is exactly what they can read.
    send_file(&state, &row.grantor_id, &vault_id, &item_id, &attachment_id).await
}

#[utoipa::path(
    put, path = "/v1/emergency-contacts/{id}/key", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    request_body = RenewEmergencyKeyRequest,
    responses(
        (status = 200, body = EmergencyContactRecord, description = "The contact holds the vault's current key again"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Not a vault scope"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the grantor can renew"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-key-changed: `keyId` is no longer the vault's key"),
    )
)]
pub async fn renew_key(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<RenewEmergencyKeyRequest>,
) -> ApiResult<Json<EmergencyContactRecord>> {
    let (row, side) = load(&state, &id, &session.account_id).await?;
    if side != Side::Grantor {
        return Err(ApiError::Forbidden);
    }
    let Some(vault_id) = row.scope_vault_id.as_deref() else {
        return Err(ApiError::BadRequest(
            "only a vault scope renews: an account scope seals the account key, which doesn't rotate"
                .into(),
        ));
    };
    validate::sealed_key("sealedKey", &request.sealed_key)?;
    validate::exact_bytes("keyId", &request.key_id, validate::KEY_ID_LEN)?;
    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, vault_id).await?;
    current_key(&mut tx, vault_id, Some(&request.key_id)).await?;
    contacts::renew_key(&mut tx, &row.id, &request.sealed_key).await?;
    tx.commit().await?;
    Ok(Json(reload(&state, &row.id).await?))
}

/// The record a contact may take over with, as it stands now.
async fn takeover_record(state: &AppState, id: &str, account_id: &str) -> ApiResult<ContactRow> {
    let row = released(state, id, account_id).await?;
    if !row.allows_takeover() {
        return Err(ApiError::Forbidden);
    }
    Ok(row)
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts/{id}/takeover/registration", tag = "emergency-access",
    security(("bearer" = [])),
    params(("id" = String, Path)),
    request_body = TakeoverRegistrationRequest,
    responses(
        (status = 200, body = PasswordRegistrationResponse, description = "The OPAQUE registration response for the grantor's new master password. Nothing is stored."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Not released, not a takeover, or not the contact"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn takeover_registration(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<TakeoverRegistrationRequest>,
) -> ApiResult<Json<PasswordRegistrationResponse>> {
    let row = takeover_record(&state, &id, &session.account_id).await?;
    let registration_response =
        registration_response(&state, &row.grantor_email, &request.registration_request)?;
    Ok(Json(PasswordRegistrationResponse {
        registration_response,
    }))
}

/// What the grantor's signing key signs (see [`EmergencyTakeoverRequest::signature`]).
fn takeover_message(
    row: &ContactRow,
    current_account_salt: &str,
    request: &EmergencyTakeoverRequest,
) -> Vec<u8> {
    let update = &request.account;
    let fields = [
        row.id.as_str(),
        &row.grantor_id,
        &row.contact_id,
        current_account_salt,
        &request.registration_upload,
        &update.account_salt,
        &update.wrapped_ask,
        update.recovery_wrapped_ask.as_deref().unwrap_or_default(),
    ];
    let mut message = TAKEOVER_LABEL.to_vec();
    for field in fields {
        let len = u32::try_from(field.len()).expect("fields were size-checked");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message
}

#[utoipa::path(
    post, path = "/v1/emergency-contacts/{id}/takeover", tag = "emergency-access",
    security(("bearer" = [])),
    params(
        ("id" = String, Path),
        ("X-Reauth-Token" = String, Header, description = "The contact's own, from /v1/auth/reauth/finish with purpose emergency-takeover"),
    ),
    request_body = EmergencyTakeoverRequest,
    responses(
        (status = 204, description = "The grantor's new master password, Secret Key and recovery code are in place. Every device of the \
            grantor was signed out, two-step sign-in is off, and this record is gone."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required; or not released, not a \
            takeover, not the contact, or a signature that doesn't match the grantor's key and current salt"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn takeover(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<EmergencyTakeoverRequest>,
) -> ApiResult<StatusCode> {
    let token = headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(ApiError::ReauthRequired)?;
    let row = takeover_record(&state, &id, &session.account_id).await?;
    let opaque_record = new_credentials(&request.registration_upload, &request.account, true)?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    // A write first, so on SQLite this transaction holds the write lock from the start.
    let purpose = ReauthPurpose::EmergencyTakeover.as_str();
    // Reauth tokens are stamped by the wall clock, whatever the emergency timeline's clock says.
    let reauth_now = db::now();
    if !sessions::consume_reauth_token(&mut tx, token, &session.account_id, purpose, reauth_now)
        .await?
    {
        return Err(ApiError::ReauthRequired);
    }
    // A denial or a removal that landed first wins.
    if !contacts::take_for_takeover(&mut tx, &row.id).await? {
        return Err(ApiError::Forbidden);
    }
    let (current_salt, public_sign_key) = accounts::signing_state(&mut tx, &row.grantor_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let message = takeover_message(&row, &current_salt, &request);
    if !signature_matches(&public_sign_key, &request.signature, &message) {
        tracing::warn!("an emergency takeover had a wrong signature");
        return Err(ApiError::Forbidden);
    }
    accounts::replace_credentials(&mut tx, &row.grantor_id, &opaque_record, &request.account)
        .await?;
    let revoked = sessions::revoke_other_devices(&mut tx, &row.grantor_id, None, now).await?;
    let two_step_was_on = two_step::disable(&mut tx, &row.grantor_id).await?;
    if two_step_was_on {
        let event = SecurityEventType::TwoStepDisabled;
        audit::record(&mut *tx, &row.grantor_id, event, None, None, now).await?;
    }
    audit::record(
        &mut *tx,
        &row.grantor_id,
        SecurityEventType::EmergencyTakeover,
        Some(&row.contact_id),
        Some(&row.id),
        now,
    )
    .await?;
    tx.commit().await?;
    for device_id in revoked {
        state.session_revoked(&row.grantor_id, &device_id);
    }
    state.send_email(
        &row.grantor_email,
        Email::EmergencyTakeover {
            contact: row.contact_email.clone(),
        },
    );
    tracing::info!("emergency takeover completed");
    Ok(StatusCode::NO_CONTENT)
}
