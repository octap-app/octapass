//! Families: an organiser invites up to `OCTAPASS_FAMILY_MAX_MEMBERS` people
//! (6 by default, the organiser included) to share a Family vault. Each
//! account is in at most one family.
//!
//! An invite carries the invitee's grant to the Family vault, sealed and
//! signed on the organiser's device, so accepting needs nothing more from
//! the organiser. Removing a member works like any shared vault: the
//! organiser rotates the Family vault's key next, and the rotation re-seals
//! the pending invites to the new key (or cancels them).
//!
//! A member can also opt in to organiser recovery (plan 06): an emergency
//! record, held by the organiser, that lasts as long as the membership.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use octapass_api::problem::Problem;
use octapass_api::{
    CreateFamilyRequest, EmergencyContactRecord, FamiliesResponse, FamilyMember, FamilyRecord,
    FamilyRole, InviteRequest, OrganiserRecoveryRequest, SecurityEventType, VaultRole,
};

use super::emergency::MAX_WAIT_DAYS;
use super::sharing::{
    charge_lookup, current_key, insert_vault, own_grant, public_sign_key, validate_key_id,
    validate_new_vault,
};
use crate::db::emergency::{self as contacts, NewContact};
use crate::db::families::{self, FamilyRow};
use crate::db::{self, accounts, audit, sharing};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated};
use crate::mail::Email;
use crate::state::AppState;
use crate::validate;

async fn record(state: &AppState, family: &FamilyRow, viewer: &str) -> ApiResult<FamilyRecord> {
    let members = families::members(&state.db, family)
        .await?
        .into_iter()
        .map(|(account_id, email, joined_at)| FamilyMember {
            role: if account_id == family.organiser_id {
                FamilyRole::Organiser
            } else {
                FamilyRole::Member
            },
            account_id,
            email,
            joined_at: db::rfc3339(joined_at),
        })
        .collect();
    let invites = if viewer == family.organiser_id {
        families::invites(&state.db, &family.id).await?
    } else {
        Vec::new()
    };
    Ok(FamilyRecord {
        id: family.id.clone(),
        organiser_id: family.organiser_id.clone(),
        vault_id: family.vault_id.clone(),
        max_members: state.config.family_max_members,
        members,
        invites,
        created_at: db::rfc3339(family.created_at),
    })
}

/// The family `family_id` if the account belongs to it. Families the account
/// isn't in don't exist, as far as it's concerned.
async fn own_family(state: &AppState, family_id: &str, account_id: &str) -> ApiResult<FamilyRow> {
    let mut conn = state.db.acquire().await?;
    families::of_account(&mut conn, account_id)
        .await?
        .filter(|family| family.id == family_id)
        .ok_or(ApiError::NotFound)
}

#[utoipa::path(
    post, path = "/v1/families", tag = "families",
    security(("bearer" = [])),
    request_body = CreateFamilyRequest,
    responses(
        (status = 201, body = FamilyRecord, description = "The family, with the signed-in account as organiser, and its Family vault"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: the account is in a family; vault-exists"),
    )
)]
pub async fn create_family(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<CreateFamilyRequest>,
) -> ApiResult<(StatusCode, Json<FamilyRecord>)> {
    let me = session.account_id.as_str();
    let family_id = validate::id("id", &request.id)?;
    validate_new_vault("vault", &request.vault, me)?;
    let sign_key = public_sign_key(&state, me).await?;
    let family = FamilyRow {
        id: family_id,
        organiser_id: me.to_owned(),
        vault_id: request.vault.id.clone(),
        created_at: db::now(),
    };

    let mut tx = state.db.begin().await?;
    insert_vault(
        &mut tx,
        "family",
        &request.vault,
        &sign_key,
        family.created_at,
    )
    .await?;
    if families::of_account(&mut tx, me).await?.is_some() {
        return Err(ApiError::AlreadyExists("you're already in a family"));
    }
    if families::find(&mut tx, &family.id).await?.is_some() {
        return Err(ApiError::AlreadyExists(
            "a family with this id already exists",
        ));
    }
    families::create(&mut tx, &family).await?;
    tx.commit().await?;
    state.membership_changed(&family.vault_id, &[]).await;
    Ok((
        StatusCode::CREATED,
        Json(record(&state, &family, me).await?),
    ))
}

#[utoipa::path(
    get, path = "/v1/families", tag = "families",
    security(("bearer" = [])),
    responses(
        (status = 200, body = FamiliesResponse, description = "The account's family, if any, and invitations it received"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_families(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<FamiliesResponse>> {
    let me = session.account_id.as_str();
    let mut conn = state.db.acquire().await?;
    let family = families::of_account(&mut conn, me).await?;
    drop(conn);
    let family = match family {
        Some(family) => Some(record(&state, &family, me).await?),
        None => None,
    };
    let invitations = families::invitations_for(&state.db, me).await?;
    Ok(Json(FamiliesResponse {
        family,
        invitations,
    }))
}

#[utoipa::path(
    delete, path = "/v1/families/{familyId}", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path)),
    responses(
        (status = 204, description = "The family and its Family vault were deleted"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the organiser can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_family(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(family_id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let family = own_family(&state, &validate::id("familyId", &family_id)?, me).await?;
    if family.organiser_id != me {
        return Err(ApiError::Forbidden);
    }
    let members = db::items::members(&state.db, &family.vault_id).await?;
    let mut tx = state.db.begin().await?;
    let now = state.clock.now();
    for (record_id, member) in contacts::remove_organiser_recoveries_to(&mut tx, me).await? {
        let event = SecurityEventType::OrganiserRecoveryDisabled;
        audit::record(&mut *tx, &member, event, Some(me), Some(&record_id), now).await?;
    }
    families::delete(&mut tx, &family.id).await?;
    sharing::delete_vault(&mut tx, &family.vault_id).await?;
    tx.commit().await?;
    crate::storage::drain_soon(&state);
    state.membership_changed(&family.vault_id, &members).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/families/{familyId}/invites", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path)),
    request_body = InviteRequest,
    responses(
        (status = 202, description = "Accepted. The same answer whether or not the email has an account; only an \
            account with that email gets the invite (and an email about it)."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The grant must be for the Family vault, role write"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the organiser can invite"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "family-full; vault-key-changed: \
            `keyId` is no longer the Family vault's key"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(family_id): ApiPath<String>,
    ApiJson(request): ApiJson<InviteRequest>,
) -> ApiResult<StatusCode> {
    charge_lookup(&state, &session.account_id)?;
    let me = session.account_id.as_str();
    let family = own_family(&state, &validate::id("familyId", &family_id)?, me).await?;
    if family.organiser_id != me {
        return Err(ApiError::Forbidden);
    }
    let email = validate::email(&request.email)?;
    let grant = &request.grant;
    own_grant("grant", grant, &family.vault_id, me)?;
    validate_key_id(request.key_id.as_deref())?;
    if grant.role != VaultRole::Write {
        return Err(ApiError::BadRequest(
            "family members get the write role".into(),
        ));
    }
    if grant.recipient_account_id == me {
        return Err(ApiError::BadRequest("you're already in this family".into()));
    }
    let recipient = accounts::find_by_email(&state.db, &email).await?;
    let sign_key = public_sign_key(&state, me).await?;

    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &family.vault_id).await?;
    current_key(&mut tx, &family.vault_id, request.key_id.as_deref()).await?;
    if families::size(&mut tx, &family.id).await? >= i64::from(state.config.family_max_members) {
        return Err(ApiError::FamilyFull);
    }
    // As for vault members: past this point an unknown email, or a grant for
    // someone else, quietly stores nothing.
    let Some(recipient) = recipient.filter(|account| account.id == grant.recipient_account_id)
    else {
        return Ok(StatusCode::ACCEPTED);
    };
    if families::of_account(&mut tx, &recipient.id)
        .await?
        .is_some_and(|theirs| theirs.id == family.id)
    {
        return Ok(StatusCode::ACCEPTED);
    }
    families::put_invite(&mut tx, &family.id, grant, &sign_key, db::now()).await?;
    tx.commit().await?;
    let organiser = accounts::find_by_id(&state.db, me)
        .await?
        .map(|account| account.email)
        .unwrap_or_default();
    state.send_email(&recipient.email, Email::FamilyInvite { organiser });
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    delete, path = "/v1/families/{familyId}/invites/{accountId}", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path), ("accountId" = String, Path)),
    responses(
        (status = 204, description = "The organiser cancelled the invite, or the invitee declined it"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((family_id, account_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let family_id = validate::id("familyId", &family_id)?;
    let invitee = validate::id("accountId", &account_id)?;
    let mut tx = state.db.begin().await?;
    let family = families::find(&mut tx, &family_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if family.organiser_id != me && invitee != me {
        return Err(ApiError::NotFound);
    }
    if !families::delete_invite(&mut tx, &family_id, &invitee).await? {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/families/{familyId}/invites/accept", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path)),
    responses(
        (status = 200, body = FamilyRecord, description = "Joined; the Family vault is in the next sync"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No invite to this family"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: leave the current family first"),
    )
)]
pub async fn accept_invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(family_id): ApiPath<String>,
) -> ApiResult<Json<FamilyRecord>> {
    let me = session.account_id.as_str();
    let family_id = validate::id("familyId", &family_id)?;
    let mut conn = state.db.acquire().await?;
    let family = families::find(&mut conn, &family_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);

    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &family.vault_id).await?;
    if families::of_account(&mut tx, me).await?.is_some() {
        return Err(ApiError::AlreadyExists("leave your current family first"));
    }
    let (grant, granter_sign_key) = families::take_invite(&mut tx, &family, me)
        .await?
        .ok_or(ApiError::NotFound)?;
    let now = db::now();
    families::add_member(&mut tx, &family.id, me, now).await?;
    sharing::put_member(&mut tx, &grant, &granter_sign_key, now).await?;
    tx.commit().await?;
    state.membership_changed(&family.vault_id, &[]).await;
    Ok(Json(record(&state, &family, me).await?))
}

#[utoipa::path(
    delete, path = "/v1/families/{familyId}/members/{accountId}", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path), ("accountId" = String, Path)),
    responses(
        (status = 204, description = "The member left, or the organiser removed them. The organiser rotates the \
            Family vault's key next."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The organiser can't leave: delete the family instead"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only the organiser removes others"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((family_id, account_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let family = own_family(&state, &validate::id("familyId", &family_id)?, me).await?;
    let target = validate::id("accountId", &account_id)?;
    if target == family.organiser_id {
        return Err(ApiError::BadRequest(
            "the organiser can't leave: delete the family instead".into(),
        ));
    }
    if target != me && me != family.organiser_id {
        return Err(ApiError::Forbidden);
    }
    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &family.vault_id).await?;
    if !families::remove_member(&mut tx, &family.id, &target).await? {
        return Err(ApiError::NotFound);
    }
    sharing::remove_member(&mut tx, &family.vault_id, &target).await?;
    // Organiser recovery only lasts as long as the membership it came from.
    if let Some((record_id, organiser)) =
        contacts::remove_organiser_recovery(&mut tx, &target).await?
    {
        let event = SecurityEventType::OrganiserRecoveryDisabled;
        let now = state.clock.now();
        audit::record(
            &mut *tx,
            &target,
            event,
            Some(&organiser),
            Some(&record_id),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    state.membership_changed(&family.vault_id, &[target]).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/families/{familyId}/organiser-recovery", tag = "families",
    security(("bearer" = [])),
    params(("familyId" = String, Path)),
    request_body = OrganiserRecoveryRequest,
    responses(
        (status = 201, body = EmergencyContactRecord, description = "The organiser holds the member's sealed account key. \
            It's an emergency record: `DELETE /v1/emergency-contacts/{id}` turns it off."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The organiser has no one to recover them"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: on already, or the organiser is already an emergency contact"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn enable_organiser_recovery(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(family_id): ApiPath<String>,
    ApiJson(request): ApiJson<OrganiserRecoveryRequest>,
) -> ApiResult<(StatusCode, Json<EmergencyContactRecord>)> {
    let me = session.account_id.as_str();
    let family = own_family(&state, &validate::id("familyId", &family_id)?, me).await?;
    if family.organiser_id == me {
        return Err(ApiError::BadRequest(
            "organiser recovery is for the family's other members".into(),
        ));
    }
    validate::sealed_key("sealedKey", &request.sealed_key)?;
    if !(1..=MAX_WAIT_DAYS).contains(&request.wait_days) {
        return Err(ApiError::BadRequest(format!(
            "waitDays must be 1 to {MAX_WAIT_DAYS}"
        )));
    }
    let organiser = accounts::find_by_id(&state.db, &family.organiser_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    state
        .emergency_contact_limiter
        .check(me)
        .and_then(|()| state.emergency_recipient_limiter.check(&organiser.email))
        .map_err(ApiError::RateLimited)?;

    let id = uuid::Uuid::now_v7().to_string();
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    // Under the vault's lock, so leaving the family can't slip in and leave this record behind.
    sharing::lock_vault(&mut tx, &family.vault_id).await?;
    if sharing::membership(&mut tx, &family.vault_id, me)
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound);
    }
    let new = NewContact {
        id: &id,
        grantor_id: me,
        contact_id: &family.organiser_id,
        scope_vault_id: None,
        access_level: "takeover",
        wait_days: request.wait_days,
        sealed_key: &request.sealed_key,
        organiser_recovery: true,
        now,
    };
    contacts::insert(&mut *tx, new)
        .await
        .map_err(|error| match error.as_database_error() {
            Some(db_error) if db_error.is_unique_violation() => ApiError::AlreadyExists(
                "the organiser can already help: remove them as an emergency contact first",
            ),
            _ => error.into(),
        })?;
    let event = SecurityEventType::OrganiserRecoveryEnabled;
    let organiser_id = family.organiser_id.as_str();
    audit::record(&mut *tx, me, event, Some(organiser_id), Some(&id), now).await?;
    tx.commit().await?;
    let record = contacts::find(&state.db, &id)
        .await?
        .ok_or(ApiError::NotFound)?
        .into_record();
    state.send_email(
        &organiser.email,
        Email::EmergencyContactAdded {
            grantor: record.grantor_email.clone(),
        },
    );
    Ok((StatusCode::CREATED, Json(record)))
}
