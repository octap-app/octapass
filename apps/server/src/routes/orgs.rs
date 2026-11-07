//! Organisations: members, invites, groups, the vaults they reach, policies and the activity log.
//! The rules are in plan 03, "Organisations and single sign-on". Roles here open nothing: a vault
//! key reaches someone only through a grant made on a key holder's device.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use octapass_api::problem::Problem;
use octapass_api::{
    CreateOrgGroupRequest, CreateOrgRequest, CreateVaultRequest, DeleteOrgRequest,
    OrgAccessResponse, OrgEventsResponse, OrgGroupRecord, OrgGroupsResponse, OrgInviteRequest,
    OrgMemberUpdate, OrgMembersResponse, OrgPolicies, OrgRecord, OrgRole, OrgVaultGrantsRequest,
    OrgVaultGroupUpdate, OrgVaultsResponse, OrgsResponse, REAUTH_TOKEN_HEADER, ReauthPurpose,
    RenameOrgGroupRequest, RenameOrgRequest, VaultRecord, VaultRole, VaultType,
};
use serde::Deserialize;

use super::sharing::{
    charge_lookup, current_key, insert_vault, new_vault_record, own_grant, public_sign_key,
    validate_new_vault,
};
use crate::db::orgs::{self, NewInvite, OrgRow, Reconciled};
use crate::db::{self, Conn, accounts, days, sessions, sharing};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, Authenticated};
use crate::mail::Email;
use crate::state::AppState;
use crate::validate;

const MAX_NAME: usize = 64;
const INVITE_LIFETIME: i64 = days(14);
const MAX_SSO_AGE_HOURS: u32 = 8760;
const MAX_AUTO_LOCK_MINUTES: u32 = 1440;
const MIN_PASSWORD_LENGTH: std::ops::RangeInclusive<u32> = 8..=128;

fn unique_violation_as(conflict: ApiError) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |error| match error.as_database_error() {
        Some(db_error) if db_error.is_unique_violation() => conflict,
        _ => error.into(),
    }
}

/// Takes the organisation's lock, then checks the caller's role under it, so a role lost a moment
/// ago doesn't count. Organisations the account isn't in don't exist, as far as it's concerned.
pub(super) async fn locked(
    conn: &mut Conn,
    org_id: &str,
    account_id: &str,
    needed: OrgRole,
) -> ApiResult<OrgRole> {
    if !orgs::lock(conn, org_id).await? {
        return Err(ApiError::NotFound);
    }
    let role = orgs::member_role(conn, org_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if role < needed {
        return Err(ApiError::Forbidden);
    }
    Ok(role)
}

/// The caller's organisation, if it's this one, for reads.
async fn mine(state: &AppState, org_id: &str, me: &str, needed: OrgRole) -> ApiResult<OrgRow> {
    let mut conn = state.db.acquire().await?;
    let (org, role) = orgs::of_account(&mut conn, me)
        .await?
        .filter(|(org, _)| org.id == org_id)
        .ok_or(ApiError::NotFound)?;
    if role < needed {
        return Err(ApiError::Forbidden);
    }
    Ok(org)
}

/// Refuses a change that leaves a vault with nobody able to manage it.
fn refuse_orphans(reconciled: &Reconciled) -> ApiResult<()> {
    if reconciled.orphaned.is_empty() {
        Ok(())
    } else {
        Err(ApiError::OrgVaultOrphaned(reconciled.orphaned.clone()))
    }
}

/// Tells the people who lost a vault, and its remaining members. The change already committed.
async fn notify(state: &AppState, reconciled: &Reconciled) {
    for (vault_id, lost) in &reconciled.lost {
        state.membership_changed(vault_id, lost).await;
    }
}

async fn record(state: &AppState, org: &OrgRow, role: OrgRole, me: &str) -> ApiResult<OrgRecord> {
    Ok(OrgRecord {
        id: org.id.clone(),
        name: org.name.clone(),
        role,
        policies: org.policies(),
        member_count: u64::try_from(orgs::member_count(&state.db, &org.id).await?)
            .unwrap_or_default(),
        access_withheld: orgs::access_withheld(&state.db, me).await?,
        created_at: db::rfc3339(org.created_at),
    })
}

fn group_id(raw: &str) -> ApiResult<String> {
    validate::id("groupId", raw)
}

async fn email_of(state: &AppState, account_id: &str) -> ApiResult<String> {
    accounts::find_by_id(&state.db, account_id)
        .await?
        .map(|account| account.email)
        .ok_or(ApiError::Unauthorized)
}

async fn consume_reauth(
    conn: &mut Conn,
    headers: &HeaderMap,
    account_id: &str,
    now: i64,
) -> ApiResult<()> {
    let token = headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::ReauthRequired)?;
    let purpose = ReauthPurpose::Organisation.as_str();
    if sessions::consume_reauth_token(conn, token.trim(), account_id, purpose, now).await? {
        Ok(())
    } else {
        Err(ApiError::ReauthRequired)
    }
}

#[utoipa::path(
    post, path = "/v1/orgs", tag = "organisations",
    security(("bearer" = [])),
    request_body = CreateOrgRequest,
    responses(
        (status = 201, body = OrgRecord, description = "The organisation, with the signed-in account as its owner"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: an account is in one organisation at a time"),
    )
)]
pub async fn create_org(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<CreateOrgRequest>,
) -> ApiResult<(StatusCode, Json<OrgRecord>)> {
    let me = session.account_id.as_str();
    let org_id = validate::id("id", &request.id)?;
    let name = validate::text("name", &request.name, MAX_NAME)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    orgs::create(&mut tx, &org_id, &name, me, now)
        .await
        .map_err(unique_violation_as(ApiError::AlreadyExists(
            "you're already in an organisation, or this id is taken",
        )))?;
    orgs::record_event(&mut tx, &org_id, me, "org-created", Some(&name), now).await?;
    let org = orgs::find(&mut tx, &org_id)
        .await?
        .ok_or_else(|| ApiError::internal("a new organisation is missing"))?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(record(&state, &org, OrgRole::Owner, me).await?),
    ))
}

#[utoipa::path(
    get, path = "/v1/orgs", tag = "organisations",
    security(("bearer" = [])),
    responses(
        (status = 200, body = OrgsResponse, description = "The account's organisation, if any, and invitations to its email"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_orgs(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<OrgsResponse>> {
    let me = session.account_id.as_str();
    let email = email_of(&state, me).await?;
    let mut conn = state.db.acquire().await?;
    let membership = orgs::of_account(&mut conn, me).await?;
    let invitations = orgs::invitations_for(&mut conn, &email, state.clock.now()).await?;
    drop(conn);
    let organisation = match membership {
        Some((org, role)) => Some(record(&state, &org, role, me).await?),
        None => None,
    };
    Ok(Json(OrgsResponse {
        organisation,
        invitations,
    }))
}

#[utoipa::path(
    patch, path = "/v1/orgs/{orgId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = RenameOrgRequest,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn rename_org(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<RenameOrgRequest>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let name = validate::text("name", &request.name, MAX_NAME)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    orgs::rename(&mut tx, &org_id, &name).await?;
    orgs::record_event(&mut tx, &org_id, me, "org-renamed", Some(&name), db::now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}", tag = "organisations",
    security(("bearer" = [])),
    params(
        ("orgId" = String, Path),
        ("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose organisation"),
    ),
    request_body = DeleteOrgRequest,
    responses(
        (status = 204, description = "The organisation and all its vaults were deleted"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "confirmName doesn't match"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can; reauth-required"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_org(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<DeleteOrgRequest>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    let org = orgs::find(&mut tx, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if org.name != request.confirm_name.trim() {
        return Err(ApiError::BadRequest(
            "confirmName must be the organisation's name".into(),
        ));
    }
    consume_reauth(&mut tx, &headers, me, now).await?;
    let gone = orgs::delete(&mut tx, &org_id).await?;
    tx.commit().await?;
    crate::storage::drain_soon(&state);
    for (vault_id, members) in gone {
        state.membership_changed(&vault_id, &members).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/members", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgMembersResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgMembersResponse>> {
    let org_id = validate::id("orgId", &org_id)?;
    mine(&state, &org_id, &session.account_id, OrgRole::Admin).await?;
    Ok(Json(OrgMembersResponse {
        members: orgs::members(&state.db, &org_id).await?,
        invites: orgs::invites(&state.db, &org_id, state.clock.now()).await?,
    }))
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/invites", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = OrgInviteRequest,
    responses(
        (status = 202, description = "Accepted. The same answer whether or not the email has an account, or is already a member."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The role must be member or admin"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<OrgInviteRequest>,
) -> ApiResult<StatusCode> {
    charge_lookup(&state, &session.account_id)?;
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let email = validate::email(&request.email)?;
    if request.role == OrgRole::Owner {
        return Err(ApiError::BadRequest(
            "invite as member or admin; an owner promotes someone afterwards".into(),
        ));
    }
    mine(&state, &org_id, me, OrgRole::Admin).await?;
    // An invite can email anyone, so one address gets only so many.
    let recipient_key = format!("org\0{email}");
    state
        .emergency_recipient_limiter
        .check(&recipient_key)
        .map_err(ApiError::RateLimited)?;

    let existing = accounts::find_by_email(&state.db, &email).await?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    if let Some(account) = &existing
        && orgs::member_role(&mut tx, &org_id, &account.id)
            .await?
            .is_some()
    {
        return Ok(StatusCode::ACCEPTED);
    }
    let id = uuid::Uuid::now_v7().to_string();
    let invite = NewInvite {
        id: &id,
        org_id: &org_id,
        email: &email,
        role: request.role,
        invited_by: me,
        now,
        expires_at: now + INVITE_LIFETIME,
    };
    orgs::put_invite(&mut tx, invite).await?;
    orgs::record_event(&mut tx, &org_id, me, "member-invited", Some(&email), now).await?;
    tx.commit().await?;
    // The inviter's address only: an organisation's name is free text, and this reaches strangers.
    let inviter = email_of(&state, me).await?;
    state.send_email(&email, Email::OrgInvite { inviter });
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/invites/{inviteId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("inviteId" = String, Path)),
    responses(
        (status = 204, description = "An admin cancelled the invite, or the invitee declined it"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, invite_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let invite_id = validate::id("inviteId", &invite_id)?;
    let email = email_of(&state, me).await?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    if !orgs::lock(&mut tx, &org_id).await? {
        return Err(ApiError::NotFound);
    }
    let (invited, _) = orgs::find_invite(&mut tx, &org_id, &invite_id, now)
        .await?
        .ok_or(ApiError::NotFound)?;
    let admin = orgs::member_role(&mut tx, &org_id, me)
        .await?
        .is_some_and(|role| role >= OrgRole::Admin);
    if !admin && invited != email {
        return Err(ApiError::NotFound);
    }
    orgs::delete_invite(&mut tx, &org_id, &invite_id).await?;
    let event = if admin {
        "invite-cancelled"
    } else {
        "invite-declined"
    };
    orgs::record_event(&mut tx, &org_id, me, event, Some(&invited), now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/invites/{inviteId}/accept", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("inviteId" = String, Path)),
    responses(
        (status = 200, body = OrgRecord, description = "Joined. The organisation's policies apply from now on."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such invite for this account's email"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: leave the current organisation first"),
    )
)]
pub async fn accept_invite(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, invite_id)): ApiPath<(String, String)>,
) -> ApiResult<Json<OrgRecord>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let invite_id = validate::id("inviteId", &invite_id)?;
    let email = email_of(&state, me).await?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    if !orgs::lock(&mut tx, &org_id).await? {
        return Err(ApiError::NotFound);
    }
    let (invited, role) = orgs::find_invite(&mut tx, &org_id, &invite_id, now)
        .await?
        .filter(|(invited, _)| *invited == email)
        .ok_or(ApiError::NotFound)?;
    orgs::add_member(&mut tx, &org_id, me, role, now)
        .await
        .map_err(unique_violation_as(ApiError::AlreadyExists(
            "leave your current organisation first",
        )))?;
    orgs::delete_invite(&mut tx, &org_id, &invite_id).await?;
    orgs::record_event(&mut tx, &org_id, me, "member-joined", Some(&invited), now).await?;
    let org = orgs::find(&mut tx, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    Ok(Json(record(&state, &org, role, me).await?))
}

#[utoipa::path(
    patch, path = "/v1/orgs/{orgId}/members/{accountId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("accountId" = String, Path)),
    request_body = OrgMemberUpdate,
    responses(
        (status = 204, description = "The role changed. A new owner gets vaults when a key holder applies access."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The last owner has to stay one"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned"),
    )
)]
pub async fn update_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, account_id)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<OrgMemberUpdate>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let target = validate::id("accountId", &account_id)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    let current = orgs::member_role(&mut tx, &org_id, &target)
        .await?
        .ok_or(ApiError::NotFound)?;
    if current == OrgRole::Owner
        && request.role != OrgRole::Owner
        && orgs::owner_count(&mut tx, &org_id).await? == 1
    {
        return Err(ApiError::BadRequest(
            "the last owner has to stay one: make someone else an owner first".into(),
        ));
    }
    orgs::set_member_role(&mut tx, &org_id, &target, request.role).await?;
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    refuse_orphans(&reconciled)?;
    let subject = format!("{target}: {}", request.role.as_str());
    let event = "member-role-changed";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&subject), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct RemoveQuery {
    /// Go ahead even if a vault is left with nobody able to manage it. It stays unreadable to
    /// everyone else and can only be deleted.
    #[serde(default)]
    orphan_vaults: bool,
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/members/{accountId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("accountId" = String, Path), RemoveQuery),
    responses(
        (status = 204, description = "The member left, or was removed. They lost its vaults at once; a key holder rotates those keys next."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The last owner can't leave"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Admins remove members; only owners remove an owner"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned: repeat with orphanVaults=true to go ahead"),
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, account_id)): ApiPath<(String, String)>,
    ApiQuery(query): ApiQuery<RemoveQuery>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let target = validate::id("accountId", &account_id)?;
    let target_email = email_of(&state, &target).await.ok();
    let now = db::now();
    let mut tx = state.db.begin().await?;
    let mine = locked(&mut tx, &org_id, me, OrgRole::Member).await?;
    let theirs = orgs::member_role(&mut tx, &org_id, &target)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target != me
        && (mine < OrgRole::Admin || (theirs == OrgRole::Owner && mine != OrgRole::Owner))
    {
        return Err(ApiError::Forbidden);
    }
    if theirs == OrgRole::Owner && orgs::owner_count(&mut tx, &org_id).await? == 1 {
        return Err(ApiError::BadRequest(
            "the last owner can't leave: make someone else an owner, or delete the organisation"
                .into(),
        ));
    }
    orgs::remove_member(&mut tx, &org_id, &target).await?;
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    if !query.orphan_vaults {
        refuse_orphans(&reconciled)?;
    }
    let event = if target == me {
        "member-left"
    } else {
        "member-removed"
    };
    orgs::record_event(&mut tx, &org_id, me, event, target_email.as_deref(), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    if target != me
        && let Some(email) = target_email
    {
        state.send_email(&email, Email::OrgRemoved);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/groups", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgGroupsResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list_groups(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgGroupsResponse>> {
    let org_id = validate::id("orgId", &org_id)?;
    mine(&state, &org_id, &session.account_id, OrgRole::Admin).await?;
    Ok(Json(OrgGroupsResponse {
        groups: orgs::groups(&state.db, &org_id).await?,
    }))
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/groups", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = CreateOrgGroupRequest,
    responses(
        (status = 201, body = OrgGroupRecord),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: a group with this name or id"),
    )
)]
pub async fn create_group(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<CreateOrgGroupRequest>,
) -> ApiResult<(StatusCode, Json<OrgGroupRecord>)> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let id = validate::id("id", &request.id)?;
    let name = validate::text("name", &request.name, MAX_NAME)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    orgs::create_group(&mut tx, &org_id, &id, &name, now)
        .await
        .map_err(unique_violation_as(ApiError::AlreadyExists(
            "a group with this name already exists",
        )))?;
    orgs::record_event(&mut tx, &org_id, me, "group-created", Some(&name), now).await?;
    tx.commit().await?;
    let group = OrgGroupRecord {
        id,
        name,
        members: Vec::new(),
        created_at: db::rfc3339(now),
    };
    Ok((StatusCode::CREATED, Json(group)))
}

#[utoipa::path(
    patch, path = "/v1/orgs/{orgId}/groups/{groupId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("groupId" = String, Path)),
    request_body = RenameOrgGroupRequest,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: a group with this name"),
    )
)]
pub async fn rename_group(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, group)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<RenameOrgGroupRequest>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let group = group_id(&group)?;
    let name = validate::text("name", &request.name, MAX_NAME)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let renamed = orgs::rename_group(&mut tx, &org_id, &group, &name)
        .await
        .map_err(unique_violation_as(ApiError::AlreadyExists(
            "a group with this name already exists",
        )))?;
    if !renamed {
        return Err(ApiError::NotFound);
    }
    orgs::record_event(
        &mut tx,
        &org_id,
        me,
        "group-renamed",
        Some(&name),
        db::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/groups/{groupId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("groupId" = String, Path)),
    responses(
        (status = 204, description = "Deleted. Its members lost the vaults only it gave them."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned"),
    )
)]
pub async fn delete_group(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, group)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let group = group_id(&group)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let name = orgs::group_name(&mut tx, &org_id, &group)
        .await?
        .ok_or(ApiError::NotFound)?;
    orgs::delete_group(&mut tx, &group).await?;
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    refuse_orphans(&reconciled)?;
    orgs::record_event(&mut tx, &org_id, me, "group-deleted", Some(&name), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put, path = "/v1/orgs/{orgId}/groups/{groupId}/members/{accountId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("groupId" = String, Path), ("accountId" = String, Path)),
    responses(
        (status = 204, description = "Added. They get the group's vaults when a key holder applies access."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such group, or not a member of the organisation"),
    )
)]
pub async fn add_group_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, group, account_id)): ApiPath<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let group = group_id(&group)?;
    let target = validate::id("accountId", &account_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let name = orgs::group_name(&mut tx, &org_id, &group)
        .await?
        .ok_or(ApiError::NotFound)?;
    orgs::member_role(&mut tx, &org_id, &target)
        .await?
        .ok_or(ApiError::NotFound)?;
    orgs::add_to_group(&mut tx, &group, &target).await?;
    let subject = format!("{name}: {target}");
    let (event, now) = ("group-member-added", db::now());
    orgs::record_event(&mut tx, &org_id, me, event, Some(&subject), now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/groups/{groupId}/members/{accountId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("groupId" = String, Path), ("accountId" = String, Path)),
    responses(
        (status = 204, description = "Removed. They lost the vaults only this group gave them."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned"),
    )
)]
pub async fn remove_group_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, group, account_id)): ApiPath<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let group = group_id(&group)?;
    let target = validate::id("accountId", &account_id)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let name = orgs::group_name(&mut tx, &org_id, &group)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !orgs::remove_from_group(&mut tx, &group, &target).await? {
        return Err(ApiError::NotFound);
    }
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    refuse_orphans(&reconciled)?;
    let subject = format!("{name}: {target}");
    let event = "group-member-removed";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&subject), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/vaults", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgVaultsResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list_vaults(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgVaultsResponse>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    mine(&state, &org_id, me, OrgRole::Admin).await?;
    Ok(Json(OrgVaultsResponse {
        vaults: orgs::vaults(&state.db, &org_id, me).await?,
    }))
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/vaults", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = CreateVaultRequest,
    responses(
        (status = 201, body = VaultRecord, description = "A shared vault belonging to the organisation, owned by the signed-in account"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-exists"),
    )
)]
pub async fn create_vault(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<CreateVaultRequest>,
) -> ApiResult<(StatusCode, Json<VaultRecord>)> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    validate_new_vault("body", &request, me)?;
    let sign_key = public_sign_key(&state, me).await?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    insert_vault(&mut tx, "shared", &request, &sign_key, now).await?;
    orgs::adopt_vault(&mut tx, &org_id, &request.id, me).await?;
    orgs::record_event(
        &mut tx,
        &org_id,
        me,
        "vault-created",
        Some(&request.id),
        now,
    )
    .await?;
    tx.commit().await?;
    state.membership_changed(&request.id, &[]).await;
    let mut record = new_vault_record(VaultType::Shared, &request, sign_key);
    record.org_id = Some(org_id);
    Ok((StatusCode::CREATED, Json(record)))
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/vaults/{vaultId}", tag = "organisations",
    security(("bearer" = [])),
    params(
        ("orgId" = String, Path),
        ("vaultId" = String, Path),
        ("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose organisation"),
    ),
    responses(
        (status = 204, description = "The vault and everything in it were deleted. This needs no key: it's how an organisation clears a vault nobody can open."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can; reauth-required"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_vault(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiPath((org_id, vault_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let vault_id = validate::id("vaultId", &vault_id)?;
    let now = db::now();
    let members = db::items::members(&state.db, &vault_id).await?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    if !orgs::has_vault(&mut tx, &org_id, &vault_id).await? {
        return Err(ApiError::NotFound);
    }
    consume_reauth(&mut tx, &headers, me, now).await?;
    sharing::delete_vault(&mut tx, &vault_id).await?;
    orgs::record_event(&mut tx, &org_id, me, "vault-deleted", Some(&vault_id), now).await?;
    tx.commit().await?;
    crate::storage::drain_soon(&state);
    state.membership_changed(&vault_id, &members).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put, path = "/v1/orgs/{orgId}/vaults/{vaultId}/groups/{groupId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("vaultId" = String, Path), ("groupId" = String, Path)),
    request_body = OrgVaultGroupUpdate,
    responses(
        (status = 204, description = "Linked. Its members get the vault when a key holder applies access."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The role must be read, write or manage"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned"),
    )
)]
pub async fn link_group(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, vault_id, group)): ApiPath<(String, String, String)>,
    ApiJson(request): ApiJson<OrgVaultGroupUpdate>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let vault_id = validate::id("vaultId", &vault_id)?;
    let group = group_id(&group)?;
    if request.role == VaultRole::Owner {
        return Err(ApiError::BadRequest(
            "a group's role must be read, write or manage".into(),
        ));
    }
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let name = orgs::group_name(&mut tx, &org_id, &group)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !orgs::has_vault(&mut tx, &org_id, &vault_id).await? {
        return Err(ApiError::NotFound);
    }
    orgs::link_group(&mut tx, &vault_id, &group, request.role).await?;
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    refuse_orphans(&reconciled)?;
    let subject = format!("{vault_id}: {name}, {}", request.role.as_str());
    let event = "vault-group-linked";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&subject), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/vaults/{vaultId}/groups/{groupId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("vaultId" = String, Path), ("groupId" = String, Path)),
    responses(
        (status = 204, description = "Unlinked. Members who had the vault only through this group lost it."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "org-vault-orphaned"),
    )
)]
pub async fn unlink_group(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, vault_id, group)): ApiPath<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let vault_id = validate::id("vaultId", &vault_id)?;
    let group = group_id(&group)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Admin).await?;
    let name = orgs::group_name(&mut tx, &org_id, &group)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !orgs::has_vault(&mut tx, &org_id, &vault_id).await?
        || !orgs::unlink_group(&mut tx, &vault_id, &group).await?
    {
        return Err(ApiError::NotFound);
    }
    let reconciled = orgs::reconcile(&mut tx, &org_id, now).await?;
    refuse_orphans(&reconciled)?;
    let subject = format!("{vault_id}: {name}");
    let event = "vault-group-unlinked";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&subject), now).await?;
    tx.commit().await?;
    notify(&state, &reconciled).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/access", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgAccessResponse, description = "What vaults are waiting for from a key holder. \
            This comes from the server: show every person and a fingerprint computed on the device to a person, \
            and seal nothing without their confirmation."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn access(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgAccessResponse>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    mine(&state, &org_id, me, OrgRole::Member).await?;
    let mut conn = state.db.acquire().await?;
    let admin = orgs::member_role(&mut conn, &org_id, me)
        .await?
        .is_some_and(|role| role >= OrgRole::Admin);
    drop(conn);
    Ok(Json(OrgAccessResponse {
        vaults: orgs::access_plan(&state.db, &org_id, me, admin).await?,
    }))
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/vaults/{vaultId}/grants", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("vaultId" = String, Path)),
    request_body = OrgVaultGrantsRequest,
    responses(
        (status = 204, description = "Stored"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "A grant doesn't match what the organisation entitles"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role on the vault (owner to grant owner)"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-key-changed"),
    )
)]
pub async fn grant_access(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, vault_id)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<OrgVaultGrantsRequest>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let vault_id = validate::id("vaultId", &vault_id)?;
    validate::exact_bytes("keyId", &request.key_id, validate::KEY_ID_LEN)?;
    for (i, grant) in request.grants.iter().enumerate() {
        own_grant(&format!("grants[{i}]"), grant, &vault_id, me)?;
    }
    let sign_key = public_sign_key(&state, me).await?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Member).await?;
    sharing::lock_vault(&mut tx, &vault_id).await?;
    let vault = sharing::membership(&mut tx, &vault_id, me)
        .await?
        .filter(|vault| vault.org_id.as_deref() == Some(&org_id))
        .ok_or(ApiError::NotFound)?;
    if vault.role < VaultRole::Manage {
        return Err(ApiError::Forbidden);
    }
    current_key(&mut tx, &vault_id, Some(&request.key_id)).await?;
    let entitled = orgs::entitlements(&mut tx, &org_id, &vault_id).await?;
    let mut seen = std::collections::HashSet::new();
    for grant in &request.grants {
        if entitled.get(&grant.recipient_account_id) != Some(&grant.role) {
            return Err(ApiError::BadRequest(
                "every grant must be for someone the organisation entitles, with that role".into(),
            ));
        }
        if grant.role == VaultRole::Owner && vault.role != VaultRole::Owner {
            return Err(ApiError::Forbidden);
        }
        if !seen.insert(grant.recipient_account_id.as_str()) {
            return Err(ApiError::BadRequest("one grant per person".into()));
        }
    }
    orgs::store_grants(&mut tx, &request.grants, &sign_key, now).await?;
    let event = "access-granted";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&vault_id), now).await?;
    tx.commit().await?;
    state.membership_changed(&vault_id, &[]).await;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_policies(policies: &OrgPolicies) -> ApiResult<()> {
    if policies.sso_max_age_hours > MAX_SSO_AGE_HOURS {
        return Err(ApiError::BadRequest(format!(
            "ssoMaxAgeHours must be 0 to {MAX_SSO_AGE_HOURS}"
        )));
    }
    if policies
        .max_auto_lock_minutes
        .is_some_and(|minutes| !(1..=MAX_AUTO_LOCK_MINUTES).contains(&minutes))
    {
        return Err(ApiError::BadRequest(format!(
            "maxAutoLockMinutes must be 1 to {MAX_AUTO_LOCK_MINUTES}"
        )));
    }
    if policies
        .min_password_length
        .is_some_and(|length| !MIN_PASSWORD_LENGTH.contains(&length))
    {
        return Err(ApiError::BadRequest(format!(
            "minPasswordLength must be {} to {}",
            MIN_PASSWORD_LENGTH.start(),
            MIN_PASSWORD_LENGTH.end()
        )));
    }
    Ok(())
}

#[utoipa::path(
    put, path = "/v1/orgs/{orgId}/policies", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = OrgPolicies,
    responses(
        (status = 200, body = OrgPolicies),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Out of range, or requireSso without a finished test sign-in"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn put_policies(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(policies): ApiJson<OrgPolicies>,
) -> ApiResult<Json<OrgPolicies>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    validate_policies(&policies)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    if policies.require_sso && orgs::tested_at(&mut tx, &org_id).await?.is_none() {
        return Err(ApiError::SsoConfig(
            "finish a test sign-in with these settings before requiring SSO".into(),
        ));
    }
    orgs::set_policies(&mut tx, &org_id, &policies).await?;
    orgs::record_event(&mut tx, &org_id, me, "policies-changed", None, db::now()).await?;
    tx.commit().await?;
    Ok(Json(policies))
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/events", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgEventsResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only admins can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn events(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgEventsResponse>> {
    let org_id = validate::id("orgId", &org_id)?;
    mine(&state, &org_id, &session.account_id, OrgRole::Admin).await?;
    Ok(Json(OrgEventsResponse {
        events: orgs::events(&state.db, &org_id).await?,
    }))
}
