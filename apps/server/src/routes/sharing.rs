//! Shared vaults: creating them, their members and key rotation, and looking
//! up the public keys a grant is sealed to. Keys are sealed and grants signed
//! on the clients; the server checks who may grant what, and stores them.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use octapass_api::problem::Problem;
use octapass_api::{
    AccountLookupResponse, CreateVaultRequest, Grant, InviteRequest, MemberRecord, MembersResponse,
    RevisionResponse, RotateVaultRequest, VaultGrant, VaultRecord, VaultRole, VaultType,
};
use serde::Deserialize;

use crate::crypto::fingerprint;
use crate::db::sharing::{self, RotateError};
use crate::db::{self, Conn, accounts, items, orgs};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, Authenticated};
use crate::push::PushKind;
use crate::state::AppState;
use crate::validate;

/// Lookups and invites by email share this budget per account: they're where
/// an email's existence shows.
pub fn charge_lookup(state: &AppState, account_id: &str) -> ApiResult<()> {
    state
        .lookup_limiter
        .check(account_id)
        .map_err(ApiError::RateLimited)
}

/// The signing key stored next to every grant an account gives.
pub async fn public_sign_key(state: &AppState, account_id: &str) -> ApiResult<String> {
    let account = accounts::find_by_id(&state.db, account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    Ok(account.into_bundle().public_sign_key)
}

/// A grant made by the signed-in account for `vault_id`.
pub fn own_grant(field: &str, grant: &Grant, vault_id: &str, account_id: &str) -> ApiResult<()> {
    validate::grant(field, grant)?;
    if grant.vault_id != vault_id {
        return Err(ApiError::BadRequest(format!(
            "{field}.vaultId must be {vault_id}"
        )));
    }
    if grant.granted_by != account_id {
        return Err(ApiError::BadRequest(format!(
            "{field}.grantedBy must be the signed-in account"
        )));
    }
    Ok(())
}

/// Refuses a grant of a vault key that has been rotated since, when the request names the key
/// it seals. Runs holding the vault's lock, so a rotation can't land between check and write.
pub async fn current_key(conn: &mut Conn, vault_id: &str, key_id: Option<&str>) -> ApiResult<()> {
    let Some(key_id) = key_id else {
        return Ok(());
    };
    if sharing::key_id(conn, vault_id).await?.as_deref() != Some(key_id) {
        return Err(ApiError::VaultKeyChanged(
            "this grant seals an old vault key: sync and grant again",
        ));
    }
    Ok(())
}

/// Checks the optional `keyId` of an invite.
pub fn validate_key_id(key_id: Option<&str>) -> ApiResult<()> {
    if let Some(key_id) = key_id {
        validate::exact_bytes("keyId", key_id, validate::KEY_ID_LEN)?;
    }
    Ok(())
}

/// Checks a new vault's request: the owner's own grant, by and to the
/// signed-in account.
pub fn validate_new_vault(
    field: &str,
    request: &CreateVaultRequest,
    account_id: &str,
) -> ApiResult<()> {
    validate::id(&format!("{field}.id"), &request.id)?;
    validate::exact_bytes(
        &format!("{field}.keyId"),
        &request.key_id,
        validate::KEY_ID_LEN,
    )?;
    own_grant(
        &format!("{field}.grant"),
        &request.grant,
        &request.id,
        account_id,
    )?;
    if request.grant.recipient_account_id != account_id || request.grant.role != VaultRole::Owner {
        return Err(ApiError::BadRequest(format!(
            "{field}.grant must give the signed-in account the owner role"
        )));
    }
    Ok(())
}

/// Creates a vault from a validated request, inside the caller's transaction. It writes first and
/// lets the primary key report an existing id: a read before the first write would leave a SQLite
/// transaction on a snapshot that any concurrent write makes stale (`SQLITE_BUSY_SNAPSHOT`, a 500).
pub async fn insert_vault(
    conn: &mut Conn,
    vault_type: &'static str,
    request: &CreateVaultRequest,
    sign_key: &str,
    now: i64,
) -> ApiResult<()> {
    sharing::create_vault(
        conn,
        vault_type,
        &request.key_id,
        &request.grant,
        sign_key,
        now,
    )
    .await
    .map_err(|error| match error.as_database_error() {
        Some(db_error) if db_error.is_unique_violation() => ApiError::VaultExists,
        _ => error.into(),
    })
}

/// The new vault as its owner's next sync will show it.
pub fn new_vault_record(
    vault_type: VaultType,
    request: &CreateVaultRequest,
    sign_key: String,
) -> VaultRecord {
    let grant = &request.grant;
    VaultRecord {
        id: request.id.clone(),
        vault_type,
        revision: 0,
        wrapped_vault_key: grant.wrapped_vault_key.clone(),
        role: VaultRole::Owner,
        key_id: Some(request.key_id.clone()),
        grant: Some(VaultGrant {
            granted_by: grant.granted_by.clone(),
            granter_public_sign_key: sign_key,
            granted_at: grant.granted_at,
            signature: grant.signature.clone(),
        }),
        org_id: None,
    }
}

#[utoipa::path(
    post, path = "/v1/vaults", tag = "sharing",
    security(("bearer" = [])),
    request_body = CreateVaultRequest,
    responses(
        (status = 201, body = VaultRecord, description = "The shared vault, owned by the signed-in account"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-exists"),
    )
)]
pub async fn create_vault(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<CreateVaultRequest>,
) -> ApiResult<(StatusCode, Json<VaultRecord>)> {
    validate_new_vault("body", &request, &session.account_id)?;
    let sign_key = public_sign_key(&state, &session.account_id).await?;
    let mut tx = state.db.begin().await?;
    insert_vault(&mut tx, "shared", &request, &sign_key, db::now()).await?;
    tx.commit().await?;
    state.membership_changed(&request.id, &[]).await;
    let record = new_vault_record(VaultType::Shared, &request, sign_key);
    Ok((StatusCode::CREATED, Json(record)))
}

#[utoipa::path(
    get, path = "/v1/vaults/{vaultId}/members", tag = "sharing",
    security(("bearer" = [])),
    params(("vaultId" = String, Path)),
    responses(
        (status = 200, body = MembersResponse),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such vault, or not a member"),
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(vault_id): ApiPath<String>,
) -> ApiResult<Json<MembersResponse>> {
    let vault_id = validate::id("vaultId", &vault_id)?;
    let mut conn = state.db.acquire().await?;
    sharing::membership(&mut conn, &vault_id, &session.account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);
    let members = sharing::members(&state.db, &vault_id)
        .await?
        .into_iter()
        .map(|row| MemberRecord {
            fingerprint: fingerprint(&row.public_enc_key, &row.public_sign_key),
            role: items::parse_role(&row.role),
            added_at: db::rfc3339(row.added_at),
            account_id: row.account_id,
            email: row.email,
            public_enc_key: row.public_enc_key,
            public_sign_key: row.public_sign_key,
            key_record: row.key_record.as_deref().map(accounts::key_record),
            granted_by: row.granted_by,
        })
        .collect();
    Ok(Json(MembersResponse { members }))
}

#[utoipa::path(
    post, path = "/v1/vaults/{vaultId}/members", tag = "sharing",
    security(("bearer" = [])),
    params(("vaultId" = String, Path)),
    request_body = InviteRequest,
    responses(
        (status = 202, description = "Accepted. The same answer whether or not the email has an account: only a \
            grant for the account with that email is stored."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role (owner to grant owner)"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-key-changed: `keyId` is no longer the vault's key"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn add_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(vault_id): ApiPath<String>,
    ApiJson(request): ApiJson<InviteRequest>,
) -> ApiResult<StatusCode> {
    charge_lookup(&state, &session.account_id)?;
    let me = session.account_id.as_str();
    let vault_id = validate::id("vaultId", &vault_id)?;
    let email = validate::email(&request.email)?;
    let grant = &request.grant;
    own_grant("grant", grant, &vault_id, me)?;
    validate_key_id(request.key_id.as_deref())?;
    if grant.recipient_account_id == me {
        return Err(ApiError::BadRequest(
            "you can't change your own grant".into(),
        ));
    }

    let recipient = accounts::find_by_email(&state.db, &email).await?;
    let sign_key = public_sign_key(&state, me).await?;
    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &vault_id).await?;
    let mine = sharing::membership(&mut tx, &vault_id, me)
        .await?
        .ok_or(ApiError::NotFound)?;
    if mine.vault_type != "shared" {
        return Err(ApiError::BadRequest(
            "only shared vaults take members this way; families invite through /v1/families".into(),
        ));
    }
    if mine.role < VaultRole::Manage
        || (grant.role == VaultRole::Owner && mine.role != VaultRole::Owner)
    {
        return Err(ApiError::Forbidden);
    }
    current_key(&mut tx, &vault_id, request.key_id.as_deref()).await?;
    // Everything above answers the same for any email. From here on an email
    // without an account, or a grant for someone else, quietly stores nothing.
    if recipient.is_none_or(|account| account.id != grant.recipient_account_id) {
        return Ok(StatusCode::ACCEPTED);
    }
    // An organisation vault only holds the organisation's members, and adding one directly is
    // remembered, so it outlasts their groups. Anyone else answers like an unknown email.
    if let Some(org_id) = &mine.org_id {
        let recipient = &grant.recipient_account_id;
        if orgs::member_role(&mut tx, org_id, recipient)
            .await?
            .is_none()
        {
            return Ok(StatusCode::ACCEPTED);
        }
        orgs::set_direct(&mut tx, &vault_id, recipient, grant.role).await?;
    }
    if let Some(theirs) =
        sharing::membership(&mut tx, &vault_id, &grant.recipient_account_id).await?
        && theirs.role == VaultRole::Owner
        && mine.role != VaultRole::Owner
    {
        return Err(ApiError::Forbidden);
    }
    let recipient_id = grant.recipient_account_id.clone();
    sharing::put_member(&mut tx, grant, &sign_key, db::now()).await?;
    tx.commit().await?;
    state.membership_changed(&vault_id, &[]).await;
    // Someone shared a vault with them: worth a notice, not only a quiet sync.
    state.wake(&recipient_id, PushKind::Alert);
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    delete, path = "/v1/vaults/{vaultId}/members/{accountId}", tag = "sharing",
    security(("bearer" = [])),
    params(("vaultId" = String, Path), ("accountId" = String, Path)),
    responses(
        (status = 204, description = "Removed. Rotate the vault key next (`POST /v1/vaults/{vaultId}/rotate`)."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The last owner can't leave"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role (owner to remove an owner)"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((vault_id, account_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let vault_id = validate::id("vaultId", &vault_id)?;
    let target = validate::id("accountId", &account_id)?;
    let mut tx = state.db.begin().await?;
    sharing::lock_vault(&mut tx, &vault_id).await?;
    let mine = sharing::membership(&mut tx, &vault_id, me)
        .await?
        .ok_or(ApiError::NotFound)?;
    match mine.vault_type.as_str() {
        "shared" => {}
        "family" => {
            return Err(ApiError::BadRequest(
                "family members leave, or are removed, through /v1/families".into(),
            ));
        }
        _ => return Err(ApiError::Forbidden),
    }
    let theirs = sharing::membership(&mut tx, &vault_id, &target)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target == me {
        if mine.role == VaultRole::Owner && sharing::owner_count(&mut tx, &vault_id).await? == 1 {
            return Err(ApiError::BadRequest(
                "the last owner can't leave: make someone else an owner first".into(),
            ));
        }
    } else if mine.role < VaultRole::Manage
        || (theirs.role == VaultRole::Owner && mine.role != VaultRole::Owner)
    {
        return Err(ApiError::Forbidden);
    }
    if let Some(org_id) = &mine.org_id {
        orgs::clear_direct(&mut tx, &vault_id, &target).await?;
        if orgs::entitlements(&mut tx, org_id, &vault_id)
            .await?
            .contains_key(&target)
        {
            return Err(ApiError::BadRequest(
                "this person has the vault through a group or as an organisation owner: \
                 change that instead"
                    .into(),
            ));
        }
        orgs::mark_rotation(&mut tx, &vault_id, db::now()).await?;
    }
    sharing::remove_member(&mut tx, &vault_id, &target).await?;
    tx.commit().await?;
    state.membership_changed(&vault_id, &[target]).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/vaults/{vaultId}/rotate", tag = "sharing",
    security(("bearer" = [])),
    params(("vaultId" = String, Path)),
    request_body = RotateVaultRequest,
    responses(
        (status = 200, body = RevisionResponse, description = "The new key is in place; every item has the new revision. \
            Pending family invites hold the new key, or were cancelled if `invites` left them out. Vault-scoped \
            emergency contacts are `keyStale` until the grantor renews them."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Grants or items don't cover the vault exactly, \
            an invite grant isn't for a pending invite, or `wrappedVaultKey` doesn't fit the vault (personal vaults need it, others can't have it)"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Needs the manage role"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "vault-changed: sync and rotate again"),
        (status = 413, body = Problem, content_type = "application/problem+json", description = "Body over 16 MiB"),
    )
)]
pub async fn rotate_vault(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(vault_id): ApiPath<String>,
    ApiJson(request): ApiJson<RotateVaultRequest>,
) -> ApiResult<Json<RevisionResponse>> {
    let me = session.account_id.as_str();
    let vault_id = validate::id("vaultId", &vault_id)?;
    validate::exact_bytes("keyId", &request.key_id, validate::KEY_ID_LEN)?;
    for (i, grant) in request.grants.iter().enumerate() {
        own_grant(&format!("grants[{i}]"), grant, &vault_id, me)?;
    }
    for (i, grant) in request.invites.iter().enumerate() {
        own_grant(&format!("invites[{i}]"), grant, &vault_id, me)?;
    }
    for (i, grant) in request.service_grants.iter().enumerate() {
        own_grant(&format!("serviceGrants[{i}]"), grant, &vault_id, me)?;
    }
    if let Some(wrapped) = &request.wrapped_vault_key {
        validate::envelope("wrappedVaultKey", wrapped, super::vaults::MAX_ITEM_KEY)?;
    }
    for (i, item) in request.items.iter().enumerate() {
        let field = format!("items[{i}].encryptedItemKey");
        validate::id(&format!("items[{i}].itemId"), &item.item_id)?;
        validate::envelope(
            &field,
            &item.encrypted_item_key,
            super::vaults::MAX_ITEM_KEY,
        )?;
        if validate::envelope_key_id(&item.encrypted_item_key).as_deref() != Some(&request.key_id) {
            return Err(ApiError::BadRequest(format!(
                "{field} must be wrapped under the new key"
            )));
        }
    }

    let mut conn = state.db.acquire().await?;
    let mine = sharing::membership(&mut conn, &vault_id, me)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);
    if mine.role < VaultRole::Manage {
        return Err(ApiError::Forbidden);
    }
    let sign_key = public_sign_key(&state, me).await?;
    let revision = sharing::rotate(&state.db, &vault_id, me, &request, &sign_key, db::now())
        .await
        .map_err(|error| match error {
            RotateError::VaultChanged => ApiError::VaultChanged,
            RotateError::Forbidden => ApiError::Forbidden,
            RotateError::Invalid(reason) => ApiError::BadRequest(reason),
            RotateError::Db(error) => error.into(),
        })?;
    if mine.org_id.is_some() {
        orgs::rotation_done(&state.db, &vault_id).await?;
    }
    state.vault_changed(&vault_id, revision).await;
    state.membership_changed(&vault_id, &[]).await;
    Ok(Json(RevisionResponse { revision }))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LookupQuery {
    email: String,
}

#[utoipa::path(
    get, path = "/v1/accounts/lookup", tag = "sharing",
    security(("bearer" = [])),
    params(LookupQuery),
    responses(
        (status = 200, body = AccountLookupResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No account with that email"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "Shared budget with invites, per account"),
    )
)]
pub async fn lookup(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiQuery(query): ApiQuery<LookupQuery>,
) -> ApiResult<Json<AccountLookupResponse>> {
    charge_lookup(&state, &session.account_id)?;
    let email = validate::email(&query.email)?;
    let account = accounts::find_by_email(&state.db, &email)
        .await?
        .ok_or(ApiError::NotFound)?
        .into_bundle();
    Ok(Json(AccountLookupResponse {
        fingerprint: fingerprint(&account.public_enc_key, &account.public_sign_key),
        account_id: account.account_id.unwrap_or_default(),
        email: account.email,
        public_enc_key: account.public_enc_key,
        public_sign_key: account.public_sign_key,
        key_record: account.key_record,
    }))
}
