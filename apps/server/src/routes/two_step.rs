//! Two-step sign-in settings for the signed-in account. Every change that
//! adds, removes or reveals a method needs a fresh `two-step` reauth token.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use octapass_api::problem::Problem;
use octapass_api::{
    AddSecurityKeyRequest, REAUTH_TOKEN_HEADER, ReauthPurpose, RecoveryCodesResponse,
    SecondFactorMethod, SecurityEventType, SecurityKeyOptionsResponse, SecurityKeyRecord,
    TotpConfirmRequest, TotpConfirmResponse, TotpSetupResponse, TwoStepStatus,
    WebAuthnCreationOptions, WebAuthnRelyingParty, WebAuthnUser,
};

use crate::crypto::{base64url, random_bytes};
use crate::db::{self, Conn, accounts, audit, sessions, two_step as two_step_db};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated};
use crate::mail::Email;
use crate::routes::auth::WEBAUTHN_TIMEOUT_MS;
use crate::state::AppState;
use crate::two_step::{self, totp, webauthn};
use crate::validate;

const SETUP_TTL: i64 = 10 * 60 * 1000;
const TOTP_SETUP: &str = "totp";
const WEBAUTHN_SETUP: &str = "webauthn";
const MAX_SECURITY_KEYS: usize = 10;
const ISSUER: &str = "Octa Pass";

fn reauth_token(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(ApiError::ReauthRequired)
}

/// Uses up the request's `two-step` reauth token inside `conn`'s transaction,
/// so a failed change leaves it usable.
async fn consume_reauth(
    conn: &mut Conn,
    headers: &HeaderMap,
    account_id: &str,
    now: i64,
) -> ApiResult<()> {
    let token = reauth_token(headers)?;
    let purpose = ReauthPurpose::TwoStep.as_str();
    if !sessions::consume_reauth_token(conn, token, account_id, purpose, now).await? {
        return Err(ApiError::ReauthRequired);
    }
    Ok(())
}

async fn email_of(state: &AppState, account_id: &str) -> ApiResult<String> {
    accounts::find_by_id(&state.db, account_id)
        .await?
        .map(|account| account.email)
        .ok_or(ApiError::Unauthorized)
}

/// Stores fresh recovery codes, replacing the old ones, and returns them.
async fn new_recovery_codes(
    state: &AppState,
    conn: &mut Conn,
    account_id: &str,
) -> ApiResult<Vec<String>> {
    let codes = two_step::new_recovery_codes();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| two_step::recovery_code_hash(&state.secrets, account_id, code))
        .collect();
    two_step_db::replace_recovery_codes(conn, account_id, &hashes).await?;
    Ok(codes)
}

#[utoipa::path(
    get, path = "/v1/account/two-step", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, body = TwoStepStatus),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn status(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<Json<TwoStepStatus>> {
    let account_id = &session.account_id;
    let enabled = two_step_db::is_enabled(&state.db, account_id).await?;
    let keys = two_step_db::security_keys(&state.db, account_id).await?;
    let mut methods = Vec::new();
    if enabled {
        methods.push(SecondFactorMethod::Totp);
        if !keys.is_empty() {
            methods.push(SecondFactorMethod::Webauthn);
        }
        methods.push(SecondFactorMethod::RecoveryCode);
    }
    let left = two_step_db::recovery_codes_left(&state.db, account_id).await?;
    Ok(Json(TwoStepStatus {
        enabled,
        methods,
        security_keys: keys
            .iter()
            .map(two_step_db::SecurityKeyRow::record)
            .collect(),
        recovery_codes_left: u32::try_from(left).unwrap_or(0),
        rp_id: state.config.webauthn_rp_id.clone(),
    }))
}

#[utoipa::path(
    post, path = "/v1/account/two-step/totp", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose two-step")),
    responses(
        (status = 200, body = TotpSetupResponse, description = "A new authenticator secret. Nothing changes until a code from it is confirmed."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn start_totp(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> ApiResult<Json<TotpSetupResponse>> {
    let account_id = &session.account_id;
    let email = email_of(&state, account_id).await?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    consume_reauth(&mut tx, &headers, account_id, now).await?;
    tx.commit().await?;

    let secret = random_bytes::<{ totp::SECRET_LEN }>();
    let sealed = two_step::seal(&state.secrets, account_id, &secret);
    let setup_id =
        two_step_db::insert_setup(&state.db, account_id, TOTP_SETUP, &sealed, now + SETUP_TTL)
            .await?;
    Ok(Json(TotpSetupResponse {
        setup_id,
        secret: totp::base32(&secret),
        otpauth_uri: totp::otpauth_uri(&secret, ISSUER, &email),
        expires_in: (SETUP_TTL / 1000) as u64,
    }))
}

#[utoipa::path(
    post, path = "/v1/account/two-step/totp/confirm", tag = "account",
    security(("bearer" = [])),
    request_body = TotpConfirmRequest,
    responses(
        (status = 200, body = TotpConfirmResponse, description = "Two-step sign-in is on with this authenticator. Recovery codes come back only when it was off."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The setup is unknown or expired: start again"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "invalid-second-factor: the code is wrong, try again"),
    )
)]
pub async fn confirm_totp(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<TotpConfirmRequest>,
) -> ApiResult<Json<TotpConfirmResponse>> {
    let account_id = &session.account_id;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    let sealed = two_step_db::find_setup(&mut tx, &request.setup_id, account_id, TOTP_SETUP, now)
        .await?
        .ok_or_else(|| ApiError::BadRequest("this setup expired: start again".into()))?;
    let secret = two_step::open(&state.secrets, account_id, &sealed)
        .ok_or_else(|| ApiError::internal("a pending authenticator secret doesn't open"))?;
    let step = totp::verify(&secret, &request.code, state.clock.now(), i64::MIN)
        .ok_or(ApiError::InvalidSecondFactor)?;
    if !two_step_db::delete_setup(&mut tx, &request.setup_id).await? {
        return Err(ApiError::BadRequest(
            "this setup expired: start again".into(),
        ));
    }
    let turned_on = two_step_db::set_totp(&mut tx, account_id, &sealed, step, now).await?;
    if turned_on {
        // Devices trusted while it was off would skip the step it now adds.
        two_step_db::forget_devices(&mut *tx, account_id, Some(&session.device_id)).await?;
    }
    let recovery_codes = if turned_on {
        Some(new_recovery_codes(&state, &mut tx, account_id).await?)
    } else {
        None
    };
    let event = if turned_on {
        SecurityEventType::TwoStepEnabled
    } else {
        SecurityEventType::AuthenticatorChanged
    };
    audit::record(&mut *tx, account_id, event, None, None, state.clock.now()).await?;
    tx.commit().await?;
    if turned_on {
        state.send_email(&email_of(&state, account_id).await?, Email::TwoStepEnabled);
    }
    Ok(Json(TotpConfirmResponse { recovery_codes }))
}

#[utoipa::path(
    post, path = "/v1/account/two-step/recovery-codes", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose two-step")),
    responses(
        (status = 200, body = RecoveryCodesResponse, description = "New codes; every earlier one stops working"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Two-step sign-in is off"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn renew_recovery_codes(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> ApiResult<Json<RecoveryCodesResponse>> {
    let account_id = &session.account_id;
    if !two_step_db::is_enabled(&state.db, account_id).await? {
        return Err(ApiError::BadRequest("two-step sign-in is off".into()));
    }
    let now = db::now();
    let mut tx = state.db.begin().await?;
    consume_reauth(&mut tx, &headers, account_id, now).await?;
    let recovery_codes = new_recovery_codes(&state, &mut tx, account_id).await?;
    let event = SecurityEventType::RecoveryCodesRenewed;
    audit::record(&mut *tx, account_id, event, None, None, state.clock.now()).await?;
    tx.commit().await?;
    Ok(Json(RecoveryCodesResponse { recovery_codes }))
}

#[utoipa::path(
    delete, path = "/v1/account/two-step", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose two-step")),
    responses(
        (status = 204, description = "Two-step sign-in is off: the authenticator, security keys and recovery codes are gone"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn disable(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let account_id = &session.account_id;
    let policies = db::orgs::policies_of(&state.db, account_id).await?;
    if policies.is_some_and(|policies| policies.require_two_step) {
        return Err(ApiError::OrgPolicy(
            "your organisation requires two-step sign-in",
        ));
    }
    let now = db::now();
    let mut tx = state.db.begin().await?;
    consume_reauth(&mut tx, &headers, account_id, now).await?;
    let was_on = turn_off(&state, &mut tx, account_id).await?;
    tx.commit().await?;
    if was_on {
        state.send_email(&email_of(&state, account_id).await?, Email::TwoStepDisabled);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/account/two-step/trusted-devices", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Every other device asks for the second step at its next sign-in. Sessions aren't touched: sign devices out with DELETE /v1/devices/{deviceId}."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn forget_trusted_devices(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<StatusCode> {
    let account_id = &session.account_id;
    let mut tx = state.db.begin().await?;
    two_step_db::forget_devices(&mut *tx, account_id, Some(&session.device_id)).await?;
    let event = SecurityEventType::TrustedDevicesForgotten;
    audit::record(&mut *tx, account_id, event, None, None, state.clock.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes every method and logs it. Shared with the admin command.
pub async fn turn_off(state: &AppState, conn: &mut Conn, account_id: &str) -> ApiResult<bool> {
    let was_on = two_step_db::disable(conn, account_id).await?;
    if was_on {
        let event = SecurityEventType::TwoStepDisabled;
        audit::record(&mut *conn, account_id, event, None, None, state.clock.now()).await?;
    }
    Ok(was_on)
}

#[utoipa::path(
    post, path = "/v1/account/two-step/security-keys/options", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose two-step")),
    responses(
        (status = 200, body = SecurityKeyOptionsResponse, description = "Options for navigator.credentials.create()"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Two-step sign-in is off (turn it on with an authenticator app first), or the account has the most keys allowed (10)"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn security_key_options(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> ApiResult<Json<SecurityKeyOptionsResponse>> {
    let account_id = &session.account_id;
    if !two_step_db::is_enabled(&state.db, account_id).await? {
        return Err(ApiError::BadRequest(
            "turn on two-step sign-in with an authenticator app first".into(),
        ));
    }
    let keys = two_step_db::security_keys(&state.db, account_id).await?;
    if keys.len() >= MAX_SECURITY_KEYS {
        return Err(ApiError::BadRequest(format!(
            "an account can have at most {MAX_SECURITY_KEYS} security keys"
        )));
    }
    let email = email_of(&state, account_id).await?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    consume_reauth(&mut tx, &headers, account_id, now).await?;
    tx.commit().await?;

    let challenge = base64url(random_bytes::<32>());
    let setup_id = two_step_db::insert_setup(
        &state.db,
        account_id,
        WEBAUTHN_SETUP,
        &challenge,
        now + SETUP_TTL,
    )
    .await?;
    Ok(Json(SecurityKeyOptionsResponse {
        setup_id,
        public_key: WebAuthnCreationOptions {
            challenge,
            rp: WebAuthnRelyingParty {
                id: state.config.webauthn_rp_id.clone(),
                name: ISSUER.into(),
            },
            user: WebAuthnUser {
                id: two_step::webauthn_user_id(&state.secrets, account_id),
                name: email.clone(),
                display_name: email,
            },
            algorithms: vec![webauthn::ES256, webauthn::EDDSA],
            exclude_credentials: keys.into_iter().map(|key| key.credential_id).collect(),
            timeout: WEBAUTHN_TIMEOUT_MS,
        },
    }))
}

#[utoipa::path(
    post, path = "/v1/account/two-step/security-keys", tag = "account",
    security(("bearer" = [])),
    request_body = AddSecurityKeyRequest,
    responses(
        (status = 200, body = SecurityKeyRecord),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The setup expired, the answer doesn't match it, or the key type isn't supported"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: this key is registered"),
    )
)]
pub async fn add_security_key(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<AddSecurityKeyRequest>,
) -> ApiResult<Json<SecurityKeyRecord>> {
    let account_id = &session.account_id;
    let name = validate::text("name", &request.name, 64)?;
    let client_data = validate::base64url("clientDataJson", &request.client_data_json, 16 * 1024)?;
    let attestation =
        validate::base64url("attestationObject", &request.attestation_object, 64 * 1024)?;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    let challenge =
        two_step_db::find_setup(&mut tx, &request.setup_id, account_id, WEBAUTHN_SETUP, now)
            .await?
            .ok_or_else(|| ApiError::BadRequest("this setup expired: start again".into()))?;
    if !two_step_db::delete_setup(&mut tx, &request.setup_id).await? {
        return Err(ApiError::BadRequest(
            "this setup expired: start again".into(),
        ));
    }
    let challenge = validate::base64url("challenge", &challenge, 64).map_err(ApiError::internal)?;
    let origins = state.config.webauthn_origins();
    let ceremony = webauthn::Ceremony {
        rp_id: &state.config.webauthn_rp_id,
        origins: &origins,
        challenge: &challenge,
    };
    let credential = ceremony
        .register(&client_data, &attestation)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let credential_id = base64url(&credential.id);
    if credential_id != request.credential_id {
        return Err(ApiError::BadRequest(
            "credentialId doesn't match the attestation".into(),
        ));
    }
    if !two_step_db::is_enabled(&state.db, account_id).await? {
        return Err(ApiError::BadRequest(
            "turn on two-step sign-in with an authenticator app first".into(),
        ));
    }
    let key = two_step_db::NewSecurityKey {
        account_id,
        credential_id: &credential_id,
        algorithm: credential.algorithm,
        public_key: &base64url(&credential.public_key),
        sign_count: i64::from(credential.sign_count),
        name: &name,
        now,
    };
    let id = two_step_db::insert_security_key(&mut tx, key)
        .await
        .map_err(|error| match error.as_database_error() {
            Some(db_error) if db_error.is_unique_violation() => {
                ApiError::AlreadyExists("this security key is already registered")
            }
            _ => error.into(),
        })?;
    let event = SecurityEventType::SecurityKeyAdded;
    audit::record(&mut *tx, account_id, event, None, None, state.clock.now()).await?;
    tx.commit().await?;
    Ok(Json(SecurityKeyRecord {
        id,
        name,
        created_at: db::rfc3339(now),
        last_used_at: None,
    }))
}

#[utoipa::path(
    delete, path = "/v1/account/two-step/security-keys/{id}", tag = "account",
    security(("bearer" = [])),
    params(
        ("id" = String, Path),
        ("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose two-step"),
    ),
    responses(
        (status = 204, description = "The key no longer works for signing in"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn remove_security_key(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let account_id = &session.account_id;
    let now = db::now();
    let mut tx = state.db.begin().await?;
    consume_reauth(&mut tx, &headers, account_id, now).await?;
    if !two_step_db::delete_security_key(&mut tx, account_id, &id).await? {
        return Err(ApiError::NotFound);
    }
    let event = SecurityEventType::SecurityKeyRemoved;
    audit::record(&mut *tx, account_id, event, None, None, state.clock.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
