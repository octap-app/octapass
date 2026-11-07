//! A new master password: changed while signed in, or reset with the recovery
//! code (plan 03, Recovery).
//!
//! Either way the ASK stays the same: the client sends a new OPAQUE record and
//! the ASK wrapped for the new password, and the server swaps them in. A reset
//! has no session, so the client proves it opened the ASK by signing the new
//! credentials with the account's Ed25519 key, which only the ASK unwraps. That
//! keeps someone who can read the account's email, but has no recovery code,
//! from replacing its credentials.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use ed25519_dalek::{Signature, VerifyingKey};
use octapass_api::problem::Problem;
use octapass_api::{
    ChangePasswordRequest, CredentialsUpdate, PasswordRegistrationRequest,
    PasswordRegistrationResponse, REAUTH_TOKEN_HEADER, ReauthPurpose, RecoverFinishRequest,
    RecoverStartRequest, RecoverStartResponse, RecoverVerifyRequest, RecoverVerifyResponse,
    SecurityEventType,
};
use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration};

use crate::crypto::{
    Suite, base64url, constant_time_eq, keyed_hash, random_bytes, random_token, six_digit_code,
};
use crate::db::{self, accounts, audit, sessions};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, Authenticated, ClientIp};
use crate::login::PendingRecovery;
use crate::mail::Email;
use crate::routes::auth::{
    CODES_PER_DAY, FAILURES_PER_DAY, MAX_KEY_ENVELOPE, MAX_VERIFICATION_ATTEMPTS, charge,
    opaque_message, until_tomorrow,
};
use crate::state::AppState;
use crate::validate::{self, ACCOUNT_SALT_LEN};

const RECOVERY_LABEL: &[u8] = b"openpass/v1/account-recovery\0";

fn reset_code_hash(state: &AppState, email: &str, code: &str) -> [u8; 32] {
    keyed_hash(
        &*state.secrets.hmac_key,
        "openpass/reset-code",
        format!("{email}\0{code}").as_bytes(),
    )
}

/// The OPAQUE registration for a new password. Like `register/start`, it
/// stores nothing.
pub fn registration_response(state: &AppState, email: &str, request: &str) -> ApiResult<String> {
    let request = opaque_message(
        "registrationRequest",
        request,
        RegistrationRequest::<Suite>::deserialize,
    )?;
    let started =
        ServerRegistration::<Suite>::start(&state.secrets.opaque_setup, request, email.as_bytes())
            .map_err(|_| {
                ApiError::BadRequest("registrationRequest is not a valid OPAQUE message".into())
            })?;
    Ok(base64url(started.message.serialize()))
}

/// Checks the new credentials and returns the OPAQUE record to store.
pub fn new_credentials(
    registration_upload: &str,
    update: &CredentialsUpdate,
    recovery_required: bool,
) -> ApiResult<String> {
    validate::kdf(&update.kdf)?;
    validate::exact_bytes(
        "account.accountSalt",
        &update.account_salt,
        ACCOUNT_SALT_LEN,
    )?;
    validate::envelope("account.wrappedAsk", &update.wrapped_ask, MAX_KEY_ENVELOPE)?;
    match &update.recovery_wrapped_ask {
        Some(wrapped) => {
            validate::envelope("account.recoveryWrappedAsk", wrapped, MAX_KEY_ENVELOPE)?;
        }
        None if recovery_required => {
            return Err(ApiError::BadRequest(
                "a reset must replace account.recoveryWrappedAsk".into(),
            ));
        }
        None => {}
    }
    let upload = opaque_message(
        "registrationUpload",
        registration_upload,
        RegistrationUpload::<Suite>::deserialize,
    )?;
    Ok(base64url(
        ServerRegistration::<Suite>::finish(upload).serialize(),
    ))
}

/// Swaps in the new credentials and signs out every device but `keep`, in one
/// transaction, then closes the signed-out devices' live connections.
async fn replace_credentials(
    state: &AppState,
    account_id: &str,
    opaque_record: &str,
    update: &CredentialsUpdate,
    keep: Option<&str>,
    event: SecurityEventType,
    reauth: Option<(&str, &str)>,
) -> ApiResult<()> {
    let now = db::now();
    let mut tx = state.db.begin().await?;
    // A write first, so on SQLite this transaction holds the write lock from the start.
    if let Some((token, purpose)) = reauth
        && !sessions::consume_reauth_token(&mut tx, token, account_id, purpose, now).await?
    {
        return Err(ApiError::ReauthRequired);
    }
    accounts::replace_credentials(&mut tx, account_id, opaque_record, update).await?;
    let revoked = sessions::revoke_other_devices(&mut tx, account_id, keep, now).await?;
    audit::record(&mut *tx, account_id, event, None, None, now).await?;
    tx.commit().await?;
    for device_id in revoked {
        state.session_revoked(account_id, &device_id);
    }
    Ok(())
}

// ---------- Changing it while signed in ----------

#[utoipa::path(
    post, path = "/v1/account/password/registration", tag = "account",
    security(("bearer" = [])),
    request_body = PasswordRegistrationRequest,
    responses(
        (status = 200, body = PasswordRegistrationResponse, description = "The OPAQUE registration response for the new master password. Nothing is stored."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn change_registration(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<PasswordRegistrationRequest>,
) -> ApiResult<Json<PasswordRegistrationResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let account = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let registration_response =
        registration_response(&state, &account.email, &request.registration_request)?;
    Ok(Json(PasswordRegistrationResponse {
        registration_response,
    }))
}

#[utoipa::path(
    put, path = "/v1/account/password", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose change-password")),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "The new master password is in place. Every other device was signed out."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    let token = headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(ApiError::ReauthRequired)?;
    let opaque_record = new_credentials(&request.registration_upload, &request.account, false)?;
    let email = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .email;
    replace_credentials(
        &state,
        &session.account_id,
        &opaque_record,
        &request.account,
        Some(&session.device_id),
        SecurityEventType::PasswordChanged,
        Some((token, ReauthPurpose::ChangePassword.as_str())),
    )
    .await?;
    state.send_email(&email, Email::PasswordChanged);
    tracing::info!("master password changed");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put, path = "/v1/account/secret-key", tag = "account",
    security(("bearer" = [])),
    params(("X-Reauth-Token" = String, Header, description = "From /v1/auth/reauth/finish with purpose rotate-secret-key")),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "The new Secret Key is in place, with the same master password. The recovery code stays unless the request replaced it. Every other device was signed out."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "reauth-required"),
    )
)]
pub async fn rotate_secret_key(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    let token = headers
        .get(REAUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(ApiError::ReauthRequired)?;
    let opaque_record = new_credentials(&request.registration_upload, &request.account, false)?;
    let email = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .email;
    replace_credentials(
        &state,
        &session.account_id,
        &opaque_record,
        &request.account,
        Some(&session.device_id),
        SecurityEventType::SecretKeyRotated,
        Some((token, ReauthPurpose::RotateSecretKey.as_str())),
    )
    .await?;
    state.send_email(&email, Email::SecretKeyRotated);
    tracing::info!("secret key rotated");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Resetting it with the recovery code ----------

#[utoipa::path(
    post, path = "/v1/auth/recover/start", tag = "auth",
    request_body = RecoverStartRequest,
    responses(
        (status = 200, body = RecoverStartResponse, description = "A 6-digit code was emailed if the email has an account. The response is the same either way."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "email-unavailable"),
    )
)]
pub async fn recover_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RecoverStartRequest>,
) -> ApiResult<Json<RecoverStartResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let email = validate::email(&request.email)?;
    if !state.config.can_deliver_codes() {
        return Err(ApiError::EmailUnavailable);
    }
    charge(&state.signup_limiter, &format!("recover\0{email}"))?;
    let now = db::now();
    let counter_key = state.recovery_counter_key(&email);
    if !accounts::count_code_sent(&state.db, &counter_key, &db::utc_day(now), CODES_PER_DAY).await?
    {
        return Err(ApiError::RateLimited(until_tomorrow(now)));
    }

    let code = six_digit_code();
    let account_id = accounts::find_by_email(&state.db, &email)
        .await?
        .map(|account| account.id);
    if account_id.is_some() {
        state.send_email(&email, Email::PasswordResetCode(code.clone()));
    }
    let recovery_id = random_token();
    let pending = PendingRecovery {
        account_id,
        code_hash: reset_code_hash(&state, &email, &code),
        email,
        failures: 0,
        challenge: None,
    };
    state
        .pending_recoveries
        .insert(recovery_id.clone(), &ip, pending);
    Ok(Json(RecoverStartResponse {
        recovery_id,
        dev_verification_code: state.config.dev_mode.then_some(code),
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/recover/verify", tag = "auth",
    request_body = RecoverVerifyRequest,
    responses(
        (status = 200, body = RecoverVerifyResponse, description = "The account bundle, for the recovery code to open, and the challenge to sign"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "invalid-verification-code (try again), or recovery-expired (start again)"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn recover_verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RecoverVerifyRequest>,
) -> ApiResult<Json<RecoverVerifyResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let (mut pending, expires) = state
        .pending_recoveries
        .take_until(&request.recovery_id)
        .ok_or(ApiError::RecoveryExpired)?;
    let now = db::now();
    let (counter_key, day) = (state.recovery_counter_key(&pending.email), db::utc_day(now));
    let code = request.verification_code.trim();
    let code_ok = accounts::failures_today(&state.db, &counter_key, &day).await? < FAILURES_PER_DAY
        && constant_time_eq(
            &pending.code_hash,
            &reset_code_hash(&state, &pending.email, code),
        );
    let account = match &pending.account_id {
        Some(id) if code_ok => accounts::find_by_id(&state.db, id).await?,
        _ => None,
    };
    let Some(account) = account else {
        accounts::count_failure(&state.db, &counter_key, &day).await?;
        pending.failures += 1;
        if pending.failures < u32::try_from(MAX_VERIFICATION_ATTEMPTS).unwrap_or(5) {
            state
                .pending_recoveries
                .reinsert(request.recovery_id, &ip, pending, expires);
        }
        return Err(ApiError::InvalidVerificationCode);
    };
    let challenge = *pending.challenge.get_or_insert_with(random_bytes::<32>);
    state
        .pending_recoveries
        .reinsert(request.recovery_id, &ip, pending, expires);
    Ok(Json(RecoverVerifyResponse {
        account: account.into_bundle(),
        challenge: base64url(challenge),
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/recover/registration", tag = "auth",
    request_body = PasswordRegistrationRequest,
    responses(
        (status = 200, body = PasswordRegistrationResponse, description = "The OPAQUE registration response for the new master password. Nothing is stored."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "recovery-expired: unknown, expired, or not verified yet"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn recover_registration(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<PasswordRegistrationRequest>,
) -> ApiResult<Json<PasswordRegistrationResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let recovery_id = request.recovery_id.ok_or(ApiError::RecoveryExpired)?;
    let (pending, expires) = state
        .pending_recoveries
        .take_until(&recovery_id)
        .ok_or(ApiError::RecoveryExpired)?;
    let verified = pending.challenge.is_some();
    let response = verified
        .then(|| registration_response(&state, &pending.email, &request.registration_request));
    state
        .pending_recoveries
        .reinsert(recovery_id, &ip, pending, expires);
    let registration_response = response.ok_or(ApiError::RecoveryExpired)??;
    Ok(Json(PasswordRegistrationResponse {
        registration_response,
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/recover/finish", tag = "auth",
    request_body = RecoverFinishRequest,
    responses(
        (status = 204, description = "The new master password and recovery code are in place. Every device was signed out: sign in with the new password."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "invalid-request, or recovery-expired (start again)"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "login-failed: the signature doesn't match the account. Start again."),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn recover_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RecoverFinishRequest>,
) -> ApiResult<StatusCode> {
    charge(&state.ip_limiter, &ip)?;
    let (pending, expires) = state
        .pending_recoveries
        .take_until(&request.recovery_id)
        .ok_or(ApiError::RecoveryExpired)?;
    let (Some(account_id), Some(challenge)) = (pending.account_id.clone(), pending.challenge)
    else {
        return Err(ApiError::RecoveryExpired);
    };
    let opaque_record = match new_credentials(&request.registration_upload, &request.account, true)
    {
        Ok(record) => record,
        Err(error) => {
            // A malformed request doesn't use up the reset.
            state
                .pending_recoveries
                .reinsert(request.recovery_id, &ip, pending, expires);
            return Err(error);
        }
    };
    let account = accounts::find_by_id(&state.db, &account_id)
        .await?
        .ok_or(ApiError::RecoveryExpired)?;
    let message = recovery_message(&account_id, &base64url(challenge), &request);
    if !signature_matches(&account.public_sign_key, &request.signature, &message) {
        tracing::warn!("a master password reset had a wrong signature");
        return Err(ApiError::LoginFailed);
    }
    replace_credentials(
        &state,
        &account_id,
        &opaque_record,
        &request.account,
        None,
        SecurityEventType::PasswordReset,
        None,
    )
    .await?;
    state.send_email(&account.email, Email::PasswordReset);
    tracing::info!("master password reset with the recovery code");
    Ok(StatusCode::NO_CONTENT)
}

/// What the account signs (see [`RecoverFinishRequest::signature`]).
fn recovery_message(account_id: &str, challenge: &str, request: &RecoverFinishRequest) -> Vec<u8> {
    let update = &request.account;
    let fields = [
        account_id,
        challenge,
        &request.registration_upload,
        &update.account_salt,
        &update.wrapped_ask,
        update.recovery_wrapped_ask.as_deref().unwrap_or_default(),
    ];
    let mut message = RECOVERY_LABEL.to_vec();
    for field in fields {
        let len = u32::try_from(field.len()).expect("fields were size-checked");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message
}

pub fn signature_matches(public_sign_key: &str, signature: &str, message: &[u8]) -> bool {
    let Ok(key) = validate::exact_bytes("publicSignKey", public_sign_key, 32) else {
        return false;
    };
    let Ok(signature) = validate::exact_bytes("signature", signature, 64) else {
        return false;
    };
    let key = <[u8; 32]>::try_from(key.as_slice()).expect("32 bytes");
    let signature = <[u8; 64]>::try_from(signature.as_slice()).expect("64 bytes");
    // Strict verification also rejects small-order keys and non-canonical signatures.
    VerifyingKey::from_bytes(&key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(&signature))
            .is_ok()
    })
}
