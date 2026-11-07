//! Sign-up, login and tokens. The server only ever sees OPAQUE messages: the
//! master password and `auth_secret` never leave the client.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use octapass_api::problem::Problem;
use octapass_api::{
    KdfAlgorithm, KdfParams, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PreloginRequest, PreloginResponse, ReauthFinishRequest,
    ReauthFinishResponse, ReauthStartRequest, ReauthStartResponse, RefreshRequest, RefreshResponse,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
    SecondFactorChallenge, SecondFactorMethod, SecondFactorRequest, SecurityEventType, SignupMode,
    SsoChallenge, SsoLoginRequest, WebAuthnAssertion, WebAuthnRequestOptions,
};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand_core::OsRng;
use std::time::Duration;

use crate::crypto::{Suite, base64url, constant_time_eq, keyed_hash, random_token, six_digit_code};
use crate::db::{self, accounts, audit, items, orgs, sessions, two_step as two_step_db};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, Authenticated, ClientIp};
use crate::login::{PendingLogin, SsoBrowser, SsoLogin, SsoPurpose};
use crate::mail::{Email, readable_time};
use crate::rate_limit::RateLimiter;
use crate::state::{AppState, SECOND_FACTOR_TTL, SSO_TTL};
use crate::two_step::{self, SecondFactorLogin, totp, webauthn};
use crate::validate::{self, ACCOUNT_SALT_LEN};

const DEFAULT_KDF: KdfParams = KdfParams {
    algorithm: KdfAlgorithm::Argon2id,
    memory_kib: 65_536,
    iterations: 3,
    parallelism: 1,
};
const VERIFICATION_TTL: i64 = 15 * 60 * 1000;
/// Wrong guesses allowed per code, including codes re-sent before it expired.
pub(crate) const MAX_VERIFICATION_ATTEMPTS: i64 = 5;
/// Codes one email can be sent per UTC day.
pub(crate) const CODES_PER_DAY: i64 = 10;
/// Wrong codes one email can try per UTC day, whatever the number of codes.
pub(crate) const FAILURES_PER_DAY: i64 = 20;
/// Generous upper bound for any serialised OPAQUE message in this ciphersuite.
const MAX_OPAQUE_MESSAGE: usize = 512;
/// Ciphertext envelopes holding keys are small; this leaves room for growth.
pub(crate) const MAX_KEY_ENVELOPE: usize = 4096;
/// Wrong second steps one sign-in may try before the password is needed again.
const MAX_SECOND_FACTOR_TRIES: u32 = 5;
/// Wrong SSO codes one sign-in may try before it starts over.
const MAX_SSO_CODE_TRIES: u32 = 5;
/// How long the browser may wait for a security key, in milliseconds.
pub const WEBAUTHN_TIMEOUT_MS: u64 = 120_000;

pub(crate) fn charge(limiter: &RateLimiter, key: &str) -> ApiResult<()> {
    limiter.check(key).map_err(ApiError::RateLimited)
}

fn login_key(email: &str, ip: &str) -> String {
    format!("{email}\0{ip}")
}

/// Refuses a login or reauth once the email's failure budget is spent,
/// without charging it: only failed attempts do.
fn check_login_budget(state: &AppState, email: &str, ip: &str) -> ApiResult<()> {
    state
        .login_limiter
        .peek(&login_key(email, ip))
        .and_then(|()| state.login_email_limiter.peek(email))
        .map_err(ApiError::RateLimited)
}

fn charge_login_failure(state: &AppState, email: &str, ip: &str) {
    // Already-empty buckets just stay empty.
    let _ = state.login_limiter.check(&login_key(email, ip));
    let _ = state.login_email_limiter.check(email);
}

pub(crate) fn until_tomorrow(now: i64) -> Duration {
    let day = db::days(1);
    Duration::from_millis(u64::try_from(day - now.rem_euclid(day)).unwrap_or(0))
}

pub(crate) fn opaque_message<T, E>(
    field: &str,
    value: &str,
    parse: impl FnOnce(&[u8]) -> Result<T, E>,
) -> ApiResult<T> {
    let bytes = validate::base64url(field, value, MAX_OPAQUE_MESSAGE)?;
    parse(&bytes)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not a valid OPAQUE message")))
}

fn verification_code_hash(state: &AppState, email: &str, code: &str) -> [u8; 32] {
    keyed_hash(
        &*state.secrets.hmac_key,
        "openpass/verification-code",
        format!("{email}\0{code}").as_bytes(),
    )
}

#[utoipa::path(
    post, path = "/v1/auth/prelogin", tag = "auth",
    request_body = PreloginRequest,
    responses(
        (status = 200, body = PreloginResponse, description = "KDF parameters and salt. Unknown emails get a deterministic fake salt."),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn prelogin(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let email = validate::email(&request.email)?;
    let response = match accounts::find_by_email(&state.db, &email).await? {
        Some(account) => PreloginResponse {
            kdf: account.kdf(),
            account_salt: account.account_salt,
        },
        None => {
            // Same shape and length as a real salt, and stable across calls,
            // so the response doesn't reveal whether the account exists.
            let fake = keyed_hash(
                &*state.secrets.hmac_key,
                "openpass/prelogin-salt",
                email.as_bytes(),
            );
            PreloginResponse {
                kdf: DEFAULT_KDF,
                account_salt: base64url(&fake[..ACCOUNT_SALT_LEN]),
            }
        }
    };
    Ok(Json(response))
}

#[utoipa::path(
    post, path = "/v1/auth/register/start", tag = "auth",
    request_body = RegisterStartRequest,
    responses(
        (status = 200, body = RegisterStartResponse, description = "A 6-digit code was emailed. The response is the same whether or not the email already has an account."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "signups-closed or invite-required"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json", description = "email-unavailable"),
    )
)]
pub async fn register_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let email = validate::email(&request.email)?;
    match state.config.signups {
        SignupMode::Open => {}
        SignupMode::Invite if accounts::is_invited(&state.db, &email).await? => {}
        SignupMode::Invite => return Err(ApiError::InviteRequired),
        SignupMode::Closed => return Err(ApiError::SignupsClosed),
    }
    if !state.config.can_deliver_codes() {
        return Err(ApiError::EmailUnavailable);
    }

    let registration_request = opaque_message(
        "registrationRequest",
        &request.registration_request,
        RegistrationRequest::<Suite>::deserialize,
    )?;
    let started = ServerRegistration::<Suite>::start(
        &state.secrets.opaque_setup,
        registration_request,
        email.as_bytes(),
    )
    .map_err(|_| {
        ApiError::BadRequest("registrationRequest is not a valid OPAQUE message".into())
    })?;

    // Charged only now, so malformed requests can't use up someone's budget.
    charge(&state.signup_limiter, &email)?;
    let now = db::now();
    let counter_key = state.signup_counter_key(&email);
    if !accounts::count_code_sent(&state.db, &counter_key, &db::utc_day(now), CODES_PER_DAY).await?
    {
        return Err(ApiError::RateLimited(until_tomorrow(now)));
    }

    let code = six_digit_code();
    let code_hash = base64url(verification_code_hash(&state, &email, &code));
    accounts::upsert_pending(&state.db, &email, &code_hash, now, now + VERIFICATION_TTL).await?;
    // Existing accounts get a notice instead of a code, and the response is
    // identical either way.
    let exists = accounts::email_exists(&state.db, &email).await?;
    state.send_email(
        &email,
        if exists {
            Email::AccountExists
        } else {
            Email::VerificationCode(code.clone())
        },
    );

    Ok(Json(RegisterStartResponse {
        registration_response: base64url(started.message.serialize()),
        verification_required: true,
        dev_verification_code: state.config.dev_mode.then_some(code),
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/register/finish", tag = "auth",
    request_body = RegisterFinishRequest,
    responses(
        (status = 200, body = RegisterFinishResponse),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "invalid-request or invalid-verification-code"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "account-exists or vault-exists"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn register_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RegisterFinishRequest>,
) -> ApiResult<Json<RegisterFinishResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let email = validate::email(&request.email)?;
    let RegisterFinishRequest {
        account,
        personal_vault,
        ..
    } = &request;
    if validate::email(&account.email)? != email {
        return Err(ApiError::BadRequest(
            "account.email must match email".into(),
        ));
    }
    validate::kdf(&account.kdf)?;
    validate::exact_bytes(
        "account.accountSalt",
        &account.account_salt,
        ACCOUNT_SALT_LEN,
    )?;
    validate::exact_bytes("account.publicEncKey", &account.public_enc_key, 32)?;
    validate::exact_bytes("account.publicSignKey", &account.public_sign_key, 32)?;
    validate::envelope("account.wrappedAsk", &account.wrapped_ask, MAX_KEY_ENVELOPE)?;
    validate::envelope(
        "account.wrappedPrivateKeys",
        &account.wrapped_private_keys,
        MAX_KEY_ENVELOPE,
    )?;
    validate::envelope(
        "account.recoveryWrappedAsk",
        &account.recovery_wrapped_ask,
        MAX_KEY_ENVELOPE,
    )?;
    let vault_id = validate::id("personalVault.id", &personal_vault.id)?;
    validate::envelope(
        "personalVault.wrappedVaultKey",
        &personal_vault.wrapped_vault_key,
        MAX_KEY_ENVELOPE,
    )?;
    let upload = opaque_message(
        "registrationUpload",
        &request.registration_upload,
        RegistrationUpload::<Suite>::deserialize,
    )?;
    let opaque_record = base64url(ServerRegistration::<Suite>::finish(upload).serialize());

    charge(&state.signup_limiter, &email)?;
    let now = db::now();
    let (counter_key, day) = (state.signup_counter_key(&email), db::utc_day(now));
    let code_ok = accounts::failures_today(&state.db, &counter_key, &day).await? < FAILURES_PER_DAY
        && match accounts::take_attempt(&state.db, &email, MAX_VERIFICATION_ATTEMPTS, now).await? {
            Some(code_hash) => {
                let expected =
                    validate::base64url("code", &code_hash, 32).map_err(ApiError::internal)?;
                constant_time_eq(
                    &expected,
                    &verification_code_hash(&state, &email, request.verification_code.trim()),
                )
            }
            None => false,
        };
    if !code_ok {
        accounts::count_failure(&state.db, &counter_key, &day).await?;
        return Err(ApiError::InvalidVerificationCode);
    }

    let account_id = uuid::Uuid::now_v7().to_string();
    let mut tx = state.db.begin().await?;
    // A write first, so on SQLite this transaction holds the write lock from the start.
    accounts::delete_pending(&mut tx, &email).await?;
    if accounts::email_exists(&mut *tx, &email).await? {
        return Err(ApiError::AccountExists);
    }
    if items::vault_exists(&mut tx, &vault_id).await? {
        return Err(ApiError::VaultExists);
    }
    let new_account = accounts::NewAccount {
        id: &account_id,
        email: &email,
        bundle: account,
        opaque_record: &opaque_record,
        now,
    };
    accounts::insert(&mut tx, new_account)
        .await
        .map_err(unique_violation_as(ApiError::AccountExists))?;
    items::insert_personal_vault(
        &mut tx,
        &vault_id,
        &account_id,
        &personal_vault.wrapped_vault_key,
        now,
    )
    .await
    // PostgreSQL doesn't serialise this transaction, so the check above can race.
    .map_err(unique_violation_as(ApiError::VaultExists))?;
    accounts::delete_invite(&mut tx, &email).await?;
    tx.commit().await?;

    tracing::info!("account created");
    Ok(Json(RegisterFinishResponse { account_id }))
}

fn unique_violation_as(conflict: ApiError) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |error| match error.as_database_error() {
        Some(db_error) if db_error.is_unique_violation() => conflict,
        _ => error.into(),
    }
}

/// Starts an OPAQUE login. `None` as the password file makes opaque-ke answer
/// with a fake record that is indistinguishable from a real one.
fn start_login(
    state: &AppState,
    email: &str,
    password_file: Option<&str>,
    credential_request: &str,
) -> ApiResult<(ServerLogin<Suite>, String)> {
    let credential_request = opaque_message(
        "credentialRequest",
        credential_request,
        CredentialRequest::<Suite>::deserialize,
    )?;
    let password_file = password_file
        .map(|record| {
            let bytes = validate::base64url("opaque_record", record, MAX_OPAQUE_MESSAGE)
                .map_err(ApiError::internal)?;
            ServerRegistration::<Suite>::deserialize(&bytes)
                .map_err(|e| ApiError::internal(e.to_string()))
        })
        .transpose()?;
    let started = ServerLogin::start(
        &mut OsRng,
        &state.secrets.opaque_setup,
        password_file,
        credential_request,
        email.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|_| ApiError::BadRequest("credentialRequest is not a valid OPAQUE message".into()))?;
    Ok((started.state, base64url(started.message.serialize())))
}

/// Finishes an OPAQUE login. Every failure is the same `LoginFailed`.
fn finish_login(login: PendingLogin, credential_finalization: &str) -> ApiResult<String> {
    let finalization = validate::base64url(
        "credentialFinalization",
        credential_finalization,
        MAX_OPAQUE_MESSAGE,
    )
    .ok()
    .and_then(|bytes| CredentialFinalization::<Suite>::deserialize(&bytes).ok())
    .ok_or(ApiError::LoginFailed)?;
    login
        .state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| ApiError::LoginFailed)?;
    login.account_id.ok_or(ApiError::LoginFailed)
}

#[utoipa::path(
    post, path = "/v1/auth/login/start", tag = "auth",
    request_body = LoginStartRequest,
    responses(
        (status = 200, body = LoginStartResponse, description = "Unknown emails get a fake but well-formed response."),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn login_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let email = validate::email(&request.email)?;
    check_login_budget(&state, &email, &ip)?;
    let account = accounts::find_by_email(&state.db, &email).await?;
    let (login, credential_response) = start_login(
        &state,
        &email,
        account.as_ref().map(|a| a.opaque_record.as_str()),
        &request.credential_request,
    )?;
    let login_id = random_token();
    let pending = PendingLogin {
        state: login,
        account_id: account.map(|a| a.id),
        email,
    };
    state.pending_logins.insert(login_id.clone(), &ip, pending);
    Ok(Json(LoginStartResponse {
        login_id,
        credential_response,
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/login/finish", tag = "auth",
    request_body = LoginFinishRequest,
    responses(
        (status = 200, body = LoginFinishResponse),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Malformed device info"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "login-failed, for every failure; or, once the password was right, sso-required with an sso member (finish with /v1/auth/login/sso) or second-factor-required with a secondFactor member (finish with /v1/auth/login/second-factor)"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn login_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let name = validate::text("device.name", &request.device.name, 64)?;
    let platform = validate::text("device.platform", &request.device.platform, 32)?;
    let login = state
        .pending_logins
        .take(&request.login_id)
        .ok_or(ApiError::LoginFailed)?;
    let email = login.email.clone();
    let account_id = finish_login(login, &request.credential_finalization)
        .inspect_err(|_| charge_login_failure(&state, &email, &ip))?;

    let progress = LoginProgress {
        account_id,
        email,
        device_name: name,
        device_platform: platform,
        trusted_device_token: request.trusted_device_token,
        sso_at: None,
    };
    Ok(Json(continue_login(&state, &ip, progress).await?))
}

/// A sign-in the password has accepted, on its way through whatever else the account asks for.
struct LoginProgress {
    account_id: String,
    email: String,
    device_name: String,
    device_platform: String,
    trusted_device_token: Option<String>,
    /// When SSO passed for this sign-in, if it has.
    sso_at: Option<i64>,
}

/// The steps after the password, in order: SSO if the account's organisation requires it, then
/// two-step sign-in. SSO comes first because a second step is used up by the session it creates.
async fn continue_login(
    state: &AppState,
    ip: &str,
    login: LoginProgress,
) -> ApiResult<LoginFinishResponse> {
    if login.sso_at.is_none()
        && let Some(rule) = orgs::sso_rule(&state.db, &login.account_id).await?
    {
        return Err(sso_required(state, ip, login, rule));
    }
    let LoginProgress {
        account_id,
        email,
        device_name: name,
        device_platform: platform,
        trusted_device_token,
        sso_at,
    } = login;

    let now = db::now();
    let enabled = two_step_db::is_enabled(&state.db, &account_id).await?;
    let trusted_token = match trusted_device_token.as_deref() {
        Some(token) if two_step_db::is_trusted(&state.db, &account_id, token, now).await? => {
            Some(token)
        }
        _ => None,
    };
    if trusted_token.is_some() || !enabled {
        let mut tx = state.db.begin().await?;
        let device = NewDevice {
            account_id: &account_id,
            name: &name,
            platform: &platform,
            sso_at,
        };
        let session = match start_session(&mut tx, &device, trusted_token, now).await? {
            // Another sign-in used the token first: it counts for nothing.
            None if !enabled => start_session(&mut tx, &device, None, now)
                .await?
                .map(|session| (session, false)),
            session => session.map(|session| (session, trusted_token.is_some())),
        };
        if let Some((session, trusted)) = session {
            tx.commit().await?;
            if !trusted {
                notify_new_sign_in(state, &account_id, &email, &session, &name, &platform).await?;
            }
            return login_response(state, &account_id, session).await;
        }
    }
    let pending = SecondFactorLogin {
        account_id,
        email,
        device_name: name,
        device_platform: platform,
        webauthn_challenge: None,
        failures: 0,
        sso_at,
    };
    Err(second_factor_required(state, ip, pending).await?)
}

/// Parks a sign-in until the identity provider has answered. The client keeps the challenge id;
/// the URL, which goes to a browser and its history, carries a different token.
fn sso_required(state: &AppState, ip: &str, login: LoginProgress, rule: orgs::SsoRule) -> ApiError {
    let challenge_id = random_token();
    let browser_token = random_token();
    let pending = SsoBrowser {
        purpose: SsoPurpose::Login(challenge_id.clone()),
        org_id: rule.org_id,
        email: login.email.clone(),
        flow: None,
    };
    state
        .pending_sso_browsers
        .insert(browser_token.clone(), ip, pending);
    let waiting = SsoLogin {
        account_id: login.account_id,
        email: login.email,
        device_name: login.device_name,
        device_platform: login.device_platform,
        trusted_device_token: login.trusted_device_token,
        ip: ip.to_owned(),
        confirm_code: None,
        failures: 0,
    };
    state.pending_sso.insert(challenge_id.clone(), ip, waiting);
    ApiError::SsoRequired(Box::new(SsoChallenge {
        challenge_id,
        url: crate::routes::sso::start_url(state, &browser_token),
        org_name: rule.org_name,
        expires_in: SSO_TTL.as_secs(),
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/login/sso", tag = "auth",
    request_body = SsoLoginRequest,
    responses(
        (status = 200, body = LoginFinishResponse),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "invalid-second-factor (try again), login-failed (the challenge is unknown, expired or used up, so start over), or second-factor-required: the account's second step comes next"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "sso-pending: the browser hasn't finished at the identity provider"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn login_sso(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<SsoLoginRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let (mut login, expires) = state
        .pending_sso
        .take_until(&request.challenge_id)
        .ok_or(ApiError::LoginFailed)?;
    let Some(expected) = login.confirm_code.clone() else {
        state
            .pending_sso
            .reinsert(request.challenge_id, &ip, login, expires);
        return Err(ApiError::SsoPending);
    };
    if !constant_time_eq(expected.as_bytes(), request.code.trim().as_bytes()) {
        login.failures += 1;
        if login.failures < MAX_SSO_CODE_TRIES {
            state
                .pending_sso
                .reinsert(request.challenge_id, &ip, login, expires);
        }
        return Err(ApiError::InvalidSecondFactor);
    }
    let progress = LoginProgress {
        account_id: login.account_id,
        email: login.email,
        device_name: login.device_name,
        device_platform: login.device_platform,
        trusted_device_token: login.trusted_device_token,
        sso_at: Some(state.clock.now()),
    };
    Ok(Json(continue_login(&state, &ip, progress).await?))
}

/// A new session and the device's trusted-device token.
struct NewSession {
    device_id: String,
    tokens: sessions::Tokens,
    trusted_device_token: String,
}

/// Emails the owner about a sign-in that didn't come from a trusted device,
/// except the one that finishes sign-up.
async fn notify_new_sign_in(
    state: &AppState,
    account_id: &str,
    email: &str,
    session: &NewSession,
    device: &str,
    platform: &str,
) -> ApiResult<()> {
    let now = state.clock.now();
    if sessions::is_first_device(&state.db, account_id, &session.device_id, now).await? {
        return Ok(());
    }
    let email_body = Email::NewSignIn {
        device: device.to_owned(),
        platform: platform.to_owned(),
        at: readable_time(now),
    };
    state.send_email(email, email_body);
    Ok(())
}

/// Who a new session is for.
struct NewDevice<'a> {
    account_id: &'a str,
    name: &'a str,
    platform: &'a str,
    sso_at: Option<i64>,
}

/// Creates the device, its session and its trust, inside `conn`'s
/// transaction. A trusted-device token it signs in with is used up first:
/// `None` (and nothing written) if it's no longer valid.
async fn start_session(
    conn: &mut db::Conn,
    device: &NewDevice<'_>,
    trusted_token: Option<&str>,
    now: i64,
) -> ApiResult<Option<NewSession>> {
    let NewDevice {
        account_id,
        name,
        platform,
        sso_at,
    } = *device;
    if let Some(token) = trusted_token
        && !two_step_db::use_trust(conn, account_id, token, now).await?
    {
        return Ok(None);
    }
    let device_id = sessions::insert_device(conn, account_id, name, platform, now)
        .await
        .map_err(|_| ApiError::LoginFailed)?;
    let tokens = sessions::insert(conn, account_id, &device_id, now, sso_at).await?;
    let trusted_device_token = two_step_db::trust_device(conn, account_id, &device_id, now).await?;
    Ok(Some(NewSession {
        device_id,
        tokens,
        trusted_device_token,
    }))
}

async fn login_response(
    state: &AppState,
    account_id: &str,
    session: NewSession,
) -> ApiResult<LoginFinishResponse> {
    let account = accounts::find_by_id(&state.db, account_id)
        .await?
        .ok_or(ApiError::LoginFailed)?;
    Ok(LoginFinishResponse {
        access_token: session.tokens.access_token,
        refresh_token: session.tokens.refresh_token,
        expires_in: sessions::ACCESS_TOKEN_TTL_SECS,
        account: account.into_bundle(),
        trusted_device_token: Some(session.trusted_device_token),
    })
}

/// Parks a sign-in until its second step, and says which methods can finish it.
async fn second_factor_required(
    state: &AppState,
    ip: &str,
    mut pending: SecondFactorLogin,
) -> ApiResult<ApiError> {
    let keys = two_step_db::security_keys(&state.db, &pending.account_id).await?;
    let mut methods = vec![SecondFactorMethod::Totp];
    let webauthn = if keys.is_empty() {
        None
    } else {
        methods.push(SecondFactorMethod::Webauthn);
        let challenge = crate::crypto::random_bytes::<32>();
        pending.webauthn_challenge = Some(challenge);
        Some(WebAuthnRequestOptions {
            challenge: base64url(challenge),
            rp_id: state.config.webauthn_rp_id.clone(),
            allow_credentials: keys.into_iter().map(|key| key.credential_id).collect(),
            timeout: WEBAUTHN_TIMEOUT_MS,
            user_verification: "discouraged".into(),
        })
    };
    methods.push(SecondFactorMethod::RecoveryCode);
    let challenge_id = random_token();
    state
        .pending_second_factors
        .insert(challenge_id.clone(), ip, pending);
    Ok(ApiError::SecondFactorRequired(Box::new(
        SecondFactorChallenge {
            challenge_id,
            methods,
            webauthn,
            expires_in: SECOND_FACTOR_TTL.as_secs(),
        },
    )))
}

/// What a second step proved, if anything.
enum SecondFactor {
    Passed,
    PassedWithRecoveryCode,
    Failed,
}

#[utoipa::path(
    post, path = "/v1/auth/login/second-factor", tag = "auth",
    request_body = SecondFactorRequest,
    responses(
        (status = 200, body = LoginFinishResponse),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Not exactly one of totpCode, recoveryCode and webauthn"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "invalid-second-factor (try again), or login-failed: the challenge is unknown, expired or used up, so start over"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "Too many wrong codes for this account: the second step is paused"),
    )
)]
pub async fn login_second_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<SecondFactorRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let (mut login, expires) = state
        .pending_second_factors
        .take_until(&request.challenge_id)
        .ok_or(ApiError::LoginFailed)?;
    let proofs = usize::from(request.totp_code.is_some())
        + usize::from(request.recovery_code.is_some())
        + usize::from(request.webauthn.is_some());
    if proofs != 1 {
        state
            .pending_second_factors
            .reinsert(request.challenge_id, &ip, login, expires);
        return Err(ApiError::BadRequest(
            "send exactly one of totpCode, recoveryCode and webauthn".into(),
        ));
    }
    // The try is charged before it's checked, so concurrent guesses can't
    // all slip under the account's budget; a right answer gets it back. While
    // the account is paused the sign-in waits, to finish once the pause is over.
    if let Err(wait) = state.two_step_limiter.check(&login.account_id) {
        state
            .pending_second_factors
            .reinsert(request.challenge_id, &ip, login, expires);
        return Err(ApiError::RateLimited(wait));
    }

    // The proof is used up in the same transaction that creates the session,
    // so a failure afterwards doesn't burn a code.
    let now = db::now();
    let mut tx = state.db.begin().await?;
    let outcome = if let Some(code) = &request.totp_code {
        check_totp(&state, &mut tx, &login.account_id, code).await?
    } else if let Some(code) = &request.recovery_code {
        check_recovery_code(&state, &mut tx, &login.account_id, code).await?
    } else if let Some(assertion) = &request.webauthn {
        check_security_key(&state, &mut tx, &login, assertion).await?
    } else {
        unreachable!("exactly one proof was sent")
    };

    match outcome {
        SecondFactor::Failed => {
            drop(tx);
            login.failures += 1;
            second_factor_failed(&state, &login).await?;
            if login.failures < MAX_SECOND_FACTOR_TRIES {
                state
                    .pending_second_factors
                    .reinsert(request.challenge_id, &ip, login, expires);
            }
            Err(ApiError::InvalidSecondFactor)
        }
        passed => {
            let device = NewDevice {
                account_id: &login.account_id,
                name: &login.device_name,
                platform: &login.device_platform,
                sso_at: login.sso_at,
            };
            let session = start_session(&mut tx, &device, None, now)
                .await?
                .ok_or_else(|| ApiError::internal("a session without a token to use up failed"))?;
            tx.commit().await?;
            state.two_step_limiter.refund(&login.account_id);
            // A recovery code's own email already says a new device signed in.
            if !matches!(passed, SecondFactor::PassedWithRecoveryCode) {
                let (device, platform) = (&login.device_name, &login.device_platform);
                notify_new_sign_in(
                    &state,
                    &login.account_id,
                    &login.email,
                    &session,
                    device,
                    platform,
                )
                .await?;
            }
            let response = login_response(&state, &login.account_id, session).await?;
            if let SecondFactor::PassedWithRecoveryCode = passed {
                let now = state.clock.now();
                let event = SecurityEventType::RecoveryCodeUsed;
                audit::record(&state.db, &login.account_id, event, None, None, now).await?;
                let left = two_step_db::recovery_codes_left(&state.db, &login.account_id).await?;
                state.send_email(&login.email, Email::RecoveryCodeUsed { left });
            }
            Ok(Json(response))
        }
    }
}

/// A wrong second step was already charged to the account. The try that
/// empties its budget is logged and emailed (at most hourly): whoever it is
/// knows the master password and Secret Key.
async fn second_factor_failed(state: &AppState, login: &SecondFactorLogin) -> ApiResult<()> {
    if state.two_step_limiter.peek(&login.account_id).is_err()
        && state
            .two_step_alert_limiter
            .check(&login.account_id)
            .is_ok()
    {
        let event = SecurityEventType::TwoStepLocked;
        let now = state.clock.now();
        audit::record(&state.db, &login.account_id, event, None, None, now).await?;
        state.send_email(&login.email, Email::TwoStepLocked);
        tracing::warn!("too many wrong second steps; two-step sign-in paused for an account");
    }
    Ok(())
}

// Each check reads through the pool and writes only through `tx`, so on
// SQLite the transaction's first statement is a write and holds the lock.

async fn check_totp(
    state: &AppState,
    tx: &mut db::Conn,
    account_id: &str,
    code: &str,
) -> ApiResult<SecondFactor> {
    let mut conn = state.db.acquire().await?;
    let Some(row) = two_step_db::totp(&mut conn, account_id).await? else {
        return Ok(SecondFactor::Failed);
    };
    drop(conn);
    let secret = two_step::open(&state.secrets, account_id, &row.totp_secret)
        .ok_or_else(|| ApiError::internal("an authenticator secret doesn't open"))?;
    let Some(step) = totp::verify(&secret, code, state.clock.now(), row.totp_last_step) else {
        return Ok(SecondFactor::Failed);
    };
    // Conditional, so the same code can't finish two sign-ins at once.
    Ok(if two_step_db::use_totp_step(tx, account_id, step).await? {
        SecondFactor::Passed
    } else {
        SecondFactor::Failed
    })
}

async fn check_recovery_code(
    state: &AppState,
    tx: &mut db::Conn,
    account_id: &str,
    code: &str,
) -> ApiResult<SecondFactor> {
    if two_step::normalize_recovery_code(code).is_none() {
        return Ok(SecondFactor::Failed);
    }
    let hash = two_step::recovery_code_hash(&state.secrets, account_id, code);
    Ok(
        if two_step_db::use_recovery_code(tx, account_id, &hash).await? {
            SecondFactor::PassedWithRecoveryCode
        } else {
            SecondFactor::Failed
        },
    )
}

async fn check_security_key(
    state: &AppState,
    tx: &mut db::Conn,
    login: &SecondFactorLogin,
    assertion: &WebAuthnAssertion,
) -> ApiResult<SecondFactor> {
    let Some(challenge) = login.webauthn_challenge else {
        return Ok(SecondFactor::Failed);
    };
    let decode = |field: &str, value: &str| validate::base64url(field, value, 16 * 1024);
    let client_data = decode("webauthn.clientDataJson", &assertion.client_data_json)?;
    let authenticator_data = decode("webauthn.authenticatorData", &assertion.authenticator_data)?;
    let signature = decode("webauthn.signature", &assertion.signature)?;
    let keys = two_step_db::security_keys(&state.db, &login.account_id).await?;
    let Some(key) = keys
        .into_iter()
        .find(|key| key.credential_id == assertion.credential_id)
    else {
        return Ok(SecondFactor::Failed);
    };
    let credential = webauthn::Credential {
        id: Vec::new(),
        algorithm: key.algorithm,
        public_key: validate::base64url("public_key", &key.public_key, 256)
            .map_err(ApiError::internal)?,
        sign_count: u32::try_from(key.sign_count).unwrap_or(u32::MAX),
    };
    let origins = state.config.webauthn_origins();
    let ceremony = webauthn::Ceremony {
        rp_id: &state.config.webauthn_rp_id,
        origins: &origins,
        challenge: &challenge,
    };
    let Ok(count) = ceremony.assert(&credential, &client_data, &authenticator_data, &signature)
    else {
        return Ok(SecondFactor::Failed);
    };
    let used =
        two_step_db::use_security_key(tx, &key.id, key.sign_count, i64::from(count), db::now())
            .await?;
    Ok(if used {
        SecondFactor::Passed
    } else {
        SecondFactor::Failed
    })
}

/// Refuses to refresh a session whose SSO sign-in is too old, or never happened. The device signs
/// in again, through the provider, so someone disabled there is gone within the policy's limit.
async fn check_sso_age(state: &AppState, refresh_token: &str) -> ApiResult<()> {
    let Some((account_id, sso_at)) = sessions::sso_state(&state.db, refresh_token).await? else {
        return Ok(());
    };
    let Some(rule) = orgs::sso_rule(&state.db, &account_id).await? else {
        return Ok(());
    };
    let limit = rule.max_age_hours.saturating_mul(60 * 60 * 1000);
    let fresh = sso_at.is_some_and(|at| limit == 0 || state.clock.now() - at < limit);
    if fresh {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

#[utoipa::path(
    post, path = "/v1/auth/refresh", tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, body = RefreshResponse),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "unauthorized, or account-deleted"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RefreshRequest>,
) -> ApiResult<Json<RefreshResponse>> {
    charge(&state.ip_limiter, &ip)?;
    check_sso_age(&state, &request.refresh_token).await?;
    let now = db::now();
    match sessions::refresh(&state.db, &request.refresh_token, now).await? {
        sessions::Refresh::Rotated(tokens) => Ok(Json(RefreshResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: sessions::ACCESS_TOKEN_TTL_SECS,
            trusted_device_token: None,
        })),
        sessions::Refresh::Reused(session) => {
            tracing::warn!("a rotated refresh token was reused; the session was revoked");
            // Someone copied a token: no device of the account skips the second step any more.
            two_step_db::forget_devices(&state.db, &session.account_id, None).await?;
            state.session_revoked(&session.account_id, &session.device_id);
            Err(ApiError::Unauthorized)
        }
        sessions::Refresh::Invalid => {
            let hash = crate::crypto::token_hash(&request.refresh_token);
            if db::deletion::is_deleted_account_token(&state.db, &hash, now).await? {
                return Err(ApiError::AccountDeleted);
            }
            Err(ApiError::Unauthorized)
        }
    }
}

#[utoipa::path(
    post, path = "/v1/auth/logout", tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 204, description = "This device's tokens were revoked, and it no longer skips two-step sign-in"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<StatusCode> {
    state
        .revoke_device(&session.account_id, &session.device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/auth/reauth/start", tag = "auth",
    security(("bearer" = [])),
    request_body = ReauthStartRequest,
    responses(
        (status = 200, body = ReauthStartResponse),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn reauth_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<ReauthStartRequest>,
) -> ApiResult<Json<ReauthStartResponse>> {
    let account = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    charge(&state.ip_limiter, &ip)?;
    check_login_budget(&state, &account.email, &ip)?;
    let (login, credential_response) = start_login(
        &state,
        &account.email,
        Some(&account.opaque_record),
        &request.credential_request,
    )?;
    let reauth_id = random_token();
    let pending = PendingLogin {
        state: login,
        account_id: Some(account.id),
        email: account.email,
    };
    state
        .pending_reauths
        .insert(reauth_id.clone(), &ip, pending);
    Ok(Json(ReauthStartResponse {
        reauth_id,
        credential_response,
    }))
}

#[utoipa::path(
    post, path = "/v1/auth/reauth/finish", tag = "auth",
    security(("bearer" = [])),
    request_body = ReauthFinishRequest,
    responses(
        (status = 200, body = ReauthFinishResponse, description = "A single-use token for the given purpose, valid for 5 minutes"),
        (status = 401, body = Problem, content_type = "application/problem+json", description = "login-failed for a wrong password"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn reauth_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<ReauthFinishRequest>,
) -> ApiResult<Json<ReauthFinishResponse>> {
    charge(&state.ip_limiter, &ip)?;
    let login = state
        .pending_reauths
        .take(&request.reauth_id)
        .ok_or(ApiError::LoginFailed)?;
    let email = login.email.clone();
    if login.account_id.as_deref() != Some(session.account_id.as_str()) {
        charge_login_failure(&state, &email, &ip);
        return Err(ApiError::LoginFailed);
    }
    let account_id = finish_login(login, &request.credential_finalization)
        .inspect_err(|_| charge_login_failure(&state, &email, &ip))?;
    let reauth_token =
        sessions::insert_reauth_token(&state.db, &account_id, request.purpose.as_str(), db::now())
            .await?;
    Ok(Json(ReauthFinishResponse {
        reauth_token,
        expires_in: sessions::REAUTH_TOKEN_TTL_SECS,
    }))
}
