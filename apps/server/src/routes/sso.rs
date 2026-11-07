//! SSO settings, and the browser's way through the identity provider. The provider decides only
//! whether a sign-in that already passed OPAQUE may go on (plan 03, "SSO is sign-in only").

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{OrgRole, OrgSsoRecord, OrgSsoRequest, OrgSsoTestResponse};
use serde::Deserialize;

use super::orgs::locked;
use crate::crypto::{random_token, six_digit_code};
use crate::db::{self, accounts, orgs};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated, ClientIp};
use crate::login::{SsoBrowser, SsoPurpose};
use crate::sso::page::{self, Failure, Page};
use crate::sso::{self, Exchange, Flow, SsoError};
use crate::state::{AppState, SSO_TTL};
use crate::validate;

const MAX_ISSUER: usize = 512;
const MAX_CLIENT_FIELD: usize = 512;

fn public_url(state: &AppState) -> &str {
    state.config.public_url.trim_end_matches('/')
}

pub fn start_url(state: &AppState, browser_token: &str) -> String {
    format!("{}/v1/sso/start/{browser_token}", public_url(state))
}

fn callback_url(state: &AppState) -> String {
    format!("{}/v1/sso/callback", public_url(state))
}

fn config_error(error: SsoError) -> ApiError {
    ApiError::SsoConfig(error.to_string())
}

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/sso", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgSsoRecord),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_sso(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgSsoRecord>> {
    let org_id = validate::id("orgId", &org_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, &session.account_id, OrgRole::Owner).await?;
    let tested_at = orgs::tested_at(&mut tx, &org_id).await?;
    tx.commit().await?;
    let settings = orgs::sso_settings(&state.db, &org_id).await?;
    Ok(Json(OrgSsoRecord {
        has_client_secret: settings
            .as_ref()
            .is_some_and(|settings| settings.client_secret.is_some()),
        issuer: settings.as_ref().map(|settings| settings.issuer.clone()),
        client_id: settings.map(|settings| settings.client_id),
        tested_at: tested_at.map(db::rfc3339),
        callback_url: callback_url(&state),
    }))
}

#[utoipa::path(
    put, path = "/v1/orgs/{orgId}/sso", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = OrgSsoRequest,
    responses(
        (status = 200, body = OrgSsoRecord, description = "Saved after fetching the issuer's discovery document. A test sign-in is needed again."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "invalid-request, or sso-config: the provider can't be used; SSO is required right now"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn put_sso(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<OrgSsoRequest>,
) -> ApiResult<Json<OrgSsoRecord>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let issuer = validate::text("issuer", &request.issuer, MAX_ISSUER)?;
    let client_id = validate::text("clientId", &request.client_id, MAX_CLIENT_FIELD)?;
    let new_secret = request
        .client_secret
        .as_deref()
        .map(|secret| validate::text("clientSecret", secret, MAX_CLIENT_FIELD))
        .transpose()?;
    {
        let mut tx = state.db.begin().await?;
        locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
        tx.commit().await?;
    }
    // Outside any transaction: this is a network call to somewhere an admin chose.
    state.oidc.discover(&issuer).await.map_err(config_error)?;

    let sealed = new_secret.map(|secret| sso::seal_client_secret(&state.secrets, &org_id, &secret));
    let kept = orgs::sso_settings(&state.db, &org_id)
        .await?
        .and_then(|settings| settings.client_secret);
    let client_secret = sealed.or(kept);
    let now = db::now();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    let org = orgs::find(&mut tx, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if org.policies().require_sso {
        return Err(ApiError::SsoConfig(
            "turn off Require SSO before changing these settings".into(),
        ));
    }
    orgs::put_sso(
        &mut tx,
        &org_id,
        &issuer,
        &client_id,
        client_secret.as_deref(),
        now,
    )
    .await?;
    orgs::record_event(&mut tx, &org_id, me, "sso-changed", Some(&issuer), now).await?;
    tx.commit().await?;
    Ok(Json(OrgSsoRecord {
        issuer: Some(issuer),
        client_id: Some(client_id),
        has_client_secret: client_secret.is_some(),
        tested_at: None,
        callback_url: callback_url(&state),
    }))
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/sso", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 204, description = "The settings and every member's link were removed"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "sso-config: SSO is required right now"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_sso(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    let org = orgs::find(&mut tx, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if org.policies().require_sso {
        return Err(ApiError::SsoConfig(
            "turn off Require SSO before removing these settings".into(),
        ));
    }
    orgs::delete_sso(&mut tx, &org_id).await?;
    orgs::record_event(&mut tx, &org_id, me, "sso-removed", None, db::now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/sso/test", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgSsoTestResponse, description = "Open the URL in a browser. A sign-in that finishes there allows requireSso."),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "No such organisation, or no settings to test"),
    )
)]
pub async fn test_sso(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgSsoTestResponse>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    tx.commit().await?;
    let settings = orgs::sso_settings(&state.db, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let email = accounts::find_by_id(&state.db, me)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .email;
    let token = random_token();
    let pending = SsoBrowser {
        purpose: SsoPurpose::Test {
            updated_at: settings.updated_at,
        },
        org_id,
        email,
        flow: None,
    };
    state
        .pending_sso_browsers
        .insert(token.clone(), &ip, pending);
    Ok(Json(OrgSsoTestResponse {
        url: start_url(&state, &token),
        expires_in: SSO_TTL.as_secs(),
    }))
}

/// Sends the browser to the identity provider.
#[utoipa::path(
    get, path = "/v1/sso/start/{token}", tag = "auth",
    params(("token" = String, Path)),
    responses(
        (status = 302, description = "To the identity provider"),
        (status = 400, description = "An HTML page: the link expired, or the provider can't be reached"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiPath(token): ApiPath<String>,
) -> ApiResult<Response> {
    super::auth::charge(&state.ip_limiter, &ip)?;
    let failed = |failure| page::render(&Page::Failed(failure), &headers);
    let Some(mut browser) = state.pending_sso_browsers.take(&token) else {
        return Ok(failed(Failure::Expired));
    };
    let Some(settings) = orgs::sso_settings(&state.db, &browser.org_id).await? else {
        return Ok(failed(Failure::Expired));
    };
    let provider = match state.oidc.discover(&settings.issuer).await {
        Ok(provider) => provider,
        Err(error) => {
            tracing::warn!(%error, "an identity provider's discovery failed");
            return Ok(failed(Failure::Provider));
        }
    };
    let flow = Flow::new();
    let url = flow.authorization_url(
        &provider,
        &settings.client_id,
        &callback_url(&state),
        &browser.email,
    );
    let key = flow.state.clone();
    browser.flow = Some((flow, provider));
    state.pending_sso_browsers.insert(key, &ip, browser);
    Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response())
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

/// Where the identity provider sends the browser back to.
#[utoipa::path(
    get, path = "/v1/sso/callback", tag = "auth",
    params(CallbackQuery),
    responses(
        (status = 200, description = "An HTML page with the 6-digit code to type into the app"),
        (status = 400, description = "An HTML page saying what went wrong"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Response> {
    super::auth::charge(&state.ip_limiter, &ip)?;
    let failed = |failure| Ok(page::render(&Page::Failed(failure), &headers));
    let browser = query
        .state
        .as_deref()
        .and_then(|key| state.pending_sso_browsers.take(key));
    let Some(browser) = browser else {
        return failed(Failure::Expired);
    };
    let (Some(code), Some((flow, provider))) = (query.code.as_deref(), browser.flow.as_ref())
    else {
        return failed(Failure::Provider);
    };
    let Some(settings) = orgs::sso_settings(&state.db, &browser.org_id).await? else {
        return failed(Failure::Expired);
    };
    let secret = match settings.client_secret.as_deref() {
        Some(sealed) => {
            let opened = sso::open_client_secret(&state.secrets, &browser.org_id, sealed);
            let Some(opened) = opened else {
                tracing::error!("an organisation's SSO client secret doesn't open");
                return failed(Failure::Provider);
            };
            Some(opened)
        }
        None => None,
    };
    let redirect_uri = callback_url(&state);
    let exchange = Exchange {
        client_id: &settings.client_id,
        client_secret: secret.as_deref(),
        code,
        verifier: &flow.verifier,
        redirect_uri: &redirect_uri,
    };
    let verified = match state.oidc.exchange(provider, exchange).await {
        Ok(token) => sso::verify_id_token(
            &token,
            &settings.issuer,
            &settings.client_id,
            &flow.nonce,
            state.clock.now(),
        ),
        Err(error) => Err(error),
    };
    let claims = match verified {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "an SSO sign-in failed");
            return failed(Failure::Provider);
        }
    };

    let challenge = match browser.purpose {
        SsoPurpose::Test { updated_at } => {
            let now = state.clock.now();
            if !orgs::sso_tested(&state.db, &browser.org_id, updated_at, now).await? {
                return failed(Failure::Expired);
            }
            return Ok(page::render(&Page::Tested, &headers));
        }
        SsoPurpose::Login(challenge) => challenge,
    };
    let Some((mut login, expires)) = state.pending_sso.take_until(&challenge) else {
        return failed(Failure::Expired);
    };
    let (org_id, now) = (&browser.org_id, state.clock.now());
    let same_person = match orgs::sso_subject(&state.db, org_id, &login.account_id).await? {
        Some(subject) => subject == claims.subject,
        None => {
            claims.email.as_deref() == Some(login.email.as_str())
                && claims.email_verified != Some(false)
                && orgs::link_sso(&state.db, org_id, &login.account_id, &claims.subject, now)
                    .await?
        }
    };
    if !same_person {
        return failed(Failure::WrongAccount);
    }
    let code = six_digit_code();
    login.confirm_code = Some(code.clone());
    let (device, platform, parked_ip) = (
        login.device_name.clone(),
        login.device_platform.clone(),
        login.ip.clone(),
    );
    state
        .pending_sso
        .reinsert(challenge, &parked_ip, login, expires);
    let page = Page::Code {
        code: &code,
        device: &device,
        platform: &platform,
    };
    Ok(page::render(&page, &headers))
}
