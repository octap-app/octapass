//! SSO settings, and the browser's way through the identity provider, by OpenID Connect or SAML
//! 2.0. The provider decides only whether a sign-in that already passed OPAQUE may go on (plan 03,
//! "SSO is sign-in only").

use axum::Json;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{
    OrgRole, OrgSamlCertificate, OrgSamlIdpRecord, OrgSamlRequest, OrgSamlServiceProvider,
    OrgSsoRecord, OrgSsoRequest, OrgSsoTestResponse, SsoProtocol,
};
use serde::Deserialize;

use super::orgs::locked;
use crate::crypto::{random_token, six_digit_code};
use crate::db::orgs::{SsoRule, SsoSettings};
use crate::db::{self, accounts, orgs};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated, ClientIp};
use crate::login::{BrowserFlow, SsoBrowser, SsoPurpose};
use crate::saml::{self, IdpSettings, SamlError, ServiceProvider};
use crate::sso::page::{self, Failure, Page};
use crate::sso::{self, Claims, Exchange, Flow, SsoError};
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

fn saml_config_error(error: SamlError) -> ApiError {
    ApiError::SsoConfig(error.to_string())
}

fn service_provider(state: &AppState, org_id: &str) -> ServiceProvider {
    ServiceProvider::for_org(public_url(state), org_id)
}

fn sp_record(state: &AppState, org_id: &str) -> OrgSamlServiceProvider {
    let sp = service_provider(state, org_id);
    OrgSamlServiceProvider {
        metadata_url: sp.entity_id.clone(),
        entity_id: sp.entity_id,
        acs_url: sp.acs_url,
    }
}

/// The stored SAML settings, ready to use. `None` if the row isn't SAML or no longer parses.
fn idp_settings(state: &AppState, rule: &SsoRule) -> Option<IdpSettings> {
    if !rule.is_saml() {
        return None;
    }
    let sso_url = saml::sso_url(rule.saml_sso_url.as_deref()?, state.config.dev_mode).ok()?;
    let certificates = saml::parse_stored_certificates(rule.saml_certificates.as_deref()?);
    if certificates.is_empty() {
        return None;
    }
    Some(IdpSettings {
        entity_id: rule.issuer.clone(),
        sso_url,
        certificates,
    })
}

fn saml_record(settings: &IdpSettings) -> OrgSamlIdpRecord {
    OrgSamlIdpRecord {
        entity_id: settings.entity_id.clone(),
        sso_url: settings.sso_url.to_string(),
        certificates: settings
            .certificates
            .iter()
            .map(|certificate| OrgSamlCertificate {
                sha256: certificate.fingerprint(),
                not_after: certificate.not_after.map(db::rfc3339),
            })
            .collect(),
    }
}

fn record(
    state: &AppState,
    org_id: &str,
    settings: Option<&SsoRule>,
    tested_at: Option<i64>,
) -> OrgSsoRecord {
    let saml = settings.and_then(|settings| idp_settings(state, settings));
    let oidc = settings.filter(|settings| !settings.is_saml());
    OrgSsoRecord {
        has_client_secret: oidc.is_some_and(|settings| settings.client_secret.is_some()),
        issuer: oidc.map(|settings| settings.issuer.clone()),
        client_id: oidc.map(|settings| settings.client_id.clone()),
        tested_at: tested_at.map(db::rfc3339),
        callback_url: callback_url(state),
        protocol: settings.map(|settings| {
            if settings.is_saml() {
                SsoProtocol::Saml
            } else {
                SsoProtocol::Oidc
            }
        }),
        saml: saml.as_ref().map(saml_record),
        saml_service_provider: sp_record(state, org_id),
    }
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
    Ok(Json(record(&state, &org_id, settings.as_ref(), tested_at)))
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
        .filter(|settings| !settings.is_saml() && settings.issuer == issuer)
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
    let settings = SsoSettings::Oidc {
        issuer: &issuer,
        client_id: &client_id,
        client_secret: client_secret.as_deref(),
    };
    orgs::put_sso(&mut tx, &org_id, settings, now).await?;
    orgs::record_event(&mut tx, &org_id, me, "sso-changed", Some(&issuer), now).await?;
    tx.commit().await?;
    let saved = orgs::sso_settings(&state.db, &org_id).await?;
    Ok(Json(record(&state, &org_id, saved.as_ref(), None)))
}

/// What a SAML settings request describes, checked.
fn saml_settings(state: &AppState, request: &OrgSamlRequest) -> ApiResult<IdpSettings> {
    let allow_http = state.config.dev_mode;
    if let Some(metadata) = request.metadata_xml.as_deref() {
        if request.entity_id.is_some()
            || request.sso_url.is_some()
            || !request.certificates.is_empty()
        {
            return Err(ApiError::BadRequest(
                "send metadataXml, or entityId, ssoUrl and certificates, not both".into(),
            ));
        }
        return saml::parse_metadata(metadata, allow_http).map_err(saml_config_error);
    }
    let (Some(entity_id), Some(sso_url)) =
        (request.entity_id.as_deref(), request.sso_url.as_deref())
    else {
        return Err(ApiError::BadRequest(
            "send metadataXml, or entityId, ssoUrl and certificates".into(),
        ));
    };
    let entity_id = validate::text("entityId", entity_id, MAX_ISSUER)?;
    let sso_url = saml::sso_url(sso_url, allow_http).map_err(saml_config_error)?;
    if request.certificates.is_empty() || request.certificates.len() > saml::MAX_CERTIFICATES {
        return Err(ApiError::BadRequest(format!(
            "certificates must hold 1 to {} certificates",
            saml::MAX_CERTIFICATES
        )));
    }
    let certificates = request
        .certificates
        .iter()
        .map(|certificate| saml::Certificate::parse(certificate))
        .collect::<Result<Vec<_>, _>>()
        .map_err(saml_config_error)?;
    Ok(IdpSettings {
        entity_id,
        sso_url,
        certificates,
    })
}

#[utoipa::path(
    put, path = "/v1/orgs/{orgId}/sso/saml", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = OrgSamlRequest,
    responses(
        (status = 200, body = OrgSsoRecord, description = "Saved, replacing any OpenID Connect settings. A test sign-in is needed again."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "invalid-request, or sso-config: the metadata or a certificate can't be used; SSO is required right now"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn put_saml(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<OrgSamlRequest>,
) -> ApiResult<Json<OrgSsoRecord>> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let idp = saml_settings(&state, &request)?;
    let certificates = saml::store_certificates(&idp.certificates);
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
    let settings = SsoSettings::Saml {
        entity_id: &idp.entity_id,
        sso_url: idp.sso_url.as_str(),
        certificates: &certificates,
    };
    orgs::put_sso(&mut tx, &org_id, settings, now).await?;
    let event = "sso-changed";
    orgs::record_event(&mut tx, &org_id, me, event, Some(&idp.entity_id), now).await?;
    tx.commit().await?;
    let saved = orgs::sso_settings(&state.db, &org_id).await?;
    Ok(Json(record(&state, &org_id, saved.as_ref(), None)))
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
    if settings.is_saml() {
        let Some(idp) = idp_settings(&state, &settings) else {
            tracing::error!("an organisation's SAML settings don't parse");
            return Ok(failed(Failure::Provider));
        };
        let flow = saml::Flow::new();
        let sp = service_provider(&state, &browser.org_id);
        let url = flow.redirect_url(&sp, &idp, state.clock.now());
        browser.flow = Some(BrowserFlow::Saml {
            request_id: flow.request_id,
            updated_at: settings.updated_at,
        });
        state
            .pending_sso_browsers
            .insert(flow.relay_state, &ip, browser);
        return Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response());
    }
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
    browser.flow = Some(BrowserFlow::Oidc(flow, provider));
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
    let (Some(code), Some(BrowserFlow::Oidc(flow, provider))) =
        (query.code.as_deref(), browser.flow.as_ref())
    else {
        return failed(Failure::Provider);
    };
    let Some(settings) = orgs::sso_settings(&state.db, &browser.org_id)
        .await?
        .filter(|settings| !settings.is_saml())
    else {
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
    finish(&state, &headers, browser, claims).await
}

/// After the provider vouched for `claims`: a test sign-in is done, or the sign-in gets its code,
/// if the provider signed in this member.
async fn finish(
    state: &AppState,
    headers: &HeaderMap,
    browser: SsoBrowser,
    claims: Claims,
) -> ApiResult<Response> {
    let failed = |failure| Ok(page::render(&Page::Failed(failure), headers));
    let challenge = match browser.purpose {
        SsoPurpose::Test { updated_at } => {
            let now = state.clock.now();
            if !orgs::sso_tested(&state.db, &browser.org_id, updated_at, now).await? {
                return failed(Failure::Expired);
            }
            return Ok(page::render(&Page::Tested, headers));
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
    Ok(page::render(&page, headers))
}

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(default, rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(default, rename = "RelayState")]
    relay_state: Option<String>,
}

/// The assertion consumer service: where the identity provider posts the browser back with its
/// signed Response (HTTP-POST binding).
#[utoipa::path(
    post, path = "/v1/sso/saml/{orgId}/acs", tag = "auth",
    params(("orgId" = String, Path)),
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "SAMLResponse and RelayState"),
    responses(
        (status = 200, description = "An HTML page with the 6-digit code to type into the app"),
        (status = 400, description = "An HTML page saying what went wrong"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn saml_acs(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiPath(org_id): ApiPath<String>,
    Form(form): Form<AcsForm>,
) -> ApiResult<Response> {
    super::auth::charge(&state.ip_limiter, &ip)?;
    let failed = |failure| Ok(page::render(&Page::Failed(failure), &headers));
    let browser = form
        .relay_state
        .as_deref()
        .and_then(|key| state.pending_sso_browsers.take(key));
    let Some(browser) = browser.filter(|browser| browser.org_id == org_id) else {
        return failed(Failure::Expired);
    };
    let (
        Some(response),
        Some(BrowserFlow::Saml {
            request_id,
            updated_at,
        }),
    ) = (form.saml_response.as_deref(), browser.flow.as_ref())
    else {
        return failed(Failure::Provider);
    };
    let settings = orgs::sso_settings(&state.db, &org_id)
        .await?
        .filter(|settings| settings.updated_at == *updated_at);
    let Some(idp) = settings
        .as_ref()
        .and_then(|settings| idp_settings(&state, settings))
    else {
        return failed(Failure::Expired);
    };
    let sp = service_provider(&state, &org_id);
    let expected = saml::Expected {
        idp: &idp,
        sp: &sp,
        request_id,
        now_ms: state.clock.now(),
    };
    let claims = match saml::verify_response(response, &expected) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "a SAML sign-in failed");
            return failed(Failure::Provider);
        }
    };
    finish(&state, &headers, browser, claims).await
}

/// This server's SAML service provider metadata for an organisation. It's the same for any id
/// and needs no lookup, so it says nothing about which organisations exist.
#[utoipa::path(
    get, path = "/v1/sso/saml/{orgId}/metadata", tag = "auth",
    params(("orgId" = String, Path)),
    responses(
        (status = 200, description = "SAML 2.0 metadata (application/samlmetadata+xml)", content_type = "application/samlmetadata+xml"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn saml_metadata(
    State(state): State<AppState>,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Response> {
    let org_id = validate::id("orgId", &org_id)?;
    let metadata = service_provider(&state, &org_id).metadata();
    let mut response = (StatusCode::OK, metadata).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/samlmetadata+xml"),
    );
    Ok(response)
}
