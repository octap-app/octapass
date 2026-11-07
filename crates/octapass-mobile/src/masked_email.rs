//! Masked email aliases (plan 06, Phase A), as the web vault's `maskedEmail/providers.ts` and
//! `service.ts` make them. Calls go from the phone straight to the provider with the user's own
//! token, which is kept in the vault as a `maskedEmailProvider` item and never sent to the Open
//! Pass server unencrypted. Unlike a web page, the apps can call every provider.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use octapass_mobile_vault::model::{Item as StoredItem, ItemDraft as StoredDraft};
use serde_json::{Value, json};
use ureq::tls::{RootCerts, TlsConfig};

use crate::api::secure_origin;
use crate::error::{ErrorCode, Result, VaultError};
use crate::health::{hostname_of, registrable_domain};
use crate::items::type_of;
use crate::vault::Ctx;

const FASTMAIL_SESSION: &str = "https://api.fastmail.com/jmap/session";
const FASTMAIL_CAPABILITY: &str = "https://www.fastmail.com/dev/maskedemail";
/// Provider answers are a few hundred bytes.
const MAX_BODY: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MaskedEmailProvider {
    /// `simplelogin`, `addy`, `firefoxRelay`, `fastmail`, `duckduckgo` or `forwardEmail`.
    pub id: String,
    pub name: String,
    /// Where the user makes an API token.
    pub token_url: String,
    /// The API's default origin, for providers that can be self-hosted.
    pub default_base_url: Option<String>,
    /// New aliases need a domain.
    pub needs_domain: bool,
}

/// A connected provider, without its token.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MaskedEmailConnection {
    /// The vault item that holds the token.
    pub item_id: String,
    pub provider: String,
    pub base_url: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MaskedAlias {
    pub email: String,
    pub provider: String,
    /// The provider's id for the alias, or the address when it has none.
    pub alias_id: String,
}

/// The providers the apps know, in the order the web vault lists them.
#[uniffi::export]
pub fn masked_email_providers() -> Vec<MaskedEmailProvider> {
    let provider = |id: &str, name: &str, token_url: &str, base: Option<&str>, needs_domain| {
        MaskedEmailProvider {
            id: id.into(),
            name: name.into(),
            token_url: token_url.into(),
            default_base_url: base.map(str::to_owned),
            needs_domain,
        }
    };
    vec![
        provider(
            "simplelogin",
            "SimpleLogin",
            "https://app.simplelogin.io/dashboard/api_key",
            Some("https://app.simplelogin.io"),
            false,
        ),
        provider(
            "addy",
            "addy.io",
            "https://app.addy.io/settings/api",
            Some("https://app.addy.io"),
            true,
        ),
        provider(
            "firefoxRelay",
            "Firefox Relay",
            "https://relay.firefox.com/accounts/settings/",
            None,
            false,
        ),
        provider(
            "fastmail",
            "Fastmail",
            "https://app.fastmail.com/settings/security/tokens",
            None,
            false,
        ),
        provider(
            "duckduckgo",
            "DuckDuckGo",
            "https://duckduckgo.com/email/settings/autofill",
            None,
            false,
        ),
        provider(
            "forwardEmail",
            "Forward Email",
            "https://forwardemail.net/my-account/security",
            None,
            true,
        ),
    ]
}

fn provider_info(id: &str) -> Result<MaskedEmailProvider> {
    masked_email_providers()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| {
            VaultError::new(
                ErrorCode::MaskedEmailFailed,
                format!("unknown provider: {id}"),
            )
        })
}

pub(crate) struct ProviderRequest {
    pub url: String,
    pub method: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<String>,
}

pub(crate) struct ProviderResponse {
    pub status: u16,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// One request to a provider. Fails only when nothing came back.
pub(crate) trait ProviderHttp: Send + Sync {
    fn send(&self, request: ProviderRequest) -> std::result::Result<ProviderResponse, String>;
}

/// HTTPS only (plain HTTP to this device, for a self-hosted server in development), and no
/// redirects, so the token can't follow one to another host.
pub(crate) struct Ureq {
    agent: ureq::Agent,
}

impl Ureq {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(0)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        Self { agent }
    }
}

impl ProviderHttp for Ureq {
    fn send(&self, request: ProviderRequest) -> std::result::Result<ProviderResponse, String> {
        secure_origin(&request.url).ok_or("not HTTPS")?;
        let mut builder = ureq::http::Request::builder()
            .method(request.method)
            .uri(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        let built = builder
            .body(request.body.unwrap_or_default())
            .map_err(|error| error.to_string())?;
        let response = self.agent.run(built).map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    name.as_str().to_lowercase(),
                    value.to_str().ok()?.to_owned(),
                ))
            })
            .collect();
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(|error| error.to_string())?;
        Ok(ProviderResponse {
            status,
            headers,
            body,
        })
    }
}

/// What a new alias is for: the site's domain, and its origin for providers that take one.
struct AliasFor {
    domain: String,
    origin: String,
}

fn alias_site(site: &str) -> Result<AliasFor> {
    let host = hostname_of(site).ok_or_else(|| {
        VaultError::new(
            ErrorCode::MaskedEmailFailed,
            "Enter a website for the alias.",
        )
    })?;
    Ok(AliasFor {
        domain: registrable_domain(&host),
        origin: format!("https://{host}"),
    })
}

/// A self-hosted server must use HTTPS, except on this device (development and tests).
fn check_base_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| ErrorCode::InsecureServerUrl)?;
    secure_origin(url).ok_or(ErrorCode::InsecureServerUrl)?;
    Ok(format!(
        "{}{}",
        parsed.origin().ascii_serialization(),
        parsed.path().trim_end_matches('/')
    ))
}

fn failed(message: impl Into<String>) -> VaultError {
    VaultError::new(ErrorCode::MaskedEmailFailed, message)
}

fn unreadable() -> VaultError {
    failed("The provider sent an answer Octa Pass could not read.")
}

/// The provider's own words about an error, from the usual JSON shapes.
fn provider_message(body: &str) -> Option<String> {
    let json: Value = serde_json::from_str(body).ok()?;
    ["error", "message", "detail", "description"]
        .iter()
        .filter_map(|key| json.get(*key)?.as_str())
        .map(str::trim)
        .find(|text| !text.is_empty())
        .map(|text| text.chars().take(200).collect())
}

/// The provider's answer, once errors are returned. `gone_is_fine` accepts 404: what was asked for
/// is already so.
fn answer(http: &dyn ProviderHttp, request: ProviderRequest, gone_is_fine: bool) -> Result<String> {
    let response = http
        .send(request)
        .map_err(|reason| VaultError::new(ErrorCode::MaskedEmailUnreachable, reason))?;
    let message = || provider_message(&response.body);
    match response.status {
        401 | 403 => {
            return Err(VaultError::new(
                ErrorCode::MaskedEmailToken,
                message().unwrap_or_default(),
            ));
        }
        429 => {
            let retry = response
                .headers
                .get("retry-after")
                .map(|seconds| format!(" (retry after {seconds})"))
                .unwrap_or_default();
            return Err(VaultError::new(
                ErrorCode::MaskedEmailRateLimited,
                format!("{}{retry}", message().unwrap_or_default()),
            ));
        }
        200..=299 => {}
        404 if gone_is_fine => return Ok(String::new()),
        status => {
            return Err(failed(
                message().unwrap_or_else(|| format!("HTTP {status}")),
            ));
        }
    }
    Ok(response.body)
}

fn send(http: &dyn ProviderHttp, request: ProviderRequest) -> Result<Value> {
    serde_json::from_str(&answer(http, request, false)?).map_err(|_| unreadable())
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn json_headers() -> Vec<(&'static str, String)> {
    vec![
        ("content-type", "application/json".into()),
        ("accept", "application/json".into()),
    ]
}

struct Config {
    token: String,
    base_url: Option<String>,
    domain: Option<String>,
}

/// `(email, alias id)`
fn create(
    http: &dyn ProviderHttp,
    provider: &str,
    config: &Config,
    site: &AliasFor,
) -> Result<(String, String)> {
    let found = |email: Option<String>, id: Option<String>| {
        let email = email.ok_or_else(unreadable)?;
        Ok((email.clone(), id.unwrap_or(email)))
    };
    match provider {
        "simplelogin" => {
            let base = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://app.simplelogin.io".into());
            let mut headers = json_headers();
            headers.push(("authentication", config.token.clone()));
            let json = send(
                http,
                ProviderRequest {
                    url: format!(
                        "{base}/api/alias/random/new?hostname={}",
                        url::form_urlencoded::byte_serialize(site.domain.as_bytes())
                            .collect::<String>()
                    ),
                    method: "POST",
                    headers,
                    body: Some(json!({ "note": site.domain }).to_string()),
                },
            )?;
            found(text(json.get("alias")), text(json.get("id")))
        }
        "addy" => {
            let base = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://app.addy.io".into());
            let mut headers = json_headers();
            headers.push(("authorization", format!("Bearer {}", config.token)));
            headers.push(("x-requested-with", "XMLHttpRequest".into()));
            let json = send(
                http,
                ProviderRequest {
                    url: format!("{base}/api/v1/aliases"),
                    method: "POST",
                    headers,
                    body: Some(
                        json!({ "domain": config.domain, "description": site.domain }).to_string(),
                    ),
                },
            )?;
            let data = json.get("data");
            found(
                text(data.and_then(|d| d.get("email"))),
                text(data.and_then(|d| d.get("id"))),
            )
        }
        "firefoxRelay" => {
            let mut headers = json_headers();
            headers.push(("authorization", format!("Token {}", config.token)));
            let json = send(http, ProviderRequest {
                url: "https://relay.firefox.com/api/v1/relayaddresses/".into(),
                method: "POST",
                headers,
                body: Some(json!({ "enabled": true, "generated_for": site.domain, "description": site.domain }).to_string()),
            })?;
            found(text(json.get("full_address")), text(json.get("id")))
        }
        "fastmail" => {
            // JMAP: `MaskedEmail/set` creates one.
            let (account_id, api_url) = fastmail_session(http, &config.token)?;
            let mut headers = json_headers();
            headers.push(("authorization", format!("Bearer {}", config.token)));
            let json = send(http, ProviderRequest {
                url: api_url,
                method: "POST",
                headers,
                body: Some(json!({
                    "using": ["urn:ietf:params:jmap:core", FASTMAIL_CAPABILITY],
                    "methodCalls": [["MaskedEmail/set", { "accountId": account_id, "create": { "octapass": { "state": "enabled", "description": site.domain, "forDomain": site.origin } } }, "0"]],
                }).to_string()),
            })?;
            let first = json.get("methodResponses").and_then(|r| r.get(0));
            let name = first.and_then(|r| r.get(0)).and_then(Value::as_str);
            let result = first.and_then(|r| r.get(1));
            if name == Some("error") {
                return Err(failed(
                    text(result.and_then(|r| r.get("description")))
                        .or_else(|| text(result.and_then(|r| r.get("type"))))
                        .unwrap_or_default(),
                ));
            }
            if let Some(refused) = result
                .and_then(|r| r.get("notCreated"))
                .and_then(|n| n.get("octapass"))
            {
                return Err(failed(
                    text(refused.get("description"))
                        .or_else(|| text(refused.get("type")))
                        .unwrap_or_default(),
                ));
            }
            let created = result
                .and_then(|r| r.get("created"))
                .and_then(|c| c.get("octapass"));
            found(
                text(created.and_then(|c| c.get("email"))),
                text(created.and_then(|c| c.get("id"))),
            )
        }
        "duckduckgo" => {
            // No description, no id, just a new address on duck.com.
            let json = send(
                http,
                ProviderRequest {
                    url: "https://quack.duckduckgo.com/api/email/addresses".into(),
                    method: "POST",
                    headers: vec![
                        ("accept", "application/json".into()),
                        ("authorization", format!("Bearer {}", config.token)),
                    ],
                    body: None,
                },
            )?;
            let local = text(json.get("address"))
                .filter(|a| {
                    a.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                })
                .ok_or_else(unreadable)?;
            let email = format!("{local}@duck.com");
            Ok((email.clone(), email))
        }
        "forwardEmail" => {
            // Basic auth with the token as the user name; no alias name gets a random one.
            let domain = config.domain.clone().unwrap_or_default();
            let mut headers = json_headers();
            let basic =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:", config.token));
            headers.push(("authorization", format!("Basic {basic}")));
            let json = send(http, ProviderRequest {
                url: format!(
                    "https://api.forwardemail.net/v1/domains/{}/aliases",
                    url::form_urlencoded::byte_serialize(domain.as_bytes()).collect::<String>()
                ),
                method: "POST",
                headers,
                body: Some(json!({ "description": site.domain, "labels": site.domain, "is_enabled": true }).to_string()),
            })?;
            let name = text(json.get("name"));
            let email = name.map(|name| {
                format!(
                    "{name}@{}",
                    text(json.get("domain").and_then(|d| d.get("name"))).unwrap_or(domain)
                )
            });
            found(email, text(json.get("id")))
        }
        other => Err(failed(format!("unknown provider: {other}"))),
    }
}

/// What can be done to an alias already made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasAction {
    Enable,
    Disable,
    Delete,
}

/// Whether Octa Pass can turn an alias off or delete it. DuckDuckGo has no call for it, and an
/// alias with no id of its own can only be managed on the provider's site.
#[uniffi::export]
pub fn can_manage_alias(provider: String, alias_id: String, email: String) -> bool {
    provider != "duckduckgo" && !alias_id.is_empty() && alias_id != email
}

/// One part of a URL's path.
fn segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The JMAP session names the account that has masked email and where to call.
fn fastmail_session(http: &dyn ProviderHttp, token: &str) -> Result<(String, String)> {
    let session = send(
        http,
        ProviderRequest {
            url: FASTMAIL_SESSION.into(),
            method: "GET",
            headers: vec![
                ("authorization", format!("Bearer {token}")),
                ("accept", "application/json".into()),
            ],
            body: None,
        },
    )?;
    let Some(account_id) = text(
        session
            .get("primaryAccounts")
            .and_then(|p| p.get(FASTMAIL_CAPABILITY)),
    ) else {
        // A token without the Masked Email scope gets a session without it.
        return Err(VaultError::new(
            ErrorCode::MaskedEmailToken,
            "This token has no access to Masked Email.",
        ));
    };
    let api_url = text(session.get("apiUrl"))
        .filter(|u| u.starts_with("https://"))
        .ok_or_else(unreadable)?;
    Ok((account_id, api_url))
}

/// SimpleLogin only toggles, so the alias's state comes first and a repeat changes nothing.
fn change_alias(
    http: &dyn ProviderHttp,
    provider: &str,
    config: &Config,
    alias_id: &str,
    action: AliasAction,
) -> Result<()> {
    let id = segment(alias_id);
    let on = action == AliasAction::Enable;
    let request = |url: String, method: &'static str, headers, body| ProviderRequest {
        url,
        method,
        headers,
        body,
    };
    match provider {
        "simplelogin" => {
            let base = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://app.simplelogin.io".into());
            let mut headers = json_headers();
            headers.push(("authentication", config.token.clone()));
            let url = format!("{base}/api/aliases/{id}");
            if action == AliasAction::Delete {
                answer(http, request(url, "DELETE", headers, None), true)?;
                return Ok(());
            }
            let alias = send(http, request(url.clone(), "GET", headers.clone(), None))?;
            let enabled = alias
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(unreadable)?;
            if enabled != on {
                let toggle = format!("{url}/toggle");
                answer(http, request(toggle, "POST", headers, None), false)?;
            }
        }
        "addy" => {
            let base = config
                .base_url
                .clone()
                .unwrap_or_else(|| "https://app.addy.io".into());
            let mut headers = json_headers();
            headers.push(("authorization", format!("Bearer {}", config.token)));
            headers.push(("x-requested-with", "XMLHttpRequest".into()));
            let call = match action {
                AliasAction::Delete => {
                    let url = format!("{base}/api/v1/aliases/{id}");
                    answer(http, request(url, "DELETE", headers, None), true)
                }
                AliasAction::Disable => {
                    let url = format!("{base}/api/v1/active-aliases/{id}");
                    answer(http, request(url, "DELETE", headers, None), false)
                }
                AliasAction::Enable => {
                    let url = format!("{base}/api/v1/active-aliases");
                    let body = json!({ "id": alias_id }).to_string();
                    answer(http, request(url, "POST", headers, Some(body)), false)
                }
            };
            call?;
        }
        "firefoxRelay" => {
            let url = format!("https://relay.firefox.com/api/v1/relayaddresses/{id}/");
            let mut headers = json_headers();
            headers.push(("authorization", format!("Token {}", config.token)));
            if action == AliasAction::Delete {
                answer(http, request(url, "DELETE", headers, None), true)?;
            } else {
                let body = json!({ "enabled": on }).to_string();
                answer(http, request(url, "PATCH", headers, Some(body)), false)?;
            }
        }
        "fastmail" => {
            let state = match action {
                AliasAction::Enable => "enabled",
                AliasAction::Disable => "disabled",
                AliasAction::Delete => "deleted",
            };
            let (account_id, api_url) = fastmail_session(http, &config.token)?;
            let mut headers = json_headers();
            headers.push(("authorization", format!("Bearer {}", config.token)));
            let body = json!({
                "using": ["urn:ietf:params:jmap:core", FASTMAIL_CAPABILITY],
                "methodCalls": [["MaskedEmail/set", {
                    "accountId": account_id,
                    "update": { alias_id: { "state": state } },
                }, "0"]],
            })
            .to_string();
            let json = send(http, request(api_url, "POST", headers, Some(body)))?;
            let first = json.pointer("/methodResponses/0").ok_or_else(unreadable)?;
            let result = first.get(1).unwrap_or(&Value::Null);
            let describe = |value: &Value| {
                text(value.get("description"))
                    .or_else(|| text(value.get("type")))
                    .unwrap_or_else(|| "Fastmail refused the change.".into())
            };
            if first.get(0).and_then(Value::as_str) == Some("error") {
                return Err(failed(describe(result)));
            }
            if let Some(refused) = result.get("notUpdated").and_then(|n| n.get(alias_id)) {
                let gone = refused.get("type").and_then(Value::as_str) == Some("notFound");
                if !(gone && action == AliasAction::Delete) {
                    return Err(failed(describe(refused)));
                }
            }
        }
        "forwardEmail" => {
            let domain = segment(config.domain.as_deref().unwrap_or_default());
            let url = format!("https://api.forwardemail.net/v1/domains/{domain}/aliases/{id}");
            let mut headers = json_headers();
            let basic =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:", config.token));
            headers.push(("authorization", format!("Basic {basic}")));
            if action == AliasAction::Delete {
                answer(http, request(url, "DELETE", headers, None), true)?;
            } else {
                let body = json!({ "is_enabled": on }).to_string();
                answer(http, request(url, "PUT", headers, Some(body)), false)?;
            }
        }
        other => return Err(failed(format!("{other} has no API for this."))),
    }
    Ok(())
}

fn connection(item: &StoredItem) -> MaskedEmailConnection {
    let field = |key: &str| {
        item.details
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    MaskedEmailConnection {
        item_id: item.id.clone(),
        provider: field("provider").unwrap_or_default(),
        base_url: field("baseUrl"),
        domain: field("domain"),
    }
}

impl Ctx<'_> {
    fn alias_action(
        &self,
        provider: &str,
        alias_id: &str,
        email: &str,
        action: AliasAction,
    ) -> Result<()> {
        if !can_manage_alias(provider.into(), alias_id.into(), email.into()) {
            let name = provider_info(provider)?.name;
            return Err(failed(format!("{name} can only do this on its own site.")));
        }
        let items = self.provider_items()?;
        let item = items
            .iter()
            .find(|item| item.details.get("provider").and_then(Value::as_str) == Some(provider))
            .ok_or(ErrorCode::MaskedEmailNotSetUp)?;
        let field = |key: &str| {
            item.details
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let config = Config {
            token: field("token").unwrap_or_default(),
            base_url: field("baseUrl").map(|b| check_base_url(&b)).transpose()?,
            domain: field("domain").filter(|d| !d.is_empty()),
        };
        change_alias(self.provider_http, provider, &config, alias_id, action)
    }

    /// Turns an alias on or off at its provider.
    pub fn set_alias_enabled(
        &self,
        provider: &str,
        alias_id: &str,
        email: &str,
        enabled: bool,
    ) -> Result<()> {
        let action = if enabled {
            AliasAction::Enable
        } else {
            AliasAction::Disable
        };
        self.alias_action(provider, alias_id, email, action)
    }

    /// Deletes an alias at its provider, then unlinks it from these logins. The address stays on
    /// them as text: it's still what the site has.
    pub fn delete_alias(
        &self,
        provider: &str,
        alias_id: &str,
        email: &str,
        login_ids: &[String],
    ) -> Result<()> {
        self.alias_action(provider, alias_id, email, AliasAction::Delete)?;
        for id in login_ids {
            let item = self.vault.get_item(id)?;
            let mut details = item.details.clone();
            let Some(recovery) = details.get_mut("recovery").and_then(Value::as_object_mut) else {
                continue;
            };
            let source = recovery.get("emailSource");
            let linked = |key: &str, value: &str| {
                source.and_then(|s| s.get(key)).and_then(Value::as_str) == Some(value)
            };
            if linked("kind", "alias")
                && linked("provider", provider)
                && linked("aliasId", alias_id)
            {
                recovery.remove("emailSource");
                self.vault.save_item(StoredDraft {
                    id: Some(item.id.clone()),
                    vault_id: item.vault_id.clone(),
                    revision: Some(item.revision),
                    overview: item.overview.clone(),
                    details,
                })?;
            }
        }
        Ok(())
    }

    /// The provider items, oldest first, so the first one connected stays the default.
    fn provider_items(&self) -> Result<Vec<StoredItem>> {
        let mut items: Vec<StoredItem> = self
            .vault
            .all_items()?
            .into_iter()
            .filter(|item| item.deleted_at.is_none() && type_of(item) == "maskedEmailProvider")
            .collect();
        items.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(items)
    }

    pub fn masked_email_connections(&self) -> Result<Vec<MaskedEmailConnection>> {
        Ok(self.provider_items()?.iter().map(connection).collect())
    }

    /// Stores the token in the personal vault. Doesn't call the provider.
    pub fn connect_masked_email(
        &self,
        provider: &str,
        token: &str,
        base_url: Option<&str>,
        domain: Option<&str>,
        personal_vault_id: &str,
    ) -> Result<MaskedEmailConnection> {
        let info = provider_info(provider)?;
        let token = token.trim();
        let domain = domain
            .map(|d| d.trim().trim_start_matches('@').to_lowercase())
            .filter(|d| !d.is_empty());
        let base_url = base_url
            .filter(|b| !b.trim().is_empty())
            .map(check_base_url)
            .transpose()?;
        if token.is_empty() {
            return Err(ErrorCode::MaskedEmailToken.into());
        }
        if info.needs_domain && domain.is_none() {
            return Err(failed(format!(
                "{} needs a domain for new aliases.",
                info.name
            )));
        }
        let base_url = base_url.filter(|b| Some(b) != info.default_base_url.as_ref());
        let mut details = json!({ "schemaVersion": 1, "provider": info.id, "token": token });
        if let Some(base_url) = &base_url {
            details["baseUrl"] = Value::String(base_url.clone());
        }
        if let Some(domain) = &domain {
            details["domain"] = Value::String(domain.clone());
        }
        let subtitle = domain.clone().or_else(|| {
            base_url
                .as_deref()
                .and_then(|b| url::Url::parse(b).ok())
                .and_then(|u| u.host_str().map(str::to_owned))
        });
        let mut overview =
            json!({ "schemaVersion": 1, "type": "maskedEmailProvider", "title": info.name });
        if let Some(subtitle) = subtitle {
            overview["subtitle"] = Value::String(subtitle);
        }
        let item = self.vault.save_item(StoredDraft {
            id: None,
            vault_id: personal_vault_id.into(),
            revision: None,
            overview,
            details,
        })?;
        Ok(connection(&item))
    }

    /// Moves the token's item to the trash. Aliases made with it keep working.
    pub fn disconnect_masked_email(&self, item_id: &str) -> Result<()> {
        let item = self.vault.get_item(item_id)?;
        if type_of(&item) != "maskedEmailProvider" {
            return Err(ErrorCode::NotFound.into());
        }
        Ok(self.vault.delete_item(item_id)?)
    }

    /// A new alias for `site` (a URL or host), described with the site's domain, from the given
    /// connection or the first one.
    pub fn create_alias(&self, site: &str, connection_id: Option<&str>) -> Result<MaskedAlias> {
        let site = alias_site(site)?;
        let items = self.provider_items()?;
        let item = match connection_id {
            Some(id) => items.iter().find(|item| item.id == id),
            None => items.first(),
        }
        .ok_or(ErrorCode::MaskedEmailNotSetUp)?;
        let field = |key: &str| {
            item.details
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let provider = field("provider").unwrap_or_default();
        let info = provider_info(&provider)?;
        let domain = field("domain").filter(|d| !d.is_empty());
        if info.needs_domain && domain.is_none() {
            return Err(failed(format!(
                "{} needs a domain for new aliases.",
                info.name
            )));
        }
        let config = Config {
            token: field("token").unwrap_or_default(),
            base_url: field("baseUrl").map(|b| check_base_url(&b)).transpose()?,
            domain,
        };
        let (email, alias_id) = create(self.provider_http, &info.id, &config, &site)?;
        Ok(MaskedAlias {
            email,
            provider: info.id,
            alias_id,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A request as sent: method, URL, headers and body.
    type Sent = (String, String, Vec<(String, String)>, Option<String>);

    /// Answers every request with the next canned response and records what was sent.
    #[derive(Default)]
    pub struct FakeProvider {
        pub answers: Mutex<Vec<(u16, String)>>,
        pub sent: Mutex<Vec<Sent>>,
    }

    impl ProviderHttp for FakeProvider {
        fn send(&self, request: ProviderRequest) -> std::result::Result<ProviderResponse, String> {
            self.sent.lock().unwrap().push((
                request.method.into(),
                request.url,
                request
                    .headers
                    .iter()
                    .map(|(n, v)| ((*n).into(), v.clone()))
                    .collect(),
                request.body,
            ));
            let mut answers = self.answers.lock().unwrap();
            if answers.is_empty() {
                return Err("offline".into());
            }
            let (status, body) = answers.remove(0);
            Ok(ProviderResponse {
                status,
                headers: HashMap::from([("retry-after".into(), "30".into())]),
                body,
            })
        }
    }

    fn config(domain: Option<&str>) -> Config {
        Config {
            token: "t0k".into(),
            base_url: None,
            domain: domain.map(str::to_owned),
        }
    }

    #[test]
    fn each_provider_makes_an_alias() {
        let site = alias_site("https://accounts.example.co.uk/login").unwrap();
        assert_eq!(site.domain, "example.co.uk");
        let cases = [
            (
                "simplelogin",
                json!({ "alias": "a@sl.co", "id": 7 }),
                "a@sl.co",
                "7",
            ),
            (
                "addy",
                json!({ "data": { "email": "b@anonaddy.me", "id": "x" } }),
                "b@anonaddy.me",
                "x",
            ),
            (
                "firefoxRelay",
                json!({ "full_address": "c@relay", "id": 3 }),
                "c@relay",
                "3",
            ),
            (
                "duckduckgo",
                json!({ "address": "quiet-fox" }),
                "quiet-fox@duck.com",
                "quiet-fox@duck.com",
            ),
            (
                "forwardEmail",
                json!({ "name": "d", "id": "e", "domain": { "name": "fe.test" } }),
                "d@fe.test",
                "e",
            ),
        ];
        for (provider, answer, email, id) in cases {
            let http = FakeProvider::default();
            http.answers.lock().unwrap().push((201, answer.to_string()));
            let made = create(&http, provider, &config(Some("fe.test")), &site).unwrap();
            assert_eq!(made, (email.into(), id.into()), "{provider}");
        }
    }

    #[test]
    fn fastmail_uses_its_jmap_session() {
        let http = FakeProvider::default();
        http.answers.lock().unwrap().extend([
            (200, json!({ "apiUrl": "https://api.fastmail.com/jmap/api/", "primaryAccounts": { FASTMAIL_CAPABILITY: "u1" } }).to_string()),
            (200, json!({ "methodResponses": [["MaskedEmail/set", { "created": { "octapass": { "email": "m@fastmail.com", "id": "me1" } } }, "0"]] }).to_string()),
        ]);
        let site = alias_site("github.com").unwrap();
        assert_eq!(
            create(&http, "fastmail", &config(None), &site).unwrap(),
            ("m@fastmail.com".into(), "me1".into())
        );
        let sent = http.sent.lock().unwrap();
        assert!(
            sent[1]
                .3
                .as_deref()
                .unwrap()
                .contains("\"forDomain\":\"https://github.com\"")
        );
    }

    /// Each action's method and URL, with the bodies that say what to do.
    #[test]
    fn each_provider_changes_an_alias() {
        let gone = (404, String::new());
        let ok = (204, String::new());
        let run = |provider: &str, action, answers: Vec<(u16, String)>| {
            let http = FakeProvider::default();
            *http.answers.lock().unwrap() = answers;
            change_alias(
                &http,
                provider,
                &config(Some("mail.example")),
                "a/7",
                action,
            )
            .unwrap();
            let sent = http.sent.into_inner().unwrap();
            sent.into_iter()
                .map(|(method, url, _, body)| (method, url, body))
                .collect::<Vec<_>>()
        };
        use AliasAction::*;
        assert_eq!(
            run("addy", Disable, vec![ok.clone()])[0],
            (
                "DELETE".into(),
                "https://app.addy.io/api/v1/active-aliases/a%2F7".into(),
                None
            )
        );
        assert_eq!(
            run("addy", Enable, vec![ok.clone()])[0],
            (
                "POST".into(),
                "https://app.addy.io/api/v1/active-aliases".into(),
                Some(r#"{"id":"a/7"}"#.into())
            )
        );
        assert_eq!(
            run("addy", Delete, vec![gone.clone()])[0].1,
            "https://app.addy.io/api/v1/aliases/a%2F7",
            "an alias already gone counts as deleted"
        );
        assert_eq!(
            run("firefoxRelay", Disable, vec![ok.clone()])[0],
            (
                "PATCH".into(),
                "https://relay.firefox.com/api/v1/relayaddresses/a%2F7/".into(),
                Some(r#"{"enabled":false}"#.into())
            )
        );
        assert_eq!(
            run("forwardEmail", Enable, vec![ok.clone()])[0],
            (
                "PUT".into(),
                "https://api.forwardemail.net/v1/domains/mail.example/aliases/a%2F7".into(),
                Some(r#"{"is_enabled":true}"#.into())
            )
        );
        assert_eq!(run("forwardEmail", Delete, vec![gone])[0].0, "DELETE");
    }

    #[test]
    fn simplelogin_toggles_only_when_needed() {
        let run = |enabled: bool, action| {
            let http = FakeProvider::default();
            *http.answers.lock().unwrap() = vec![
                (200, json!({ "enabled": enabled }).to_string()),
                (200, json!({ "enabled": !enabled }).to_string()),
            ];
            change_alias(&http, "simplelogin", &config(None), "7", action).unwrap();
            http.sent.into_inner().unwrap().len()
        };
        assert_eq!(run(true, AliasAction::Disable), 2, "reads, then toggles");
        assert_eq!(run(false, AliasAction::Disable), 1, "already off");
    }

    #[test]
    fn fastmail_sets_the_alias_state() {
        let session = json!({
            "apiUrl": "https://api.fastmail.com/jmap/api/",
            "primaryAccounts": { FASTMAIL_CAPABILITY: "u1" },
        })
        .to_string();
        let run = |action, reply: Value| {
            let http = FakeProvider::default();
            *http.answers.lock().unwrap() = vec![
                (200, session.clone()),
                (200, json!({ "methodResponses": [reply] }).to_string()),
            ];
            let result = change_alias(&http, "fastmail", &config(None), "m1", action);
            (result, http.sent.into_inner().unwrap())
        };
        let (result, sent) = run(
            AliasAction::Disable,
            json!(["MaskedEmail/set", { "updated": { "m1": null } }, "0"]),
        );
        result.unwrap();
        let body: Value = serde_json::from_str(sent[1].3.as_ref().unwrap()).unwrap();
        assert_eq!(
            body["methodCalls"][0][1]["update"]["m1"]["state"],
            "disabled"
        );

        let missing =
            json!(["MaskedEmail/set", { "notUpdated": { "m1": { "type": "notFound" } } }, "0"]);
        run(AliasAction::Delete, missing.clone()).0.unwrap();
        let error = run(AliasAction::Disable, missing).0.unwrap_err();
        assert!(error.to_string().contains("notFound"), "{error}");
    }

    #[test]
    fn only_aliases_with_an_id_of_their_own_can_be_managed() {
        let can = |p: &str, id: &str| can_manage_alias(p.into(), id.into(), "a@b.co".into());
        assert!(can("simplelogin", "7"));
        assert!(!can("duckduckgo", "x"));
        assert!(!can("simplelogin", "a@b.co"));
        assert!(!can("simplelogin", ""));
    }

    #[test]
    fn provider_errors_become_codes() {
        let site = alias_site("github.com").unwrap();
        let code = |status: u16, body: &str| {
            let http = FakeProvider::default();
            http.answers.lock().unwrap().push((status, body.into()));
            create(&http, "addy", &config(Some("x")), &site).unwrap_err()
        };
        assert_eq!(code(401, "{}").code(), ErrorCode::MaskedEmailToken);
        let limited = code(429, r#"{"message":"slow down"}"#);
        assert_eq!(limited.code(), ErrorCode::MaskedEmailRateLimited);
        assert!(limited.to_string().contains("slow down (retry after 30)"));
        assert_eq!(code(500, "oops").code(), ErrorCode::MaskedEmailFailed);
        assert_eq!(code(200, "not json").code(), ErrorCode::MaskedEmailFailed);
        let offline =
            create(&FakeProvider::default(), "addy", &config(Some("x")), &site).unwrap_err();
        assert_eq!(offline.code(), ErrorCode::MaskedEmailUnreachable);
        assert!(alias_site("mailto:a@b.c").is_err());
        assert_eq!(
            check_base_url("http://evil.example").unwrap_err().code(),
            ErrorCode::InsecureServerUrl
        );
        assert_eq!(
            check_base_url("https://sl.example/api/").unwrap(),
            "https://sl.example/api"
        );
    }
}
