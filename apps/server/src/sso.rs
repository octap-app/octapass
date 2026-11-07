//! Single sign-on with OpenID Connect (plan 03, "SSO is sign-in only"). The server is the relying
//! party: an authorization code flow with PKCE, `state` and `nonce`. It decides only whether a
//! sign-in that already passed OPAQUE may go on. Nothing here touches a key.
//!
//! The issuer is supplied by an organisation's admin, so every request is made the way website
//! icons are fetched: HTTPS, public addresses only, no redirects, no proxy, short and small.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::{Host, Url, form_urlencoded};

use crate::config::Config;
use crate::crypto::{base64url, keyed_hash, random_bytes, random_token};
use crate::icons::net::{PublicResolver, is_public};
use crate::secrets::ServerSecrets;
use crate::validate;

/// Discovery documents and token responses are small.
const MAX_RESPONSE: usize = 64 * 1024;
/// A provider's clock may be this far from ours.
const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, thiserror::Error)]
pub enum SsoError {
    #[error("{0}")]
    Refused(&'static str),
    #[error("the identity provider answered with status {0}")]
    Status(u16),
    #[error("the identity provider's answer was too large")]
    TooLarge,
    #[error("the identity provider's answer wasn't what OpenID Connect expects")]
    Malformed,
    #[error("the identity provider can't be reached")]
    Network(#[from] reqwest::Error),
    #[error("the identity token isn't valid: {0}")]
    InvalidToken(&'static str),
}

/// What a discovery document says, as far as this flow needs it.
#[derive(Clone, Debug)]
pub struct Provider {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    /// `client_secret_post`, for a provider that doesn't take `client_secret_basic`.
    pub post_secret: bool,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// The claims this flow uses, after [`verify_id_token`].
#[derive(Debug, PartialEq, Eq)]
pub struct Claims {
    pub subject: String,
    pub email: Option<String>,
    /// `Some(false)` when the provider says the email isn't verified.
    pub email_verified: Option<bool>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct IdToken {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    iat: i64,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
}

/// The HTTP client for identity providers, and the rules for which URLs it may fetch.
pub struct Oidc {
    client: reqwest::Client,
    allow_http: bool,
    allow_private: bool,
}

impl Oidc {
    pub fn new(config: &Config) -> Self {
        let builder = reqwest::Client::builder()
            .redirect(Policy::none())
            // A proxy would do its own DNS and skip the address checks.
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("OctaPass/", env!("CARGO_PKG_VERSION")))
            .referer(false);
        let builder = if config.sso_private_network {
            builder
        } else {
            builder.dns_resolver(Arc::new(PublicResolver::new(None)))
        };
        Self {
            client: builder.build().expect("the SSO HTTP client builds"),
            allow_http: config.dev_mode,
            allow_private: config.sso_private_network,
        }
    }

    /// Checks a URL the browser will be sent to.
    fn browser_url(&self, raw: &str) -> Result<Url, SsoError> {
        let url = Url::parse(raw).map_err(|_| SsoError::Refused("that isn't a URL"))?;
        let allowed = url.scheme() == "https" || (self.allow_http && url.scheme() == "http");
        if !allowed {
            return Err(SsoError::Refused("identity providers must use HTTPS"));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(SsoError::Refused(
                "the URL can't hold a user name, password or fragment",
            ));
        }
        Ok(url)
    }

    /// Checks a URL this server will fetch. The resolver refuses private addresses behind names,
    /// but a literal IP address never reaches it, so that's checked here.
    fn server_url(&self, raw: &str) -> Result<Url, SsoError> {
        let url = self.browser_url(raw)?;
        let ip = match url.host() {
            Some(Host::Ipv4(ip)) => Some(ip.into()),
            Some(Host::Ipv6(ip)) => Some(ip.into()),
            Some(Host::Domain(_)) => None,
            None => return Err(SsoError::Refused("the URL has no host")),
        };
        if !self.allow_private && ip.is_some_and(|ip| !is_public(ip)) {
            return Err(SsoError::Refused(
                "that address isn't public; self-hosters can set OCTAPASS_SSO_PRIVATE_NETWORK=on",
            ));
        }
        Ok(url)
    }

    async fn read(mut response: reqwest::Response) -> Result<Vec<u8>, SsoError> {
        let status = response.status();
        if !status.is_success() {
            return Err(SsoError::Status(status.as_u16()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE {
                return Err(SsoError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Fetches the issuer's discovery document, and checks it names that same issuer.
    pub async fn discover(&self, issuer: &str) -> Result<Provider, SsoError> {
        self.server_url(issuer)?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let response = self.client.get(self.server_url(&url)?).send().await?;
        let body = Self::read(response).await?;
        let discovery: Discovery =
            serde_json::from_slice(&body).map_err(|_| SsoError::Malformed)?;
        if discovery.issuer != issuer {
            return Err(SsoError::Refused(
                "the discovery document names a different issuer",
            ));
        }
        let post_secret = discovery
            .token_endpoint_auth_methods_supported
            .is_some_and(|methods| {
                !methods.iter().any(|m| m == "client_secret_basic")
                    && methods.iter().any(|m| m == "client_secret_post")
            });
        Ok(Provider {
            authorization_endpoint: self.browser_url(&discovery.authorization_endpoint)?,
            token_endpoint: self.server_url(&discovery.token_endpoint)?,
            post_secret,
        })
    }

    /// Exchanges an authorization code for an ID token, straight from the token endpoint.
    pub async fn exchange(
        &self,
        provider: &Provider,
        exchange: Exchange<'_>,
    ) -> Result<String, SsoError> {
        let mut request = self
            .client
            .post(provider.token_endpoint.clone())
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(token_form(provider, &exchange));
        if !provider.post_secret
            && let Some(secret) = exchange.client_secret
        {
            // RFC 6749 section 2.3.1: both parts are form-encoded first.
            let encode = |value: &str| form_urlencoded::byte_serialize(value.as_bytes()).collect();
            let (user, password): (String, String) = (encode(exchange.client_id), encode(secret));
            request = request.basic_auth(user, Some(password));
        }
        let body = Self::read(request.send().await?).await?;
        let token: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| SsoError::Malformed)?;
        Ok(token.id_token)
    }
}

fn token_form(provider: &Provider, exchange: &Exchange<'_>) -> String {
    let mut form = form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("code", exchange.code)
        .append_pair("redirect_uri", exchange.redirect_uri)
        .append_pair("code_verifier", exchange.verifier);
    if exchange.client_secret.is_none() || provider.post_secret {
        form.append_pair("client_id", exchange.client_id);
    }
    if provider.post_secret
        && let Some(secret) = exchange.client_secret
    {
        form.append_pair("client_secret", secret);
    }
    form.finish()
}

pub struct Exchange<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub code: &'a str,
    pub verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// One browser's trip to the provider.
#[derive(Clone)]
pub struct Flow {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

impl Flow {
    pub fn new() -> Self {
        Self {
            state: random_token(),
            nonce: random_token(),
            verifier: random_token(),
        }
    }

    /// Where to send the browser.
    pub fn authorization_url(
        &self,
        provider: &Provider,
        client_id: &str,
        redirect_uri: &str,
        email: &str,
    ) -> Url {
        let challenge = base64url(Sha256::digest(self.verifier.as_bytes()));
        let mut url = provider.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid email")
            .append_pair("state", &self.state)
            .append_pair("nonce", &self.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("login_hint", email);
        url
    }
}

/// Checks an ID token that came straight from the token endpoint. Its signature isn't checked:
/// TLS to the token endpoint, with the client's own authentication and PKCE, already establishes
/// who issued it, as OpenID Connect Core 3.1.3.7 allows for this flow. Everything else is.
pub fn verify_id_token(
    token: &str,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now_ms: i64,
) -> Result<Claims, SsoError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SsoError::InvalidToken("it isn't a signed JWT"));
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| SsoError::InvalidToken("it isn't base64url"))
    };
    let header: Header = serde_json::from_slice(&decode(header)?)
        .map_err(|_| SsoError::InvalidToken("its header can't be read"))?;
    if header.alg.eq_ignore_ascii_case("none") {
        return Err(SsoError::InvalidToken("it's unsigned"));
    }
    let claims: IdToken = serde_json::from_slice(&decode(payload)?)
        .map_err(|_| SsoError::InvalidToken("its claims can't be read"))?;

    if claims.iss != issuer {
        return Err(SsoError::InvalidToken("wrong issuer"));
    }
    let audiences = match &claims.aud {
        Audience::One(one) => std::slice::from_ref(one),
        Audience::Many(many) => many.as_slice(),
    };
    if !audiences.iter().any(|aud| aud == client_id) {
        return Err(SsoError::InvalidToken("wrong audience"));
    }
    if audiences.len() > 1 && claims.azp.as_deref() != Some(client_id) {
        return Err(SsoError::InvalidToken("wrong authorized party"));
    }
    if claims.exp.saturating_mul(1000) + CLOCK_SKEW_MS <= now_ms {
        return Err(SsoError::InvalidToken("expired"));
    }
    if claims.iat.saturating_mul(1000) - CLOCK_SKEW_MS > now_ms {
        return Err(SsoError::InvalidToken("issued in the future"));
    }
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(SsoError::InvalidToken("wrong nonce"));
    }
    if claims.sub.is_empty() {
        return Err(SsoError::InvalidToken("no subject"));
    }
    Ok(Claims {
        subject: claims.sub,
        email: claims.email.and_then(|email| validate::email(&email).ok()),
        // Some providers send the string "true".
        email_verified: claims.email_verified.and_then(|value| match value {
            serde_json::Value::Bool(verified) => Some(verified),
            serde_json::Value::String(text) => text.parse().ok(),
            _ => None,
        }),
    })
}

fn seal_cipher(secrets: &ServerSecrets) -> XChaCha20Poly1305 {
    let key = keyed_hash(&*secrets.hmac_key, "octapass/sso-client-secret", b"");
    XChaCha20Poly1305::new((&key).into())
}

/// Seals an OIDC client secret under a key derived from the server secret, bound to the
/// organisation. The server reads it back by design; it opens a token endpoint, never a vault.
pub fn seal_client_secret(secrets: &ServerSecrets, org_id: &str, secret: &str) -> String {
    let nonce = random_bytes::<24>();
    let ciphertext = seal_cipher(secrets)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret.as_bytes(),
                aad: org_id.as_bytes(),
            },
        )
        .expect("XChaCha20-Poly1305 encrypts any length");
    base64url([nonce.as_slice(), &ciphertext].concat())
}

pub fn open_client_secret(secrets: &ServerSecrets, org_id: &str, sealed: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
    let (nonce, ciphertext) = bytes.split_at_checked(24)?;
    let secret = seal_cipher(secrets)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: org_id.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(secret).ok()
}

/// The pages the browser sees at the end. They're the only HTML the API serves: no script, no
/// external anything, and every value escaped.
pub mod page {
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use axum::response::{IntoResponse, Response};

    /// Inline styles and nothing else.
    const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'";

    pub enum Page<'a> {
        /// The code to type into the app, with the device it's for.
        Code {
            code: &'a str,
            device: &'a str,
            platform: &'a str,
        },
        Tested,
        Failed(Failure),
    }

    #[derive(Clone, Copy)]
    pub enum Failure {
        /// The link expired or was already used.
        Expired,
        /// The provider said no, or its answer wasn't valid.
        Provider,
        /// The account the provider signed in isn't this member.
        WrongAccount,
    }

    struct Text {
        title: &'static str,
        body: String,
        warning: Option<String>,
    }

    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn text(page: &Page<'_>, arabic: bool) -> Text {
        match (page, arabic) {
            (
                Page::Code {
                    device, platform, ..
                },
                false,
            ) => Text {
                title: "Finish signing in",
                body: "Type this code into Octa Pass to finish signing in.".into(),
                warning: Some(format!(
                    "This sign-in is for {} ({}). If you didn't start it, close this page and \
                     don't share the code: someone may have your master password.",
                    escape(device),
                    escape(platform)
                )),
            },
            (
                Page::Code {
                    device, platform, ..
                },
                true,
            ) => Text {
                title: "أكمل تسجيل الدخول",
                body: "اكتب هذا الرمز في Octa Pass لإكمال تسجيل الدخول.".into(),
                warning: Some(format!(
                    "تسجيل الدخول هذا لجهاز {} ({}). إذا لم تبدأه أنت، فأغلق هذه الصفحة ولا تشارك \
                     الرمز: ربما يعرف شخص آخر كلمة مرورك الرئيسية.",
                    escape(device),
                    escape(platform)
                )),
            },
            (Page::Tested, false) => Text {
                title: "It works",
                body: "The identity provider signed you in. You can close this page.".into(),
                warning: None,
            },
            (Page::Tested, true) => Text {
                title: "نجح الاختبار",
                body: "سجّل موفّر الهوية دخولك. يمكنك إغلاق هذه الصفحة.".into(),
                warning: None,
            },
            (Page::Failed(Failure::Expired), false) => Text {
                title: "This link has expired",
                body: "Go back to Octa Pass and sign in again.".into(),
                warning: None,
            },
            (Page::Failed(Failure::Expired), true) => Text {
                title: "انتهت صلاحية هذا الرابط",
                body: "ارجع إلى Octa Pass وسجّل الدخول من جديد.".into(),
                warning: None,
            },
            (Page::Failed(Failure::Provider), false) => Text {
                title: "Sign-in didn't finish",
                body: "The identity provider didn't confirm this sign-in. Ask your administrator \
                       if this keeps happening."
                    .into(),
                warning: None,
            },
            (Page::Failed(Failure::Provider), true) => Text {
                title: "لم يكتمل تسجيل الدخول",
                body: "لم يؤكد موفّر الهوية تسجيل الدخول هذا. اسأل مسؤول مؤسستك إذا تكرر ذلك."
                    .into(),
                warning: None,
            },
            (Page::Failed(Failure::WrongAccount), false) => Text {
                title: "That's a different account",
                body: "The identity provider signed in someone other than this Octa Pass member. \
                       Sign out there and try again, or ask your administrator."
                    .into(),
                warning: None,
            },
            (Page::Failed(Failure::WrongAccount), true) => Text {
                title: "هذا حساب مختلف",
                body: "سجّل موفّر الهوية دخول شخص غير هذا العضو في Octa Pass. سجّل الخروج هناك وحاول \
                       مجددًا، أو اسأل مسؤول مؤسستك."
                    .into(),
                warning: None,
            },
        }
    }

    pub fn render(page: &Page<'_>, headers: &HeaderMap) -> Response {
        let arabic = headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim_start().to_ascii_lowercase().starts_with("ar"));
        let text = text(page, arabic);
        let (lang, dir) = if arabic { ("ar", "rtl") } else { ("en", "ltr") };
        let code = match page {
            Page::Code { code, .. } => format!("<p class=\"code\">{}</p>", escape(code)),
            _ => String::new(),
        };
        let warning = text
            .warning
            .map(|warning| format!("<p class=\"warning\">{warning}</p>"))
            .unwrap_or_default();
        let (title, body) = (text.title, text.body);
        let html = format!(
            "<!doctype html><html lang=\"{lang}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{title} · Octa Pass</title><style>\
             :root{{color-scheme:light dark;--ink:#0B1220;--mist:#5E6576;--paper:#FBFBFD;--line:#E3E5EC}}\
             @media (prefers-color-scheme:dark){{:root{{--ink:#F5F6F8;--mist:#9BA3B4;--paper:#000;--line:#232838}}}}\
             body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--paper);\
             color:var(--ink);font:400 17px/1.5 system-ui,sans-serif;padding:16px;box-sizing:border-box}}\
             main{{max-width:28rem}}h1{{font-size:1.5rem;letter-spacing:-.02em;margin:0 0 .5rem}}\
             p{{margin:0 0 1rem}}.code{{font:600 2.25rem/1.2 ui-monospace,monospace;letter-spacing:.12em;\
             padding:.75rem 1rem;border:1px solid var(--line);border-radius:12px;text-align:center;direction:ltr}}\
             .warning{{color:var(--mist);font-size:.9375rem}}</style></head>\
             <body><main><h1>{title}</h1><p>{body}</p>{code}{warning}</main></body></html>"
        );
        let status = match page {
            Page::Failed(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        };
        let mut response = (status, html).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://idp.example";
    const CLIENT: &str = "octapass";
    const NONCE: &str = "the-nonce";
    const NOW: i64 = 1_800_000_000_000;

    fn jwt(claims: serde_json::Value) -> String {
        let part = |value: serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
        format!("{}.{}.sig", part(json!({ "alg": "RS256" })), part(claims))
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": ISSUER, "sub": "user-1", "aud": CLIENT, "exp": NOW / 1000 + 60,
            "iat": NOW / 1000, "nonce": NONCE, "email": "A@Example.com", "email_verified": true,
        })
    }

    fn verify(token: &str) -> Result<Claims, SsoError> {
        verify_id_token(token, ISSUER, CLIENT, NONCE, NOW)
    }

    fn with(key: &str, value: serde_json::Value) -> String {
        let mut claims = claims();
        claims[key] = value;
        jwt(claims)
    }

    #[test]
    fn a_good_token_gives_its_claims() {
        let claims = verify(&jwt(claims())).unwrap();
        assert_eq!(claims.subject, "user-1");
        assert_eq!(claims.email.as_deref(), Some("a@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn every_claim_is_checked() {
        for (key, value) in [
            ("iss", json!("https://evil.example")),
            ("aud", json!("someone-else")),
            ("nonce", json!("another")),
            ("exp", json!(NOW / 1000 - 3600)),
            ("iat", json!(NOW / 1000 + 3600)),
            ("sub", json!("")),
        ] {
            assert!(verify(&with(key, value.clone())).is_err(), "{key} {value}");
        }
    }

    #[test]
    fn a_shared_audience_needs_this_client_as_authorized_party() {
        let many = json!([CLIENT, "other"]);
        assert!(verify(&with("aud", many.clone())).is_err());
        let mut claims = claims();
        claims["aud"] = many;
        claims["azp"] = json!(CLIENT);
        assert!(verify(&jwt(claims)).is_ok());
    }

    #[test]
    fn unsigned_and_malformed_tokens_are_refused() {
        let part = |value: serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
        let unsigned = format!("{}.{}.", part(json!({ "alg": "none" })), part(claims()));
        assert!(verify(&unsigned).is_err());
        assert!(verify("one.two").is_err());
        assert!(verify("not base64.at.all").is_err());
    }

    #[test]
    fn email_verified_as_a_string_counts() {
        let claims = verify(&with("email_verified", json!("false"))).unwrap();
        assert_eq!(claims.email_verified, Some(false));
    }

    fn oidc(private: bool) -> Oidc {
        let mut config = Config::from_lookup(|_| None).unwrap();
        config.sso_private_network = private;
        Oidc::new(&config)
    }

    #[test]
    fn only_https_public_urls_are_fetched() {
        let oidc = oidc(false);
        assert!(oidc.server_url("https://idp.example/x").is_ok());
        for url in [
            "http://idp.example",
            "ftp://idp.example",
            "https://user:pw@idp.example",
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://169.254.169.254/latest",
            "https://[::1]",
            "https://[::ffff:10.0.0.1]",
            "not a url",
        ] {
            assert!(oidc.server_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn self_hosters_can_allow_private_addresses_but_not_plain_http() {
        let oidc = oidc(true);
        assert!(oidc.server_url("https://10.0.0.1").is_ok());
        assert!(oidc.server_url("http://10.0.0.1").is_err());
    }

    #[test]
    fn client_secrets_are_bound_to_their_organisation() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = ServerSecrets::load_or_create(dir.path()).unwrap();
        let sealed = seal_client_secret(&secrets, "org-1", "s3cret");
        assert_eq!(
            open_client_secret(&secrets, "org-1", &sealed).as_deref(),
            Some("s3cret")
        );
        assert_eq!(open_client_secret(&secrets, "org-2", &sealed), None);
        assert_eq!(open_client_secret(&secrets, "org-1", "AAAA"), None);
    }

    #[test]
    fn pages_escape_what_the_device_sent() {
        use axum::http::HeaderMap;
        use http_body_util::BodyExt;
        let page = page::Page::Code {
            code: "123456",
            device: "<script>alert(1)</script>",
            platform: "web",
        };
        let response = page::render(&page, &HeaderMap::new());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let body = runtime
            .block_on(response.into_body().collect())
            .unwrap()
            .to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }
}
