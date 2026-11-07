//! Live OAuth2 tokens for API credential items: the client-credentials and refresh-token flows.
//! An item keeps its client in `details.oauth2`; the current access token is cached there too, so
//! it's encrypted like everything else and reused until it nearly expires.
//!
//! The token endpoint is the only network use. It must be `https` (or loopback, for development),
//! it's the user's own URL, and redirects are never followed, so the client secret can't be walked
//! to another host.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use octapass_desktop_vault::model::Item;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

/// A token this close to expiring is replaced.
pub const EXPIRY_MARGIN_SECONDS: u64 = 60;
const TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_LIFETIME_SECONDS: u64 = 3600;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// The field names that ask for the live token.
pub const TOKEN_FIELDS: &[&str] = &["accesstoken", "access_token", "bearer", "bearertoken"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    ClientCredentials,
    RefreshToken,
}

/// `details.oauth2`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2 {
    pub flow: Flow,
    pub token_url: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    #[error("\"{0}\" has no OAuth2 client.")]
    NotConfigured(String),
    #[error("The token URL must be https (http only on this computer).")]
    InsecureUrl,
    #[error("This client needs a {0}.")]
    Missing(&'static str),
    #[error("Couldn't reach the token endpoint: {0}")]
    Network(String),
    /// The provider's own words. Bodies aren't echoed: they can repeat what was sent.
    #[error("The token endpoint refused: {0}")]
    Refused(String),
    #[error("The token endpoint sent an answer that isn't a token.")]
    BadResponse,
}

/// What a token response gave. Fields it left out stay as they were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub access_token: Zeroizing<String>,
    /// Unix seconds.
    pub expires_at: u64,
    /// A new refresh token, when the provider rotates them. It must be saved, or the next
    /// refresh fails.
    pub refresh_token: Option<Zeroizing<String>>,
}

pub fn has_live_token(item: &Item) -> bool {
    config(item).is_some()
}

pub fn wants_live_token(name: &str) -> bool {
    TOKEN_FIELDS.contains(&name.trim().to_lowercase().as_str())
}

pub fn config(item: &Item) -> Option<OAuth2> {
    serde_json::from_value(item.details.get("oauth2")?.clone()).ok()
}

impl OAuth2 {
    /// The cached token, while it's good for a while yet.
    pub fn cached(&self, now: u64) -> Option<&str> {
        let expires = self.expires_at?;
        (expires > now + EXPIRY_MARGIN_SECONDS)
            .then_some(self.access_token.as_deref())
            .flatten()
    }

    fn check(&self) -> Result<(), OAuthError> {
        let url = url::Url::parse(&self.token_url).map_err(|_| OAuthError::InsecureUrl)?;
        let loopback = matches!(
            url.host(),
            Some(url::Host::Domain("localhost"))
                | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
        ) || url.host() == Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(OAuthError::InsecureUrl);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OAuthError::InsecureUrl);
        }
        match self.flow {
            Flow::ClientCredentials if self.client_secret.is_none() => {
                Err(OAuthError::Missing("client secret"))
            }
            Flow::RefreshToken if self.refresh_token.is_none() => {
                Err(OAuthError::Missing("refresh token"))
            }
            _ => Ok(()),
        }
    }

    /// The form of a token request (RFC 6749 §4.4, §6). The secret goes in the form, which every
    /// provider accepts; Basic auth isn't.
    pub fn form(&self) -> Vec<(&'static str, String)> {
        let mut form = vec![("client_id", self.client_id.clone())];
        if let Some(secret) = &self.client_secret {
            form.push(("client_secret", secret.clone()));
        }
        match self.flow {
            Flow::ClientCredentials => form.push(("grant_type", "client_credentials".into())),
            Flow::RefreshToken => {
                form.push(("grant_type", "refresh_token".into()));
                form.push((
                    "refresh_token",
                    self.refresh_token.clone().unwrap_or_default(),
                ));
            }
        }
        if let Some(scope) = &self.scope {
            form.push(("scope", scope.clone()));
        }
        if let Some(audience) = &self.audience {
            form.push(("audience", audience.clone()));
        }
        form
    }

    /// Fetches a new access token.
    pub async fn fetch(&self, now: u64) -> Result<Token, OAuthError> {
        self.check()?;
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| OAuthError::Network(error.to_string()))?;
        let response = http
            .post(&self.token_url)
            .header("accept", "application/json")
            .form(&self.form())
            .send()
            .await
            .map_err(|error| OAuthError::Network(error.without_url().to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| OAuthError::Network(error.without_url().to_string()))?;
        if body.len() > MAX_TOKEN_BYTES {
            return Err(OAuthError::BadResponse);
        }
        parse_response(status.as_u16(), &body, now)
    }

    /// The item's details with a token saved in them.
    pub fn apply(&mut self, token: &Token) {
        self.access_token = Some(token.access_token.to_string());
        self.expires_at = Some(token.expires_at);
        if let Some(refresh) = &token.refresh_token {
            self.refresh_token = Some(refresh.to_string());
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("configs serialize")
    }
}

/// Parses a token endpoint's answer (RFC 6749 §5).
pub fn parse_response(status: u16, body: &[u8], now: u64) -> Result<Token, OAuthError> {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let code = value["error"].as_str().unwrap_or("unknown_error");
        // Only the standard short code: descriptions can quote the request.
        let code: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(64)
            .collect();
        return Err(OAuthError::Refused(format!("{code} (HTTP {status})")));
    }
    let access_token = value["access_token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or(OAuthError::BadResponse)?;
    if value["token_type"]
        .as_str()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
    {
        return Err(OAuthError::BadResponse);
    }
    let lifetime = value["expires_in"]
        .as_u64()
        .or_else(|| value["expires_in"].as_str()?.parse().ok());
    let expires_at = lifetime
        .map(|seconds| now.saturating_add(seconds))
        .or_else(|| jwt_expiry(access_token))
        .unwrap_or(now + DEFAULT_LIFETIME_SECONDS);
    Ok(Token {
        access_token: Zeroizing::new(access_token.to_owned()),
        expires_at,
        refresh_token: value["refresh_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .map(|token| Zeroizing::new(token.to_owned())),
    })
}

/// A JWT's claims, without checking its signature: only for showing them. `None` for an opaque
/// token.
pub fn jwt_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .filter(Value::is_object)
}

fn jwt_expiry(token: &str) -> Option<u64> {
    jwt_claims(token)?.get("exp")?.as_u64()
}

/// What `octapass oauth token --json` and `show` print: claims and expiry, no secrets.
pub fn describe(token: &str, expires_at: Option<u64>) -> Value {
    let mut out = json!({ "expiresAt": expires_at });
    if let Some(claims) = jwt_claims(token) {
        out["claims"] = claims;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn client(flow: Flow) -> OAuth2 {
        OAuth2 {
            flow,
            token_url: "https://auth.example/token".into(),
            client_id: "id".into(),
            client_secret: Some("secret".into()),
            refresh_token: Some("rt".into()),
            scope: Some("read write".into()),
            audience: None,
            access_token: None,
            expires_at: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn forms_follow_the_flows() {
        let form = client(Flow::ClientCredentials).form();
        assert!(form.contains(&("grant_type", "client_credentials".into())));
        assert!(!form.iter().any(|(key, _)| *key == "refresh_token"));
        let form = client(Flow::RefreshToken).form();
        assert!(form.contains(&("grant_type", "refresh_token".into())));
        assert!(form.contains(&("refresh_token", "rt".into())));
        assert!(form.contains(&("scope", "read write".into())));
    }

    #[test]
    fn urls_must_be_https_or_this_computer() {
        for bad in [
            "http://auth.example/token",
            "ftp://auth.example",
            "not a url",
            "https://user:pass@auth.example/token",
        ] {
            let mut config = client(Flow::ClientCredentials);
            config.token_url = bad.into();
            assert_eq!(config.check(), Err(OAuthError::InsecureUrl), "{bad}");
        }
        for good in [
            "https://auth.example/token",
            "http://127.0.0.1:9/token",
            "http://localhost:9/token",
        ] {
            let mut config = client(Flow::ClientCredentials);
            config.token_url = good.into();
            assert_eq!(config.check(), Ok(()), "{good}");
        }
    }

    #[test]
    fn each_flow_needs_its_secret() {
        let mut config = client(Flow::ClientCredentials);
        config.client_secret = None;
        assert_eq!(config.check(), Err(OAuthError::Missing("client secret")));
        let mut config = client(Flow::RefreshToken);
        config.refresh_token = None;
        assert_eq!(config.check(), Err(OAuthError::Missing("refresh token")));
    }

    #[test]
    fn responses_become_tokens() {
        let body =
            br#"{"access_token":"a","token_type":"Bearer","expires_in":600,"refresh_token":"b"}"#;
        let token = parse_response(200, body, NOW).unwrap();
        assert_eq!(token.access_token.as_str(), "a");
        assert_eq!(token.expires_at, NOW + 600);
        assert_eq!(token.refresh_token.unwrap().as_str(), "b");

        let body = br#"{"access_token":"a","expires_in":"60"}"#;
        assert_eq!(parse_response(200, body, NOW).unwrap().expires_at, NOW + 60);
        let body = br#"{"access_token":"a"}"#;
        assert_eq!(
            parse_response(200, body, NOW).unwrap().expires_at,
            NOW + DEFAULT_LIFETIME_SECONDS
        );
        assert_eq!(
            parse_response(200, b"{}", NOW),
            Err(OAuthError::BadResponse)
        );
        let body = br#"{"access_token":"a","token_type":"mac"}"#;
        assert_eq!(parse_response(200, body, NOW), Err(OAuthError::BadResponse));
    }

    #[test]
    fn refusals_show_only_the_standard_code() {
        let body = br#"{"error":"invalid_client","error_description":"bad secret: hunter2"}"#;
        let refused = parse_response(401, body, NOW).unwrap_err();
        assert_eq!(
            refused,
            OAuthError::Refused("invalid_client (HTTP 401)".into())
        );
        assert!(!refused.to_string().contains("hunter2"));
    }

    #[test]
    fn jwts_give_their_expiry_and_claims() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1900000000,"iss":"me"}"#);
        let token = format!("e30.{payload}.sig");
        let body = serde_json::to_vec(&json!({ "access_token": token })).unwrap();
        assert_eq!(
            parse_response(200, &body, NOW).unwrap().expires_at,
            1_900_000_000
        );
        assert_eq!(jwt_claims(&token).unwrap()["iss"], "me");
        assert_eq!(describe(&token, Some(5))["claims"]["iss"], "me");
        assert_eq!(jwt_claims("opaque"), None);
        assert_eq!(jwt_claims("a.b.c.d"), None);
    }

    #[test]
    fn a_token_near_its_end_isnt_reused() {
        let mut config = client(Flow::ClientCredentials);
        assert_eq!(config.cached(NOW), None);
        config.access_token = Some("a".into());
        config.expires_at = Some(NOW + EXPIRY_MARGIN_SECONDS + 1);
        assert_eq!(config.cached(NOW), Some("a"));
        config.expires_at = Some(NOW + EXPIRY_MARGIN_SECONDS);
        assert_eq!(config.cached(NOW), None);
    }

    #[test]
    fn a_rotated_refresh_token_replaces_the_old_one_and_unknown_fields_stay() {
        let mut value = client(Flow::RefreshToken).to_value();
        value["futureField"] = json!(1);
        let mut config: OAuth2 = serde_json::from_value(value).unwrap();
        config.apply(&Token {
            access_token: Zeroizing::new("a".into()),
            expires_at: NOW,
            refresh_token: Some(Zeroizing::new("new".into())),
        });
        let value = config.to_value();
        assert_eq!(value["refreshToken"], "new");
        assert_eq!(value["futureField"], 1);
    }
}
