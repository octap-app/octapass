//! Firebase Cloud Messaging, HTTP v1, with a service account's OAuth token.

use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use ring::signature::RsaKeyPair;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::config::FcmConfig;
use crate::jwt::{self, KeyError};
use crate::{Kind, Outcome};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Asked for again this long before Google says it expires.
const EARLY: Duration = Duration::from_secs(5 * 60);

pub struct Fcm {
    http: Client,
    key: RsaKeyPair,
    client_email: String,
    token_uri: String,
    send_url: String,
    access: Mutex<Option<(String, Instant)>>,
}

/// A data message: the app decides what to do, and the only thing it's told is the kind.
pub fn message(device_token: &str, kind: Kind) -> Value {
    json!({
        "message": {
            "token": device_token,
            "data": { "octapass": kind.as_str() },
            "android": {
                "priority": match kind { Kind::Sync => "NORMAL", Kind::Alert => "HIGH" },
                "ttl": "86400s",
                "collapse_key": kind.as_str(),
            },
        }
    })
}

impl Fcm {
    pub fn new(config: &FcmConfig, http: Client) -> Result<Self, KeyError> {
        Ok(Self {
            http,
            key: jwt::rsa_key(&config.private_key)?,
            client_email: config.client_email.clone(),
            token_uri: config.token_uri.clone(),
            send_url: format!(
                "{}/v1/projects/{}/messages:send",
                config.send_url.trim_end_matches('/'),
                config.project_id
            ),
            access: Mutex::new(None),
        })
    }

    async fn access_token(&self, fresh: bool) -> Option<String> {
        let mut cached = self.access.lock().await;
        if !fresh
            && let Some((token, until)) = cached.as_ref()
            && Instant::now() < *until
        {
            return Some(token.clone());
        }
        let now = jwt::unix_seconds();
        let assertion = jwt::rs256(
            &self.key,
            &json!({ "alg": "RS256", "typ": "JWT" }),
            &json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": self.token_uri,
                "iat": now,
                "exp": now + 3600,
            }),
        );
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let response = self
            .http
            .post(&self.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            tracing::error!(status = %response.status(), "Google refused the service account");
            return None;
        }
        let answer: Value = response.json().await.ok()?;
        let token = answer["access_token"].as_str()?.to_owned();
        let lifetime = Duration::from_secs(answer["expires_in"].as_u64().unwrap_or(3600));
        *cached = Some((
            token.clone(),
            Instant::now() + lifetime.saturating_sub(EARLY),
        ));
        Some(token)
    }

    pub async fn send(&self, device_token: &str, kind: Kind) -> Outcome {
        for fresh in [false, true] {
            let Some(access) = self.access_token(fresh).await else {
                return Outcome::Failed;
            };
            let response = self
                .http
                .post(&self.send_url)
                .bearer_auth(access)
                .header("content-type", "application/json")
                .body(message(device_token, kind).to_string())
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(error = %error.without_url(), "FCM couldn't be reached");
                    return Outcome::Failed;
                }
            };
            let status = response.status();
            if status.is_success() {
                return Outcome::Sent;
            }
            let body: Value = response.json().await.unwrap_or_default();
            let code = error_code(&body);
            match status {
                StatusCode::NOT_FOUND => return Outcome::Unregistered,
                _ if code == Some("UNREGISTERED") => return Outcome::Unregistered,
                StatusCode::UNAUTHORIZED if !fresh => continue,
                _ => {
                    tracing::warn!(%status, code, "FCM refused a push");
                    return Outcome::Failed;
                }
            }
        }
        Outcome::Failed
    }
}

/// `error.details[].errorCode` of an FCM error (`UNREGISTERED`, `INVALID_ARGUMENT`, …).
fn error_code(body: &Value) -> Option<&str> {
    body["error"]["details"]
        .as_array()?
        .iter()
        .find_map(|detail| detail["errorCode"].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_hold_only_the_kind() {
        let sync = message("token", Kind::Sync);
        assert_eq!(sync["message"]["data"], json!({ "octapass": "sync" }));
        assert_eq!(sync["message"]["android"]["priority"], "NORMAL");
        assert!(sync["message"].get("notification").is_none());
        assert_eq!(
            message("t", Kind::Alert)["message"]["android"]["priority"],
            "HIGH"
        );
    }

    #[test]
    fn reads_error_codes() {
        let body = json!({ "error": { "status": "NOT_FOUND", "details": [
            { "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED" }
        ] } });
        assert_eq!(error_code(&body), Some("UNREGISTERED"));
        assert_eq!(error_code(&json!({})), None);
    }
}
