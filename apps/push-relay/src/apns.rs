//! Apple Push Notification service, token-based (HTTP/2, `POST /3/device/<token>`).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use ring::signature::EcdsaKeyPair;
use serde_json::{Value, json};

use crate::config::ApnsConfig;
use crate::jwt::{self, KeyError};
use crate::{Kind, Outcome};

/// Apple accepts a provider token for an hour and refuses one refreshed more often than every
/// 20 minutes.
const TOKEN_LIFETIME: Duration = Duration::from_secs(40 * 60);
/// A wakeup a day late is no use; a newer one replaces it anyway.
const EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Apns {
    http: Client,
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    production_url: String,
    sandbox_url: String,
    token: Mutex<Option<(String, Instant)>>,
}

/// The body of a push: the kind and nothing else. An alert names strings in the app, which the
/// phone puts in its own language, so even the words shown aren't in the push.
pub fn payload(kind: Kind) -> Value {
    match kind {
        Kind::Sync => json!({ "aps": { "content-available": 1 }, "octapass": "sync" }),
        Kind::Alert => json!({
            "aps": {
                "alert": {
                    "title-loc-key": "phone.native.pushAlertTitle",
                    "loc-key": "phone.native.pushAlertBody",
                },
                "sound": "default",
                "content-available": 1,
            },
            "octapass": "alert",
        }),
    }
}

impl Apns {
    pub fn new(config: &ApnsConfig, http: Client) -> Result<Self, KeyError> {
        Ok(Self {
            http,
            key: jwt::ecdsa_key(&config.key_pem)?,
            key_id: config.key_id.clone(),
            team_id: config.team_id.clone(),
            topic: config.topic.clone(),
            production_url: config.production_url.trim_end_matches('/').to_owned(),
            sandbox_url: config.sandbox_url.trim_end_matches('/').to_owned(),
            token: Mutex::new(None),
        })
    }

    fn provider_token(&self, fresh: bool) -> String {
        let mut cached = self.token.lock().unwrap_or_else(|p| p.into_inner());
        if !fresh
            && let Some((token, made)) = cached.as_ref()
            && made.elapsed() < TOKEN_LIFETIME
        {
            return token.clone();
        }
        let token = jwt::es256(
            &self.key,
            &json!({ "alg": "ES256", "kid": self.key_id }),
            &json!({ "iss": self.team_id, "iat": jwt::unix_seconds() }),
        );
        *cached = Some((token.clone(), Instant::now()));
        token
    }

    pub async fn send(&self, device_token: &str, sandbox: bool, kind: Kind) -> Outcome {
        match self.try_send(device_token, sandbox, kind, false).await {
            Retry::Done(outcome) => outcome,
            // Apple says the provider token expired or is unknown: make a new one, once.
            Retry::FreshToken => match self.try_send(device_token, sandbox, kind, true).await {
                Retry::Done(outcome) => outcome,
                Retry::FreshToken => Outcome::Failed,
            },
        }
    }

    async fn try_send(&self, device_token: &str, sandbox: bool, kind: Kind, fresh: bool) -> Retry {
        let base = if sandbox {
            &self.sandbox_url
        } else {
            &self.production_url
        };
        let expiration = jwt::unix_seconds() + EXPIRY.as_secs();
        let (push_type, priority) = match kind {
            Kind::Sync => ("background", "5"),
            Kind::Alert => ("alert", "10"),
        };
        let response = self
            .http
            .post(format!("{base}/3/device/{device_token}"))
            .header(
                "authorization",
                format!("bearer {}", self.provider_token(fresh)),
            )
            .header("apns-topic", &self.topic)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("apns-expiration", expiration.to_string())
            .header("apns-collapse-id", kind.as_str())
            .header("content-type", "application/json")
            .body(payload(kind).to_string())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                // reqwest puts the URL, with the device token, in its errors.
                tracing::warn!(error = %error.without_url(), "APNs couldn't be reached");
                return Retry::Done(Outcome::Failed);
            }
        };
        let status = response.status();
        if status.is_success() {
            return Retry::Done(Outcome::Sent);
        }
        let body: Value = response.json().await.unwrap_or_default();
        let reason = body["reason"].as_str().unwrap_or_default();
        match (status, reason) {
            (StatusCode::GONE, _)
            | (StatusCode::BAD_REQUEST, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                Retry::Done(Outcome::Unregistered)
            }
            (StatusCode::FORBIDDEN, "ExpiredProviderToken" | "InvalidProviderToken") if !fresh => {
                Retry::FreshToken
            }
            _ => {
                tracing::warn!(%status, reason, "APNs refused a push");
                Retry::Done(Outcome::Failed)
            }
        }
    }
}

enum Retry {
    Done(Outcome),
    FreshToken,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_hold_only_the_kind() {
        assert_eq!(
            payload(Kind::Sync),
            json!({ "aps": { "content-available": 1 }, "octapass": "sync" })
        );
        let alert = payload(Kind::Alert);
        assert_eq!(alert["octapass"], "alert");
        assert_eq!(
            alert["aps"]["alert"]["loc-key"],
            "phone.native.pushAlertBody"
        );
        assert!(alert["aps"]["alert"].get("body").is_none());
    }
}
