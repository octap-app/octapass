//! Configuration from `OCTAPASS_PUSH_RELAY_*` environment variables. The credentials are read
//! from files, so they never sit in the environment of every process.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

pub const APNS_PRODUCTION: &str = "https://api.push.apple.com";
pub const APNS_SANDBOX: &str = "https://api.sandbox.push.apple.com";
pub const FCM_SEND: &str = "https://fcm.googleapis.com";
pub const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    /// Take the client address from the last `X-Forwarded-For` entry (behind a reverse proxy).
    pub trust_proxy: bool,
    pub apns: Option<ApnsConfig>,
    pub fcm: Option<FcmConfig>,
    pub limits: Limits,
}

/// Apple's token-based provider authentication: a `.p8` signing key.
#[derive(Clone)]
pub struct ApnsConfig {
    /// The `.p8` file's PKCS#8 PEM.
    pub key_pem: String,
    pub key_id: String,
    pub team_id: String,
    /// The iPhone app's bundle id.
    pub topic: String,
    pub production_url: String,
    pub sandbox_url: String,
}

impl std::fmt::Debug for ApnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsConfig")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .finish_non_exhaustive()
    }
}

/// A Google service account allowed to send through Firebase Cloud Messaging (HTTP v1).
#[derive(Clone, Deserialize)]
pub struct FcmConfig {
    pub project_id: String,
    pub client_email: String,
    /// PKCS#8 PEM.
    pub private_key: String,
    #[serde(default = "google_token_uri")]
    pub token_uri: String,
    #[serde(skip, default = "fcm_send")]
    pub send_url: String,
}

fn google_token_uri() -> String {
    GOOGLE_TOKEN_URI.into()
}

fn fcm_send() -> String {
    FCM_SEND.into()
}

impl std::fmt::Debug for FcmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmConfig")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Pushes one installation may send a minute, with as many at once.
    pub pushes_per_minute: u32,
    /// New installations from one address an hour.
    pub registrations_per_hour: u32,
    /// Pushes in one request.
    pub max_batch: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pushes_per_minute: 600,
            registrations_per_hour: 5,
            max_batch: 100,
        }
    }
}

impl Limits {
    pub fn push_refill(&self) -> Duration {
        Duration::from_secs(60) / self.pushes_per_minute.max(1)
    }

    pub fn registration_refill(&self) -> Duration {
        Duration::from_secs(60 * 60) / self.registrations_per_hour.max(1)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
    #[error("{0}: {1}")]
    File(&'static str, std::io::Error),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(
            |name| std::env::var(name).ok().filter(|v| !v.is_empty()),
            |path| std::fs::read_to_string(path),
        )
    }

    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        read: impl Fn(&str) -> std::io::Result<String>,
    ) -> Result<Self, ConfigError> {
        let bind = get("OCTAPASS_PUSH_RELAY_BIND")
            .unwrap_or_else(|| "127.0.0.1:8092".into())
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                ConfigError::Invalid("OCTAPASS_PUSH_RELAY_BIND", e.to_string())
            })?;
        let database_url = get("OCTAPASS_PUSH_RELAY_DATABASE_URL")
            .ok_or(ConfigError::Missing("OCTAPASS_PUSH_RELAY_DATABASE_URL"))?;
        let trust_proxy = flag(&get, "OCTAPASS_PUSH_RELAY_TRUST_PROXY")?;

        let apns = match get("OCTAPASS_PUSH_RELAY_APNS_KEY_FILE") {
            None => None,
            Some(path) => {
                let need = |name: &'static str| get(name).ok_or(ConfigError::Missing(name));
                Some(ApnsConfig {
                    key_pem: read(&path)
                        .map_err(|e| ConfigError::File("OCTAPASS_PUSH_RELAY_APNS_KEY_FILE", e))?,
                    key_id: need("OCTAPASS_PUSH_RELAY_APNS_KEY_ID")?,
                    team_id: need("OCTAPASS_PUSH_RELAY_APNS_TEAM_ID")?,
                    topic: get("OCTAPASS_PUSH_RELAY_APNS_TOPIC")
                        .unwrap_or_else(|| "app.octap.ios".into()),
                    production_url: APNS_PRODUCTION.into(),
                    sandbox_url: APNS_SANDBOX.into(),
                })
            }
        };
        let fcm = match get("OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE") {
            None => None,
            Some(path) => {
                const NAME: &str = "OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE";
                let json = read(&path).map_err(|e| ConfigError::File(NAME, e))?;
                let fcm: FcmConfig = serde_json::from_str(&json).map_err(|e| {
                    ConfigError::Invalid(NAME, format!("not a service account key: {e}"))
                })?;
                Some(fcm)
            }
        };
        if apns.is_none() && fcm.is_none() {
            return Err(ConfigError::Missing(
                "OCTAPASS_PUSH_RELAY_APNS_KEY_FILE or OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE",
            ));
        }
        let base = Limits::default();
        let limits = Limits {
            pushes_per_minute: number(
                &get,
                "OCTAPASS_PUSH_RELAY_PUSHES_PER_MINUTE",
                base.pushes_per_minute,
            )?,
            registrations_per_hour: number(
                &get,
                "OCTAPASS_PUSH_RELAY_REGISTRATIONS_PER_HOUR",
                base.registrations_per_hour,
            )?,
            max_batch: base.max_batch,
        };
        Ok(Self {
            bind,
            database_url,
            trust_proxy,
            apns,
            fcm,
            limits,
        })
    }
}

fn flag(get: &impl Fn(&str) -> Option<String>, name: &'static str) -> Result<bool, ConfigError> {
    match get(name).as_deref() {
        None | Some("false") | Some("off") => Ok(false),
        Some("true") | Some("on") => Ok(true),
        Some(other) => Err(ConfigError::Invalid(
            name,
            format!("{other:?} is not true or false"),
        )),
    }
}

fn number(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(raw) => match raw.parse::<u32>() {
            Ok(0) => Err(ConfigError::Invalid(name, "must be at least 1".into())),
            Ok(value) => Ok(value),
            Err(e) => Err(ConfigError::Invalid(name, e.to_string())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)], files: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let files: HashMap<String, String> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(
            |name| vars.get(name).cloned(),
            |path| {
                files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            },
        )
    }

    const DB: (&str, &str) = ("OCTAPASS_PUSH_RELAY_DATABASE_URL", "sqlite://relay.db");

    #[test]
    fn needs_a_database_and_one_platform() {
        assert!(matches!(config(&[], &[]), Err(ConfigError::Missing(_))));
        assert!(matches!(config(&[DB], &[]), Err(ConfigError::Missing(_))));
    }

    #[test]
    fn reads_apns_and_fcm_from_files() {
        let fcm = r#"{"type":"service_account","project_id":"octa-pass","client_email":"push@octa-pass.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"}"#;
        let config = config(
            &[
                DB,
                ("OCTAPASS_PUSH_RELAY_APNS_KEY_FILE", "/keys/apns.p8"),
                ("OCTAPASS_PUSH_RELAY_APNS_KEY_ID", "KEY123"),
                ("OCTAPASS_PUSH_RELAY_APNS_TEAM_ID", "TEAM123"),
                ("OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE", "/keys/fcm.json"),
                ("OCTAPASS_PUSH_RELAY_PUSHES_PER_MINUTE", "60"),
            ],
            &[("/keys/apns.p8", "pem"), ("/keys/fcm.json", fcm)],
        )
        .unwrap();
        let apns = config.apns.unwrap();
        assert_eq!(apns.topic, "app.octap.ios");
        assert_eq!(apns.production_url, APNS_PRODUCTION);
        let fcm = config.fcm.unwrap();
        assert_eq!(fcm.project_id, "octa-pass");
        assert_eq!(fcm.token_uri, GOOGLE_TOKEN_URI);
        assert_eq!(fcm.send_url, FCM_SEND);
        assert!(!format!("{fcm:?}").contains("PRIVATE"));
        assert_eq!(config.limits.pushes_per_minute, 60);
        assert_eq!(config.limits.push_refill(), Duration::from_secs(1));
    }

    #[test]
    fn rejects_bad_values() {
        let apns = [
            DB,
            ("OCTAPASS_PUSH_RELAY_APNS_KEY_FILE", "/keys/apns.p8"),
            ("OCTAPASS_PUSH_RELAY_APNS_KEY_ID", "KEY123"),
        ];
        assert!(matches!(
            config(&apns, &[("/keys/apns.p8", "pem")]),
            Err(ConfigError::Missing("OCTAPASS_PUSH_RELAY_APNS_TEAM_ID"))
        ));
        assert!(matches!(config(&apns, &[]), Err(ConfigError::File(..))));
        let fcm = [DB, ("OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE", "/f")];
        assert!(config(&fcm, &[("/f", "{}")]).is_err());
        let mut zero = fcm.to_vec();
        zero.push(("OCTAPASS_PUSH_RELAY_PUSHES_PER_MINUTE", "0"));
        let good = r#"{"project_id":"p","client_email":"e","private_key":"k"}"#;
        assert!(config(&zero, &[("/f", good)]).is_err());
    }
}
