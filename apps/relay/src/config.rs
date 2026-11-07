//! Configuration from `OCTAPASS_RELAY_*`. The relay has no defaults for what makes it a mail
//! server: without a domain, secret, smart host and signing key it refuses to start.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::address::Address;
use crate::auth::FixedDns;
use crate::limits::Bucket;

pub const REQUIRED: [&str; 7] = [
    "OCTAPASS_RELAY_DOMAIN",
    "OCTAPASS_RELAY_SECRET (or OCTAPASS_RELAY_SECRET_FILE)",
    "OCTAPASS_RELAY_API_TOKEN",
    "OCTAPASS_RELAY_DATABASE_URL",
    "OCTAPASS_RELAY_SMART_HOST",
    "OCTAPASS_RELAY_DKIM_SELECTOR",
    "OCTAPASS_RELAY_DKIM_KEY_FILE",
];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "the Octa Pass relay is off: masked email forwarding only runs when it is configured. \
         Set {}. See docs/self-hosting/relay.md.",
        REQUIRED.join(", ")
    )]
    Off,
    #[error("the relay needs {0}. See docs/self-hosting/relay.md.")]
    Missing(&'static str),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Clone)]
pub struct Config {
    /// The domain aliases live on. One relay, one domain.
    pub domain: String,
    /// The name the relay gives in its banner and to the smart host.
    pub hostname: String,
    pub smtp_bind: SocketAddr,
    /// The internal API. Loopback unless the operator says otherwise: it speaks for every account.
    pub api_bind: SocketAddr,
    pub api_token: Zeroizing<String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub database_url: String,
    /// Where all outgoing mail goes, as a lettre URL (`smtps://user:pass@host`).
    pub smart_host: String,
    pub dkim_selector: String,
    pub dkim_key_pem: Zeroizing<String>,
    /// PEM certificate chain and key for STARTTLS. Without them, inbound mail is plaintext.
    pub tls: Option<(Vec<u8>, Zeroizing<Vec<u8>>)>,
    /// Where `postmaster@` and `abuse@` go. Without it, they're refused.
    pub operator: Option<Address>,
    pub limits: Limits,
    /// Tests only: fixed DNS answers, so the real verifiers run without a network.
    pub dns: Option<Arc<FixedDns>>,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_message_bytes: usize,
    /// `Received` headers a message may already carry.
    pub max_hops: usize,
    /// Connections handled at once.
    pub max_connections: usize,
    pub command_timeout: Duration,
    /// All of DATA, from first byte to last.
    pub data_timeout: Duration,
    /// Rejected commands and recipients before a connection is dropped.
    pub max_errors: u32,
    pub max_transactions: u32,
    pub connections_per_ip: Bucket,
    pub messages_per_alias: Bucket,
    pub messages_per_sender: Bucket,
    pub messages_per_account: Bucket,
    pub replies_per_account: Bucket,
    pub aliases_per_account: i64,
    pub aliases_per_day: i64,
    pub contacts_per_alias: i64,
    pub return_path_days: u64,
    /// Bounce and complaint counts look back this far.
    pub feedback_window_days: i64,
    pub alias_hard_bounces: i64,
    pub alias_complaints: i64,
    pub account_hard_bounces: i64,
    pub account_complaints: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 25 * 1024 * 1024,
            max_hops: 25,
            max_connections: 256,
            command_timeout: Duration::from_secs(60),
            data_timeout: Duration::from_secs(300),
            max_errors: 10,
            max_transactions: 20,
            connections_per_ip: Bucket::per_minute(60),
            messages_per_alias: Bucket::per_hour(60),
            messages_per_sender: Bucket::per_hour(120),
            messages_per_account: Bucket::per_hour(300),
            replies_per_account: Bucket::per_hour(60),
            aliases_per_account: 200,
            aliases_per_day: 25,
            contacts_per_alias: 2000,
            return_path_days: 21,
            feedback_window_days: 30,
            alias_hard_bounces: 3,
            alias_complaints: 3,
            account_hard_bounces: 10,
            account_complaints: 10,
        }
    }
}

fn number<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: T,
) -> Result<T, ConfigError> {
    match get(name) {
        Some(value) => value
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("{name} must be a number"))),
        None => Ok(default),
    }
}

fn read(path: &str, what: &str) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(Path::new(path)).map_err(|e| ConfigError::Invalid(format!("{what}: {e}")))
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }

    pub fn from(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let need = |name: &'static str| get(name).ok_or(ConfigError::Missing(name));
        let domain = get("OCTAPASS_RELAY_DOMAIN")
            .ok_or(ConfigError::Off)?
            .to_ascii_lowercase();
        if Address::parse(&format!("postmaster@{domain}")).is_err() {
            return Err(ConfigError::Invalid(
                "OCTAPASS_RELAY_DOMAIN must be a plain domain name".into(),
            ));
        }
        let secret = match (
            get("OCTAPASS_RELAY_SECRET"),
            get("OCTAPASS_RELAY_SECRET_FILE"),
        ) {
            (Some(secret), _) => secret.into_bytes(),
            (None, Some(path)) => read(&path, "OCTAPASS_RELAY_SECRET_FILE")?,
            (None, None) => return Err(ConfigError::Missing("OCTAPASS_RELAY_SECRET")),
        };
        if secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "the relay secret must be at least 32 bytes".into(),
            ));
        }
        let api_token = need("OCTAPASS_RELAY_API_TOKEN")?;
        if api_token.len() < 32 {
            return Err(ConfigError::Invalid(
                "OCTAPASS_RELAY_API_TOKEN must be at least 32 characters".into(),
            ));
        }
        let dkim_key_pem = String::from_utf8(read(
            &need("OCTAPASS_RELAY_DKIM_KEY_FILE")?,
            "OCTAPASS_RELAY_DKIM_KEY_FILE",
        )?)
        .map_err(|_| ConfigError::Invalid("the DKIM key must be a PEM file".into()))?;
        let tls = match (
            get("OCTAPASS_RELAY_TLS_CERT_FILE"),
            get("OCTAPASS_RELAY_TLS_KEY_FILE"),
        ) {
            (Some(cert), Some(key)) => Some((
                read(&cert, "OCTAPASS_RELAY_TLS_CERT_FILE")?,
                Zeroizing::new(read(&key, "OCTAPASS_RELAY_TLS_KEY_FILE")?),
            )),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid(
                    "set both OCTAPASS_RELAY_TLS_CERT_FILE and OCTAPASS_RELAY_TLS_KEY_FILE".into(),
                ));
            }
        };
        let operator = get("OCTAPASS_RELAY_OPERATOR_EMAIL")
            .map(|text| {
                Address::parse(&text).map_err(|_| {
                    ConfigError::Invalid("OCTAPASS_RELAY_OPERATOR_EMAIL isn't an address".into())
                })
            })
            .transpose()?;
        let socket = |name: &str, default: &str| {
            get(name)
                .unwrap_or_else(|| default.to_owned())
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::Invalid(format!("{name} must be an address and port")))
        };
        let base = Limits::default();
        let limits = Limits {
            max_message_bytes: number(
                &get,
                "OCTAPASS_RELAY_MAX_MESSAGE_BYTES",
                base.max_message_bytes,
            )?,
            max_connections: number(&get, "OCTAPASS_RELAY_MAX_CONNECTIONS", base.max_connections)?,
            connections_per_ip: Bucket::per_minute(number(
                &get,
                "OCTAPASS_RELAY_CONNECTIONS_PER_IP_MINUTE",
                60,
            )?),
            messages_per_alias: Bucket::per_hour(number(
                &get,
                "OCTAPASS_RELAY_MESSAGES_PER_ALIAS_HOUR",
                60,
            )?),
            messages_per_sender: Bucket::per_hour(number(
                &get,
                "OCTAPASS_RELAY_MESSAGES_PER_SENDER_HOUR",
                120,
            )?),
            messages_per_account: Bucket::per_hour(number(
                &get,
                "OCTAPASS_RELAY_MESSAGES_PER_ACCOUNT_HOUR",
                300,
            )?),
            replies_per_account: Bucket::per_hour(number(
                &get,
                "OCTAPASS_RELAY_REPLIES_PER_ACCOUNT_HOUR",
                60,
            )?),
            aliases_per_account: number(
                &get,
                "OCTAPASS_RELAY_ALIASES_PER_ACCOUNT",
                base.aliases_per_account,
            )?,
            aliases_per_day: number(&get, "OCTAPASS_RELAY_ALIASES_PER_DAY", base.aliases_per_day)?,
            contacts_per_alias: number(
                &get,
                "OCTAPASS_RELAY_CONTACTS_PER_ALIAS",
                base.contacts_per_alias,
            )?,
            feedback_window_days: number(
                &get,
                "OCTAPASS_RELAY_FEEDBACK_WINDOW_DAYS",
                base.feedback_window_days,
            )?,
            alias_hard_bounces: number(
                &get,
                "OCTAPASS_RELAY_ALIAS_HARD_BOUNCES",
                base.alias_hard_bounces,
            )?,
            alias_complaints: number(
                &get,
                "OCTAPASS_RELAY_ALIAS_COMPLAINTS",
                base.alias_complaints,
            )?,
            account_hard_bounces: number(
                &get,
                "OCTAPASS_RELAY_ACCOUNT_HARD_BOUNCES",
                base.account_hard_bounces,
            )?,
            account_complaints: number(
                &get,
                "OCTAPASS_RELAY_ACCOUNT_COMPLAINTS",
                base.account_complaints,
            )?,
            ..base
        };
        Ok(Self {
            hostname: get("OCTAPASS_RELAY_HOSTNAME").unwrap_or_else(|| domain.clone()),
            domain,
            smtp_bind: socket("OCTAPASS_RELAY_SMTP_BIND", "0.0.0.0:25")?,
            api_bind: socket("OCTAPASS_RELAY_API_BIND", "127.0.0.1:8025")?,
            api_token: Zeroizing::new(api_token),
            secret: Zeroizing::new(secret),
            database_url: need("OCTAPASS_RELAY_DATABASE_URL")?,
            smart_host: need("OCTAPASS_RELAY_SMART_HOST")?,
            dkim_selector: need("OCTAPASS_RELAY_DKIM_SELECTOR")?,
            dkim_key_pem: Zeroizing::new(dkim_key_pem),
            tls,
            operator,
            limits,
            dns: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn with(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from(move |name| map.get(name).cloned())
    }

    #[test]
    fn without_configuration_it_says_it_is_off() {
        let error = with(&[]).err().unwrap();
        assert!(matches!(error, ConfigError::Off));
        let text = error.to_string();
        assert!(text.contains("is off"), "{text}");
        for name in REQUIRED {
            assert!(text.contains(name.split(' ').next().unwrap()), "{text}");
        }
    }

    #[test]
    fn half_a_configuration_names_what_is_missing() {
        let error = with(&[("OCTAPASS_RELAY_DOMAIN", "relay.example")])
            .err()
            .unwrap();
        assert!(matches!(
            error,
            ConfigError::Missing("OCTAPASS_RELAY_SECRET")
        ));
    }

    #[test]
    fn weak_secrets_and_bad_domains_are_refused() {
        let error = with(&[("OCTAPASS_RELAY_DOMAIN", "not a domain")])
            .err()
            .unwrap();
        assert!(matches!(error, ConfigError::Invalid(_)));
        let error = with(&[
            ("OCTAPASS_RELAY_DOMAIN", "relay.example"),
            ("OCTAPASS_RELAY_SECRET", "short"),
        ])
        .err()
        .unwrap();
        assert!(matches!(error, ConfigError::Invalid(_)));
    }
}
