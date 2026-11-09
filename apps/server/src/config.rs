//! Server configuration, read from `OCTAPASS_*` environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::HeaderValue;
use octapass_api::SignupMode;

use crate::db::items::Quota;
use crate::storage::{S3Config, StorageConfig};

#[derive(Clone, Debug)]
pub struct Config {
    /// The public base URL, used in emails and to decide whether to send HSTS.
    pub public_url: String,
    pub bind: SocketAddr,
    /// Holds the SQLite database and the server's long-term secrets.
    pub data_dir: PathBuf,
    pub database_url: String,
    /// Logs and returns email verification codes. Never enable in production.
    pub dev_mode: bool,
    pub smtp_url: Option<String>,
    pub smtp_from: Option<String>,
    pub signups: SignupMode,
    pub web_origins: Vec<HeaderValue>,
    /// The WebAuthn relying party id security keys are registered for: the web vault's host, or a
    /// registrable suffix of it.
    pub webauthn_rp_id: String,
    /// Take the client IP from the last `X-Forwarded-For` entry (set when behind a reverse proxy).
    pub trust_proxy: bool,
    pub rate_limits: RateLimits,
    /// How often WebSocket connections are pinged. One missed pong closes them.
    pub ws_heartbeat: Duration,
    /// Items and ciphertext bytes each account may store in the vaults it owns.
    pub quota: Quota,
    /// Members plus pending invites a family may have, the organiser included.
    pub family_max_members: u32,
    pub attachments: Attachments,
    /// Serves the built web vault from this folder on the API's origin (`OCTAPASS_WEB_DIR`).
    pub web_dir: Option<PathBuf>,
    /// Emails invited at every start while they have no account (`OCTAPASS_INVITES`).
    pub invites: Vec<String>,
    /// Writes every email's subject to the log, for servers without SMTP whose operator reads
    /// sign-up codes there. Unlike dev mode, codes never go back to clients.
    pub email_to_log: bool,
    pub backups: Option<Backups>,
    pub icons: Icons,
    /// The masked email relay's internal API (`OCTAPASS_RELAY_API_URL`), when this server has one.
    pub relay: Option<Relay>,
    /// The push relay that wakes phones (`OCTAPASS_PUSH_RELAY`), off unless turned on.
    pub push: Option<PushRelay>,
    /// Witnesses the key log sends its checkpoints to (`OCTAPASS_KEY_LOG_WITNESSES`). None: the
    /// log isn't witnessed.
    pub key_log_witnesses: Option<KeyLogWitnesses>,
    /// Email breach alerts, off unless `OCTAPASS_HIBP_API_KEY` is set.
    pub hibp: Option<Hibp>,
    /// Where to fetch newer health data from (plan 06); the bundled file is served either way.
    pub health_data: HealthDataSource,
    /// Lets the server reach an identity provider on a private address, for self-hosters with one
    /// on their own network (`OCTAPASS_SSO_PRIVATE_NETWORK`). Off, only public addresses are used.
    pub sso_private_network: bool,
}

/// Independent witnesses that cosign the key log's checkpoints (plan 03, "Witnesses").
#[derive(Clone, Debug)]
pub struct KeyLogWitnesses {
    pub witnesses: Vec<KeyLogWitness>,
    /// How many must cosign before a checkpoint is served (`OCTAPASS_KEY_LOG_WITNESS_QUORUM`,
    /// a majority by default).
    pub quorum: u32,
    /// How often checkpoints go to the witnesses (`OCTAPASS_KEY_LOG_WITNESS_INTERVAL`, seconds).
    pub interval: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogWitness {
    /// The submission prefix: checkpoints go to `<url>/add-checkpoint`.
    pub url: String,
    /// The witness's C2SP verifier key (`name+id+base64`, an Ed25519 cosignature/v1 key).
    pub vkey: String,
}

/// The push relay (plan 04): it holds the APNs and FCM credentials, so this server can wake the
/// official phone apps. The server registers with it on its own and keeps the installation in
/// its database.
#[derive(Clone, Debug)]
pub struct PushRelay {
    pub url: String,
    /// How long changes gather before their pushes go out, so an import of a thousand items
    /// wakes each phone once. Not an environment variable; tests shorten it.
    pub batch_delay: Duration,
}

/// Where the masked email relay's internal API is. Without it, `/v1/masked-email` answers 404 and
/// nothing about the relay runs.
#[derive(Clone)]
pub struct Relay {
    pub url: String,
    pub token: String,
}

// By hand, so the token can't reach a log.
impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// The Have I Been Pwned breach API, for `POST /v1/health/breach-email`.
#[derive(Clone)]
pub struct Hibp {
    pub api_key: String,
    pub base_url: String,
    /// What the key's plan allows, for the whole server (`OCTAPASS_HIBP_REQUESTS_PER_MINUTE`).
    pub requests_per_minute: u32,
}

/// The key stays out of `Config`'s debug output.
impl std::fmt::Debug for Hibp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hibp")
            .field("base_url", &self.base_url)
            .field("requests_per_minute", &self.requests_per_minute)
            .finish_non_exhaustive()
    }
}

/// The health report's signed site lists (plan 06).
#[derive(Clone, Debug)]
pub struct HealthDataSource {
    /// `OCTAPASS_HEALTH_DATA_URL`, the project's published file. None: only the bundled copy.
    pub url: Option<String>,
    /// `OCTAPASS_HEALTH_DATA_INTERVAL`, seconds (default a day).
    pub interval: Duration,
    /// The key a file must be signed with. Always the pinned one outside tests: there's no setting.
    pub key: [u8; 32],
}

/// Scheduled online backups of a SQLite server (`OCTAPASS_BACKUP_DIR`).
#[derive(Clone, Debug)]
pub struct Backups {
    pub dir: PathBuf,
    pub every: Duration,
    /// How many backups to keep; older ones are deleted after each new one.
    pub keep: usize,
}

/// The website icon proxy, `GET /v1/icons/{domain}`.
#[derive(Clone, Debug)]
pub struct Icons {
    /// `OCTAPASS_ICONS=off` turns it off: every icon request then gets a 404.
    pub enabled: bool,
    /// Tests only: fixed DNS answers and test sites the fetcher may reach. From the environment
    /// only in dev mode (`OCTAPASS_DEV_ICON_HOSTS`), for end-to-end tests.
    pub test_network: Option<std::sync::Arc<crate::icons::TestNetwork>>,
    pub limits: crate::icons::Limits,
}

/// Where attachment files go and how much they may take.
#[derive(Clone, Debug)]
pub struct Attachments {
    pub storage: StorageConfig,
    /// Stored bytes each account may keep in the vaults it owns, trash included.
    pub quota_bytes: u64,
    /// The largest single file, as stored (encrypted).
    pub max_file_bytes: u64,
}

/// Token buckets for the auth endpoints: `burst` requests at once, then one
/// more every `refill`.
#[derive(Clone, Copy, Debug)]
pub struct RateLimits {
    /// Every auth request from one client IP.
    pub per_ip: Bucket,
    /// Failed logins and reauths for one email from one IP. Starting a login
    /// is free, so nobody can lock an account by flooding `login/start`.
    pub login_per_email_ip: Bucket,
    /// Failed logins for one email from anywhere: a ceiling high enough that
    /// the owner, on their own IP bucket, isn't locked out by a spread attack.
    pub login_per_email: Bucket,
    /// Sign-up starts and code checks for one email. A daily cap on codes
    /// sent and wrong codes applies on top.
    pub signup_per_email: Bucket,
    /// Account lookups and invites by email for one signed-in account: the
    /// places an email's existence shows, so they share one budget.
    pub lookup_per_account: Bucket,
    /// Key log labels: each is an offline-free test of one email against the log.
    pub key_log_label_per_account: Bucket,
    /// Share-link views from one client IP. Viewing needs no account.
    pub share_link_per_ip: Bucket,
    /// Emergency contacts one account adds. Each one emails the contact, so
    /// adding, removing and adding again can't be used to flood an inbox.
    pub emergency_contact_per_account: Bucket,
    /// Emergency contact emails to one address, from any number of accounts.
    pub emergency_contact_per_recipient: Bucket,
    /// Wrong second-step codes for one account, from anywhere. Running out pauses the second
    /// step, records it in the security log and emails the owner.
    pub two_step_per_account: Bucket,
    /// Website icon requests from one client IP. Needs no account.
    pub icons_per_ip: Bucket,
    /// Email breach lookups for one account: room for a day's check of every alias a client
    /// sends, little for trying other people's addresses. The HIBP key's own limit is separate.
    pub breach_email_per_account: Bucket,
}

#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    pub burst: u32,
    pub refill: Duration,
}

impl RateLimits {
    /// No practical limit, for local development and test suites that sign in many times from
    /// one address. Only allowed in dev mode.
    pub fn unlimited() -> Self {
        let bucket = Bucket {
            burst: u32::MAX,
            refill: Duration::from_millis(1),
        };
        Self {
            per_ip: bucket,
            login_per_email_ip: bucket,
            login_per_email: bucket,
            signup_per_email: bucket,
            lookup_per_account: bucket,
            key_log_label_per_account: bucket,
            share_link_per_ip: bucket,
            emergency_contact_per_account: bucket,
            emergency_contact_per_recipient: bucket,
            two_step_per_account: bucket,
            icons_per_ip: bucket,
            breach_email_per_account: bucket,
        }
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        let bucket = |burst, refill_secs| Bucket {
            burst,
            refill: Duration::from_secs(refill_secs),
        };
        Self {
            per_ip: bucket(30, 2),
            login_per_email_ip: bucket(10, 60),
            login_per_email: bucket(100, 10),
            signup_per_email: bucket(20, 60),
            lookup_per_account: bucket(20, 30),
            key_log_label_per_account: bucket(40, 30),
            share_link_per_ip: bucket(10, 6),
            emergency_contact_per_account: bucket(10, 15 * 60),
            emergency_contact_per_recipient: bucket(5, 60 * 60),
            two_step_per_account: bucket(10, 5 * 60),
            // A vault's first screens ask for a few dozen; the device keeps what it got.
            icons_per_ip: Bucket {
                burst: 200,
                refill: Duration::from_millis(250),
            },
            breach_email_per_account: bucket(60, 30 * 60),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid value for {name}: {reason}")]
pub struct ConfigError {
    name: &'static str,
    reason: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let bind: SocketAddr = parse(&get, "OCTAPASS_BIND", "127.0.0.1:8080")?;
        let data_dir = PathBuf::from(get("OCTAPASS_DATA_DIR").unwrap_or_else(|| "./data".into()));
        let database_url = get("OCTAPASS_DATABASE_URL")
            .unwrap_or_else(|| format!("sqlite://{}/octapass.db", data_dir.display()));
        let signups = match get("OCTAPASS_SIGNUPS").as_deref() {
            None | Some("open") => SignupMode::Open,
            Some("invite") => SignupMode::Invite,
            Some("closed") => SignupMode::Closed,
            Some(other) => {
                return Err(invalid(
                    "OCTAPASS_SIGNUPS",
                    format!("{other:?} is not open, invite or closed"),
                ));
            }
        };
        let web_origins: Vec<HeaderValue> = get("OCTAPASS_WEB_ORIGINS")
            .unwrap_or_else(|| "http://localhost:5173".into())
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(|origin| {
                HeaderValue::from_str(origin.trim_end_matches('/')).map_err(|_| {
                    invalid(
                        "OCTAPASS_WEB_ORIGINS",
                        format!("{origin:?} is not a valid origin"),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        let dev_mode = parse(&get, "OCTAPASS_DEV_MODE", "false")?;
        let rate_limits = match get("OCTAPASS_RATE_LIMITS").as_deref() {
            None | Some("on") => RateLimits::default(),
            Some("off") if dev_mode => RateLimits::unlimited(),
            Some("off") => {
                return Err(invalid(
                    "OCTAPASS_RATE_LIMITS",
                    "\"off\" is only allowed with OCTAPASS_DEV_MODE=true".into(),
                ));
            }
            Some(other) => {
                return Err(invalid(
                    "OCTAPASS_RATE_LIMITS",
                    format!("{other:?} is not on or off"),
                ));
            }
        };

        let attachments = Attachments {
            storage: attachment_storage(&get, &data_dir)?,
            quota_bytes: parse(&get, "OCTAPASS_MAX_ATTACHMENT_BYTES", "1073741824")?,
            max_file_bytes: parse(&get, "OCTAPASS_MAX_FILE_BYTES", "104857600")?,
        };
        let backups = backups(&get, &database_url)?;
        let public_url = get("OCTAPASS_PUBLIC_URL").unwrap_or_else(|| format!("http://{bind}"));
        let webauthn_rp_id = match get("OCTAPASS_WEBAUTHN_RP_ID") {
            Some(rp_id) => rp_id.trim().to_ascii_lowercase(),
            None => web_origins
                .first()
                .and_then(|origin| origin.to_str().ok())
                .and_then(host_of)
                .or_else(|| host_of(&public_url))
                .unwrap_or_else(|| "localhost".into()),
        };

        Ok(Self {
            public_url,
            bind,
            data_dir,
            database_url,
            dev_mode,
            smtp_url: get("OCTAPASS_SMTP_URL"),
            smtp_from: get("OCTAPASS_SMTP_FROM"),
            signups,
            web_origins,
            webauthn_rp_id,
            trust_proxy: parse(&get, "OCTAPASS_TRUST_PROXY", "false")?,
            rate_limits,
            ws_heartbeat: Duration::from_secs(30),
            quota: Quota {
                items: parse(&get, "OCTAPASS_MAX_ITEMS", "50000")?,
                bytes: parse(&get, "OCTAPASS_MAX_ITEM_BYTES", "1073741824")?,
            },
            family_max_members: family_max_members(&get)?,
            attachments,
            web_dir: get("OCTAPASS_WEB_DIR").map(PathBuf::from),
            invites: get("OCTAPASS_INVITES")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|email| !email.is_empty())
                .map(|email| {
                    crate::validate::email(email).map_err(|_| {
                        invalid("OCTAPASS_INVITES", format!("{email:?} is not an email"))
                    })
                })
                .collect::<Result<_, _>>()?,
            email_to_log: parse(&get, "OCTAPASS_EMAIL_TO_LOG", "false")?,
            backups,
            icons: Icons {
                enabled: on_off(&get, "OCTAPASS_ICONS")?,
                test_network: dev_icon_hosts(&get, dev_mode)?,
                limits: crate::icons::Limits::default(),
            },
            relay: relay(&get)?,
            push: push_relay(&get)?,
            key_log_witnesses: key_log_witnesses(&get)?,
            hibp: hibp(&get, dev_mode)?,
            health_data: health_data(&get)?,
            sso_private_network: get("OCTAPASS_SSO_PRIVATE_NETWORK")
                .is_some_and(|value| value.eq_ignore_ascii_case("on") || value == "true"),
        })
    }

    /// Whether sign-up codes can reach anyone: by email, or in the log.
    pub fn can_deliver_codes(&self) -> bool {
        self.smtp_url.is_some() || self.email_to_log || self.dev_mode
    }

    /// Whether clients reach the server over HTTPS (so HSTS is safe to send).
    pub fn is_https(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    /// Origins a WebAuthn ceremony may come from: the web vault origins, and the server itself,
    /// which can serve the web vault too.
    pub fn webauthn_origins(&self) -> Vec<String> {
        let mut origins: Vec<String> = self
            .web_origins
            .iter()
            .filter_map(|origin| origin.to_str().ok().map(str::to_owned))
            .collect();
        origins.push(self.public_url.trim_end_matches('/').to_owned());
        origins
    }
}

/// The Octa Pass project's relay. Not running yet: until it is, set `OCTAPASS_PUSH_RELAY_URL` to
/// one you run (`apps/push-relay`).
pub const DEFAULT_PUSH_RELAY_URL: &str = "https://push.octap.app";

/// Off by default: turning it on sends the relay a wakeup, with a device's push token, whenever
/// that device has something to sync.
fn push_relay(get: &impl Fn(&str) -> Option<String>) -> Result<Option<PushRelay>, ConfigError> {
    const NAME: &str = "OCTAPASS_PUSH_RELAY";
    let on = match get(NAME).as_deref() {
        None | Some("false") | Some("off") => false,
        Some("true") | Some("on") => true,
        Some(other) => return Err(invalid(NAME, format!("{other:?} is not true or false"))),
    };
    let url = get("OCTAPASS_PUSH_RELAY_URL");
    if !on {
        if url.is_some() {
            return Err(invalid(
                "OCTAPASS_PUSH_RELAY_URL",
                "needs OCTAPASS_PUSH_RELAY=true as well".into(),
            ));
        }
        return Ok(None);
    }
    let url = url.unwrap_or_else(|| DEFAULT_PUSH_RELAY_URL.into());
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(invalid(
            "OCTAPASS_PUSH_RELAY_URL",
            format!("{url:?} is not an http(s) URL"),
        ));
    }
    Ok(Some(PushRelay {
        url: url.trim_end_matches('/').to_owned(),
        batch_delay: Duration::from_secs(2),
    }))
}

fn relay(get: &impl Fn(&str) -> Option<String>) -> Result<Option<Relay>, ConfigError> {
    match (
        get("OCTAPASS_RELAY_API_URL"),
        get("OCTAPASS_RELAY_API_TOKEN"),
    ) {
        (None, _) => Ok(None),
        (Some(_), None) => Err(invalid(
            "OCTAPASS_RELAY_API_TOKEN",
            "needed with OCTAPASS_RELAY_API_URL".into(),
        )),
        (Some(url), Some(token)) if url.starts_with("http://") || url.starts_with("https://") => {
            Ok(Some(Relay {
                url: url.trim_end_matches('/').to_owned(),
                token,
            }))
        }
        (Some(url), _) => Err(invalid(
            "OCTAPASS_RELAY_API_URL",
            format!("{url:?} is not an http(s) URL"),
        )),
    }
}

/// Off unless `OCTAPASS_HEALTH_DATA_URL` is set: fetching it tells that site when this server runs.
fn health_data(get: &impl Fn(&str) -> Option<String>) -> Result<HealthDataSource, ConfigError> {
    let url = get("OCTAPASS_HEALTH_DATA_URL");
    if let Some(url) = &url
        && !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(invalid(
            "OCTAPASS_HEALTH_DATA_URL",
            format!("{url:?} is not an http(s) URL"),
        ));
    }
    let interval: u64 = parse(get, "OCTAPASS_HEALTH_DATA_INTERVAL", "86400")?;
    if interval < 60 {
        return Err(invalid(
            "OCTAPASS_HEALTH_DATA_INTERVAL",
            "must be at least 60 seconds".into(),
        ));
    }
    Ok(HealthDataSource {
        url,
        interval: Duration::from_secs(interval),
        key: octapass_core::health_data::PUBLIC_KEY,
    })
}

/// `OCTAPASS_KEY_LOG_WITNESSES`: entries separated by commas or newlines, each a submission URL
/// and the witness's verifier key, separated by a space.
fn key_log_witnesses(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<KeyLogWitnesses>, ConfigError> {
    use octapass_core::transparency::witness::{MAX_WITNESSES, WitnessPolicy};
    const NAME: &str = "OCTAPASS_KEY_LOG_WITNESSES";
    let Some(raw) = get(NAME) else {
        return Ok(None);
    };
    let witnesses: Vec<KeyLogWitness> = raw
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (url, vkey) = entry
                .split_once(char::is_whitespace)
                .ok_or_else(|| invalid(NAME, format!("{entry:?} is not \"<url> <vkey>\"")))?;
            let vkey = vkey.trim();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(invalid(NAME, format!("{url:?} is not an http(s) URL")));
            }
            let policy = WitnessPolicy {
                witnesses: vec![vkey.to_owned()],
                quorum: 1,
            };
            if policy.verifiers().is_err() {
                return Err(invalid(
                    NAME,
                    format!("{vkey:?} is not an Ed25519 cosignature/v1 verifier key"),
                ));
            }
            Ok(KeyLogWitness {
                url: url.trim_end_matches('/').to_owned(),
                vkey: vkey.to_owned(),
            })
        })
        .collect::<Result<_, _>>()?;
    if witnesses.is_empty() {
        return Ok(None);
    }
    let all = WitnessPolicy {
        witnesses: witnesses.iter().map(|w| w.vkey.clone()).collect(),
        quorum: 1,
    };
    if witnesses.len() > MAX_WITNESSES || all.verifiers().is_err() {
        return Err(invalid(
            NAME,
            format!("needs at most {MAX_WITNESSES} witnesses, each with its own key"),
        ));
    }
    let majority = WitnessPolicy::majority(witnesses.len()).to_string();
    let quorum: u32 = parse(get, "OCTAPASS_KEY_LOG_WITNESS_QUORUM", &majority)?;
    if quorum == 0 || quorum as usize > witnesses.len() {
        return Err(invalid(
            "OCTAPASS_KEY_LOG_WITNESS_QUORUM",
            format!(
                "must be between 1 and the number of witnesses ({})",
                witnesses.len()
            ),
        ));
    }
    let interval: u64 = parse(get, "OCTAPASS_KEY_LOG_WITNESS_INTERVAL", "600")?;
    if !(10..=86_400).contains(&interval) {
        return Err(invalid(
            "OCTAPASS_KEY_LOG_WITNESS_INTERVAL",
            "must be between 10 and 86400 seconds".into(),
        ));
    }
    Ok(Some(KeyLogWitnesses {
        witnesses,
        quorum,
        interval: Duration::from_secs(interval),
    }))
}

/// The host of an `http(s)://host[:port][/…]` URL, lowercased.
fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = match authority.strip_prefix('[') {
        Some(ipv6) => ipv6.split(']').next()?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// `<data dir>/attachments`, or a bucket when `OCTAPASS_S3_BUCKET` is set.
fn attachment_storage(
    get: &impl Fn(&str) -> Option<String>,
    data_dir: &std::path::Path,
) -> Result<StorageConfig, ConfigError> {
    const VARS: [&str; 5] = [
        "OCTAPASS_S3_ENDPOINT",
        "OCTAPASS_S3_REGION",
        "OCTAPASS_S3_ACCESS_KEY_ID",
        "OCTAPASS_S3_SECRET_ACCESS_KEY",
        "OCTAPASS_S3_PATH_STYLE",
    ];
    let Some(bucket) = get("OCTAPASS_S3_BUCKET") else {
        if let Some(name) = VARS.into_iter().find(|name| get(name).is_some()) {
            return Err(invalid(name, "needs OCTAPASS_S3_BUCKET as well".into()));
        }
        return Ok(StorageConfig::Local {
            dir: data_dir.join("attachments"),
        });
    };
    let required = |name: &'static str| {
        get(name).ok_or_else(|| invalid(name, "is required with OCTAPASS_S3_BUCKET".into()))
    };
    let region = get("OCTAPASS_S3_REGION").unwrap_or_else(|| "us-east-1".into());
    let endpoint = get("OCTAPASS_S3_ENDPOINT");
    // Self-hosted S3 servers usually need path-style URLs; AWS prefers virtual hosts.
    let path_style_default = if endpoint.is_some() { "true" } else { "false" };
    Ok(StorageConfig::S3(S3Config {
        endpoint: endpoint.unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com")),
        bucket,
        region,
        access_key_id: required("OCTAPASS_S3_ACCESS_KEY_ID")?,
        secret_access_key: required("OCTAPASS_S3_SECRET_ACCESS_KEY")?,
        path_style: parse(get, "OCTAPASS_S3_PATH_STYLE", path_style_default)?,
    }))
}

/// Backups need SQLite: PostgreSQL has its own tools (`pg_dump`).
fn backups(
    get: &impl Fn(&str) -> Option<String>,
    database_url: &str,
) -> Result<Option<Backups>, ConfigError> {
    let Some(dir) = get("OCTAPASS_BACKUP_DIR") else {
        return Ok(None);
    };
    if crate::db::Backend::of_url(database_url) != Some(crate::db::Backend::Sqlite) {
        return Err(invalid(
            "OCTAPASS_BACKUP_DIR",
            "only works with SQLite; back up PostgreSQL with pg_dump".into(),
        ));
    }
    let hours: u64 = parse(get, "OCTAPASS_BACKUP_EVERY_HOURS", "24")?;
    let keep: usize = parse(get, "OCTAPASS_BACKUP_KEEP", "14")?;
    if hours == 0 {
        return Err(invalid(
            "OCTAPASS_BACKUP_EVERY_HOURS",
            "must be at least 1".into(),
        ));
    }
    if keep == 0 {
        return Err(invalid("OCTAPASS_BACKUP_KEEP", "must be at least 1".into()));
    }
    Ok(Some(Backups {
        dir: PathBuf::from(dir),
        every: Duration::from_secs(hours * 60 * 60),
        keep,
    }))
}

fn family_max_members(get: &impl Fn(&str) -> Option<String>) -> Result<u32, ConfigError> {
    const NAME: &str = "OCTAPASS_FAMILY_MAX_MEMBERS";
    let max: u32 = parse(get, NAME, "6")?;
    if (2..=100).contains(&max) {
        Ok(max)
    } else {
        Err(invalid(NAME, format!("{max} is not between 2 and 100")))
    }
}

const HIBP_API: &str = "https://haveibeenpwned.com/api/v3";

/// Nothing without a key. Another API address is for tests, so it needs dev mode.
fn hibp(
    get: &impl Fn(&str) -> Option<String>,
    dev_mode: bool,
) -> Result<Option<Hibp>, ConfigError> {
    let url = get("OCTAPASS_HIBP_API_URL");
    if url.is_some() && !dev_mode {
        return Err(invalid("OCTAPASS_HIBP_API_URL", "needs dev mode".into()));
    }
    let Some(api_key) = get("OCTAPASS_HIBP_API_KEY") else {
        return Ok(None);
    };
    let requests_per_minute = parse(get, "OCTAPASS_HIBP_REQUESTS_PER_MINUTE", "10")?;
    if requests_per_minute == 0 {
        return Err(invalid(
            "OCTAPASS_HIBP_REQUESTS_PER_MINUTE",
            "must be at least 1".into(),
        ));
    }
    Ok(Some(Hibp {
        api_key,
        base_url: url.unwrap_or_else(|| HIBP_API.into()),
        requests_per_minute,
    }))
}

/// `name=ip:port,…`: the icon fetcher resolves these names to these addresses, which it may then
/// reach although they're local. Dev mode only, for end-to-end tests against local pages.
fn dev_icon_hosts(
    get: &impl Fn(&str) -> Option<String>,
    dev_mode: bool,
) -> Result<Option<std::sync::Arc<crate::icons::TestNetwork>>, ConfigError> {
    const NAME: &str = "OCTAPASS_DEV_ICON_HOSTS";
    let Some(raw) = get(NAME) else {
        return Ok(None);
    };
    if !dev_mode {
        return Err(invalid(
            NAME,
            "is only allowed with OCTAPASS_DEV_MODE=true".into(),
        ));
    }
    let mut network = crate::icons::TestNetwork::default();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (host, addr) = entry
            .split_once('=')
            .ok_or_else(|| invalid(NAME, format!("{entry:?} is not name=ip:port")))?;
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| invalid(NAME, format!("{addr:?} is not ip:port")))?;
        network
            .hosts
            .entry(host.to_ascii_lowercase())
            .or_default()
            .push(addr);
        network.reachable.push(addr);
    }
    Ok(Some(std::sync::Arc::new(network)))
}

fn on_off(get: &impl Fn(&str) -> Option<String>, name: &'static str) -> Result<bool, ConfigError> {
    match get(name).as_deref() {
        None | Some("on") => Ok(true),
        Some("off") => Ok(false),
        Some(other) => Err(invalid(name, format!("{other:?} is not on or off"))),
    }
}

fn parse<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: &str,
) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    let raw = get(name).unwrap_or_else(|| default.into());
    raw.parse()
        .map_err(|e: T::Err| invalid(name, e.to_string()))
}

fn invalid(name: &'static str, reason: String) -> ConfigError {
    ConfigError { name, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|name| vars.get(name).cloned())
    }

    fn witness_vkey(seed: u8) -> String {
        use octapass_core::transparency::note::{COSIGNATURE_V1, Verifier};
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        Verifier::new(&format!("witness.example/{seed}"), COSIGNATURE_V1, key)
            .unwrap()
            .vkey()
    }

    #[test]
    fn key_log_witnesses() {
        assert!(config(&[]).unwrap().key_log_witnesses.is_none());
        let list = format!(
            "https://w1.example/ {},\nhttp://127.0.0.1:9000 {}, https://w3.example {}",
            witness_vkey(1),
            witness_vkey(2),
            witness_vkey(3)
        );
        let witnesses = config(&[("OCTAPASS_KEY_LOG_WITNESSES", &list)])
            .unwrap()
            .key_log_witnesses
            .unwrap();
        assert_eq!(witnesses.witnesses.len(), 3);
        assert_eq!(witnesses.witnesses[0].url, "https://w1.example");
        assert_eq!(witnesses.quorum, 2);
        assert_eq!(witnesses.interval, Duration::from_secs(600));

        let quorum = |q: &str| {
            config(&[
                ("OCTAPASS_KEY_LOG_WITNESSES", &list),
                ("OCTAPASS_KEY_LOG_WITNESS_QUORUM", q),
            ])
        };
        assert_eq!(quorum("3").unwrap().key_log_witnesses.unwrap().quorum, 3);
        assert!(quorum("4").is_err());
        assert!(quorum("0").is_err());

        let bad = [
            format!("w1.example {}", witness_vkey(1)),
            "https://w1.example not-a-key".to_owned(),
            format!(
                "https://w1.example {0}, https://w2.example {0}",
                witness_vkey(1)
            ),
        ];
        for value in &bad {
            assert!(
                config(&[("OCTAPASS_KEY_LOG_WITNESSES", value)]).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn defaults() {
        let config = config(&[]).unwrap();
        assert_eq!(config.bind, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.database_url, "sqlite://./data/octapass.db");
        assert_eq!(config.public_url, "http://127.0.0.1:8080");
        assert_eq!(config.signups, SignupMode::Open);
        assert_eq!(
            config.web_origins,
            vec![HeaderValue::from_static("http://localhost:5173")]
        );
        assert!(!config.dev_mode);
        assert!(!config.is_https());
        assert_eq!(config.quota.items, 50_000);
        assert_eq!(config.quota.bytes, 1 << 30);
        assert_eq!(config.family_max_members, 6);
        assert_eq!(config.attachments.quota_bytes, 1 << 30);
        assert_eq!(config.attachments.max_file_bytes, 100 << 20);
        assert!(matches!(
            &config.attachments.storage,
            StorageConfig::Local { dir } if dir == std::path::Path::new("./data/attachments")
        ));
        assert_eq!(config.webauthn_rp_id, "localhost");
        assert!(config.icons.enabled);
        assert!(config.icons.test_network.is_none());
        assert_eq!(
            config.webauthn_origins(),
            ["http://localhost:5173", "http://127.0.0.1:8080"]
        );
    }

    #[test]
    fn webauthn_rp_id_follows_the_web_vault() {
        let derived =
            config(&[("OCTAPASS_WEB_ORIGINS", "https://Vault.Example.com:8443/app")]).unwrap();
        assert_eq!(derived.webauthn_rp_id, "vault.example.com");
        let set = config(&[("OCTAPASS_WEBAUTHN_RP_ID", "example.com")]).unwrap();
        assert_eq!(set.webauthn_rp_id, "example.com");
    }

    #[test]
    fn attachments_can_go_to_s3() {
        let keys = [
            ("OCTAPASS_S3_BUCKET", "files"),
            ("OCTAPASS_S3_ACCESS_KEY_ID", "id"),
            ("OCTAPASS_S3_SECRET_ACCESS_KEY", "secret"),
        ];
        let aws = config(&keys).unwrap();
        let StorageConfig::S3(s3) = &aws.attachments.storage else {
            panic!("expected S3");
        };
        assert_eq!(s3.endpoint, "https://s3.us-east-1.amazonaws.com");
        assert!(!s3.path_style);

        let mut minio = keys.to_vec();
        minio.push(("OCTAPASS_S3_ENDPOINT", "http://minio:9000"));
        minio.push(("OCTAPASS_S3_REGION", "eu"));
        let StorageConfig::S3(s3) = config(&minio).unwrap().attachments.storage else {
            panic!("expected S3");
        };
        assert_eq!(
            (s3.endpoint.as_str(), s3.region.as_str()),
            ("http://minio:9000", "eu")
        );
        assert!(s3.path_style);

        assert!(config(&keys[..2]).is_err(), "no secret");
        assert!(
            config(&[("OCTAPASS_S3_ENDPOINT", "http://minio:9000")]).is_err(),
            "no bucket"
        );
        assert!(config(&[("OCTAPASS_MAX_FILE_BYTES", "big")]).is_err());
    }

    #[test]
    fn database_follows_data_dir() {
        let config = config(&[("OCTAPASS_DATA_DIR", "/data")]).unwrap();
        assert_eq!(config.database_url, "sqlite:///data/octapass.db");
    }

    #[test]
    fn parses_origins_and_modes() {
        let config = config(&[
            (
                "OCTAPASS_WEB_ORIGINS",
                "https://vault.example.com/, https://other.example.com",
            ),
            ("OCTAPASS_SIGNUPS", "invite"),
            ("OCTAPASS_DEV_MODE", "true"),
            ("OCTAPASS_PUBLIC_URL", "https://vault.example.com"),
        ])
        .unwrap();
        assert_eq!(config.web_origins.len(), 2);
        assert_eq!(config.web_origins[0], "https://vault.example.com");
        assert_eq!(config.signups, SignupMode::Invite);
        assert!(config.dev_mode);
        assert!(config.is_https());
    }

    #[test]
    fn rate_limits_can_be_turned_off_only_in_dev_mode() {
        assert_eq!(config(&[]).unwrap().rate_limits.per_ip.burst, 30);
        let off = config(&[
            ("OCTAPASS_DEV_MODE", "true"),
            ("OCTAPASS_RATE_LIMITS", "off"),
        ])
        .unwrap();
        assert_eq!(off.rate_limits.per_ip.burst, u32::MAX);
        assert_eq!(off.rate_limits.login_per_email.burst, u32::MAX);
        assert_eq!(off.rate_limits.signup_per_email.burst, u32::MAX);
        assert_eq!(
            off.rate_limits.emergency_contact_per_account.burst,
            u32::MAX
        );
        assert_eq!(
            off.rate_limits.emergency_contact_per_recipient.burst,
            u32::MAX
        );
        assert!(config(&[("OCTAPASS_RATE_LIMITS", "off")]).is_err());
        assert!(config(&[("OCTAPASS_RATE_LIMITS", "sometimes")]).is_err());
    }

    #[test]
    fn self_hosting_settings() {
        let defaults = config(&[]).unwrap();
        assert!(defaults.web_dir.is_none() && defaults.invites.is_empty());
        assert!(!defaults.email_to_log && defaults.backups.is_none());
        assert!(!defaults.can_deliver_codes());

        let set = config(&[
            ("OCTAPASS_WEB_DIR", "/web"),
            (
                "OCTAPASS_INVITES",
                " Owner@Example.com, second@example.com ,",
            ),
            ("OCTAPASS_EMAIL_TO_LOG", "true"),
            ("OCTAPASS_BACKUP_DIR", "/backups"),
            ("OCTAPASS_BACKUP_KEEP", "7"),
        ])
        .unwrap();
        assert_eq!(set.web_dir.as_deref(), Some(std::path::Path::new("/web")));
        assert_eq!(set.invites, ["owner@example.com", "second@example.com"]);
        assert!(set.can_deliver_codes());
        let backups = set.backups.unwrap();
        assert_eq!(backups.dir, PathBuf::from("/backups"));
        assert_eq!(backups.every, Duration::from_secs(24 * 60 * 60));
        assert_eq!(backups.keep, 7);

        assert!(config(&[("OCTAPASS_INVITES", "not-an-email")]).is_err());
        assert!(config(&[("OCTAPASS_EMAIL_TO_LOG", "yes")]).is_err());
        assert!(config(&[("OCTAPASS_BACKUP_DIR", "/b"), ("OCTAPASS_BACKUP_KEEP", "0")]).is_err());
        assert!(
            config(&[
                ("OCTAPASS_BACKUP_DIR", "/b"),
                ("OCTAPASS_BACKUP_EVERY_HOURS", "0")
            ])
            .is_err()
        );
        let postgres = config(&[
            ("OCTAPASS_BACKUP_DIR", "/b"),
            ("OCTAPASS_DATABASE_URL", "postgres://db/octapass"),
        ]);
        assert!(postgres.is_err());
    }

    #[test]
    fn email_breach_checks_are_off_without_a_key() {
        assert!(config(&[]).unwrap().hibp.is_none());
        let on = config(&[("OCTAPASS_HIBP_API_KEY", "secret")]).unwrap();
        let hibp = on.hibp.unwrap();
        assert_eq!(hibp.base_url, "https://haveibeenpwned.com/api/v3");
        assert_eq!(hibp.requests_per_minute, 10);
        assert!(!format!("{hibp:?}").contains("secret"));
        let rate = config(&[
            ("OCTAPASS_HIBP_API_KEY", "secret"),
            ("OCTAPASS_HIBP_REQUESTS_PER_MINUTE", "100"),
        ])
        .unwrap();
        assert_eq!(rate.hibp.unwrap().requests_per_minute, 100);
        assert!(
            config(&[
                ("OCTAPASS_HIBP_API_KEY", "secret"),
                ("OCTAPASS_HIBP_REQUESTS_PER_MINUTE", "0"),
            ])
            .is_err()
        );
    }

    #[test]
    fn the_hibp_address_can_change_only_in_dev_mode() {
        assert!(config(&[("OCTAPASS_HIBP_API_URL", "http://127.0.0.1:1")]).is_err());
        let dev = config(&[
            ("OCTAPASS_DEV_MODE", "true"),
            ("OCTAPASS_HIBP_API_KEY", "k"),
            ("OCTAPASS_HIBP_API_URL", "http://127.0.0.1:1"),
        ])
        .unwrap();
        assert_eq!(dev.hibp.unwrap().base_url, "http://127.0.0.1:1");
    }

    #[test]
    fn push_is_off_until_turned_on() {
        assert!(config(&[]).unwrap().push.is_none());
        assert!(
            config(&[("OCTAPASS_PUSH_RELAY", "false")])
                .unwrap()
                .push
                .is_none()
        );
        let on = config(&[("OCTAPASS_PUSH_RELAY", "true")]).unwrap();
        assert_eq!(on.push.unwrap().url, DEFAULT_PUSH_RELAY_URL);
        let own = config(&[
            ("OCTAPASS_PUSH_RELAY", "on"),
            ("OCTAPASS_PUSH_RELAY_URL", "https://push.example.com/"),
        ])
        .unwrap();
        assert_eq!(own.push.unwrap().url, "https://push.example.com");
        assert!(config(&[("OCTAPASS_PUSH_RELAY", "yes")]).is_err());
        assert!(config(&[("OCTAPASS_PUSH_RELAY_URL", "https://push.example.com")]).is_err());
        assert!(
            config(&[
                ("OCTAPASS_PUSH_RELAY", "true"),
                ("OCTAPASS_PUSH_RELAY_URL", "push.example.com")
            ])
            .is_err()
        );
    }

    #[test]
    fn icons_can_be_turned_off() {
        assert!(!config(&[("OCTAPASS_ICONS", "off")]).unwrap().icons.enabled);
        assert!(config(&[("OCTAPASS_ICONS", "on")]).unwrap().icons.enabled);
        assert!(config(&[("OCTAPASS_ICONS", "no")]).is_err());
    }

    #[test]
    fn local_icon_hosts_only_in_dev_mode() {
        let hosts = (
            "OCTAPASS_DEV_ICON_HOSTS",
            "shop.example.com=127.0.0.1:4000, www.shop.example.com=127.0.0.1:4000",
        );
        assert!(config(&[hosts]).is_err());
        let dev = config(&[("OCTAPASS_DEV_MODE", "true"), hosts]).unwrap();
        let network = dev.icons.test_network.unwrap();
        assert_eq!(
            network.hosts["www.shop.example.com"],
            ["127.0.0.1:4000".parse().unwrap()]
        );
        assert_eq!(network.reachable.len(), 2);
        assert!(
            config(&[
                ("OCTAPASS_DEV_MODE", "true"),
                ("OCTAPASS_DEV_ICON_HOSTS", "shop=nowhere")
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_bad_values() {
        assert!(config(&[("OCTAPASS_SIGNUPS", "maybe")]).is_err());
        assert!(config(&[("OCTAPASS_BIND", "nope")]).is_err());
        assert!(config(&[("OCTAPASS_DEV_MODE", "yes")]).is_err());
        assert!(config(&[("OCTAPASS_MAX_ITEMS", "-1")]).is_err());
        assert!(config(&[("OCTAPASS_FAMILY_MAX_MEMBERS", "1")]).is_err());
        assert_eq!(
            config(&[("OCTAPASS_FAMILY_MAX_MEMBERS", "10")])
                .unwrap()
                .family_max_members,
            10
        );
    }
}
