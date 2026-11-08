//! Shared state handed to every request.

use std::collections::VecDeque;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::breach_email::BreachClient;
use crate::clock::Clock;
use crate::config::Config;
use crate::crypto::{base64url, keyed_hash};
use crate::db::{self, Db};
use crate::emergency;
use crate::events::{Event, Events};
use crate::icons::Icons;
use crate::key_log::KeyLog;
use crate::login::{PendingLogins, PendingRecovery, SsoBrowser, SsoLogin};
use crate::mail::{Email, MailConfigError, Mailer};
use crate::push::{Push, PushKind};
use crate::rate_limit::RateLimiter;
use crate::relay::RelayClient;
use crate::secrets::ServerSecrets;
use crate::sso::Oidc;
use crate::storage::{self, ObjectStorage, StorageError};
use crate::two_step::SecondFactorLogin;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub db: Db,
    pub secrets: ServerSecrets,
    pub mailer: Option<Mailer>,
    pub ip_limiter: RateLimiter,
    pub login_limiter: RateLimiter,
    pub login_email_limiter: RateLimiter,
    pub signup_limiter: RateLimiter,
    pub lookup_limiter: RateLimiter,
    pub key_log_label_limiter: RateLimiter,
    pub share_link_limiter: RateLimiter,
    pub emergency_contact_limiter: RateLimiter,
    pub emergency_recipient_limiter: RateLimiter,
    pub two_step_limiter: RateLimiter,
    /// One "wrong two-step codes" alert per account an hour, however long the attempts go on.
    pub two_step_alert_limiter: RateLimiter,
    pub icon_limiter: RateLimiter,
    /// Uploads of what Octa Pass Connect handed out, per account.
    pub connect_log_limiter: RateLimiter,
    /// The website icon proxy; `None` when `OCTAPASS_ICONS=off`.
    pub icons: Option<Icons>,
    /// The masked email relay; `None` on a server without one.
    pub relay: Option<RelayClient>,
    /// Pushes through the push relay; `None` unless `OCTAPASS_PUSH_RELAY` is on.
    pub push: Option<Push>,
    /// Email breach lookups; `None` without an HIBP key.
    pub breach_client: Option<BreachClient>,
    pub breach_email_limiter: RateLimiter,
    pub pending_logins: PendingLogins,
    /// Kept apart from `pending_logins` so a login id can't finish a reauth.
    pub pending_reauths: PendingLogins,
    /// Sign-ins that passed the password and wait for their second step.
    pub pending_second_factors: PendingLogins<SecondFactorLogin>,
    /// Master password resets with the recovery code, from `recover/start` to `recover/finish`.
    pub pending_recoveries: PendingLogins<PendingRecovery>,
    /// Sign-ins that passed the password and wait for the identity provider.
    pub pending_sso: PendingLogins<SsoLogin>,
    /// Browsers on their way through the identity provider.
    pub pending_sso_browsers: PendingLogins<SsoBrowser>,
    /// The HTTP client for identity providers.
    pub oidc: Oidc,
    /// Service accounts' sign-in challenges; each is used once.
    pub pending_service_challenges: PendingLogins<String>,
    pub events: Events,
    pub clock: Clock,
    /// The key log's own keys, derived from the server secret.
    pub key_log: KeyLog,
    /// Where attachment files live.
    pub storage: Arc<dyn ObjectStorage>,
    /// Uploads are written here first, then handed to `storage`.
    pub uploads_dir: PathBuf,
    /// Dev mode only: the last emails sent, as (recipient, subject).
    dev_outbox: Mutex<VecDeque<(String, String)>>,
}

/// How long a sign-in waits for its second step.
pub const SECOND_FACTOR_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// How long a master password reset may take, from the emailed code to the new password.
pub const RECOVERY_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a sign-in waits for the identity provider and the code it ends with.
pub const SSO_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// How many emails the dev-mode outbox keeps.
const DEV_OUTBOX_LEN: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("data directory: {0}")]
    Secrets(#[from] std::io::Error),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Mail(#[from] MailConfigError),
    #[error("attachment storage: {0}")]
    Storage(#[from] StorageError),
    #[error("OCTAPASS_WEB_DIR: {0} has no index.html")]
    WebDir(String),
    #[error("OCTAPASS_HIBP_API_URL: {0}")]
    HibpUrl(String),
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, StartupError> {
        if let Some(dir) = &config.web_dir
            && !dir.join("index.html").is_file()
        {
            return Err(StartupError::WebDir(dir.display().to_string()));
        }
        let secrets = ServerSecrets::load_or_create(&config.data_dir)?;
        let db = db::connect(&config.database_url).await?;
        let mailer = Mailer::from_config(&config)?;
        let storage = storage::open(&config.attachments.storage)?;
        let uploads_dir = config.data_dir.join("uploads");
        std::fs::create_dir_all(&uploads_dir)?;
        storage::clean_spool(&uploads_dir);
        let icons = if config.icons.enabled {
            let name_key = keyed_hash(&*secrets.hmac_key, "openpass/icon-cache-key", &[]);
            Some(Icons::new(
                config.data_dir.join("icons"),
                name_key,
                config.icons.test_network.clone(),
                config.icons.limits,
            )?)
        } else {
            None
        };
        let relay = config.relay.as_ref().map(RelayClient::new);
        let push = match &config.push {
            Some(push) => Some(Push::new(push, &db).await?),
            None => None,
        };
        if !config.can_deliver_codes() {
            tracing::warn!("OCTAPASS_SMTP_URL is not set: new accounts can't verify their email");
        }
        if config.dev_mode {
            tracing::warn!("dev mode is on: verification codes are logged and returned to clients");
        } else if config.email_to_log {
            tracing::warn!(
                "OCTAPASS_EMAIL_TO_LOG is on: email subjects, with sign-up codes, are logged"
            );
        }
        let key_log = KeyLog::new(&*secrets.hmac_key);
        let state = Self(Arc::new(Inner {
            ip_limiter: RateLimiter::new(config.rate_limits.per_ip),
            login_limiter: RateLimiter::new(config.rate_limits.login_per_email_ip),
            login_email_limiter: RateLimiter::new(config.rate_limits.login_per_email),
            signup_limiter: RateLimiter::new(config.rate_limits.signup_per_email),
            lookup_limiter: RateLimiter::new(config.rate_limits.lookup_per_account),
            key_log_label_limiter: RateLimiter::new(config.rate_limits.key_log_label_per_account),
            share_link_limiter: RateLimiter::new(config.rate_limits.share_link_per_ip),
            emergency_contact_limiter: RateLimiter::new(
                config.rate_limits.emergency_contact_per_account,
            ),
            emergency_recipient_limiter: RateLimiter::new(
                config.rate_limits.emergency_contact_per_recipient,
            ),
            two_step_limiter: RateLimiter::new(config.rate_limits.two_step_per_account),
            connect_log_limiter: RateLimiter::new(crate::config::Bucket {
                burst: 60,
                refill: std::time::Duration::from_secs(1),
            }),
            two_step_alert_limiter: RateLimiter::new(crate::config::Bucket {
                burst: 1,
                refill: std::time::Duration::from_secs(60 * 60),
            }),
            icon_limiter: RateLimiter::new(config.rate_limits.icons_per_ip),
            icons,
            relay,
            push,
            breach_client: config
                .hibp
                .as_ref()
                .map(BreachClient::new)
                .transpose()
                .map_err(|error| StartupError::HibpUrl(error.to_string()))?,
            breach_email_limiter: RateLimiter::new(config.rate_limits.breach_email_per_account),
            pending_logins: PendingLogins::default(),
            pending_reauths: PendingLogins::default(),
            pending_second_factors: PendingLogins::with_ttl(SECOND_FACTOR_TTL),
            pending_recoveries: PendingLogins::with_ttl(RECOVERY_TTL),
            pending_sso: PendingLogins::with_ttl(SSO_TTL),
            pending_sso_browsers: PendingLogins::with_ttl(SSO_TTL),
            oidc: Oidc::new(&config),
            pending_service_challenges: PendingLogins::default_ttl(),
            events: Events::default(),
            clock: Clock::default(),
            key_log,
            dev_outbox: Mutex::default(),
            storage,
            uploads_dir,
            config,
            db,
            secrets,
            mailer,
        }));
        // A server turned on for push registers with the relay once, in the background.
        crate::push::register_soon(&state);
        Ok(state)
    }

    /// Sends over SMTP when configured. Dev mode and `OCTAPASS_EMAIL_TO_LOG` also log the
    /// email's subject, which is how verification codes reach a developer or an operator without
    /// a mail server.
    pub fn send_email(&self, to: &str, email: Email) {
        if self.config.email_to_log && !self.config.dev_mode {
            let (subject, _) = email.render();
            tracing::info!(to, subject, "email");
        }
        if self.config.dev_mode {
            let (subject, _) = email.render();
            tracing::info!(to, subject, "dev mode email");
            let mut outbox = self.dev_outbox.lock().expect("outbox lock poisoned");
            if outbox.len() == DEV_OUTBOX_LEN {
                outbox.pop_front();
            }
            outbox.push_back((to.to_owned(), subject));
        }
        if let Some(mailer) = &self.mailer {
            mailer.send(to, email);
        }
    }

    /// What a reset's daily code counters are keyed by: kept apart from
    /// sign-up's, in the same table.
    pub fn recovery_counter_key(&self, email: &str) -> String {
        base64url(keyed_hash(
            &*self.secrets.hmac_key,
            "openpass/recovery-counter",
            email.as_bytes(),
        ))
    }

    /// What the daily sign-up counters are keyed by: an HMAC, so the table
    /// holds no email addresses.
    pub fn signup_counter_key(&self, email: &str) -> String {
        base64url(keyed_hash(
            &*self.secrets.hmac_key,
            "openpass/signup-counter",
            email.as_bytes(),
        ))
    }

    /// Tells every account that can see the vault about its new revision.
    /// The write already committed, so a failure here is only logged.
    pub async fn vault_changed(&self, vault_id: &str, revision: u64) {
        match db::items::members(&self.db, vault_id).await {
            Ok(accounts) => {
                for account_id in accounts {
                    let event = Event::VaultChanged {
                        vault_id: vault_id.to_owned(),
                        revision,
                    };
                    self.events.send(&account_id, event);
                    self.wake(&account_id, PushKind::Sync);
                }
            }
            Err(error) => tracing::error!(%error, "couldn't notify vault members"),
        }
    }

    /// Dev mode: the emails sent so far (recipient, subject), oldest first.
    pub fn dev_outbox(&self) -> Vec<(String, String)> {
        let outbox = self.dev_outbox.lock().expect("outbox lock poisoned");
        outbox.iter().cloned().collect()
    }

    /// Tells the vault's members, and `also` (accounts that just lost
    /// access), that its membership or key changed.
    pub async fn membership_changed(&self, vault_id: &str, also: &[String]) {
        match db::items::members(&self.db, vault_id).await {
            Ok(mut accounts) => {
                accounts.extend_from_slice(also);
                for account_id in accounts {
                    let event = Event::MembershipChanged {
                        vault_id: vault_id.to_owned(),
                    };
                    self.events.send(&account_id, event);
                    self.wake(&account_id, PushKind::Sync);
                }
            }
            Err(error) => tracing::error!(%error, "couldn't notify vault members"),
        }
    }

    /// Wakes the account's phones with a push that says only `kind`, when this server has a push
    /// relay. Nothing about what changed goes with it.
    pub fn wake(&self, account_id: &str, kind: PushKind) {
        crate::push::wake(self, account_id, kind);
    }

    /// Signs a device out and closes its live connections. Returns `false`
    /// if the account has no such signed-in device.
    pub async fn revoke_device(
        &self,
        account_id: &str,
        device_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let revoked =
            db::sessions::revoke_device(&self.db, account_id, device_id, db::now()).await?;
        if revoked {
            self.session_revoked(account_id, device_id);
            // A signed-out device is never woken again.
            if self.push.is_some()
                && let Err(error) = db::push::delete_device_token(&self.db, device_id).await
            {
                tracing::error!(%error, "couldn't forget a signed-out device's push token");
            }
        }
        Ok(revoked)
    }

    pub fn session_revoked(&self, account_id: &str, device_id: &str) {
        let event = Event::SessionRevoked {
            device_id: device_id.to_owned(),
        };
        self.events.send(account_id, event);
    }

    /// Housekeeping that bounds memory and enforces retention periods.
    pub async fn run_maintenance(&self) -> Result<(), sqlx::Error> {
        self.ip_limiter.prune();
        self.connect_log_limiter.prune();
        self.pending_service_challenges.prune();
        self.login_limiter.prune();
        self.login_email_limiter.prune();
        self.signup_limiter.prune();
        self.lookup_limiter.prune();
        self.key_log_label_limiter.prune();
        self.share_link_limiter.prune();
        self.emergency_contact_limiter.prune();
        self.emergency_recipient_limiter.prune();
        self.two_step_limiter.prune();
        self.two_step_alert_limiter.prune();
        self.icon_limiter.prune();
        if let Some(icons) = &self.icons {
            icons.purge(self.clock.now());
        }
        self.pending_logins.prune();
        self.pending_reauths.prune();
        self.pending_second_factors.prune();
        self.pending_recoveries.prune();
        self.pending_sso.prune();
        self.pending_sso_browsers.prune();
        self.events.prune();
        let now = db::now();
        for (vault_id, revision) in db::items::purge(&self.db, now).await? {
            self.vault_changed(&vault_id, revision).await;
        }
        db::sessions::purge_expired(&self.db, now).await?;
        db::service_accounts::purge_expired_sessions(&self.db, now).await?;
        db::sessions::purge_signed_out_devices(&self.db).await?;
        db::sessions::purge_expired_reauth_tokens(&self.db, now).await?;
        db::two_step::purge_expired_setups(&self.db, now).await?;
        db::two_step::purge_expired_trust(&self.db, now).await?;
        db::deletion::purge_expired_tokens(&self.db, now).await?;
        db::accounts::purge_old_counters(&self.db, &db::utc_day(now)).await?;
        db::accounts::purge_expired_pending(&self.db, now).await?;
        let now = self.clock.now();
        db::share_links::purge_expired(&self.db, now).await?;
        db::audit::purge_old(&self.db, now).await?;
        db::orgs::purge(&self.db, now).await?;
        emergency::release_due(self, now).await?;
        emergency::send_reminders(self, now).await?;
        storage::clean_spool(&self.uploads_dir);
        crate::relay::drain(self).await;
        crate::push::register_soon(self);
        storage::drain(self).await
    }
}

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}
