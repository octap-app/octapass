//! OPAQUE login state held between `login/start` and `login/finish`,
//! two-step sign-ins waiting for their second step, and master password resets.
//!
//! It lives in memory only: it contains the server's ephemeral key-exchange
//! secret, which should never reach disk. A server restart simply makes
//! in-flight logins fail and retry.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use opaque_ke::ServerLogin;

use crate::crypto::Suite;

/// A login finishes in one round trip, so this is generous.
const LOGIN_TTL: Duration = Duration::from_secs(30);
/// Bounds memory if someone floods `login/start` from many IPs.
const MAX_PENDING: usize = 10_000;
/// One IP can't crowd out everyone else's logins.
const MAX_PENDING_PER_IP: usize = 20;

pub struct PendingLogin {
    pub state: ServerLogin<Suite>,
    /// `None` for unknown emails, which still get a full, fake OPAQUE response.
    pub account_id: Option<String>,
    /// Normalised, so a failed finish can be charged to the email's limits.
    pub email: String,
}

/// A master password reset with the recovery code, between `recover/start`
/// and `recover/finish`.
pub struct PendingRecovery {
    /// `None` for unknown emails: they get a recovery id too, but no code.
    pub account_id: Option<String>,
    /// Normalised.
    pub email: String,
    /// The keyed hash of the emailed code.
    pub code_hash: [u8; 32],
    /// Wrong codes so far.
    pub failures: u32,
    /// Set once the code was right: the account must sign it in `recover/finish`.
    pub challenge: Option<[u8; 32]>,
}

/// A sign-in that passed the password and waits for the identity provider. The client holds its
/// id; the browser never sees it.
pub struct SsoLogin {
    pub account_id: String,
    pub email: String,
    pub device_name: String,
    pub device_platform: String,
    pub trusted_device_token: Option<String>,
    /// Where the sign-in came from, to park it again from the browser's request.
    pub ip: String,
    /// Set when the provider finished: what the browser page shows.
    pub confirm_code: Option<String>,
    /// Wrong codes so far.
    pub failures: u32,
}

/// Whom a browser's trip to the identity provider is for.
pub enum SsoPurpose {
    /// The `SsoLogin` with this challenge id.
    Login(String),
    /// An owner trying the settings out, as they stood at `updated_at`.
    Test { updated_at: i64 },
}

/// One browser's way through the identity provider: first under the token in its URL, then under
/// the OIDC `state`.
pub struct SsoBrowser {
    pub purpose: SsoPurpose,
    pub org_id: String,
    pub email: String,
    /// `None` until the browser has been sent to the provider.
    pub flow: Option<(crate::sso::Flow, crate::sso::Provider)>,
}

struct Entry<T> {
    login: T,
    ip: String,
    expires: Instant,
}

pub struct PendingLogins<T = PendingLogin> {
    logins: Mutex<Logins<T>>,
    ttl: Duration,
}

struct Logins<T> {
    entries: HashMap<String, Entry<T>>,
    /// Login ids per client IP, oldest first.
    by_ip: HashMap<String, VecDeque<String>>,
}

impl Default for PendingLogins<PendingLogin> {
    fn default() -> Self {
        Self::with_ttl(LOGIN_TTL)
    }
}

impl<T> PendingLogins<T> {
    /// Held for as long as a login: both finish in one round trip.
    pub fn default_ttl() -> Self {
        Self::with_ttl(LOGIN_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            logins: Mutex::new(Logins {
                entries: HashMap::new(),
                by_ip: HashMap::new(),
            }),
            ttl,
        }
    }

    /// Stores a login. When the IP, or the server as a whole, has too many in
    /// flight, the oldest one makes room: a flood delays logins but can't
    /// refuse them.
    pub fn insert(&self, login_id: String, ip: &str, login: T) {
        let now = Instant::now();
        self.insert_at(login_id, ip, login, now, now + self.ttl);
    }

    /// Puts back a login taken with `take_until`, keeping its expiry.
    pub fn reinsert(&self, login_id: String, ip: &str, login: T, expires: Instant) {
        self.insert_at(login_id, ip, login, Instant::now(), expires);
    }

    fn insert_at(&self, login_id: String, ip: &str, login: T, now: Instant, expires: Instant) {
        let mut logins = self.logins.lock().expect("pending logins lock poisoned");
        let ip_logins = logins.by_ip.get(ip).map_or(0, VecDeque::len);
        if ip_logins >= MAX_PENDING_PER_IP {
            let oldest = logins.by_ip[ip][0].clone();
            logins.remove(&oldest);
        }
        if logins.entries.len() >= MAX_PENDING {
            logins.prune(now);
        }
        if logins.entries.len() >= MAX_PENDING {
            let oldest = logins
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(id, _)| id.clone())
                .expect("the map is full");
            logins.remove(&oldest);
        }
        logins
            .by_ip
            .entry(ip.to_owned())
            .or_default()
            .push_back(login_id.clone());
        let entry = Entry {
            login,
            ip: ip.to_owned(),
            expires,
        };
        logins.entries.insert(login_id, entry);
    }

    /// Removes the login, so each one can be finished at most once.
    pub fn take(&self, login_id: &str) -> Option<T> {
        self.take_until(login_id).map(|(login, _)| login)
    }

    /// Like `take`, with the login's expiry, for putting it back after a failed try.
    pub fn take_until(&self, login_id: &str) -> Option<(T, Instant)> {
        let mut logins = self.logins.lock().expect("pending logins lock poisoned");
        logins
            .remove(login_id)
            .filter(|entry| entry.expires > Instant::now())
            .map(|entry| (entry.login, entry.expires))
    }

    pub fn prune(&self) {
        let mut logins = self.logins.lock().expect("pending logins lock poisoned");
        logins.prune(Instant::now());
    }
}

impl<T> Logins<T> {
    fn remove(&mut self, login_id: &str) -> Option<Entry<T>> {
        let entry = self.entries.remove(login_id)?;
        if let Some(ids) = self.by_ip.get_mut(&entry.ip) {
            ids.retain(|id| id != login_id);
            if ids.is_empty() {
                self.by_ip.remove(&entry.ip);
            }
        }
        Some(entry)
    }

    fn prune(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{ClientLogin, ServerLoginParameters, ServerSetup};
    use rand_core::OsRng;

    fn login() -> PendingLogin {
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let request = ClientLogin::<Suite>::start(&mut OsRng, b"password")
            .unwrap()
            .message;
        let started = ServerLogin::start(
            &mut OsRng,
            &setup,
            None,
            request,
            b"a@example.com",
            ServerLoginParameters::default(),
        )
        .unwrap();
        PendingLogin {
            state: started.state,
            account_id: None,
            email: "a@example.com".into(),
        }
    }

    fn len(logins: &PendingLogins) -> usize {
        logins.logins.lock().unwrap().entries.len()
    }

    #[test]
    fn one_ip_only_evicts_its_own_oldest_logins() {
        let logins: PendingLogins = PendingLogins::default();
        let now = Instant::now();
        let expires = now + LOGIN_TTL;
        logins.insert_at("other".into(), "192.0.2.2", login(), now, expires);
        for i in 0..MAX_PENDING_PER_IP + 5 {
            logins.insert_at(format!("flood-{i}"), "192.0.2.1", login(), now, expires);
        }
        assert_eq!(len(&logins), MAX_PENDING_PER_IP + 1);
        assert!(logins.take("flood-0").is_none(), "evicted");
        assert!(
            logins
                .take(&format!("flood-{}", MAX_PENDING_PER_IP + 4))
                .is_some()
        );
        assert!(logins.take("other").is_some(), "other IPs are untouched");
        assert!(logins.take("other").is_none(), "single use");
    }

    #[test]
    fn a_full_server_evicts_the_oldest_login() {
        let logins: PendingLogins = PendingLogins::default();
        let start = Instant::now();
        let template = login();
        {
            let mut inner = logins.logins.lock().unwrap();
            for i in 0..MAX_PENDING {
                let entry = Entry {
                    login: PendingLogin {
                        state: template.state.clone(),
                        account_id: None,
                        email: String::new(),
                    },
                    ip: format!("ip-{i}"),
                    expires: start + LOGIN_TTL + Duration::from_millis(i as u64),
                };
                inner
                    .by_ip
                    .insert(format!("ip-{i}"), VecDeque::from([format!("l-{i}")]));
                inner.entries.insert(format!("l-{i}"), entry);
            }
        }
        logins.insert_at("new".into(), "192.0.2.9", login(), start, start + LOGIN_TTL);
        assert_eq!(len(&logins), MAX_PENDING);
        assert!(!logins.logins.lock().unwrap().entries.contains_key("l-0"));
        assert!(logins.take("new").is_some());

        // Expired logins can't be finished, and pruning forgets them entirely.
        logins.insert_at(
            "late".into(),
            "192.0.2.9",
            login(),
            start - LOGIN_TTL,
            start,
        );
        logins.prune();
        assert!(
            !logins
                .logins
                .lock()
                .unwrap()
                .by_ip
                .contains_key("192.0.2.9")
        );
        assert!(logins.take("late").is_none());
    }
}
