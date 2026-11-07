//! Website icons (plan 04, "website icons"), as the web vault's `SiteIconLoader` does them in
//! `packages/vault-client/src/siteIcons.ts`: fetched through the user's own Octa Pass server,
//! which gets them from the sites themselves, and kept on the device so a long list isn't
//! fetched again. Nothing here runs while the "Show website icons" setting is off.
//!
//! The server learns the registrable domain only (`bank.com`, not `login.bank.com`), and the
//! request carries no token or cookie. Cache files are named by a SHA-256 hash, so the folder
//! isn't a list of the user's sites; it's cleared when icons are turned off and on sign-out.

use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use ureq::tls::{RootCerts, TlsConfig};

use crate::api::secure_origin;
use crate::list::{clean_host, hostname_of};

/// How long the device keeps an icon, and a miss. The server keeps them as long.
const ICON_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MISS_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Requests in flight at once, so a long list doesn't flood the server.
const CONCURRENCY: usize = 6;
const ICONS_OFF: &str = "https://octap.app/problems/icons-off";
/// The server re-encodes icons as PNGs of at most 128 px; anything bigger isn't one.
const MAX_ICON_BYTES: u64 = 512 * 1024;

// A stand-in for the Public Suffix List, as in the web vault: these common two-label suffixes
// keep `bbc.co.uk` from collapsing to `co.uk`.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au", "co.nz", "org.nz",
    "net.nz", "govt.nz", "ac.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br",
    "org.br", "gov.br", "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "co.za",
    "org.za", "com.mx", "org.mx", "com.ar", "com.co", "com.pe", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.tw", "com.tr", "com.my", "com.ph", "com.vn", "com.pk", "com.ng",
    "com.eg", "com.sa", "com.ua", "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id", "co.th",
    "in.th",
];

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The registrable domain (eTLD+1) of a hostname, approximated: `accounts.google.com` →
/// `google.com`.
pub(crate) fn registrable_domain(hostname: &str) -> String {
    let host = hostname.trim().to_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if is_ipv4(host) || host.contains(':') {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let last_two = labels[labels.len().saturating_sub(2)..].join(".");
    let take = if labels.len() > 2 && TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(take)..].join(".")
}

/// The domain an item's icon is asked for: the registrable domain of its first URL. None for IP
/// addresses, `localhost` and names without a dot.
#[uniffi::export]
pub fn icon_domain(urls: Vec<String>) -> Option<String> {
    icon_domain_of(&urls)
}

pub(crate) fn icon_domain_of(urls: &[String]) -> Option<String> {
    let host = clean_host(&hostname_of(urls.first()?)?)?;
    if !host.contains('.')
        || is_ipv4(&host)
        || host.contains(':')
        || host.contains('[')
        || host.ends_with(".localhost")
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(registrable_domain(&host))
}

/// What the server said about one domain.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IconAnswer {
    Icon(Vec<u8>),
    /// The site has no usable icon: keep the initial.
    None,
    /// The server doesn't fetch icons (`OCTAPASS_ICONS=off`): stop asking it.
    Off,
    /// Rate limited, offline or a server error: try again later.
    Retry(Option<Duration>),
}

/// Reads a server response into an answer.
pub(crate) fn icon_answer(
    status: u16,
    content_type: &str,
    retry_after: Option<&str>,
    body: &[u8],
) -> IconAnswer {
    match status {
        200 if content_type.starts_with("image/png") => IconAnswer::Icon(body.to_vec()),
        404 if content_type.contains("json") => {
            let kind = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned));
            if kind.as_deref() == Some(ICONS_OFF) {
                IconAnswer::Off
            } else {
                IconAnswer::None
            }
        }
        200 | 400 | 404 => IconAnswer::None,
        429 => IconAnswer::Retry(
            retry_after
                .and_then(|s| s.trim().parse::<u64>().ok())
                .filter(|s| *s > 0)
                .map(Duration::from_secs),
        ),
        _ => IconAnswer::Retry(None),
    }
}

fn hash_key(text: &str) -> String {
    let digest = Sha256::digest(format!("octapass/icon:{text}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// One cache entry: eight bytes of expiry (milliseconds, big-endian), then the PNG; a miss has
/// no PNG.
struct Entry {
    png: Option<Vec<u8>>,
    expires: Duration,
}

/// The device's icon cache, and the state of the servers asked this run.
pub(crate) struct SiteIcons {
    dir: Option<PathBuf>,
    agent: ureq::Agent,
    state: Mutex<IconState>,
    slots: Condvar,
}

#[derive(Default)]
struct IconState {
    running: usize,
    paused_until: Duration,
    /// Servers that answered `icons-off` this run.
    off: Vec<String>,
}

impl SiteIcons {
    /// `dir` empty keeps nothing on the device.
    pub(crate) fn new(dir: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .max_redirects(0)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        Self {
            dir: (!dir.is_empty()).then(|| PathBuf::from(dir)),
            agent,
            state: Mutex::default(),
            slots: Condvar::new(),
        }
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join(key))
    }

    fn read(&self, key: &str) -> Option<Entry> {
        let bytes = std::fs::read(self.path(key)?).ok()?;
        let (head, png) = bytes.split_at_checked(8)?;
        let expires = Duration::from_millis(u64::from_be_bytes(head.try_into().ok()?));
        Some(Entry {
            png: (!png.is_empty()).then(|| png.to_vec()),
            expires,
        })
    }

    fn write(&self, key: &str, png: Option<&[u8]>, ttl: Duration) {
        let Some(path) = self.path(key) else { return };
        let expires = (now() + ttl).as_millis() as u64;
        let mut bytes = expires.to_be_bytes().to_vec();
        bytes.extend_from_slice(png.unwrap_or_default());
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // A cache: a failed write only means asking again later.
        let _ = std::fs::write(path, bytes);
    }

    /// Forgets every icon: icons were turned off, or the account signed out.
    pub(crate) fn clear(&self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.off.clear();
        state.paused_until = Duration::ZERO;
    }

    /// The PNG for a domain from `server_url`, or none: no icon, the server doesn't do icons, or
    /// try again later. Blocks: run it on a vault thread.
    pub(crate) fn load(&self, server_url: &str, domain: &str) -> Option<Vec<u8>> {
        let origin = secure_origin(server_url)?;
        let key = hash_key(&format!("{origin}|{domain}"));
        let off_key = hash_key(&format!("{origin}|off"));
        if let Some(entry) = self.read(&key)
            && entry.expires > now()
        {
            return entry.png;
        }
        if self.is_off(&origin) {
            return None;
        }
        if self.read(&off_key).is_some_and(|e| e.expires > now()) {
            self.set_off(&origin);
            return None;
        }
        match self.limited(&origin, || self.fetch(&origin, domain)) {
            IconAnswer::Icon(png) => {
                self.write(&key, Some(&png), ICON_TTL);
                Some(png)
            }
            IconAnswer::None => {
                self.write(&key, None, MISS_TTL);
                None
            }
            IconAnswer::Off => {
                self.set_off(&origin);
                self.write(&off_key, None, MISS_TTL);
                None
            }
            // Not remembered: the next screen that shows the row asks again.
            IconAnswer::Retry(after) => {
                if let Some(after) = after {
                    let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                    state.paused_until = state.paused_until.max(now() + after);
                }
                None
            }
        }
    }

    fn is_off(&self, origin: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.off.iter().any(|o| o == origin)
    }

    fn set_off(&self, origin: &str) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.off.iter().any(|o| o == origin) {
            state.off.push(origin.to_owned());
        }
    }

    fn limited(&self, origin: &str, task: impl FnOnce() -> IconAnswer) -> IconAnswer {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            while state.running >= CONCURRENCY {
                state = self.slots.wait(state).unwrap_or_else(|p| p.into_inner());
            }
            if state.off.iter().any(|o| o == origin) {
                return IconAnswer::Off;
            }
            // Rate limited a moment ago: skip rather than wait, so scrolling stays quick.
            if now() < state.paused_until {
                return IconAnswer::Retry(None);
            }
            state.running += 1;
        }
        let answer = task();
        self.state.lock().unwrap_or_else(|p| p.into_inner()).running -= 1;
        self.slots.notify_one();
        answer
    }

    /// `GET {server}/v1/icons/{domain}`: no token, no cookie, nothing else sent.
    fn fetch(&self, origin: &str, domain: &str) -> IconAnswer {
        let url = format!("{origin}/v1/icons/{}", url_segment(domain));
        let response = match self.agent.get(&url).header("accept", "image/png").call() {
            Ok(response) => response,
            Err(_) => return IconAnswer::Retry(None),
        };
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let content_type = header("content-type").unwrap_or_default();
        let retry_after = header("retry-after");
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_ICON_BYTES)
            .read_to_vec();
        match body {
            Ok(body) => icon_answer(status, &content_type, retry_after.as_deref(), &body),
            Err(_) => IconAnswer::Retry(None),
        }
    }
}

fn url_segment(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_domains_are_registrable_domains() {
        let domain = |url: &str| icon_domain(vec![url.to_owned()]);
        assert_eq!(
            domain("https://accounts.google.com/x"),
            Some("google.com".into())
        );
        assert_eq!(domain("www.bbc.co.uk"), Some("bbc.co.uk".into()));
        assert_eq!(domain("github.com"), Some("github.com".into()));
        assert_eq!(domain("http://192.168.1.1"), None);
        assert_eq!(domain("http://localhost:8080"), None);
        assert_eq!(domain("nas"), None);
        assert_eq!(icon_domain(Vec::new()), None);
    }

    #[test]
    fn answers_follow_the_server() {
        assert_eq!(
            icon_answer(200, "image/png", None, b"png"),
            IconAnswer::Icon(b"png".to_vec())
        );
        let off = format!(r#"{{"type":"{ICONS_OFF}"}}"#);
        assert_eq!(
            icon_answer(404, "application/problem+json", None, off.as_bytes()),
            IconAnswer::Off
        );
        assert_eq!(icon_answer(404, "text/plain", None, b""), IconAnswer::None);
        assert_eq!(
            icon_answer(429, "", Some("30"), b""),
            IconAnswer::Retry(Some(Duration::from_secs(30)))
        );
        assert_eq!(icon_answer(500, "", None, b""), IconAnswer::Retry(None));
    }

    #[test]
    fn the_cache_keeps_icons_and_misses_under_hashed_names() {
        let dir = tempfile::tempdir().unwrap();
        let icons = SiteIcons::new(dir.path().to_str().unwrap());
        icons.write(&hash_key("a"), Some(b"png"), ICON_TTL);
        icons.write(&hash_key("b"), None, MISS_TTL);
        assert_eq!(
            icons.read(&hash_key("a")).unwrap().png,
            Some(b"png".to_vec())
        );
        assert_eq!(icons.read(&hash_key("b")).unwrap().png, None);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| n.len() == 64));
        icons.clear();
        assert!(!dir.path().exists());
        // An insecure server is never asked.
        assert_eq!(icons.load("http://example.com", "example.com"), None);
    }
}
