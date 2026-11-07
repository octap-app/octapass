//! Which login belongs to the focused window.
//!
//! - An item's **window rules** (`details.autoType.windowTitles`) are the user's own choice and
//!   always count. A rule with `*` or `?` must match the whole window title (or the app's name);
//!   one without is enough when the title or the app's name contains it. Case doesn't matter.
//! - In a **browser**, only the page's address counts, matched to the item's URLs like the browser
//!   extension does (registrable domain by default, plan 05). Page titles are written by the page,
//!   so a phishing page could copy one. When the address can't be read (only macOS reads it, through
//!   Accessibility), a browser window matches window rules only.
//! - In **other apps**, the window title or the app's name must contain the item's title, or the
//!   name of its website's domain (`slack` for `https://app.slack.com`), at least 3 characters.

use std::collections::HashMap;

use octapass_core::matching::{Candidate, MatchMode, MatchOptions, Site, match_items};
use serde::{Deserialize, Serialize};

/// The window keystrokes would go to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FocusedWindow {
    pub pid: u32,
    /// The app's name as the system shows it ("Safari", "Slack").
    pub app_name: String,
    /// macOS: the bundle identifier; Windows and Linux: the executable's file name without its
    /// extension. Lower case.
    pub app_id: String,
    pub title: String,
    /// The page's address, for browsers where the platform can read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The platform's handle for the window (`HWND`, X11 window id), to bring it back to the
    /// front. 0 when the platform activates by process.
    #[serde(skip)]
    pub handle: u64,
}

impl FocusedWindow {
    /// How the UI names the window: "GitHub — Safari".
    pub fn describe(&self) -> String {
        match (self.title.trim(), self.app_name.trim()) {
            ("", app) => app.to_owned(),
            (title, "") => title.to_owned(),
            (title, app) if title.contains(app) => title.to_owned(),
            (title, app) => format!("{title} — {app}"),
        }
    }

    pub fn is_browser(&self) -> bool {
        is_browser(&self.app_id)
    }

    /// The same window, for a check that focus didn't move while typing.
    pub fn same_window(&self, other: &FocusedWindow) -> bool {
        self.pid == other.pid
            && (self.handle == 0 || other.handle == 0 || self.handle == other.handle)
    }
}

/// What an item says about where it may be typed. No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRules {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub url_match: HashMap<String, MatchMode>,
    #[serde(default)]
    pub window_titles: Vec<String>,
    /// The user's equivalent domains.
    #[serde(default)]
    pub equivalent_domains: Vec<Vec<String>>,
    /// Built-in equivalent domains turned off.
    #[serde(default)]
    pub excluded_defaults: Vec<String>,
}

/// Why the window matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "by", rename_all = "camelCase")]
pub enum Reason {
    /// One of the item's window rules.
    Rule { rule: String },
    /// The browser's page address matched one of the item's URLs.
    Site { url: String },
    /// The window title or app name names the item (other apps only).
    Name { name: String },
}

const MIN_NAME_LEN: usize = 3;

impl ItemRules {
    pub fn matches(&self, window: &FocusedWindow) -> Option<Reason> {
        let rule = self
            .window_titles
            .iter()
            .map(|rule| rule.trim())
            .find(|rule| {
                !rule.is_empty()
                    && (rule_matches(rule, &window.title) || rule_matches(rule, &window.app_name))
            });
        if let Some(rule) = rule {
            return Some(Reason::Rule {
                rule: rule.to_owned(),
            });
        }
        if window.is_browser() {
            return self.site_matches(window.url.as_deref()?);
        }
        self.names()
            .into_iter()
            .find(|name| contains(&window.title, name) || contains(&window.app_name, name))
            .map(|name| Reason::Name { name })
    }

    fn site_matches(&self, page: &str) -> Option<Reason> {
        let candidate = Candidate {
            id: self.id.clone(),
            urls: self.urls.clone(),
            url_match: self.url_match.clone(),
        };
        let options = MatchOptions {
            equivalent_domains: self.equivalent_domains.clone(),
            excluded_defaults: self.excluded_defaults.clone(),
            ..MatchOptions::default()
        };
        let found = match_items(page, &[candidate], &options).ok()?;
        found
            .into_iter()
            .next()
            .map(|found| Reason::Site { url: found.url })
    }

    /// The item's title and its websites' domain names, long enough to mean something.
    fn names(&self) -> Vec<String> {
        let domains = self.urls.iter().filter_map(|url| {
            let domain = Site::parse(url).ok()?.domain?;
            domain.split('.').next().map(str::to_owned)
        });
        std::iter::once(self.title.trim().to_owned())
            .chain(domains)
            .filter(|name| name.chars().count() >= MIN_NAME_LEN)
            .collect()
    }
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn rule_matches(rule: &str, text: &str) -> bool {
    if rule.contains(['*', '?']) {
        let rule: Vec<char> = rule.to_lowercase().chars().collect();
        let text: Vec<char> = text.to_lowercase().chars().collect();
        glob(&rule, &text)
    } else {
        contains(text, rule)
    }
}

/// `*` is any run of characters, `?` one character.
fn glob(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// macOS bundle identifiers, and executable names elsewhere, of browsers. In these only the page's
/// address can match a login.
const BROWSERS: &[&str] = &[
    "com.apple.safari",
    "com.apple.safaritechnologypreview",
    "com.google.chrome",
    "org.chromium.chromium",
    "org.mozilla.firefox",
    "org.mozilla.firefoxdeveloperedition",
    "org.mozilla.nightly",
    "com.microsoft.edgemac",
    "com.brave.browser",
    "company.thebrowser.browser",
    "com.vivaldi.vivaldi",
    "com.operasoftware.opera",
    "app.zen-browser.zen",
    "io.gitlab.librewolf-community",
    "org.torproject.torbrowser",
    "chrome",
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-beta",
    "chromium",
    "chromium-browser",
    "msedge",
    "microsoft-edge",
    "microsoft-edge-stable",
    "firefox",
    "firefox-esr",
    "firefox-bin",
    "brave",
    "brave-browser",
    "vivaldi",
    "vivaldi-bin",
    "opera",
    "arc",
    "librewolf",
    "zen",
    "epiphany",
    "falkon",
    "iexplore",
];

pub fn is_browser(app_id: &str) -> bool {
    let app_id = app_id.to_ascii_lowercase();
    // Channels: `com.google.Chrome.beta`, `com.microsoft.edgemac.Dev`, `com.brave.Browser.nightly`.
    BROWSERS.iter().any(|browser| {
        app_id == *browser || (browser.contains('.') && app_id.starts_with(&format!("{browser}.")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(app_id: &str, app_name: &str, title: &str, url: Option<&str>) -> FocusedWindow {
        FocusedWindow {
            pid: 42,
            app_name: app_name.into(),
            app_id: app_id.into(),
            title: title.into(),
            url: url.map(str::to_owned),
            handle: 0,
        }
    }

    fn item(title: &str, urls: &[&str], rules: &[&str]) -> ItemRules {
        ItemRules {
            id: "i".into(),
            title: title.into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            url_match: HashMap::new(),
            window_titles: rules.iter().map(|r| r.to_string()).collect(),
            ..ItemRules::default()
        }
    }

    #[test]
    fn browsers_match_by_the_page_address_only() {
        let github = item("GitHub", &["https://github.com/login"], &[]);
        let safari =
            |title: &str, url: Option<&str>| window("com.apple.safari", "Safari", title, url);
        assert_eq!(
            github.matches(&safari(
                "Sign in to GitHub",
                Some("https://github.com/session")
            )),
            Some(Reason::Site {
                url: "https://github.com/login".into()
            })
        );
        assert!(
            github
                .matches(&safari("x", Some("https://gist.github.com/")))
                .is_some()
        );
        // Another part of the site isn't this login's (plan 05, History 2026-11-05).
        let gist = item("Gist", &["https://gist.github.com"], &[]);
        assert_eq!(
            gist.matches(&safari("x", Some("https://docs.github.com/"))),
            None
        );
        assert!(
            gist.matches(&safari("x", Some("https://github.com/")))
                .is_some()
        );
        // A phishing page can copy the title, and a look-alike domain doesn't match.
        assert_eq!(
            github.matches(&safari(
                "Sign in to GitHub",
                Some("https://github.com.evil.io/")
            )),
            None
        );
        assert_eq!(
            github.matches(&safari("Sign in to GitHub · GitHub", None)),
            None
        );
        assert_eq!(
            github.matches(&window(
                "com.google.Chrome.canary",
                "Google Chrome",
                "GitHub",
                None
            )),
            None
        );
    }

    #[test]
    fn window_rules_always_count() {
        let rule = item("Router", &[], &["*192.168.1.1*"]);
        let chrome = window(
            "chrome",
            "Google Chrome",
            "Admin – 192.168.1.1 – Google Chrome",
            None,
        );
        assert_eq!(
            rule.matches(&chrome),
            Some(Reason::Rule {
                rule: "*192.168.1.1*".into()
            })
        );
        // Without wildcards a rule is a "contains" match, on the title or the app's name.
        let slack = window("com.tinyspeck.slackmacgap", "Slack", "Huddle", None);
        assert!(item("Work chat", &[], &["slack"]).matches(&slack).is_some());
        // With wildcards it must match the whole title.
        assert!(item("x", &[], &["Huddle?"]).matches(&slack).is_none());
        assert!(item("x", &[], &["H*e"]).matches(&slack).is_some());
        assert!(item("x", &[], &["  "]).matches(&slack).is_none());
    }

    #[test]
    fn other_apps_match_by_name() {
        let slack = window("com.tinyspeck.slackmacgap", "Slack", "General — Acme", None);
        assert_eq!(
            item("Acme Slack", &["https://acme.slack.com"], &[]).matches(&slack),
            Some(Reason::Name {
                name: "slack".into()
            })
        );
        assert_eq!(
            item("acme", &[], &[]).matches(&slack),
            Some(Reason::Name {
                name: "acme".into()
            })
        );
        // Names shorter than three characters would match nearly anything.
        assert_eq!(item("Ac", &["https://x.io"], &[]).matches(&slack), None);
        assert_eq!(
            item("GitHub", &["https://github.com"], &[]).matches(&slack),
            None
        );
    }

    #[test]
    fn browsers_are_recognised_by_bundle_id_or_executable() {
        for app_id in [
            "com.apple.Safari",
            "com.google.Chrome.beta",
            "org.mozilla.firefox",
            "msedge",
            "firefox-esr",
        ] {
            assert!(is_browser(app_id), "{app_id}");
        }
        for app_id in [
            "com.apple.TextEdit",
            "com.google.chromeremotedesktop",
            "slack",
            "chrome-helper",
        ] {
            assert!(!is_browser(app_id), "{app_id}");
        }
    }

    #[test]
    fn globs() {
        let g = |p: &str, t: &str| {
            glob(
                &p.chars().collect::<Vec<_>>(),
                &t.chars().collect::<Vec<_>>(),
            )
        };
        assert!(g("*", ""));
        assert!(g("a*c", "abbbc"));
        assert!(g("a?c", "abc"));
        assert!(!g("a?c", "ac"));
        assert!(g("*.example.*", "login.example.com"));
        assert!(!g("abc", "abcd"));
        assert!(g("é*", "éa"));
    }

    #[test]
    fn windows_describe_themselves() {
        assert_eq!(
            window("x", "Safari", "GitHub", None).describe(),
            "GitHub — Safari"
        );
        assert_eq!(
            window("x", "Slack", "Slack | General", None).describe(),
            "Slack | General"
        );
        assert_eq!(window("x", "TextEdit", "", None).describe(), "TextEdit");
    }
}
