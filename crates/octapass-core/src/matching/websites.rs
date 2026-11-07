//! When two saved websites on one item are the same website, so an item lists each site once
//! (plan 07, History 2026-11-05). Every app uses this one rule: the importers when they merge an
//! item, the editors when they save one, the AutoFill save on the phones, and the item view. The
//! web vault has the same rule in TypeScript (`sameWebsite` in `packages/vault-client`), tested
//! with the same cases.
//!
//! Two URLs are the same website when autofill would offer the login on the same pages for
//! them. A URL is read the way the one kept before it matches (its `urlMatch` mode, by default
//! `subdomains`):
//!
//! - **`subdomains`** (the default) and **`baseDomain`**: the same host, ignoring case, a leading
//!   `www.`, the scheme, the port, the path, the query and the fragment. Hosts, not registrable domains:
//!   `a.example.com` and `b.example.com` fill on the same pages, but people keep both on purpose
//!   and the item shows them as two sites.
//! - **`host`**: the same host and port (the scheme's default port when none is written), as the
//!   matcher compares them. `www.` counts here.
//! - **`startsWith`** and **`never`**: the same address once written the standard way (scheme and
//!   host in lower case, the default port dropped, `/` for an empty path). A trailing slash on a
//!   longer path counts: `/admin` also starts `/administrator`.
//! - **`regex`**, on either URL: the same text. An expression is never read as an address.
//!
//! Something that isn't a web address (an app link, a typo) is the same only as the same text.
//! A mode this version doesn't know compares as text. The first URL of a group stays, with its
//! mode; the others go, with theirs.

use std::collections::HashMap;

use serde_json::{Map, Value};

use super::{MatchMode, Site};
use crate::item::ItemOverview;

/// Whether `other` is the website `kept` already is (see the module docs). `kept` is the one
/// that stays; its mode decides how the two are compared.
pub fn same_website(kept: &str, kept_mode: MatchMode, other: &str, other_mode: MatchMode) -> bool {
    let (kept, other) = (kept.trim(), other.trim());
    if kept == other {
        return true;
    }
    if kept_mode == MatchMode::Regex || other_mode == MatchMode::Regex {
        return false;
    }
    let (Ok(a), Ok(b)) = (Site::parse(kept), Site::parse(other)) else {
        return false;
    };
    match kept_mode {
        MatchMode::Subdomains | MatchMode::BaseDomain => {
            without_www(&a.host) == without_www(&b.host)
        }
        MatchMode::Host => a.host == b.host && a.port() == b.port(),
        MatchMode::StartsWith | MatchMode::Never => a.url.as_str() == b.url.as_str(),
        MatchMode::Regex => false,
    }
}

fn without_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// `urls` with each website once, in their order: the first of each group stays. `modes` is the
/// item's `urlMatch`, keyed by the URL as written; a URL without one is `subdomains`.
pub fn unique_websites(urls: &[String], modes: &HashMap<String, MatchMode>) -> Vec<String> {
    let mode = |url: &String| modes.get(url).copied().unwrap_or_default();
    let mut kept: Vec<String> = Vec::new();
    for url in urls {
        if !kept
            .iter()
            .any(|k| same_website(k, mode(k), url, mode(url)))
        {
            kept.push(url.clone());
        }
    }
    kept
}

/// Whether `url` (with no mode of its own) is a website `urls` already has.
pub fn has_website(urls: &[String], modes: &HashMap<String, MatchMode>, url: &str) -> bool {
    urls.iter().any(|k| {
        same_website(
            k,
            modes.get(k).copied().unwrap_or_default(),
            url,
            MatchMode::BaseDomain,
        )
    })
}

/// The modes in an overview's `urlMatch` object. A mode this version doesn't know compares as
/// text, as a regular expression does.
pub fn modes_of(url_match: Option<&Value>) -> HashMap<String, MatchMode> {
    url_match
        .and_then(Value::as_object)
        .map(|modes| {
            modes
                .iter()
                .map(|(url, mode)| {
                    let mode = serde_json::from_value(mode.clone()).unwrap_or(MatchMode::Regex);
                    (url.clone(), mode)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Drops repeated websites from an overview given as JSON (`urls`, and the modes of the URLs
/// that went from `urlMatch`). An empty `urlMatch` goes.
pub fn dedupe_overview_json(overview: &mut Map<String, Value>) {
    let Some(Value::Array(list)) = overview.get("urls") else {
        return;
    };
    let urls: Vec<String> = list
        .iter()
        .filter_map(|u| u.as_str().map(str::to_owned))
        .collect();
    if urls.len() != list.len() {
        return;
    }
    let modes = modes_of(overview.get("urlMatch"));
    let unique = unique_websites(&urls, &modes);
    if unique.len() == urls.len() {
        return;
    }
    overview.insert(
        "urls".into(),
        Value::Array(unique.iter().cloned().map(Value::String).collect()),
    );
    if let Some(Value::Object(modes)) = overview.get_mut("urlMatch") {
        modes.retain(|url, _| unique.contains(url));
        if modes.is_empty() {
            overview.remove("urlMatch");
        }
    }
}

/// [`dedupe_overview_json`] on an item's overview.
pub fn dedupe_overview(overview: &mut ItemOverview) {
    let Some(urls) = &overview.urls else {
        return;
    };
    let unique = unique_websites(urls, &modes_of(overview.extra.get("urlMatch")));
    if unique.len() == urls.len() {
        return;
    }
    if let Some(Value::Object(modes)) = overview.extra.get_mut("urlMatch") {
        modes.retain(|url, _| unique.contains(url));
        if modes.is_empty() {
            overview.extra.remove("urlMatch");
        }
    }
    overview.urls = Some(unique);
}

#[cfg(test)]
mod tests {
    use super::*;
    use MatchMode::*;

    /// The same table as `packages/vault-client/src/tools/url.test.ts` ("same website").
    /// `(kept, its mode, other, other's mode, same)`.
    const CASES: &[(&str, MatchMode, &str, MatchMode, bool)] = &[
        // The default: the same host, whatever else is written.
        (
            "https://saasify.example.com",
            BaseDomain,
            "https://saasify.example.com/",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com",
            BaseDomain,
            "https://saasify.example.com/login",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com",
            BaseDomain,
            "http://saasify.example.com",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com",
            BaseDomain,
            "HTTPS://Saasify.Example.COM/",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com",
            BaseDomain,
            "https://www.saasify.example.com",
            BaseDomain,
            true,
        ),
        (
            "www.saasify.example.com",
            BaseDomain,
            "saasify.example.com",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com",
            BaseDomain,
            "saasify.example.com:8443/a?b=c#d",
            BaseDomain,
            true,
        ),
        (
            "https://saasify.example.com.",
            BaseDomain,
            "https://saasify.example.com",
            BaseDomain,
            true,
        ),
        (
            "localhost:3000",
            BaseDomain,
            "http://localhost:8080/",
            BaseDomain,
            true,
        ),
        (
            "https://bücher.example",
            BaseDomain,
            "https://xn--bcher-kva.example/",
            BaseDomain,
            true,
        ),
        (
            "https://a.example.com",
            BaseDomain,
            "https://b.example.com",
            BaseDomain,
            false,
        ),
        (
            "https://a.example.com",
            BaseDomain,
            "https://example.com",
            BaseDomain,
            false,
        ),
        (
            "https://example.com",
            BaseDomain,
            "https://example.org",
            BaseDomain,
            false,
        ),
        // The kept URL's mode decides; a URL without one joins it.
        (
            "https://app.example.com",
            Host,
            "https://app.example.com/login",
            BaseDomain,
            true,
        ),
        (
            "https://app.example.com",
            Host,
            "https://APP.example.com:443",
            BaseDomain,
            true,
        ),
        (
            "https://app.example.com:8443",
            Host,
            "http://app.example.com:8443",
            BaseDomain,
            true,
        ),
        (
            "https://app.example.com",
            Host,
            "http://app.example.com",
            BaseDomain,
            false,
        ),
        (
            "https://app.example.com",
            Host,
            "https://www.app.example.com",
            BaseDomain,
            false,
        ),
        (
            "https://app.example.com",
            Host,
            "https://app.example.com:8443",
            BaseDomain,
            false,
        ),
        ("localhost:3000", Host, "localhost:8080", BaseDomain, false),
        (
            "https://example.com/admin",
            StartsWith,
            "HTTPS://Example.com:443/admin",
            BaseDomain,
            true,
        ),
        (
            "https://example.com",
            StartsWith,
            "https://example.com/",
            BaseDomain,
            true,
        ),
        (
            "https://example.com/admin",
            StartsWith,
            "https://example.com/admin/",
            BaseDomain,
            false,
        ),
        (
            "https://example.com/admin",
            StartsWith,
            "https://example.com",
            BaseDomain,
            false,
        ),
        (
            "https://example.com/admin",
            StartsWith,
            "http://example.com/admin",
            BaseDomain,
            false,
        ),
        (
            "https://example.com",
            Never,
            "https://example.com/",
            BaseDomain,
            true,
        ),
        (
            "https://example.com",
            Never,
            "https://example.com/login",
            BaseDomain,
            false,
        ),
        // Regular expressions are text, on either side.
        (
            r"^https://example\.com/",
            Regex,
            r" ^https://example\.com/ ",
            BaseDomain,
            true,
        ),
        (
            r"^https://example\.com/",
            Regex,
            "https://example.com/",
            BaseDomain,
            false,
        ),
        (
            "https://example.com",
            BaseDomain,
            "example.com",
            Regex,
            false,
        ),
        // Not web addresses: the same text only.
        (
            "androidapp://com.example.app",
            BaseDomain,
            "androidapp://com.example.app",
            BaseDomain,
            true,
        ),
        (
            "androidapp://com.example.app",
            BaseDomain,
            "androidapp://com.example.other",
            BaseDomain,
            false,
        ),
        ("not a url", BaseDomain, "not a url", BaseDomain, true),
        (
            "mailto:a@example.com",
            BaseDomain,
            "https://example.com",
            BaseDomain,
            false,
        ),
    ];

    #[test]
    fn same_website_follows_the_rule() {
        for &(kept, kept_mode, other, other_mode, same) in CASES {
            assert_eq!(
                same_website(kept, kept_mode, other, other_mode),
                same,
                "{kept} ({kept_mode:?}) vs {other} ({other_mode:?})"
            );
        }
    }

    fn strings(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|u| (*u).to_owned()).collect()
    }

    #[test]
    fn the_first_of_each_website_stays() {
        let urls = strings(&[
            "https://saasify.example.com",
            "https://other.example",
            "https://saasify.example.com/",
            "http://saasify.example.com/login",
            "https://other.example/x",
        ]);
        assert_eq!(
            unique_websites(&urls, &HashMap::new()),
            strings(&["https://saasify.example.com", "https://other.example"])
        );
    }

    #[test]
    fn a_kept_mode_stays_and_dropped_ones_go() {
        let mut overview = serde_json::json!({
            "title": "t", "type": "login",
            "urls": ["https://app.example.com", "https://app.example.com/login", "https://APP.example.com", "^x$"],
            "urlMatch": { "https://app.example.com": "host", "https://APP.example.com": "never", "^x$": "regex" }
        });
        dedupe_overview_json(overview.as_object_mut().unwrap());
        assert_eq!(
            overview["urls"],
            serde_json::json!(["https://app.example.com", "^x$"])
        );
        assert_eq!(
            overview["urlMatch"],
            serde_json::json!({ "https://app.example.com": "host", "^x$": "regex" })
        );

        let mut item: ItemOverview = serde_json::from_value(serde_json::json!({
            "title": "t", "type": "login",
            "urls": ["https://a.example", "https://a.example/"],
            "urlMatch": { "https://a.example/": "never" }
        }))
        .unwrap();
        dedupe_overview(&mut item);
        assert_eq!(item.urls, Some(strings(&["https://a.example"])));
        assert!(!item.extra.contains_key("urlMatch"));
    }

    #[test]
    fn a_new_address_is_compared_with_the_saved_ones() {
        let urls = strings(&["https://app.example.com"]);
        let host: HashMap<String, MatchMode> = [(urls[0].clone(), Host)].into();
        assert!(has_website(
            &urls,
            &HashMap::new(),
            "https://www.app.example.com/"
        ));
        assert!(!has_website(&urls, &host, "https://www.app.example.com/"));
        assert!(has_website(&urls, &host, "https://app.example.com/login"));
    }

    #[test]
    fn unknown_modes_compare_as_text() {
        let modes = modes_of(Some(&serde_json::json!({ "https://a.example": "exact" })));
        assert_eq!(modes["https://a.example"], Regex);
    }

    #[test]
    fn subdomains_compares_as_the_same_host() {
        let urls = strings(&[
            "https://saasify.example.com",
            "http://www.saasify.example.com/login",
            "https://a.saasify.example.com",
        ]);
        let modes = modes_of(Some(
            &serde_json::json!({ "https://saasify.example.com": "subdomains" }),
        ));
        assert_eq!(
            unique_websites(&urls, &modes),
            strings(&[
                "https://saasify.example.com",
                "https://a.saasify.example.com"
            ])
        );
    }
}
