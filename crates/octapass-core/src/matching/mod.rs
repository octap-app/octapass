//! Which saved logins belong to the page the user is on (plan 05, *Filling rules*).
//!
//! A saved URL matches by its **match mode**. The default, [`MatchMode::Subdomains`], offers a
//! login on the page's own host, on the domains above it and on the hosts below it, within one
//! registrable domain; a login for another part of the same domain (`shop.example.com` on
//! `login.example.com`) isn't offered, and [`other_parts`] lists those for the user to pick by
//! hand. The other modes: any host on the registrable domain, the exact host, a "starts with"
//! prefix on the same host, a regular expression, or never. Matches are ranked the page's own
//! host > a domain above it (nearest first) > a host below it > another part of the domain (only
//! under `baseDomain`) > an equivalent domain (`google.com` and `youtube.com`). Domains come from
//! the Public Suffix List, so `paypal.com.evil.io` is `evil.io` and never matches `paypal.com`,
//! and IDNs are compared as punycode.

mod equivalent;
pub(crate) mod psl;
pub mod site;
pub mod websites;

use std::cmp::Reverse;
use std::collections::HashMap;

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

pub use equivalent::{
    CleanedGroups, DEFAULT_EQUIVALENT_DOMAINS, clean_equivalent_groups, user_equivalents,
};
pub use site::{Site, registrable_domain};
pub use websites::{has_website, same_website, unique_websites};

use crate::error::Result;

/// How a saved URL matches a page. Stored per URL in the overview's `urlMatch`, as camelCase
/// names; a URL without one uses [`MatchOptions::default_mode`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchMode {
    /// The default: the same host, a domain above it, or a host below it, on one registrable
    /// domain. A login for `login.example.com` matches `login.example.com`, `example.com` and
    /// `eu.login.example.com`, not `shop.example.com`. A leading `www.` counts as the bare host,
    /// and ports are ignored. Before 2026-11-05 the default was [`MatchMode::BaseDomain`]; a URL
    /// stored without a mode now means this one (plan 05, History).
    #[default]
    Subdomains,
    /// Any host on the same registrable domain: `accounts.google.com` matches `mail.google.com`.
    /// Ports are ignored. Only when chosen, per URL (or imported, as Bitwarden's "Base domain").
    BaseDomain,
    /// Same host and port.
    Host,
    /// Same host and port, and the page's path and query start with the saved ones.
    StartsWith,
    /// The saved URL is a regular expression over the page's full URL.
    Regex,
    /// Never suggested.
    Never,
}

/// One item to match: its id, the overview's `urls`, and optional per-URL match modes keyed by
/// the URL exactly as it appears in `urls` (overview field `urlMatch`). Other overview fields are
/// ignored, so a whole `{ id, ...overview }` can be passed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub url_match: HashMap<String, MatchMode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MatchOptions {
    /// The mode for URLs without their own. No app stores a choice for it yet; it defaults to
    /// [`MatchMode::Subdomains`].
    pub default_mode: MatchMode,
    /// Extra groups of registrable domains the user treats as one site.
    pub equivalent_domains: Vec<Vec<String>>,
    /// Whether [`DEFAULT_EQUIVALENT_DOMAINS`] apply.
    pub default_equivalents: bool,
    /// Built-in groups the user turned off, each named by its first domain.
    pub excluded_defaults: Vec<String>,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            default_mode: MatchMode::default(),
            equivalent_domains: Vec::new(),
            default_equivalents: true,
            excluded_defaults: Vec::new(),
        }
    }
}

/// How closely a saved URL matched, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchQuality {
    /// Same host (a leading `www.` aside), or a "starts with" or regex rule that matched.
    Exact,
    /// Same registrable domain, another host: a domain above the page's host or a host below it
    /// (ranked in that order), or, under `baseDomain`, any other part of the domain.
    Domain,
    /// A domain listed as equivalent.
    Equivalent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub id: String,
    /// The saved URL that matched best.
    pub url: String,
    pub quality: MatchQuality,
    /// The page and the saved URL disagree on `http` vs `https`. When the page is `http`, the
    /// caller must warn before filling (plan 03).
    pub scheme_mismatch: bool,
}

/// A login saved for another part of the page's registrable domain, which the default mode
/// doesn't offer (see [`other_parts`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherPart {
    pub id: String,
    /// The saved URL on the other part.
    pub url: String,
    /// That URL's host for display: IDNs in Unicode, without a leading `www.`.
    pub host: String,
    /// The registrable domain the page and the login share, for display (`example.com`), to name
    /// the list: "Logins for other parts of example.com".
    pub site: String,
    /// As in [`Match`].
    pub scheme_mismatch: bool,
}

/// The items whose URLs match `page_url`, best first; one entry per item. A page that isn't an
/// `http`/`https` address is an error.
pub fn match_items(
    page_url: &str,
    candidates: &[Candidate],
    options: &MatchOptions,
) -> Result<Vec<Match>> {
    let page = Page::new(Site::parse(page_url)?, options);
    let mut found: Vec<(Rank, Match)> = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some((rank, url, scheme_mismatch)) = page.best(candidate, options, index) {
            found.push((
                rank,
                Match {
                    id: candidate.id.clone(),
                    url: url.clone(),
                    quality: rank.0,
                    scheme_mismatch,
                },
            ));
        }
    }
    found.sort_by_key(|(rank, _)| *rank);
    Ok(found.into_iter().map(|(_, found)| found).collect())
}

/// The items [`match_items`] leaves out because they were saved for another part of the page's
/// registrable domain under the default mode: `shop.example.com` on `login.example.com`. Apps
/// list them behind one quiet entry, never as suggestions, and never fill one without the user
/// picking it. URLs with a mode of their own (`host`, `never` …) stay out, as do items that match
/// already. Sorted by host, then input order; one entry per item.
pub fn other_parts(
    page_url: &str,
    candidates: &[Candidate],
    options: &MatchOptions,
) -> Result<Vec<OtherPart>> {
    let page = Page::new(Site::parse(page_url)?, options);
    let Some(page_domain) = page.site.domain.clone() else {
        return Ok(Vec::new());
    };
    let site = display(&page_domain);
    let mut found: Vec<(String, usize, OtherPart)> = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if page.best(candidate, options, index).is_some() {
            continue;
        }
        let other = candidate.urls.iter().find_map(|saved_url| {
            if mode_of(candidate, saved_url, options) != MatchMode::Subdomains {
                return None;
            }
            let saved = Site::parse(saved_url).ok()?;
            (saved.domain.as_deref() == Some(page_domain.as_str())
                && relation(&saved.host, &page.site.host) == Relation::Other)
                .then_some((saved_url, saved))
        });
        if let Some((url, saved)) = other {
            let host = saved.display_host();
            found.push((
                host.clone(),
                index,
                OtherPart {
                    id: candidate.id.clone(),
                    url: url.clone(),
                    host,
                    site: site.clone(),
                    scheme_mismatch: saved.explicit_scheme
                        && saved.is_https() != page.site.is_https(),
                },
            ));
        }
    }
    found.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    Ok(found.into_iter().map(|(_, _, part)| part).collect())
}

/// The website to add to a login the user filled on `page_url` from another part of its domain:
/// the page's scheme, host and port (`https://login.example.com`), so the login matches the page
/// as its own host next time. `None` for what isn't a website.
pub fn website_for_page(page_url: &str) -> Option<String> {
    let site = Site::parse(page_url).ok()?;
    Some(site.url.origin().ascii_serialization())
}

/// Best first: quality, then how the hosts relate (a domain above the page, nearest first, then a
/// host below it, then another part of the domain), then the longest saved path the page is under
/// (`example.com/admin` before `example.com`), then input order.
type Rank = (MatchQuality, (u8, usize), Reverse<usize>, usize);

/// How a saved host relates to the page's, a leading `www.` aside on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Same,
    /// The saved host is a domain above the page's, this many labels up.
    Above(usize),
    /// The saved host is below the page's, this many labels down.
    Below(usize),
    /// Neither: another part of the domain, or another domain.
    Other,
}

impl Relation {
    fn order(self) -> (u8, usize) {
        match self {
            Relation::Same => (0, 0),
            Relation::Above(n) => (1, n),
            Relation::Below(n) => (2, n),
            Relation::Other => (3, 0),
        }
    }
}

fn without_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

fn relation(saved: &str, page: &str) -> Relation {
    let (saved, page) = (without_www(saved), without_www(page));
    let labels = |host: &str| host.split('.').count();
    if saved == page {
        Relation::Same
    } else if page.len() > saved.len()
        && page.ends_with(saved)
        && page.as_bytes()[page.len() - saved.len() - 1] == b'.'
    {
        Relation::Above(labels(page) - labels(saved))
    } else if saved.len() > page.len()
        && saved.ends_with(page)
        && saved.as_bytes()[saved.len() - page.len() - 1] == b'.'
    {
        Relation::Below(labels(saved) - labels(page))
    } else {
        Relation::Other
    }
}

/// A registrable domain (punycode) for display: Unicode when it converts cleanly.
fn display(domain: &str) -> String {
    match idna::domain_to_unicode(domain) {
        (unicode, Ok(())) => unicode,
        _ => domain.to_string(),
    }
}

fn mode_of(candidate: &Candidate, saved_url: &str, options: &MatchOptions) -> MatchMode {
    candidate
        .url_match
        .get(saved_url)
        .copied()
        .unwrap_or(options.default_mode)
}

struct Page<'a> {
    site: Site,
    path_and_query: String,
    equivalents: Vec<Vec<&'a str>>,
}

impl<'a> Page<'a> {
    fn new(site: Site, options: &'a MatchOptions) -> Self {
        let mut equivalents: Vec<Vec<&str>> = options
            .equivalent_domains
            .iter()
            .map(|group| group.iter().map(String::as_str).collect())
            .collect();
        if options.default_equivalents {
            equivalents.extend(
                DEFAULT_EQUIVALENT_DOMAINS
                    .iter()
                    .filter(|group| !options.excluded_defaults.iter().any(|d| d == group[0]))
                    .map(|group| group.to_vec()),
            );
        }
        Self {
            path_and_query: site.path_and_query(),
            site,
            equivalents,
        }
    }

    /// The candidate's best-matching URL: its rank, the URL, and the scheme mismatch.
    fn best<'c>(
        &self,
        candidate: &'c Candidate,
        options: &MatchOptions,
        index: usize,
    ) -> Option<(Rank, &'c String, bool)> {
        candidate
            .urls
            .iter()
            .filter_map(|saved_url| {
                self.compare(saved_url, mode_of(candidate, saved_url, options))
                    .map(|(quality, related, depth, mismatch)| {
                        (
                            (quality, related, Reverse(depth), index),
                            saved_url,
                            mismatch,
                        )
                    })
            })
            .min_by_key(|(rank, _, _)| *rank)
    }

    /// `(quality, how the hosts relate, matched path length, scheme mismatch)` when `saved_url`
    /// matches this page.
    fn compare(
        &self,
        saved_url: &str,
        mode: MatchMode,
    ) -> Option<(MatchQuality, (u8, usize), usize, bool)> {
        let page = &self.site;
        if mode == MatchMode::Regex {
            return regex_matches(saved_url, page.url.as_str()).then_some((
                MatchQuality::Exact,
                Relation::Same.order(),
                0,
                false,
            ));
        }
        let saved = Site::parse(saved_url).ok()?;
        let same_host = saved.host == page.host;
        let same_origin = same_host && saved.port() == page.port();
        let same_domain = matches!((&saved.domain, &page.domain), (Some(a), Some(b)) if a == b);
        // Hosts relate only within one registrable domain (or as the very same host, for IP
        // addresses and `localhost`), so `github.io` never stands above `alice.github.io`.
        let related = match relation(&saved.host, &page.host) {
            Relation::Same if same_domain || same_host => Relation::Same,
            Relation::Same | Relation::Above(_) | Relation::Below(_) if !same_domain => {
                Relation::Other
            }
            other => other,
        };
        let equivalent = || match (&saved.domain, &page.domain) {
            (Some(a), Some(b)) if a != b && self.equivalent(a, b) => Some(MatchQuality::Equivalent),
            _ => None,
        };
        let quality = match mode {
            MatchMode::Never | MatchMode::Regex => None,
            MatchMode::Host => same_origin.then_some(MatchQuality::Exact),
            MatchMode::StartsWith => (same_origin
                && self.path_and_query.starts_with(&saved.path_and_query()))
            .then_some(MatchQuality::Exact),
            MatchMode::Subdomains => match related {
                Relation::Same => Some(MatchQuality::Exact),
                Relation::Above(_) | Relation::Below(_) => Some(MatchQuality::Domain),
                Relation::Other => equivalent(),
            },
            MatchMode::BaseDomain => match related {
                Relation::Same => Some(MatchQuality::Exact),
                _ if same_domain => Some(MatchQuality::Domain),
                _ => equivalent(),
            },
        }?;
        let related = if quality == MatchQuality::Equivalent {
            Relation::Other.order()
        } else {
            related.order()
        };
        let saved_path = saved.url.path();
        let depth = if related == Relation::Same.order() && page.url.path().starts_with(saved_path)
        {
            saved_path.len()
        } else {
            0
        };
        let mismatch = saved.explicit_scheme && saved.is_https() != page.is_https();
        Some((quality, related, depth, mismatch))
    }

    fn equivalent(&self, a: &str, b: &str) -> bool {
        self.equivalents
            .iter()
            .any(|group| group.contains(&a) && group.contains(&b))
    }
}

/// Regular expressions come from the user; the size limit keeps a pathological one from
/// exhausting memory. An invalid expression matches nothing.
fn regex_matches(pattern: &str, page_url: &str) -> bool {
    RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .is_ok_and(|regex| regex.is_match(page_url))
}

/// Whether the matcher can use `pattern` as a regular expression rule, for editors to say so.
pub fn is_valid_pattern(pattern: &str) -> bool {
    RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, urls: &[&str]) -> Candidate {
        Candidate {
            id: id.into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            url_match: HashMap::new(),
        }
    }

    fn with_mode(mut candidate: Candidate, url: &str, mode: MatchMode) -> Candidate {
        candidate.url_match.insert(url.into(), mode);
        candidate
    }

    fn ids(page: &str, candidates: &[Candidate]) -> Vec<String> {
        match_items(page, candidates, &MatchOptions::default())
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect()
    }

    #[test]
    fn ranks_exact_host_then_domain_then_equivalent() {
        let candidates = [
            item("youtube", &["https://youtube.com"]),
            item("google", &["https://google.com"]),
            item("accounts", &["https://accounts.google.com/signin"]),
            item("other", &["https://example.com"]),
        ];
        let found = match_items(
            "https://accounts.google.com/signin/v2",
            &candidates,
            &MatchOptions::default(),
        )
        .unwrap();
        let summary: Vec<(&str, MatchQuality)> =
            found.iter().map(|m| (m.id.as_str(), m.quality)).collect();
        assert_eq!(
            summary,
            [
                ("accounts", MatchQuality::Exact),
                ("google", MatchQuality::Domain),
                ("youtube", MatchQuality::Equivalent),
            ]
        );
    }

    #[test]
    fn phishing_lookalikes_never_match() {
        let paypal = [item("paypal", &["https://www.paypal.com"])];
        for page in [
            "https://paypal.com.evil.io/login",
            "https://www.paypal.com@evil.io/",
            "https://evilpaypal.com",
            "https://paypal.co",
            "https://pаypal.com",
            "https://xn--paypal-xyz.com",
            "https://paypal.com.evil.io:443/www.paypal.com",
        ] {
            assert!(ids(page, &paypal).is_empty(), "{page}");
        }
        assert_eq!(ids("https://paypal.com/signin", &paypal), ["paypal"]);
        // Even a "starts with" rule compares hosts, not strings.
        let prefix = [with_mode(
            item("paypal", &["https://paypal.com"]),
            "https://paypal.com",
            MatchMode::StartsWith,
        )];
        assert!(ids("https://paypal.com.evil.io/", &prefix).is_empty());
    }

    #[test]
    fn private_suffixes_separate_sites() {
        let alice = [item("alice", &["https://alice.github.io"])];
        assert!(ids("https://bob.github.io", &alice).is_empty());
        assert_eq!(ids("https://alice.github.io/blog", &alice), ["alice"]);
    }

    #[test]
    fn idns_match_their_punycode() {
        let candidates = [item("buecher", &["https://bücher.de"])];
        assert_eq!(
            ids("https://xn--bcher-kva.de/konto", &candidates),
            ["buecher"]
        );
        assert_eq!(ids("https://www.BÜCHER.de", &candidates), ["buecher"]);
    }

    #[test]
    fn match_modes() {
        let url = "https://app.example.com:8443/admin";
        let make = |mode| [with_mode(item("x", &[url]), url, mode)];
        let check = |mode, page: &str| !ids(page, &make(mode)).is_empty();

        assert!(check(MatchMode::BaseDomain, "https://www.example.com"));
        assert!(check(MatchMode::Host, "https://app.example.com:8443/other"));
        assert!(!check(MatchMode::Host, "https://app.example.com/admin"));
        assert!(!check(
            MatchMode::Host,
            "https://www.example.com:8443/admin"
        ));
        assert!(check(
            MatchMode::StartsWith,
            "https://app.example.com:8443/admin/users"
        ));
        assert!(!check(
            MatchMode::StartsWith,
            "https://app.example.com:8443/other"
        ));
        assert!(!check(MatchMode::Never, url));

        let regex = r"^https://[a-z]+\.example\.com/";
        let pattern = [with_mode(item("r", &[regex]), regex, MatchMode::Regex)];
        assert_eq!(ids("https://shop.example.com/cart", &pattern), ["r"]);
        assert!(ids("https://shop.example.com.evil.io/", &pattern).is_empty());
        let broken = [with_mode(
            item("b", &["(unclosed"]),
            "(unclosed",
            MatchMode::Regex,
        )];
        assert!(ids("https://example.com", &broken).is_empty());
    }

    #[test]
    fn default_mode_and_equivalents_are_options() {
        let candidates = [item("google", &["https://google.com"])];
        let strict = MatchOptions {
            default_mode: MatchMode::Host,
            ..MatchOptions::default()
        };
        assert!(
            match_items("https://mail.google.com", &candidates, &strict)
                .unwrap()
                .is_empty()
        );

        let none = MatchOptions {
            default_equivalents: false,
            ..MatchOptions::default()
        };
        assert!(
            match_items("https://youtube.com", &candidates, &none)
                .unwrap()
                .is_empty()
        );

        let custom = MatchOptions {
            equivalent_domains: vec![vec!["example.com".into(), "example.org".into()]],
            ..MatchOptions::default()
        };
        let example = [item("e", &["example.org"])];
        assert_eq!(
            match_items("https://example.com", &example, &custom)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_built_in_group_can_be_turned_off() {
        let candidates = [item("google", &["https://google.com"])];
        let options = MatchOptions {
            excluded_defaults: vec!["google.com".into()],
            ..MatchOptions::default()
        };
        assert!(
            match_items("https://youtube.com", &candidates, &options)
                .unwrap()
                .is_empty()
        );
        // The others stay on.
        let apple = [item("apple", &["https://apple.com"])];
        assert_eq!(
            match_items("https://icloud.com", &apple, &options)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn scheme_mismatch_is_flagged() {
        let candidates = [
            item("secure", &["https://example.com"]),
            item("plain", &["http://example.com"]),
            item("bare", &["example.com"]),
        ];
        let flags = |page| {
            match_items(page, &candidates, &MatchOptions::default())
                .unwrap()
                .into_iter()
                .map(|m| (m.id, m.scheme_mismatch))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            flags("http://example.com"),
            [
                ("secure".into(), true),
                ("plain".into(), false),
                ("bare".into(), false)
            ]
        );
        assert_eq!(
            flags("https://example.com"),
            [
                ("secure".into(), false),
                ("plain".into(), true),
                ("bare".into(), false)
            ]
        );
    }

    #[test]
    fn the_best_url_of_each_item_counts_once() {
        let candidates = [
            item("root", &["https://example.com"]),
            item("deep", &["https://other.com", "https://example.com/admin"]),
        ];
        let found = match_items(
            "https://example.com/admin/users",
            &candidates,
            &MatchOptions::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(
            (found[0].id.as_str(), found[0].url.as_str()),
            ("deep", "https://example.com/admin")
        );
        assert_eq!(found[1].id, "root");
    }

    #[test]
    fn ip_and_local_hosts_need_the_same_host() {
        let candidates = [
            item("router", &["http://192.168.1.1"]),
            item("dev", &["localhost:3000"]),
        ];
        assert_eq!(ids("http://192.168.1.1/setup", &candidates), ["router"]);
        assert!(ids("http://192.168.1.2/", &candidates).is_empty());
        assert_eq!(ids("http://localhost:5173/", &candidates), ["dev"]);
    }

    #[test]
    fn candidates_deserialize_from_overviews() {
        let candidates: Vec<Candidate> = serde_json::from_str(
            r#"[{ "id": "a", "title": "A", "type": "login", "urls": ["https://a.com"], "urlMatch": { "https://a.com": "host" } }, { "id": "b", "title": "B", "type": "secureNote" }]"#,
        )
        .unwrap();
        assert_eq!(candidates[0].url_match["https://a.com"], MatchMode::Host);
        assert!(candidates[1].urls.is_empty());
        assert!(ids("https://www.a.com", &candidates).is_empty());
    }

    fn others(page: &str, candidates: &[Candidate]) -> Vec<(String, String)> {
        other_parts(page, candidates, &MatchOptions::default())
            .unwrap()
            .into_iter()
            .map(|part| (part.id, part.host))
            .collect()
    }

    #[test]
    fn subdomains_ranks_own_host_then_above_then_below() {
        let custom = MatchOptions {
            equivalent_domains: vec![vec!["example.com".into(), "example.org".into()]],
            ..MatchOptions::default()
        };
        let candidates = [
            item("equivalent", &["https://example.org"]),
            item("child", &["https://x.a.b.example.com"]),
            item("top", &["https://example.com"]),
            item("sibling", &["https://c.example.com"]),
            item("cousin", &["https://c.b.example.com"]),
            with_mode(
                item("everywhere", &["https://shop.example.com"]),
                "https://shop.example.com",
                MatchMode::BaseDomain,
            ),
            item("parent", &["https://b.example.com/login"]),
            item("www", &["https://www.a.b.example.com"]),
            item("own", &["https://a.b.example.com:8443/signin"]),
        ];
        let found = match_items("https://a.b.example.com/signin", &candidates, &custom).unwrap();
        let summary: Vec<(&str, MatchQuality)> =
            found.iter().map(|m| (m.id.as_str(), m.quality)).collect();
        assert_eq!(
            summary,
            [
                // The longer saved path first, then input order; ports don't count.
                ("own", MatchQuality::Exact),
                ("www", MatchQuality::Exact),
                // Nearest domain above first.
                ("parent", MatchQuality::Domain),
                ("top", MatchQuality::Domain),
                ("child", MatchQuality::Domain),
                // Another part only when the login says "every part of the domain".
                ("everywhere", MatchQuality::Domain),
                ("equivalent", MatchQuality::Equivalent),
            ]
        );
        assert_eq!(
            others("https://a.b.example.com/signin", &candidates),
            [
                // By host.
                ("cousin".to_string(), "c.b.example.com".to_string()),
                ("sibling".to_string(), "c.example.com".to_string()),
            ]
        );
    }

    #[test]
    fn other_parts_of_a_domain_are_not_offered() {
        let candidates = [
            item("yyy", &["https://yyy.domain.com/login"]),
            item("bare", &["https://domain.com"]),
            item("deeper", &["https://app.xxx.domain.com"]),
        ];
        assert_eq!(
            ids("https://xxx.domain.com", &candidates),
            ["bare", "deeper"]
        );
        let parts = other_parts(
            "https://xxx.domain.com",
            &candidates,
            &MatchOptions::default(),
        )
        .unwrap();
        assert_eq!(
            parts,
            [OtherPart {
                id: "yyy".into(),
                url: "https://yyy.domain.com/login".into(),
                host: "yyy.domain.com".into(),
                site: "domain.com".into(),
                scheme_mismatch: false,
            }]
        );
        // On the bare domain every part is below it, so every login is offered.
        assert_eq!(
            ids("https://domain.com", &candidates),
            ["bare", "yyy", "deeper"]
        );
        assert!(others("https://domain.com", &candidates).is_empty());
        // A host below one part isn't below another.
        assert_eq!(ids("https://yyy.domain.com", &candidates), ["yyy", "bare"]);
        assert_eq!(
            others("https://yyy.domain.com", &candidates),
            [("deeper".to_string(), "app.xxx.domain.com".to_string())]
        );
    }

    #[test]
    fn www_counts_as_the_bare_host() {
        let bare = [item("bare", &["https://example.com"])];
        let www = [item("www", &["https://www.example.com"])];
        for (page, candidates) in [
            ("https://www.example.com/login", &bare),
            ("https://example.com/login", &www),
        ] {
            let found = match_items(page, candidates, &MatchOptions::default()).unwrap();
            assert_eq!(found[0].quality, MatchQuality::Exact, "{page}");
        }
        // `www.` only drops at the front: `www.shop.example.com` is shop's, not the domain's.
        let shop = [item("shop", &["https://www.shop.example.com"])];
        assert_eq!(ids("https://shop.example.com", &shop), ["shop"]);
        assert!(ids("https://app.example.com", &shop).is_empty());
    }

    #[test]
    fn subdomains_ignores_ports() {
        let candidates = [
            item("port", &["https://example.com:8443"]),
            item("below", &["login.example.com:9000"]),
        ];
        let found =
            match_items("https://example.com", &candidates, &MatchOptions::default()).unwrap();
        let summary: Vec<(&str, MatchQuality)> =
            found.iter().map(|m| (m.id.as_str(), m.quality)).collect();
        assert_eq!(
            summary,
            [
                ("port", MatchQuality::Exact),
                ("below", MatchQuality::Domain)
            ]
        );
    }

    #[test]
    fn idn_parts_compare_as_punycode() {
        let candidates = [
            item("konto", &["https://konto.bücher.de"]),
            item("shop", &["https://shop.xn--bcher-kva.de"]),
        ];
        assert_eq!(
            ids("https://xn--bcher-kva.de", &candidates),
            ["konto", "shop"]
        );
        assert_eq!(ids("https://konto.BÜCHER.de/x", &candidates), ["konto"]);
        let parts = other_parts(
            "https://konto.bücher.de",
            &candidates,
            &MatchOptions::default(),
        )
        .unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            (parts[0].host.as_str(), parts[0].site.as_str()),
            ("shop.bücher.de", "bücher.de")
        );
    }

    #[test]
    fn public_suffix_parts_stay_separate_sites() {
        let candidates = [
            item("alice", &["https://alice.github.io"]),
            item("suffix", &["https://github.io"]),
        ];
        assert!(ids("https://bob.github.io", &candidates).is_empty());
        assert!(others("https://bob.github.io", &candidates).is_empty());
        assert_eq!(ids("https://alice.github.io/blog", &candidates), ["alice"]);
        assert_eq!(ids("https://www.alice.github.io", &candidates), ["alice"]);
        // Under alice's own site, below it counts; a public suffix is never "above" anything.
        assert_eq!(ids("https://blog.alice.github.io", &candidates), ["alice"]);
        assert!(ids("https://github.io", &candidates[..1]).is_empty());
        let co_uk = [item("bbc", &["https://bbc.co.uk"])];
        assert!(ids("https://evil.co.uk", &co_uk).is_empty());
    }

    #[test]
    fn explicit_base_domain_still_matches_every_part() {
        let url = "https://yyy.domain.com";
        let everywhere = [with_mode(item("yyy", &[url]), url, MatchMode::BaseDomain)];
        let found = match_items(
            "https://xxx.domain.com",
            &everywhere,
            &MatchOptions::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].quality, MatchQuality::Domain);
        assert!(others("https://xxx.domain.com", &everywhere).is_empty());
        // The user's default can say so too.
        let old = MatchOptions {
            default_mode: MatchMode::BaseDomain,
            ..MatchOptions::default()
        };
        let plain = [item("yyy", &[url])];
        assert_eq!(
            match_items("https://xxx.domain.com", &plain, &old)
                .unwrap()
                .len(),
            1
        );
        assert!(
            other_parts("https://xxx.domain.com", &plain, &old)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn only_default_mode_logins_are_other_parts() {
        let url = "https://yyy.domain.com";
        let candidates = [
            with_mode(item("host", &[url]), url, MatchMode::Host),
            with_mode(item("never", &[url]), url, MatchMode::Never),
            with_mode(item("prefix", &[url]), url, MatchMode::StartsWith),
            item("default", &[url]),
            item("ip", &["http://192.168.1.1"]),
        ];
        assert_eq!(
            others("https://xxx.domain.com", &candidates),
            [("default".to_string(), "yyy.domain.com".to_string())]
        );
        assert!(others("http://192.168.1.2", &candidates).is_empty());
        assert!(other_parts("chrome://settings", &candidates, &MatchOptions::default()).is_err());
        let insecure = other_parts(
            "http://xxx.domain.com",
            &candidates,
            &MatchOptions::default(),
        )
        .unwrap();
        assert!(insecure[0].scheme_mismatch);
    }

    #[test]
    fn stored_modes_keep_their_meaning() {
        // A URL stored without a mode, and options without a default, mean the new default.
        let candidates: Vec<Candidate> = serde_json::from_str(
            r#"[{ "id": "plain", "urls": ["https://yyy.domain.com"] },
                { "id": "picked", "urls": ["https://yyy.domain.com"], "urlMatch": { "https://yyy.domain.com": "baseDomain" } },
                { "id": "new", "urls": ["https://yyy.domain.com"], "urlMatch": { "https://yyy.domain.com": "subdomains" } }]"#,
        )
        .unwrap();
        assert!(
            !candidates[0]
                .url_match
                .contains_key("https://yyy.domain.com")
        );
        assert_eq!(
            candidates[1].url_match["https://yyy.domain.com"],
            MatchMode::BaseDomain
        );
        assert_eq!(
            candidates[2].url_match["https://yyy.domain.com"],
            MatchMode::Subdomains
        );
        let options: MatchOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(options.default_mode, MatchMode::Subdomains);
        assert_eq!(MatchOptions::default().default_mode, MatchMode::Subdomains);
        assert_eq!(MatchMode::default(), MatchMode::Subdomains);
        let chosen: MatchOptions =
            serde_json::from_str(r#"{ "defaultMode": "baseDomain" }"#).unwrap();
        assert_eq!(chosen.default_mode, MatchMode::BaseDomain);
        assert_eq!(
            serde_json::to_value(MatchMode::Subdomains).unwrap(),
            "subdomains"
        );

        assert_eq!(ids("https://xxx.domain.com", &candidates), ["picked"]);
        assert_eq!(
            others("https://xxx.domain.com", &candidates)
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            ["plain", "new"]
        );
    }

    #[test]
    fn the_website_to_add_is_the_pages_origin() {
        assert_eq!(
            website_for_page("https://xxx.domain.com/login?next=/").as_deref(),
            Some("https://xxx.domain.com")
        );
        assert_eq!(
            website_for_page("http://localhost:8080/x").as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(
            website_for_page("konto.bücher.de").as_deref(),
            Some("https://konto.xn--bcher-kva.de")
        );
        assert_eq!(website_for_page("mailto:a@b.c"), None);
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_urls_never_panic(page in "\\PC{0,64}", saved in proptest::collection::vec("\\PC{0,64}", 0..4)) {
            let modes = [MatchMode::Subdomains, MatchMode::BaseDomain, MatchMode::Host, MatchMode::StartsWith, MatchMode::Regex];
            let candidates: Vec<Candidate> = modes
                .iter()
                .map(|mode| Candidate {
                    id: "x".into(),
                    url_match: saved.iter().map(|u| (u.clone(), *mode)).collect(),
                    urls: saved.clone(),
                })
                .collect();
            let _ = match_items(&page, &candidates, &MatchOptions::default());
            let _ = match_items(&format!("https://{page}"), &candidates, &MatchOptions::default());
            let _ = other_parts(&page, &candidates, &MatchOptions::default());
            let _ = other_parts(&format!("https://{page}"), &candidates, &MatchOptions::default());
            let _ = website_for_page(&page);
        }
    }

    #[test]
    fn pages_must_be_websites() {
        assert!(match_items("chrome://settings", &[], &MatchOptions::default()).is_err());
    }
}
