//! Registrable domains that belong to one sign-in system. Kept deliberately small: every group
//! here lets a login be suggested on another domain, so each one must share accounts for real.
//!
//! People add their own groups, and turn built-in ones off, in a hidden `equivalentDomains` item
//! ([`crate::item::EquivalentDomainsDetails`]), so the list is as encrypted as a login and follows
//! the account. [`clean_equivalent_groups`] is the one place that decides what a group may hold.

use serde::Serialize;

use super::MatchOptions;
use super::site::Site;
use crate::item::EquivalentDomainsDetails;

pub const DEFAULT_EQUIVALENT_DOMAINS: &[&[&str]] = &[
    &["google.com", "youtube.com", "gmail.com"],
    &["apple.com", "icloud.com"],
    &[
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "microsoftonline.com",
    ],
    &[
        "amazon.com",
        "amazon.ca",
        "amazon.co.uk",
        "amazon.de",
        "amazon.fr",
        "amazon.it",
        "amazon.es",
        "amazon.nl",
        "amazon.co.jp",
        "amazon.in",
        "amazon.com.au",
        "amazon.com.br",
        "amazon.com.mx",
        "amazon.ae",
        "amazon.sa",
        "amazon.eg",
    ],
    &["facebook.com", "messenger.com"],
    &["twitter.com", "x.com"],
    &["steampowered.com", "steamcommunity.com"],
    &["atlassian.com", "bitbucket.org"],
];

/// What [`clean_equivalent_groups`] made of the user's text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanedGroups {
    /// Registrable domains, each group sorted, at least two domains in each, no domain in two
    /// groups: groups that share one are joined.
    pub groups: Vec<Vec<String>>,
    /// What can't be matched on: public suffixes (`co.uk`, `github.io`), IP addresses, single
    /// labels, text that isn't a domain. Shown to the user rather than dropped silently.
    pub rejected: Vec<String>,
}

/// Turns what the user typed into groups the matcher can use. Matching compares registrable
/// domains, so `mail.example.com` and `https://example.com/login` both become `example.com`.
/// A public suffix is refused: `co.uk` in a group would mean nothing to the matcher, and must never
/// be able to stand for "every site under it".
pub fn clean_equivalent_groups<S: AsRef<str>, G: AsRef<[S]>>(groups: &[G]) -> CleanedGroups {
    let mut cleaned = CleanedGroups::default();
    let mut joined: Vec<Vec<String>> = Vec::new();
    for group in groups {
        let mut domains: Vec<String> = Vec::new();
        for text in group.as_ref() {
            let text = text.as_ref().trim();
            if text.is_empty() {
                continue;
            }
            match domain_of(text) {
                Some(domain) if !domains.contains(&domain) => domains.push(domain),
                Some(_) => {}
                None if !cleaned.rejected.iter().any(|seen| seen == text) => {
                    cleaned.rejected.push(text.to_string());
                }
                None => {}
            }
        }
        let (overlapping, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut joined)
            .into_iter()
            .partition(|other: &Vec<String>| other.iter().any(|d| domains.contains(d)));
        joined = rest;
        domains.extend(overlapping.into_iter().flatten());
        domains.sort();
        domains.dedup();
        joined.push(domains);
    }
    joined.retain(|group| group.len() >= 2);
    joined.sort();
    cleaned.groups = joined;
    cleaned
}

/// `Site` already leaves IP addresses and single labels without a domain.
fn domain_of(text: &str) -> Option<String> {
    Site::parse(text).ok()?.domain
}

/// [`MatchOptions`] with the user's equivalent domains, from every `equivalentDomains` item there
/// is: two devices can each make one before they sync. Groups are cleaned again here, so a group
/// written by anything else can't widen matching past what the editor allows.
pub fn user_equivalents<'a>(
    settings: impl IntoIterator<Item = &'a EquivalentDomainsDetails>,
) -> MatchOptions {
    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut excluded_defaults: Vec<String> = Vec::new();
    for details in settings {
        groups.extend(details.groups.iter().cloned());
        for domain in &details.excluded_defaults {
            if !excluded_defaults.contains(domain) {
                excluded_defaults.push(domain.clone());
            }
        }
    }
    MatchOptions {
        equivalent_domains: clean_equivalent_groups(&groups).groups,
        excluded_defaults,
        ..MatchOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{Candidate, match_items};

    fn clean(groups: &[&[&str]]) -> CleanedGroups {
        clean_equivalent_groups(groups)
    }

    #[test]
    fn groups_become_registrable_domains() {
        let cleaned = clean(&[&[
            "https://mail.example.com/login",
            "EXAMPLE.org",
            " example.net ",
        ]]);
        assert_eq!(
            cleaned.groups,
            [["example.com", "example.net", "example.org"]]
        );
        assert!(cleaned.rejected.is_empty());
    }

    #[test]
    fn suffixes_and_addresses_are_refused() {
        let cleaned = clean(&[&[
            "co.uk",
            "github.io",
            "com",
            "localhost",
            "192.168.1.1",
            "not a domain",
            "example.com",
            "example.org",
        ]]);
        assert_eq!(cleaned.groups, [["example.com", "example.org"]]);
        assert_eq!(
            cleaned.rejected,
            [
                "co.uk",
                "github.io",
                "com",
                "localhost",
                "192.168.1.1",
                "not a domain"
            ]
        );
    }

    #[test]
    fn a_site_under_a_private_suffix_is_its_own_domain() {
        let cleaned = clean(&[&["alice.github.io", "alice.example.com"]]);
        assert_eq!(cleaned.groups, [["alice.github.io", "example.com"]]);
    }

    #[test]
    fn overlapping_groups_join_and_small_ones_go() {
        let cleaned = clean(&[
            &["a-site.com", "b-site.com"],
            &["only-one.com"],
            &["b-site.com", "c-site.com"],
            &["d-site.com", "d-site.com"],
        ]);
        assert_eq!(cleaned.groups, [["a-site.com", "b-site.com", "c-site.com"]]);
    }

    fn details(groups: &[&[&str]], excluded: &[&str]) -> EquivalentDomainsDetails {
        EquivalentDomainsDetails {
            groups: groups
                .iter()
                .map(|g| g.iter().map(|d| d.to_string()).collect())
                .collect(),
            excluded_defaults: excluded.iter().map(|d| d.to_string()).collect(),
            ..EquivalentDomainsDetails::default()
        }
    }

    #[test]
    fn matching_uses_the_users_groups_from_every_copy() {
        let one = details(&[&["example.com", "example.org"]], &["google.com"]);
        let two = details(&[&["other-site.com", "example.org"]], &[]);
        let options = user_equivalents([&one, &two]);
        let login = |url: &str| Candidate {
            id: "x".into(),
            urls: vec![url.into()],
            ..Candidate::default()
        };
        let found = |page: &str, saved: &str| {
            !match_items(page, &[login(saved)], &options)
                .unwrap()
                .is_empty()
        };
        assert!(found("https://example.com", "https://other-site.com"));
        assert!(!found("https://youtube.com", "https://google.com"));
        assert!(found("https://icloud.com", "https://apple.com"));
    }

    #[test]
    fn a_stored_group_cant_hold_a_suffix() {
        // Written by something other than the editor: still only real domains match.
        let stored = details(&[&["com", "example.com"]], &[]);
        assert!(user_equivalents([&stored]).equivalent_domains.is_empty());
    }
    use crate::matching::registrable_domain;

    #[test]
    fn every_entry_is_a_registrable_domain_in_one_group() {
        let mut seen = std::collections::HashSet::new();
        for group in DEFAULT_EQUIVALENT_DOMAINS {
            assert!(group.len() >= 2);
            for domain in *group {
                assert_eq!(registrable_domain(domain).as_deref(), Some(*domain));
                assert!(seen.insert(*domain), "{domain} is in two groups");
            }
        }
    }
}
