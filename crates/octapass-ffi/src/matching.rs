//! Which saved logins may fill the site or app asking (plan 05, *Filling rules*). Websites go
//! through `octapass_core::matching`: by default the page's own host, a domain above it or a host
//! below it on the registrable domain from the Public Suffix List, each URL's match mode
//! (`urlMatch`), equivalent domains, ranked exact host first. Android apps
//! (`androidapp://<package>`), which the core doesn't know about, match only their exact package.

use std::collections::HashMap;

use octapass_core::item::ItemOverview;
use octapass_core::matching::{self, Candidate, MatchMode, MatchOptions};

use crate::error::Result;

const ANDROID_APP: &str = "androidapp://";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum MatchQuality {
    /// The same host (or a "starts with" or regex rule, or the same Android app).
    Exact,
    /// Another host on the same registrable domain: a domain above the page's host, a host below
    /// it, or, for a URL set to `baseDomain`, any other part of the domain.
    Domain,
    /// A domain the user or the built-in list treats as the same site (`youtube.com`).
    Equivalent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    pub id: String,
    /// The saved URL that matched best.
    pub url: String,
    pub quality: MatchQuality,
    /// The page and the saved URL disagree on `http` vs `https`: warn before filling an `http`
    /// page (plan 03).
    pub scheme_mismatch: bool,
}

/// The items whose URLs match `page`, best first, one entry per item. A page that is neither a
/// website nor an Android app is `InvalidUrl`.
pub(crate) fn match_overviews<'a>(
    page: &str,
    items: impl IntoIterator<Item = (&'a str, &'a ItemOverview)>,
    options: &MatchOptions,
) -> Result<Vec<Found>> {
    let page = page.trim();
    if page
        .get(..ANDROID_APP.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(ANDROID_APP))
    {
        return Ok(items
            .into_iter()
            .filter_map(|(id, overview)| {
                let url = overview
                    .urls
                    .iter()
                    .flatten()
                    .find(|url| url.trim().eq_ignore_ascii_case(page))?;
                Some(Found {
                    id: id.to_owned(),
                    url: url.clone(),
                    quality: MatchQuality::Exact,
                    scheme_mismatch: false,
                })
            })
            .collect());
    }
    let candidates: Vec<Candidate> = items
        .into_iter()
        .map(|(id, overview)| Candidate {
            id: id.to_owned(),
            urls: overview.urls.clone().unwrap_or_default(),
            url_match: url_match(overview),
        })
        .collect();
    Ok(matching::match_items(page, &candidates, options)?
        .into_iter()
        .map(|found| Found {
            id: found.id,
            url: found.url,
            quality: match found.quality {
                matching::MatchQuality::Exact => MatchQuality::Exact,
                matching::MatchQuality::Domain => MatchQuality::Domain,
                matching::MatchQuality::Equivalent => MatchQuality::Equivalent,
            },
            scheme_mismatch: found.scheme_mismatch,
        })
        .collect())
}

/// The items saved for another part of `page`'s registrable domain, which [`match_overviews`]
/// leaves out under the default mode (`shop.example.com` on `login.example.com`). Empty for an
/// Android app. A page that is neither is `InvalidUrl`.
pub(crate) fn other_parts<'a>(
    page: &str,
    items: impl IntoIterator<Item = (&'a str, &'a ItemOverview)>,
    options: &MatchOptions,
) -> Result<Vec<matching::OtherPart>> {
    let page = page.trim();
    if page
        .get(..ANDROID_APP.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(ANDROID_APP))
    {
        return Ok(Vec::new());
    }
    let candidates: Vec<Candidate> = items
        .into_iter()
        .map(|(id, overview)| Candidate {
            id: id.to_owned(),
            urls: overview.urls.clone().unwrap_or_default(),
            url_match: url_match(overview),
        })
        .collect();
    Ok(matching::other_parts(page, &candidates, options)?)
}

/// The overview's per-URL match modes; a malformed `urlMatch` falls back to the default mode.
fn url_match(overview: &ItemOverview) -> HashMap<String, MatchMode> {
    overview
        .extra
        .get("urlMatch")
        .and_then(|modes| serde_json::from_value(modes.clone()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use octapass_core::item::Item;
    use serde_json::json;

    use super::*;
    use crate::error::OctaPassError;

    fn overview(urls: serde_json::Value, url_match: serde_json::Value) -> ItemOverview {
        let item = json!({
            "overview": { "title": "t", "type": "login", "urls": urls, "urlMatch": url_match },
            "details": {}
        });
        Item::from_json(&item.to_string()).unwrap().overview
    }

    fn found(page: &str, overview: &ItemOverview) -> Option<(MatchQuality, bool)> {
        match_overviews(page, [("i", overview)], &MatchOptions::default())
            .unwrap()
            .first()
            .map(|found| (found.quality, found.scheme_mismatch))
    }

    #[test]
    fn websites_use_the_core_rules() {
        let google = overview(json!(["https://google.com"]), json!({}));
        assert_eq!(
            found("https://accounts.google.com", &google),
            Some((MatchQuality::Domain, false))
        );
        assert_eq!(
            found("http://google.com", &google),
            Some((MatchQuality::Exact, true))
        );
        assert_eq!(found("https://google.com.evil.io", &google), None);
        assert_eq!(
            found("https://www.youtube.com", &google),
            Some((MatchQuality::Equivalent, false))
        );

        let host_only = overview(
            json!(["https://google.com"]),
            json!({ "https://google.com": "host" }),
        );
        assert_eq!(
            found("https://accounts.google.com", &host_only),
            None,
            "the item's own match mode applies"
        );
        assert_eq!(
            match_overviews(
                "mailto:a@example.com",
                [("i", &google)],
                &MatchOptions::default()
            ),
            Err(OctaPassError::InvalidUrl)
        );
    }

    #[test]
    fn other_parts_of_a_domain_are_listed_apart() {
        let shop = overview(json!(["https://shop.example.com"]), json!({}));
        assert_eq!(found("https://login.example.com", &shop), None);
        let parts = other_parts(
            "https://login.example.com",
            [("i", &shop)],
            &MatchOptions::default(),
        )
        .unwrap();
        assert_eq!(
            parts
                .iter()
                .map(|p| (p.id.as_str(), p.host.as_str(), p.site.as_str()))
                .collect::<Vec<_>>(),
            [("i", "shop.example.com", "example.com")]
        );
        let everywhere = overview(
            json!(["https://shop.example.com"]),
            json!({ "https://shop.example.com": "baseDomain" }),
        );
        assert_eq!(
            found("https://login.example.com", &everywhere),
            Some((MatchQuality::Domain, false))
        );
        assert!(
            other_parts(
                "androidapp://com.example",
                [("i", &shop)],
                &MatchOptions::default()
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn android_apps_match_only_their_package() {
        let app = overview(
            json!(["androidapp://com.example.app", "https://example.com"]),
            json!({}),
        );
        assert_eq!(
            found("androidapp://com.example.app", &app),
            Some((MatchQuality::Exact, false))
        );
        assert_eq!(
            found("ANDROIDAPP://com.example.app", &app),
            Some((MatchQuality::Exact, false))
        );
        assert_eq!(found("androidapp://com.example.other", &app), None);
        let web = overview(json!(["https://example.com"]), json!({}));
        assert_eq!(found("androidapp://com.example", &web), None);
    }
}
