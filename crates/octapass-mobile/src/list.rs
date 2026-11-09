//! Which items a list shows and how it orders them: the web vault's filter and search
//! (`matchesFilter` in `packages/vault-client/src/items.ts`) and its sort orders and sections
//! (`listOrder.ts`), so every app arranges lists the same way. Section labels come from each
//! app's catalog.
//!
//! Names compare as the web vault's `Intl.Collator` does with `sensitivity: 'base'` and
//! `numeric: true`, approximated without ICU: accents and case don't matter, digit runs compare
//! as numbers, then spaces and punctuation come before digits, and digits before letters, which
//! keep code point order (Latin, then Greek, Cyrillic, Arabic, …).

use std::cmp::Ordering;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

use crate::items::{ItemSummary, ItemType, is_hidden_type};

/// The order type sections come in. Types from a newer client follow, by name.
const TYPE_SECTION_ORDER: [&str; 18] = [
    "login",
    "password",
    "card",
    "identity",
    "secureNote",
    "wifi",
    "sshKey",
    "document",
    "environment",
    "bankAccount",
    "idDocument",
    "cryptoWallet",
    "apiCredential",
    "database",
    "softwareLicense",
    "custom",
    "customTemplate",
    "maskedEmailProvider",
];

/// The section for titles that don't start with a letter.
pub const OTHER_LETTER: &str = "#";

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct ItemFilter {
    pub vault_id: Option<String>,
    /// Without it, settings-like types (masked email providers) are left out.
    pub item_type: Option<ItemType>,
    /// Words that must all appear in the title, subtitle, URLs or tags, ignoring case and
    /// accents. Secrets are never searched.
    pub query: Option<String>,
    /// The trash instead of the vault.
    pub trash: bool,
    pub favorites: bool,
    /// Only logins with a passkey.
    pub passkeys: bool,
    /// Only logins with a one-time code (the One-time codes list).
    #[uniffi(default = false)]
    pub totp: bool,
    /// Only environments of this project.
    #[uniffi(default)]
    pub project: Option<String>,
    /// Only environments of this stage.
    #[uniffi(default)]
    pub stage: Option<String>,
    /// Only pinned items (the Pinned list).
    #[uniffi(default = false)]
    pub pinned: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ListSort {
    /// A–Z
    #[default]
    Name,
    /// Z–A
    NameDesc,
    /// Recently added first.
    Newest,
    Oldest,
    /// Recently changed first.
    Changed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ListGrouping {
    #[default]
    Type,
    Letter,
    Vault,
    /// The environments of one project together.
    Project,
    None,
}

/// A row of a list: one item, or the logins for one website shown as a single row that expands
/// inline.
// Boxing would only change the Rust side: UniFFI copies the values across anyway.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ListEntry {
    Item {
        item: ItemSummary,
    },
    Site {
        host: String,
        items: Vec<ItemSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ListSection {
    /// The item type's name (`login`), the letter, the vault id, the project, or empty for the
    /// one section of an ungrouped list and for environments with no project.
    pub key: String,
    pub items: Vec<ItemSummary>,
    /// The rows, when `arrangeItems` combines logins for the same website: the same items, in the
    /// same order. Empty otherwise.
    pub entries: Vec<ListEntry>,
}

/// How one list is sorted and grouped.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Record,
)]
pub struct ListArrangement {
    #[serde(with = "crate::local::sort_name")]
    pub sort: ListSort,
    #[serde(with = "crate::local::grouping_name")]
    pub grouping: ListGrouping,
}

// Lists that mix item types; a list of one type has nothing to group by type.
const MIXED: [&str; 4] = ["all", "favorites", "pinned", "vault"];

/// Mixed lists (`all`, `favorites`, `pinned`, `vault`) start grouped by type, environments by project, other
/// lists of one type by first letter; all in name order. `view` is the list a choice is remembered for: `all`,
/// `favorites`, `pinned`, `passkeys`, `codes`, `vault`, or an item type's name.
#[uniffi::export]
pub fn default_arrangement(view: String) -> ListArrangement {
    ListArrangement {
        sort: ListSort::Name,
        grouping: if view == "environment" {
            ListGrouping::Project
        } else if MIXED.contains(&view.as_str()) {
            ListGrouping::Type
        } else {
            ListGrouping::Letter
        },
    }
}

/// What a list can be grouped by: type only when it mixes types, vault only across several
/// vaults, project only for environments.
#[uniffi::export]
pub fn list_groupings(view: String, vault_count: u32) -> Vec<ListGrouping> {
    [
        ListGrouping::Type,
        ListGrouping::Letter,
        ListGrouping::Vault,
        ListGrouping::Project,
        ListGrouping::None,
    ]
    .into_iter()
    .filter(|grouping| match grouping {
        ListGrouping::Type => MIXED.contains(&view.as_str()),
        ListGrouping::Vault => view != "vault" && vault_count > 1,
        ListGrouping::Project => view == "environment",
        _ => true,
    })
    .collect()
}

/// The remembered arrangement for a list, or its default, limited to the groupings it offers.
pub(crate) fn resolve_arrangement(
    saved: Option<&ListArrangement>,
    view: &str,
    vault_count: u32,
) -> ListArrangement {
    let groupings = list_groupings(view.into(), vault_count);
    let fallback = default_arrangement(view.into());
    let grouping = match saved {
        Some(saved) if groupings.contains(&saved.grouping) => saved.grouping,
        _ if groupings.contains(&fallback.grouping) => fallback.grouping,
        _ => ListGrouping::None,
    };
    ListArrangement {
        sort: saved.map_or(fallback.sort, |s| s.sort),
        grouping,
    }
}

/// Lists that can combine a website's logins into one row: any list that can hold logins, except
/// the trash and the one-time codes, where each row shows its code.
#[uniffi::export]
pub fn offers_site_rows(view: String) -> bool {
    !matches!(view.as_str(), "trash" | "codes")
        && (MIXED.contains(&view.as_str()) || view == "passkeys" || view == "login")
}

/// The host of a URL without the scheme, a leading `www.` or a trailing dot, in lower case
/// (`hostnameOf` in the web vault). `mailto:` and the like have none.
pub(crate) fn hostname_of(url: &str) -> Option<url::Url> {
    let text = url.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    let scheme_end = text.find(':');
    let has_authority = text.contains("://");
    if let Some(end) = scheme_end
        && !has_authority
    {
        let scheme = &text[..end];
        let after = text[end + 1..].chars().next();
        let is_scheme = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        if is_scheme && !after.is_some_and(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    let with_scheme = text.split_once("://").is_some_and(|(scheme, _)| {
        scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    });
    let parsed = if with_scheme {
        url::Url::parse(text)
    } else {
        url::Url::parse(&format!("https://{text}"))
    };
    parsed
        .ok()
        .filter(|url| url.host_str().is_some_and(|h| !h.is_empty()))
}

pub(crate) fn clean_host(url: &url::Url) -> Option<String> {
    let host = url.host_str()?.to_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// The website a URL belongs to, for combining logins: its host, plus a port other than the
/// scheme's default, since `nas.local:5000` and `nas.local:8080` are usually different apps.
/// `a.example.com` and `b.example.com` are different sites.
pub fn site_host(url: &str) -> Option<String> {
    let parsed = hostname_of(url)?;
    let host = clean_host(&parsed)?;
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn site_counts(items: &[ItemSummary]) -> std::collections::HashMap<&str, usize> {
    let mut counts = std::collections::HashMap::new();
    for site in items.iter().filter_map(|item| item.site.as_deref()) {
        *counts.entry(site).or_insert(0) += 1;
    }
    counts
}

/// Rows for sorted items, with two or more logins for the same site as one row. A site row takes
/// the place of its first login in date order, and its host's place in name order; its logins
/// keep the list's order.
pub fn combine_sites(sorted: &[ItemSummary], sort: ListSort) -> Vec<ListEntry> {
    let counts = site_counts(sorted);
    let mut entries: Vec<ListEntry> = Vec::new();
    for item in sorted {
        let site = item
            .site
            .as_deref()
            .filter(|site| counts.get(site).is_some_and(|n| *n >= 2));
        let Some(site) = site else {
            entries.push(ListEntry::Item { item: item.clone() });
            continue;
        };
        let existing = entries.iter_mut().find_map(|entry| match entry {
            ListEntry::Site { host, items } if host == site => Some(items),
            _ => None,
        });
        match existing {
            Some(items) => items.push(item.clone()),
            None => entries.push(ListEntry::Site {
                host: site.to_owned(),
                items: vec![item.clone()],
            }),
        }
    }
    if !matches!(sort, ListSort::Name | ListSort::NameDesc) {
        return entries;
    }
    let name = |entry: &ListEntry| match entry {
        ListEntry::Site { host, .. } => host.clone(),
        ListEntry::Item { item } => item.title.clone(),
    };
    // A stable sort, so a site and a title that compare equal keep the order they came in.
    entries.sort_by(|a, b| {
        let order = compare_names(&name(a), &name(b));
        if sort == ListSort::NameDesc {
            order.reverse()
        } else {
            order
        }
    });
    entries
}

/// Lower case without accents or other marks, as search and name order see text.
pub(crate) fn fold(text: &str) -> String {
    text.nfkd()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

pub(crate) fn matches_query(item: &ItemSummary, query: &str) -> bool {
    let haystack = fold(
        &[Some(item.title.as_str()), item.subtitle.as_deref()]
            .into_iter()
            .flatten()
            .chain(item.urls.iter().map(String::as_str))
            .chain(item.tags.iter().map(String::as_str))
            // Environment variable names are searchable; their values never are.
            .chain(item.variable_keys.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" "),
    );
    fold(query)
        .split_whitespace()
        .all(|term| haystack.contains(term))
}

pub(crate) fn matches_filter(item: &ItemSummary, filter: &ItemFilter) -> bool {
    if filter.trash != item.deleted_at.is_some() {
        return false;
    }
    if filter
        .vault_id
        .as_ref()
        .is_some_and(|id| *id != item.vault_id)
    {
        return false;
    }
    match &filter.item_type {
        Some(item_type) if *item_type != item.item_type => return false,
        None if is_hidden_type(item.item_type.name()) => return false,
        _ => {}
    }
    if (filter.favorites && !item.favorite)
        || (filter.pinned && !item.pinned)
        || (filter.passkeys && !item.has_passkey)
        || (filter.totp && !item.has_totp)
    {
        return false;
    }
    if filter.project.is_some() && filter.project != item.project {
        return false;
    }
    if filter.stage.is_some() && filter.stage != item.stage {
        return false;
    }
    filter
        .query
        .as_deref()
        .is_none_or(|query| matches_query(item, query))
}

/// The sidebar's counts for the vault's items (not the trash) and the trash's size.
pub(crate) fn counts(all: &[ItemSummary], trash: usize) -> std::collections::HashMap<String, u32> {
    let mut counts = std::collections::HashMap::from([
        ("all".to_owned(), all.len() as u32),
        ("favorites".to_owned(), 0),
        ("pinned".to_owned(), 0),
        ("passkeys".to_owned(), 0),
        ("codes".to_owned(), 0),
        ("trash".to_owned(), trash as u32),
    ]);
    let mut add = |key: String| *counts.entry(key).or_insert(0) += 1;
    for item in all {
        add(item.item_type.name().to_owned());
        add(format!("v-{}", item.vault_id));
        if item.favorite {
            add("favorites".into());
        }
        if item.pinned {
            add("pinned".into());
        }
        if item.has_passkey {
            add("passkeys".into());
        }
        if item.has_totp {
            add("codes".into());
        }
    }
    counts
}

/// Space and punctuation, then digits, then letters.
fn class(c: char) -> u8 {
    if c.is_numeric() {
        1
    } else if c.is_alphabetic() {
        2
    } else {
        0
    }
}

/// Name order: see the module docs.
pub fn compare_names(a: &str, b: &str) -> Ordering {
    let (a, b) = (fold(a), fold(b));
    let (mut a, mut b) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (a.peek().copied(), b.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let run = |chars: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut digits = String::new();
                    while let Some(c) = chars.peek().copied().filter(char::is_ascii_digit) {
                        digits.push(c);
                        chars.next();
                    }
                    digits.trim_start_matches('0').to_owned()
                };
                let (x, y) = (run(&mut a), run(&mut b));
                let order = x.len().cmp(&y.len()).then_with(|| x.cmp(&y));
                if order != Ordering::Equal {
                    return order;
                }
            }
            (Some(x), Some(y)) => {
                let order = class(x).cmp(&class(y)).then_with(|| x.cmp(&y));
                if order != Ordering::Equal {
                    return order;
                }
                a.next();
                b.next();
            }
        }
    }
}

pub(crate) fn is_date(text: &str) -> bool {
    OffsetDateTime::parse(text, &Rfc3339).is_ok()
}

pub(crate) fn millis(text: &str) -> i128 {
    OffsetDateTime::parse(text, &Rfc3339)
        .map(|time| time.unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(0)
}

fn created(item: &ItemSummary) -> i128 {
    millis(if item.created_at.is_empty() {
        &item.updated_at
    } else {
        &item.created_at
    })
}

/// Equal names and dates fall back to the name, then the id, so the order never jumps.
pub fn sort_items(items: &mut [ItemSummary], sort: ListSort) {
    let by_name = |a: &ItemSummary, b: &ItemSummary| compare_names(&a.title, &b.title);
    let by_id = |a: &ItemSummary, b: &ItemSummary| a.id.cmp(&b.id);
    items.sort_by(|a, b| match sort {
        ListSort::Name => by_name(a, b).then_with(|| by_id(a, b)),
        ListSort::NameDesc => by_name(b, a).then_with(|| by_id(a, b)),
        ListSort::Newest => created(b)
            .cmp(&created(a))
            .then_with(|| by_name(a, b))
            .then_with(|| by_id(a, b)),
        ListSort::Oldest => created(a)
            .cmp(&created(b))
            .then_with(|| by_name(a, b))
            .then_with(|| by_id(a, b)),
        ListSort::Changed => millis(&b.updated_at)
            .cmp(&millis(&a.updated_at))
            .then_with(|| by_name(a, b))
            .then_with(|| by_id(a, b)),
    });
}

/// The section a title is filed under: its first letter without accents, in capitals where the
/// script has them (É → E, أ → ا), or `#` when it doesn't start with a letter.
#[uniffi::export]
pub fn first_letter(title: String) -> String {
    let first = title.trim().nfkd().find(|c| !is_combining_mark(*c));
    match first {
        Some(c) if c.is_alphabetic() => {
            let upper = c.to_uppercase().next().unwrap_or(c);
            // Alef wasla is filed under alef, like the alefs that lose their marks above.
            if upper == 'ٱ' { 'ا' } else { upper }.to_string()
        }
        _ => OTHER_LETTER.into(),
    }
}

fn sections_by(
    items: Vec<ItemSummary>,
    key_of: impl Fn(&ItemSummary) -> String,
) -> Vec<ListSection> {
    let mut sections: Vec<ListSection> = Vec::new();
    for item in items {
        let key = key_of(&item);
        match sections.iter_mut().find(|section| section.key == key) {
            Some(section) => section.items.push(item),
            None => sections.push(ListSection {
                key,
                items: vec![item],
                entries: Vec::new(),
            }),
        }
    }
    sections
}

fn rank(order: &[&str], key: &str) -> usize {
    order.iter().position(|k| *k == key).unwrap_or(order.len())
}

/// Sorts, then splits into sections that keep that order inside. Type sections come in a fixed
/// order, vault sections in `vault_order`, letters in name order (backwards for Z–A) with `#`
/// last. An ungrouped list is one section; an empty one has none. With `combine`, each
/// section's logins for the same website become one entry; by first letter, those logins are
/// filed under their host's letter.
pub fn arrange(
    items: Vec<ItemSummary>,
    sort: ListSort,
    grouping: ListGrouping,
    vault_order: &[String],
    combine: bool,
) -> Vec<ListSection> {
    let mut sections = split_sections(items, sort, grouping, vault_order, combine);
    if combine {
        for section in &mut sections {
            section.entries = combine_sites(&section.items, sort);
        }
    }
    sections
}

fn split_sections(
    mut items: Vec<ItemSummary>,
    sort: ListSort,
    grouping: ListGrouping,
    vault_order: &[String],
    combine: bool,
) -> Vec<ListSection> {
    sort_items(&mut items, sort);
    match grouping {
        ListGrouping::None if items.is_empty() => Vec::new(),
        ListGrouping::None => vec![ListSection {
            key: String::new(),
            items,
            entries: Vec::new(),
        }],
        ListGrouping::Type => {
            let mut sections = sections_by(items, |item| item.item_type.name().to_owned());
            sections.sort_by(|a, b| {
                rank(&TYPE_SECTION_ORDER, &a.key)
                    .cmp(&rank(&TYPE_SECTION_ORDER, &b.key))
                    .then_with(|| compare_names(&a.key, &b.key))
            });
            sections
        }
        ListGrouping::Vault => {
            let order: Vec<&str> = vault_order.iter().map(String::as_str).collect();
            let mut sections = sections_by(items, |item| item.vault_id.clone());
            sections.sort_by(|a, b| {
                rank(&order, &a.key)
                    .cmp(&rank(&order, &b.key))
                    .then_with(|| a.key.cmp(&b.key))
            });
            sections
        }
        ListGrouping::Project => {
            // Environments with no project come last.
            let mut sections = sections_by(items, |item| item.project.clone().unwrap_or_default());
            sections.sort_by(|a, b| {
                a.key
                    .is_empty()
                    .cmp(&b.key.is_empty())
                    .then_with(|| compare_names(&a.key, &b.key))
            });
            sections
        }
        ListGrouping::Letter => {
            let counts: std::collections::HashMap<String, usize> = if combine {
                site_counts(&items)
                    .into_iter()
                    .map(|(site, n)| (site.to_owned(), n))
                    .collect()
            } else {
                Default::default()
            };
            let mut sections = sections_by(items, |item| {
                let site = item
                    .site
                    .as_ref()
                    .filter(|site| counts.get(*site).is_some_and(|n| *n > 1));
                first_letter(site.unwrap_or(&item.title).clone())
            });
            sections.sort_by(|a, b| {
                let other = |s: &ListSection| s.key == OTHER_LETTER;
                other(a).cmp(&other(b)).then_with(|| {
                    let order = compare_names(&a.key, &b.key);
                    if sort == ListSort::NameDesc {
                        order.reverse()
                    } else {
                        order
                    }
                })
            });
            sections
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(
        id: &str,
        title: &str,
        item_type: ItemType,
        created: &str,
        changed: &str,
    ) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            vault_id: if id < "m" { "a".into() } else { "b".into() },
            item_type,
            title: title.into(),
            subtitle: None,
            urls: vec!["https://example.com".into()],
            tags: vec!["Work".into()],
            favorite: false,
            has_totp: false,
            has_passkey: false,
            attachment_count: 0,
            created_at: created.into(),
            updated_at: changed.into(),
            deleted_at: None,
            site: None,
            icon_domain: None,
            project: None,
            stage: None,
            variable_keys: Vec::new(),
            pinned: false,
            places: Vec::new(),
        }
    }

    fn titles(sections: &[ListSection]) -> Vec<Vec<String>> {
        sections
            .iter()
            .map(|s| s.items.iter().map(|i| i.title.clone()).collect())
            .collect()
    }

    #[test]
    fn names_compare_like_the_web_collator() {
        let mut names = [
            "item 10", "Item 2", "éclair", "Zebra", "apple", "#tag", "ابل",
        ];
        names.sort_by(|a, b| compare_names(a, b));
        assert_eq!(
            names,
            [
                "#tag", "apple", "éclair", "Item 2", "item 10", "Zebra", "ابل"
            ]
        );
        assert_eq!(compare_names("Café", "cafe"), Ordering::Equal);
    }

    #[test]
    fn letters_drop_accents_and_marks() {
        assert_eq!(first_letter(" éclair".into()), "E");
        assert_eq!(first_letter("أحمد".into()), "ا");
        assert_eq!(first_letter("ٱلله".into()), "ا");
        assert_eq!(first_letter("42".into()), "#");
        assert_eq!(first_letter("".into()), "#");
    }

    #[test]
    fn sorts_and_sections_follow_list_order() {
        let items = vec![
            summary(
                "a1",
                "Bank",
                ItemType::Card,
                "2026-01-02T00:00:00Z",
                "2026-03-01T00:00:00Z",
            ),
            summary(
                "a2",
                "apple",
                ItemType::Login,
                "2026-01-03T00:00:00Z",
                "2026-01-03T00:00:00Z",
            ),
            summary(
                "n1",
                "7-Eleven",
                ItemType::Login,
                "2026-01-01T00:00:00Z",
                "2026-02-01T00:00:00Z",
            ),
            summary(
                "n2",
                "Note",
                ItemType::Other {
                    name: "vehicle".into(),
                },
                "",
                "2026-01-05T00:00:00Z",
            ),
        ];
        let by = |sort, grouping| {
            titles(&arrange(
                items.clone(),
                sort,
                grouping,
                &["b".into()],
                false,
            ))
        };
        assert_eq!(
            by(ListSort::Name, ListGrouping::None),
            [["7-Eleven", "apple", "Bank", "Note"]]
        );
        assert_eq!(
            by(ListSort::Newest, ListGrouping::None),
            [["Note", "apple", "Bank", "7-Eleven"]]
        );
        assert_eq!(
            by(ListSort::Changed, ListGrouping::None),
            [["Bank", "7-Eleven", "Note", "apple"]]
        );
        assert_eq!(
            by(ListSort::Name, ListGrouping::Type),
            vec![vec!["7-Eleven", "apple"], vec!["Bank"], vec!["Note"]]
        );
        assert_eq!(
            by(ListSort::Name, ListGrouping::Vault),
            vec![vec!["7-Eleven", "Note"], vec!["apple", "Bank"]]
        );
        let letters = arrange(
            items.clone(),
            ListSort::NameDesc,
            ListGrouping::Letter,
            &[],
            false,
        );
        let keys: Vec<&str> = letters.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(keys, ["N", "B", "A", "#"]);
        assert!(arrange(Vec::new(), ListSort::Name, ListGrouping::None, &[], false).is_empty());
    }

    #[test]
    fn filters_and_search() {
        let mut item = summary("a1", "Crème Brûlée", ItemType::Login, "", "");
        let filter = |query: &str| ItemFilter {
            query: Some(query.into()),
            ..ItemFilter::default()
        };
        assert!(matches_filter(&item, &filter("creme  BRULEE")));
        assert!(matches_filter(&item, &filter("example work")));
        assert!(!matches_filter(&item, &filter("creme pie")));
        assert!(!matches_filter(
            &item,
            &ItemFilter {
                favorites: true,
                ..ItemFilter::default()
            }
        ));
        item.deleted_at = Some("2026-01-01T00:00:00Z".into());
        assert!(!matches_filter(&item, &ItemFilter::default()));
        assert!(matches_filter(
            &item,
            &ItemFilter {
                trash: true,
                ..ItemFilter::default()
            }
        ));
        let provider = summary("a2", "addy.io", ItemType::MaskedEmailProvider, "", "");
        assert!(!matches_filter(&provider, &ItemFilter::default()));
        assert!(matches_filter(
            &provider,
            &ItemFilter {
                item_type: Some(ItemType::MaskedEmailProvider),
                ..ItemFilter::default()
            }
        ));
    }

    fn login(id: &str, title: &str, url: &str, created: &str) -> ItemSummary {
        let mut item = summary(id, title, ItemType::Login, created, created);
        item.urls = vec![url.into()];
        item.site = site_host(url);
        item
    }

    #[test]
    fn site_hosts_follow_the_web_vault() {
        assert_eq!(
            site_host("https://www.Example.com./login"),
            Some("example.com".into())
        );
        assert_eq!(site_host("nas.local:5000"), Some("nas.local:5000".into()));
        assert_eq!(
            site_host("https://example.com:443"),
            Some("example.com".into())
        );
        assert_eq!(site_host("a.example.com"), Some("a.example.com".into()));
        assert_eq!(site_host("mailto:me@example.com"), None);
        assert_eq!(site_host("not a url"), None);
        assert_eq!(site_host(""), None);
    }

    #[test]
    fn logins_for_one_site_share_a_row() {
        let items = vec![
            login("a1", "Work", "https://github.com", "2026-01-01T00:00:00Z"),
            login("a2", "Bank", "https://bank.com", "2026-01-02T00:00:00Z"),
            login("a3", "Personal", "github.com/login", "2026-01-03T00:00:00Z"),
            login("a4", "Zoo", "https://zoo.org", "2026-01-04T00:00:00Z"),
        ];
        let names = |entries: &[ListEntry]| -> Vec<String> {
            entries
                .iter()
                .map(|entry| match entry {
                    ListEntry::Item { item } => item.title.clone(),
                    ListEntry::Site { host, items } => format!("{host} ({})", items.len()),
                })
                .collect()
        };
        let by_name = arrange(items.clone(), ListSort::Name, ListGrouping::None, &[], true);
        assert_eq!(
            names(&by_name[0].entries),
            ["Bank", "github.com (2)", "Zoo"]
        );
        assert_eq!(by_name[0].items.len(), 4);
        // In date order, the row takes its first login's place.
        let newest = arrange(
            items.clone(),
            ListSort::Newest,
            ListGrouping::None,
            &[],
            true,
        );
        assert_eq!(names(&newest[0].entries), ["Zoo", "github.com (2)", "Bank"]);
        // By letter, a site's logins are filed under its host.
        let letters = arrange(
            items.clone(),
            ListSort::Name,
            ListGrouping::Letter,
            &[],
            true,
        );
        let keys: Vec<&str> = letters.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(keys, ["B", "G", "Z"]);
        assert!(
            arrange(items, ListSort::Name, ListGrouping::None, &[], false)[0]
                .entries
                .is_empty()
        );
    }

    #[test]
    fn arrangements_default_per_list() {
        assert_eq!(
            default_arrangement("all".into()).grouping,
            ListGrouping::Type
        );
        assert_eq!(
            default_arrangement("login".into()).grouping,
            ListGrouping::Letter
        );
        assert_eq!(
            list_groupings("login".into(), 1),
            [ListGrouping::Letter, ListGrouping::None]
        );
        assert_eq!(
            list_groupings("all".into(), 2),
            [
                ListGrouping::Type,
                ListGrouping::Letter,
                ListGrouping::Vault,
                ListGrouping::None
            ]
        );
        let saved = ListArrangement {
            sort: ListSort::Newest,
            grouping: ListGrouping::Type,
        };
        // A list of one type can't be grouped by type: its default grouping is used.
        assert_eq!(
            resolve_arrangement(Some(&saved), "card", 1),
            ListArrangement {
                sort: ListSort::Newest,
                grouping: ListGrouping::Letter
            }
        );
        assert!(offers_site_rows("all".into()));
        assert!(offers_site_rows("login".into()));
        assert!(!offers_site_rows("codes".into()));
        assert!(!offers_site_rows("card".into()));
    }

    #[test]
    fn counts_follow_the_sidebar() {
        let mut fav = summary("a1", "A", ItemType::Login, "", "");
        fav.favorite = true;
        fav.has_totp = true;
        let mut card = summary("n1", "B", ItemType::Card, "", "");
        card.pinned = true;
        let counts = counts(&[fav, card], 3);
        assert_eq!(counts["all"], 2);
        assert_eq!(counts["favorites"], 1);
        assert_eq!(counts["pinned"], 1);
        assert_eq!(counts["codes"], 1);
        assert_eq!(counts["passkeys"], 0);
        assert_eq!(counts["trash"], 3);
        assert_eq!(counts["card"], 1);
        assert_eq!((counts["v-a"], counts["v-b"]), (1, 1));
    }

    #[test]
    fn the_codes_list_has_only_logins_with_codes() {
        let mut with_code = summary("a1", "A", ItemType::Login, "", "");
        with_code.has_totp = true;
        let without = summary("a2", "B", ItemType::Login, "", "");
        let filter = ItemFilter {
            totp: true,
            ..ItemFilter::default()
        };
        assert!(matches_filter(&with_code, &filter));
        assert!(!matches_filter(&without, &filter));
    }
}
