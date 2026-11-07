//! One-time codes for a paired Apple Watch or Wear OS watch (plan 05 History, 2026-11-02).
//!
//! The phone issues the codes and the watch shows them: a TOTP seed never leaves the phone. While
//! the vault is unlocked and the per-phone setting is on, [`bundle`] computes the next
//! [`WATCH_BUNDLE_TTL_MS`] of codes for each item with a one-time code, with the core's generator,
//! so the watch has no one-time code logic of its own. What crosses is exactly [`WatchEntry`]: a
//! hash of the item's id, its title, the period, the code length and the codes. Never a username,
//! a URL, a seed or an `otpauth://` URI.
//!
//! The JSON here is the wire format. The apps pass it to the watch without reading it, so what
//! the watch may receive is decided in one place, and `tests/fixtures/watch-bundle.json` pins it
//! for the Swift and Kotlin readers.

use octapass_core::tools::totp;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The wire format's version. A watch ignores a version it doesn't know.
pub const WATCH_FORMAT: u32 = 1;
/// How far ahead a bundle reaches: all a stolen watch can give away. The watch forgets a bundle
/// at this age unless the phone sends a new one.
pub const WATCH_BUNDLE_TTL_MS: u64 = 15 * 60 * 1000;
/// Items per bundle, favourites first. A watch list longer than this isn't usable.
pub const WATCH_MAX_ENTRIES: usize = 50;
/// Codes per item. Fifteen minutes of a 30-second code is 30; an item with a period under 15
/// seconds runs out early rather than growing the bundle.
pub const WATCH_MAX_CODES: usize = 60;
/// Characters of a title. Watch rows show less than this.
pub const WATCH_MAX_TITLE: usize = 64;

/// What the phone reads an item into. Stays in Rust.
pub(crate) struct WatchSource {
    pub item_id: String,
    pub title: String,
    pub favorite: bool,
    /// The item's `totp` field: a seed. Used here and dropped.
    pub totp: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WatchEntry {
    /// A hash of the item's id, for the watch's list. Means nothing to anyone else.
    pub id: String,
    pub title: String,
    pub favorite: bool,
    /// Seconds per code.
    pub period: u64,
    /// Characters per code, from the first code itself.
    pub digits: u32,
    /// When `codes[0]` started (Unix milliseconds). `codes[n]` starts `n` periods later.
    pub start_ms: u64,
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WatchBundle {
    pub v: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub entries: Vec<WatchEntry>,
}

/// A stable name for an item that doesn't repeat its id off the phone.
fn opaque_id(item_id: &str) -> String {
    let digest = Sha256::digest(format!("octapass/watch/v1:{item_id}").as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Every code from the one current at `now_ms` until `expires_at_ms`, or `None` for anything the
/// core can't make a time-based code from (a counter-based code, a broken seed).
fn entry(source: &WatchSource, now_ms: u64, expires_at_ms: u64) -> Option<WatchEntry> {
    let first = totp::totp_code(&source.totp, now_ms / 1000).ok()?;
    let period_ms = first.period.checked_mul(1000)?;
    let start_ms = now_ms - now_ms % period_ms;
    let digits = first.code.chars().count() as u32;
    let mut codes = vec![first.code];
    let mut next_ms = start_ms + period_ms;
    while next_ms < expires_at_ms && codes.len() < WATCH_MAX_CODES {
        codes.push(totp::totp_code(&source.totp, next_ms / 1000).ok()?.code);
        next_ms += period_ms;
    }
    Some(WatchEntry {
        id: opaque_id(&source.item_id),
        title: source.title.chars().take(WATCH_MAX_TITLE).collect(),
        favorite: source.favorite,
        period: first.period,
        digits,
        start_ms,
        codes,
    })
}

/// The bundle for `sources`, in order, up to [`WATCH_MAX_ENTRIES`]. Items the core can't make
/// time-based codes for are skipped and don't use up a place.
pub(crate) fn bundle(sources: &[WatchSource], now_ms: u64) -> WatchBundle {
    let expires_at_ms = now_ms + WATCH_BUNDLE_TTL_MS;
    WatchBundle {
        v: WATCH_FORMAT,
        issued_at_ms: now_ms,
        expires_at_ms,
        entries: sources
            .iter()
            .filter_map(|source| entry(source, now_ms, expires_at_ms))
            .take(WATCH_MAX_ENTRIES)
            .collect(),
    }
}

/// Tells the watch to forget everything: locked, signed out or turned off.
pub(crate) fn clear_json(now_ms: u64) -> String {
    json!({ "v": WATCH_FORMAT, "clear": true, "issuedAtMs": now_ms }).to_string()
}

pub(crate) fn bundle_json(sources: &[WatchSource], now_ms: u64) -> String {
    serde_json::to_string(&bundle(sources, now_ms)).unwrap_or_else(|_| clear_json(now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A moment in the middle of a 30-second step.
    const NOW: u64 = 1_700_000_012_345;
    const SEED: &str = "JBSWY3DPEHPK3PXP";

    fn source(id: &str, title: &str, totp: &str) -> WatchSource {
        WatchSource {
            item_id: id.into(),
            title: title.into(),
            favorite: false,
            totp: Zeroizing::new(totp.into()),
        }
    }

    #[test]
    fn codes_cover_the_bundle_and_match_the_core() {
        let bundle = bundle(&[source("a", "GitHub", SEED)], NOW);
        assert_eq!(bundle.issued_at_ms, NOW);
        assert_eq!(bundle.expires_at_ms, NOW + 15 * 60 * 1000);
        let entry = &bundle.entries[0];
        assert_eq!((entry.period, entry.digits), (30, 6));
        assert_eq!(entry.start_ms, 1_699_999_980_000 + 30_000);
        assert!(entry.start_ms <= NOW && NOW - entry.start_ms < 30_000);
        // The step that's current now, then one for each step that starts before the end.
        assert_eq!(entry.codes.len(), 31);
        let last = entry.start_ms + 30_000 * (entry.codes.len() as u64 - 1);
        assert!(last < bundle.expires_at_ms && last + 30_000 >= bundle.expires_at_ms);
        for (n, code) in entry.codes.iter().enumerate() {
            let at = entry.start_ms / 1000 + 30 * n as u64;
            assert_eq!(*code, totp::totp_code(SEED, at).unwrap().code);
        }
    }

    #[test]
    fn every_variant_comes_from_the_core() {
        // RFC 6238's SHA-256 seed, 8 digits, 60 seconds.
        let uri = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA\
                   &algorithm=SHA256&digits=8&period=60";
        let bundle = bundle(&[source("a", "Bank", uri)], NOW);
        let entry = &bundle.entries[0];
        assert_eq!((entry.period, entry.digits), (60, 8));
        assert_eq!(entry.codes.len(), 16);
        assert_eq!(
            entry.codes[0],
            totp::totp_code(uri, entry.start_ms / 1000).unwrap().code
        );
    }

    #[test]
    fn counter_based_and_broken_codes_are_left_out_without_a_place() {
        let mut sources = vec![
            source(
                "hotp",
                "Counter",
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
            ),
            source(
                "steam",
                "Steam",
                "otpauth://steam/x?secret=JBSWY3DPEHPK3PXP",
            ),
            source("broken", "Broken", "not base32 !"),
        ];
        sources.extend((0..WATCH_MAX_ENTRIES).map(|n| source(&n.to_string(), "Code", SEED)));
        let bundle = bundle(&sources, NOW);
        assert_eq!(bundle.entries.len(), WATCH_MAX_ENTRIES);
        assert!(bundle.entries.iter().all(|e| e.title == "Code"));
    }

    #[test]
    fn the_order_given_decides_who_makes_the_cap() {
        let mut sources: Vec<WatchSource> = (0..WATCH_MAX_ENTRIES + 5)
            .map(|n| source(&n.to_string(), &format!("Item {n}"), SEED))
            .collect();
        sources[0].favorite = true;
        let bundle = bundle(&sources, NOW);
        assert_eq!(bundle.entries.len(), WATCH_MAX_ENTRIES);
        assert_eq!(bundle.entries[0].title, "Item 0");
        assert!(bundle.entries[0].favorite);
        assert_eq!(bundle.entries.last().unwrap().title, "Item 49");
    }

    #[test]
    fn nothing_but_the_codes_and_their_labels_crosses() {
        let seed_uri = format!("otpauth://totp/Acme:jane@example.com?secret={SEED}&issuer=Acme");
        let json = bundle_json(&[source("item-id-1", "GitHub", &seed_uri)], NOW);
        for leak in [
            SEED,
            "otpauth",
            "secret",
            "jane",
            "example.com",
            "Acme",
            "item-id-1",
        ] {
            assert!(!json.contains(leak), "{leak} crossed: {json}");
        }
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut keys: Vec<&String> = value["entries"][0].as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "codes", "digits", "favorite", "id", "period", "startMs", "title"
            ]
        );
        let mut keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["entries", "expiresAtMs", "issuedAtMs", "v"]);
    }

    #[test]
    fn ids_are_stable_and_not_the_items() {
        let one = opaque_id("item-1");
        assert_eq!(one, opaque_id("item-1"));
        assert_ne!(one, opaque_id("item-2"));
        assert_eq!(one.len(), 32);
    }

    #[test]
    fn titles_are_cut_by_character() {
        let title = "ب".repeat(WATCH_MAX_TITLE + 10);
        let bundle = bundle(&[source("a", &title, SEED)], NOW);
        assert_eq!(bundle.entries[0].title.chars().count(), WATCH_MAX_TITLE);
    }

    /// Watch Connectivity's messages and Wear's message client refuse more than this. Every
    /// other limit in this file exists to stay under it.
    #[test]
    fn the_largest_bundle_fits_a_message() {
        const MESSAGE_LIMIT: usize = 64 * 1024;
        let uri = format!("otpauth://totp/x?secret={SEED}&digits=8&period=5");
        let title = "\u{1F510}".repeat(WATCH_MAX_TITLE);
        let sources: Vec<WatchSource> = (0..WATCH_MAX_ENTRIES)
            .map(|n| source(&n.to_string(), &title, &uri))
            .collect();
        let bundle = bundle(&sources, NOW);
        assert!(
            bundle
                .entries
                .iter()
                .all(|e| e.codes.len() == WATCH_MAX_CODES)
        );
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.len() < MESSAGE_LIMIT, "{} bytes", json.len());
    }

    #[test]
    fn a_clear_says_only_that() {
        let value: serde_json::Value = serde_json::from_str(&clear_json(NOW)).unwrap();
        assert_eq!(value, json!({ "v": 1, "clear": true, "issuedAtMs": NOW }));
    }

    /// The Swift and Kotlin tests read this file: the format can't change without them noticing.
    #[test]
    fn the_shared_fixture_is_what_the_phone_sends() {
        let mut favourite = source("fixture-1", "GitHub", SEED);
        favourite.favorite = true;
        let sources = [
            favourite,
            source(
                "fixture-2",
                "بنك الأمل",
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256",
            ),
        ];
        let produced = serde_json::to_string_pretty(&bundle(&sources, NOW)).unwrap();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/watch-bundle.json"
        );
        if std::env::var_os("OCTAPASS_WRITE_FIXTURES").is_some() {
            std::fs::write(path, format!("{produced}\n")).unwrap();
        }
        let stored = std::fs::read_to_string(path).unwrap();
        assert_eq!(stored.trim_end(), produced);
    }
}
