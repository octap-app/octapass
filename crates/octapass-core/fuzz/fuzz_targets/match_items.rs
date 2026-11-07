#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::matching::{
    Candidate, MatchMode, MatchOptions, match_items, other_parts, website_for_page,
};

// The input is a page URL and saved URLs, one per line; every mode is tried on each.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut lines = text.lines();
    let Some(page) = lines.next() else { return };
    let urls: Vec<String> = lines.map(str::to_string).collect();
    let modes = [MatchMode::Subdomains, MatchMode::BaseDomain, MatchMode::Host, MatchMode::StartsWith, MatchMode::Regex, MatchMode::Never];
    let candidates: Vec<Candidate> = modes
        .iter()
        .enumerate()
        .map(|(i, mode)| Candidate {
            id: i.to_string(),
            urls: urls.clone(),
            url_match: urls.iter().map(|url| (url.clone(), *mode)).collect(),
        })
        .collect();
    let _ = match_items(page, &candidates, &MatchOptions::default());
    let _ = other_parts(page, &candidates, &MatchOptions::default());
    let _ = website_for_page(page);
});
