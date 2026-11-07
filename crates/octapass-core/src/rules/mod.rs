//! Site password rules in Apple's `passwordrules` syntax, from a field's `passwordrules`
//! attribute or the embedded per-site dataset, and a generator that satisfies them.
//!
//! ```text
//! minlength: 8; maxlength: 16; required: lower; required: upper, digit; allowed: [-_.]; max-consecutive: 2;
//! ```
//!
//! Each `required` line is one set the password needs at least one character from (`upper,
//! digit` means either). `allowed` lines add to the characters that may appear; without any, the
//! required sets are the alphabet, and without either it's all printable ASCII. Repeated
//! `minlength` keeps the largest value and `maxlength` / `max-consecutive` the smallest, so rules
//! from several sources (the dataset, the attribute, `minlength`/`maxlength` attributes written as
//! rules) combine by concatenating their text.
//!
//! The dataset is `quirks/password-rules.json` from Apple's
//! [password-manager-resources](https://github.com/apple/password-manager-resources) at commit
//! `91dff9aaa4d37a7e80aac3024150643d7d153392` (MIT licence, see `password-rules.LICENSE.md`;
//! SHA-256 `d3dc3b25…37263531`).

mod generate;
mod parse;

use std::collections::HashMap;
use std::sync::OnceLock;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use generate::generate_for_rules;
pub use parse::parse;

use crate::error::{Error, Result};
use crate::matching::Site;
use crate::tools::generator::RandomOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NamedClass {
    Upper,
    Lower,
    Digit,
    /// `-~!@#$%^&*_+=`|(){}[:;"'<>,.?]` and space.
    Special,
    AsciiPrintable,
    /// Any character. Generated passwords stay within printable ASCII.
    Unicode,
}

/// A set of characters: named classes plus custom characters (`[-_.]` in the syntax).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CharacterClass {
    pub named: Vec<NamedClass>,
    pub custom: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PasswordRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    /// No character may repeat more than this many times in a row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_consecutive: Option<usize>,
    pub required: Vec<CharacterClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<CharacterClass>,
}

impl PasswordRules {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

const DATASET: &str = include_str!("password-rules.json");

fn dataset() -> &'static HashMap<String, String> {
    static RULES: OnceLock<HashMap<String, String>> = OnceLock::new();
    RULES.get_or_init(|| {
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "password-rules")]
            rules: String,
        }
        let entries: HashMap<String, Entry> =
            serde_json::from_str(DATASET).expect("the embedded dataset is valid JSON");
        entries
            .into_iter()
            .map(|(domain, entry)| (domain, entry.rules))
            .collect()
    })
}

/// The dataset's rules text for a website, if it has any: the entry for the host itself or
/// for the nearest parent domain, up to the registrable domain (never a public suffix).
pub fn rules_text_for_site(url: &str) -> Option<&'static str> {
    let site = Site::parse(url).ok()?;
    let floor = site.domain.as_deref().unwrap_or(&site.host);
    let mut host = site.host.as_str();
    loop {
        if let Some(rules) = dataset().get(host) {
            return Some(rules);
        }
        if host == floor {
            return None;
        }
        host = host.split_once('.')?.1;
    }
}

/// The dataset's rules for a website, parsed.
pub fn rules_for_site(url: &str) -> Option<PasswordRules> {
    rules_text_for_site(url).map(parse)
}

/// A suggested password for a site: the user's `options`, adjusted to what the dataset knows about
/// `url` and to `field_rules` (a form field's own `passwordrules`, with `minlength`/`maxlength`
/// written as rules). Rules that contradict each other are ignored rather than failing: the user
/// asked for a password, and a site that refuses it can still be retried with the generator.
pub fn generate_for_site(
    url: &str,
    field_rules: Option<&str>,
    options: &RandomOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    let text = [rules_text_for_site(url), field_rules]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(";");
    match generate_for_rules(&parse(&text), options, rng) {
        Err(Error::InvalidPasswordRules) => {
            generate_for_rules(&PasswordRules::default(), options, rng)
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dataset_entry_parses_to_something() {
        for (domain, text) in dataset() {
            assert!(!parse(text).is_empty(), "{domain}: {text}");
        }
        assert!(dataset().len() > 400);
    }

    #[test]
    fn suggestions_follow_the_site_and_the_field() {
        // apple.com's dataset entry: 8 to 63 characters, with an upper, a lower and a digit.
        let mut rng = rand_core::OsRng;
        let options = RandomOptions::default();
        let site = generate_for_site("https://apple.com", None, &options, &mut rng).unwrap();
        let rules = rules_for_site("https://apple.com").unwrap();
        assert!(site.len() <= rules.max_length.unwrap());
        // The field's rules tighten the site's.
        let tight = generate_for_site(
            "https://apple.com",
            Some("maxlength: 12; required: digit;"),
            &options,
            &mut rng,
        )
        .unwrap();
        assert!(tight.len() <= 12);
        assert!(tight.chars().any(|c| c.is_ascii_digit()));
        // No rules known: the user's settings as they are.
        let plain =
            generate_for_site("https://no-rules.example", None, &options, &mut rng).unwrap();
        assert_eq!(plain.len(), options.length);
        // Rules that can't be met still give a password.
        let impossible = "minlength: 50; maxlength: 10;";
        let fallback = generate_for_site(
            "https://no-rules.example",
            Some(impossible),
            &options,
            &mut rng,
        )
        .unwrap();
        assert_eq!(fallback.len(), options.length);
    }

    #[test]
    fn site_lookup_walks_up_to_the_registrable_domain() {
        assert_eq!(
            rules_text_for_site("https://163.com/login"),
            Some("minlength: 6; maxlength: 16;")
        );
        assert_eq!(
            rules_text_for_site("https://mail.163.com"),
            rules_text_for_site("https://163.com")
        );
        assert!(rules_text_for_site("https://access.service.gov.uk").is_some());
        // service.gov.uk isn't in the dataset, and gov.uk is above the registrable domain.
        assert_eq!(rules_text_for_site("https://other.service.gov.uk"), None);
        assert_eq!(rules_text_for_site("https://example.com"), None);
        assert_eq!(rules_text_for_site("not a url"), None);
        assert_eq!(rules_for_site("163.com").unwrap().max_length, Some(16));
    }

    #[test]
    fn rules_serialize_for_javascript() {
        let rules = parse("minlength: 8; required: upper, [-_]; max-consecutive: 2");
        assert_eq!(
            serde_json::to_value(&rules).unwrap(),
            serde_json::json!({ "minLength": 8, "maxConsecutive": 2, "required": [{ "named": ["upper"], "custom": "-_" }] })
        );
        let back: PasswordRules =
            serde_json::from_value(serde_json::to_value(&rules).unwrap()).unwrap();
        assert_eq!(back, rules);
    }
}
