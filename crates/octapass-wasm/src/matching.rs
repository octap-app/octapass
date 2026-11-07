//! Which saved logins belong to a page.

use octapass_core::item::EquivalentDomainsDetails;
use octapass_core::matching::{self, Candidate, MatchOptions};
use wasm_bindgen::prelude::*;

use crate::{from_js, js_error, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** `subdomains` (the default): the page's own host, a domain above it or a host below it, on one registrable domain. `baseDomain`: any host on the registrable domain. */
export type MatchMode = "subdomains" | "baseDomain" | "host" | "startsWith" | "regex" | "never";
/** An item to match: its id plus its overview (`urls`, and `urlMatch` for per-URL modes). Other fields are ignored. */
export type MatchCandidate = { id: string; urls?: string[]; urlMatch?: Record<string, MatchMode>; [field: string]: unknown };
export type MatchOptions = {
  /** For URLs without their own mode. Default "subdomains". */
  defaultMode?: MatchMode;
  /** Extra groups of registrable domains treated as one site. */
  equivalentDomains?: string[][];
  /** Whether the built-in groups (google.com/youtube.com, apple.com/icloud.com …) apply. Default true. */
  defaultEquivalents?: boolean;
  /** Built-in groups turned off, each named by its first domain. */
  excludedDefaults?: string[];
};
/** What `cleanEquivalentGroups` made of what the user typed. */
export type CleanedGroups = { groups: string[][]; rejected: string[] };
/** The details of a hidden `equivalentDomains` item. */
export type EquivalentDomainsDetails = { groups: string[][]; excludedDefaults?: string[]; [field: string]: unknown };
export type MatchQuality = "exact" | "domain" | "equivalent";
/** `schemeMismatch`: the page and the saved URL disagree on http/https; warn before filling on http. */
export type ItemMatch = { id: string; url: string; quality: MatchQuality; schemeMismatch: boolean };
/** A login saved for another part of the page's domain, which isn't offered: `host` to show (Unicode, no `www.`), `site` the shared domain ("example.com"). */
export type OtherPart = { id: string; url: string; host: string; site: string; schemeMismatch: boolean };
"#;

/// The items that match `url`, best first: the page's own host, a domain above it (nearest
/// first), a host below it, then equivalent domains (plan 05, *Filling rules*). Throws
/// `invalid_url` if the page isn't an http(s) address.
#[wasm_bindgen(js_name = matchItems, unchecked_return_type = "ItemMatch[]")]
pub fn match_items(
    url: String,
    #[wasm_bindgen(unchecked_param_type = "MatchCandidate[]")] items: JsValue,
    #[wasm_bindgen(unchecked_param_type = "MatchOptions | undefined")] options: JsValue,
) -> Result<JsValue, JsValue> {
    let items: Vec<Candidate> = from_js(items, "items")?;
    let options: MatchOptions = options_from_js(options, "match options")?;
    to_js(&matching::match_items(&url, &items, &options).map_err(js_error)?)
}

/// The items saved for another part of the page's registrable domain (`shop.example.com` on
/// `login.example.com`) under the default mode, which `matchItems` leaves out: for a "Logins for
/// other parts of example.com" entry the user opens by hand, never for filling on its own.
/// Sorted by host. Throws `invalid_url` like `matchItems`.
#[wasm_bindgen(js_name = otherParts, unchecked_return_type = "OtherPart[]")]
pub fn other_parts(
    url: String,
    #[wasm_bindgen(unchecked_param_type = "MatchCandidate[]")] items: JsValue,
    #[wasm_bindgen(unchecked_param_type = "MatchOptions | undefined")] options: JsValue,
) -> Result<JsValue, JsValue> {
    let items: Vec<Candidate> = from_js(items, "items")?;
    let options: MatchOptions = options_from_js(options, "match options")?;
    to_js(&matching::other_parts(&url, &items, &options).map_err(js_error)?)
}

/// The website to add to a login filled from another part of its domain: the page's scheme,
/// host and port (`https://login.example.com`). `undefined` for what isn't a website.
#[wasm_bindgen(js_name = websiteForPage)]
pub fn website_for_page(url: String) -> Option<String> {
    matching::website_for_page(&url)
}

/// Turns the domains the user typed into groups the matcher can use: registrable domains, groups
/// that overlap joined, and what can't be matched on (public suffixes, addresses) in `rejected`.
#[wasm_bindgen(js_name = cleanEquivalentGroups, unchecked_return_type = "CleanedGroups")]
pub fn clean_equivalent_groups(
    #[wasm_bindgen(unchecked_param_type = "string[][]")] groups: JsValue,
) -> Result<JsValue, JsValue> {
    let groups: Vec<Vec<String>> = from_js(groups, "groups")?;
    to_js(&matching::clean_equivalent_groups(&groups))
}

/// The built-in equivalent domains, each group led by the domain that names it.
#[wasm_bindgen(js_name = defaultEquivalentDomains, unchecked_return_type = "string[][]")]
pub fn default_equivalent_domains() -> Result<JsValue, JsValue> {
    to_js(&matching::DEFAULT_EQUIVALENT_DOMAINS)
}

/// The match options for the user's `equivalentDomains` items (every copy of them).
#[wasm_bindgen(js_name = equivalentMatchOptions, unchecked_return_type = "MatchOptions")]
pub fn equivalent_match_options(
    #[wasm_bindgen(unchecked_param_type = "EquivalentDomainsDetails[]")] settings: JsValue,
) -> Result<JsValue, JsValue> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Options {
        equivalent_domains: Vec<Vec<String>>,
        excluded_defaults: Vec<String>,
    }
    let settings: Vec<EquivalentDomainsDetails> = from_js(settings, "settings")?;
    let options = matching::user_equivalents(&settings);
    to_js(&Options {
        equivalent_domains: options.equivalent_domains,
        excluded_defaults: options.excluded_defaults,
    })
}

/// The registrable domain (eTLD+1, from the Public Suffix List) of a URL or host, in punycode:
/// `accounts.google.com` → `google.com`. `undefined` for IP addresses, single-label hosts and
/// public suffixes themselves.
#[wasm_bindgen(js_name = registrableDomain)]
pub fn registrable_domain(url: String) -> Option<String> {
    matching::Site::parse(&url).ok()?.domain
}
