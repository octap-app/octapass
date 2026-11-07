//! Site password rules (Apple's `passwordrules` syntax) and generating passwords that satisfy them.

use octapass_core::rules::{self, PasswordRules};
use octapass_core::tools::generator::RandomOptions;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use crate::{from_js, js_error, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type NamedCharacterClass = "upper" | "lower" | "digit" | "special" | "ascii-printable" | "unicode";
export type CharacterClass = { named: NamedCharacterClass[]; custom: string };
export type PasswordRules = {
  minLength?: number;
  maxLength?: number;
  maxConsecutive?: number;
  /** The password needs at least one character from each. */
  required: CharacterClass[];
  allowed?: CharacterClass;
};
/** The user's random-password settings (`GeneratorOptions` without `type`). */
export type RandomGeneratorOptions = { length?: number; lowercase?: boolean; uppercase?: boolean; digits?: boolean; symbols?: boolean; avoidAmbiguous?: boolean };
"#;

/// Parses `passwordrules` text. Never throws: unknown or malformed parts are skipped. To combine
/// sources (the site dataset, the field's attribute, `minlength`/`maxlength`), join their texts
/// with `;`.
#[wasm_bindgen(js_name = parsePasswordRules, unchecked_return_type = "PasswordRules")]
pub fn parse_password_rules(text: String) -> Result<JsValue, JsValue> {
    to_js(&rules::parse(&text))
}

/// The rules text the embedded per-site dataset has for a URL, if any (join it with the field's
/// own `passwordrules` before parsing).
#[wasm_bindgen(js_name = passwordRulesTextForSite)]
pub fn password_rules_text_for_site(url: String) -> Option<String> {
    rules::rules_text_for_site(&url).map(str::to_string)
}

/// A suggested password for a site: the user's `options`, adjusted to the dataset's rules for `url`
/// and the form field's own `fieldRules`. Rules that contradict each other are ignored.
#[wasm_bindgen(js_name = generateForSite)]
pub fn generate_for_site(
    url: String,
    #[wasm_bindgen(js_name = fieldRules)] field_rules: Option<String>,
    #[wasm_bindgen(unchecked_param_type = "RandomGeneratorOptions | undefined")] options: JsValue,
) -> Result<String, JsValue> {
    let options: RandomOptions = options_from_js(options, "generator options")?;
    rules::generate_for_site(&url, field_rules.as_deref(), &options, &mut OsRng)
        .map(|password| password.to_string())
        .map_err(js_error)
}

/// A random password that satisfies `rules`, as close to the user's `options` as they allow.
/// Throws `invalid_password_rules` when no password can satisfy them.
#[wasm_bindgen(js_name = generateForRules)]
pub fn generate_for_rules(
    #[wasm_bindgen(unchecked_param_type = "PasswordRules")] rules: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RandomGeneratorOptions | undefined")] options: JsValue,
) -> Result<String, JsValue> {
    let rules: PasswordRules = from_js(rules, "password rules")?;
    let options: RandomOptions = options_from_js(options, "generator options")?;
    rules::generate_for_rules(&rules, &options, &mut OsRng)
        .map(|password| password.to_string())
        .map_err(js_error)
}
