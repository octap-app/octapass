//! Local tools. None of them send anything anywhere.

use octapass_core::Error;
use octapass_core::device;
use octapass_core::secret_key::SecretKey;
#[cfg(feature = "strength")]
use octapass_core::tools::strength;
#[cfg(feature = "toolkit")]
use octapass_core::tools::toolkit;
use octapass_core::tools::{breach, generator, otpauth, qr, ssh, totp};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{from_js, js_error, to_js};

/// Generates a random password or passphrase.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(
    #[wasm_bindgen(unchecked_param_type = "GeneratorOptions")] options: JsValue,
) -> Result<String, JsValue> {
    let options: generator::GeneratorOptions = from_js(options, "generator options")?;
    generator::generate(&options, &mut OsRng)
        .map(|password| password.to_string())
        .map_err(js_error)
}

/// Estimates strength with zxcvbn. `userInputs` (email, name, site) count against the password.
#[cfg(feature = "strength")]
#[wasm_bindgen(js_name = estimateStrength, unchecked_return_type = "Strength")]
pub fn estimate_strength(
    password: String,
    #[wasm_bindgen(js_name = userInputs)] user_inputs: Option<Vec<String>>,
) -> Result<JsValue, JsValue> {
    let password = Zeroizing::new(password);
    let user_inputs = user_inputs.unwrap_or_default();
    let inputs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    to_js(&strength::estimate(&password, &inputs))
}

/// The TOTP code for an item's `totp` field (`otpauth://totp/…` or a base32 secret) at
/// `atUnixSeconds` (default: now).
#[wasm_bindgen(js_name = totpCode, unchecked_return_type = "TotpCode")]
pub fn totp_code(
    totp: String,
    #[wasm_bindgen(js_name = atUnixSeconds)] at_unix_seconds: Option<f64>,
) -> Result<JsValue, JsValue> {
    let totp = Zeroizing::new(totp);
    let at = at_unix_seconds.unwrap_or_else(|| js_sys::Date::now() / 1000.0);
    if !(at.is_finite() && at >= 0.0) {
        return Err(js_error(Error::InvalidTotp));
    }
    to_js(&totp::totp_code(&totp, at as u64).map_err(js_error)?)
}

#[wasm_bindgen(typescript_custom_section)]
const HOTP_TYPES: &str = r#"
/** A counter-based code and the `totp` field to save before showing it. */
export type NextHotpCode = { code: string; counter: number; totp: string };
"#;

/// The next counter-based code of an `otpauth://hotp/…` field, and the field with its counter
/// moved on. Save `totp` before showing `code`, so a code is never handed out twice.
#[wasm_bindgen(js_name = nextHotpCode, unchecked_return_type = "NextHotpCode")]
pub fn next_hotp_code(totp: String) -> Result<JsValue, JsValue> {
    #[derive(serde::Serialize)]
    struct Next<'a> {
        code: &'a str,
        counter: u64,
        totp: &'a str,
    }
    let (code, stored) = totp::next_hotp_code(&Zeroizing::new(totp)).map_err(js_error)?;
    to_js(&Next {
        code: &code.code,
        counter: code.counter,
        totp: &stored,
    })
}

/// An `otpauth://hotp/…` field with its counter set, for bringing it back in step with the site.
#[wasm_bindgen(js_name = withHotpCounter)]
pub fn with_hotp_counter(totp: String, counter: f64) -> Result<String, JsValue> {
    if !(counter.is_finite() && counter >= 0.0 && counter.fract() == 0.0) {
        return Err(js_error(Error::InvalidTotp));
    }
    totp::with_hotp_counter(&Zeroizing::new(totp), counter as u64)
        .map(|uri| uri.to_string())
        .map_err(js_error)
}

/// Converts a Google Authenticator export (`otpauth-migration://offline?data=…`) into one
/// `otpauth://` URI per account, ready for an item's `totp` field.
#[wasm_bindgen(js_name = parseOtpMigration)]
pub fn parse_otp_migration(uri: String) -> Result<Vec<String>, JsValue> {
    let accounts = otpauth::parse_migration(&Zeroizing::new(uri)).map_err(js_error)?;
    Ok(accounts
        .iter()
        .map(|account| account.to_uri().to_string())
        .collect())
}

#[wasm_bindgen(typescript_custom_section)]
const QR_TYPES: &str = r#"
/** What scanned QR codes hold. `codes` are `otpauth://` links: they hold secrets. */
export type QrScan = {
  codes: { uri: string; issuer?: string; account?: string; counterBased: boolean }[];
  /** Google Authenticator exports split over several QR codes that still miss some (`scanned` counts from 1). */
  incomplete: { id: number; size: number; scanned: number[] }[];
  /** QR codes that aren't one-time codes. */
  other: number;
  /** QR codes that look like one-time codes but can't be read. */
  broken: number;
};
"#;

/// The text of every QR code in a PNG, JPEG, WebP or GIF image, read here on the device. Throws
/// `invalid_image` when the bytes aren't such an image; an image without QR codes gives `[]`. Not in
/// the web vault's build, which decodes images with the browser for [`read_qr_pixels`].
#[cfg(feature = "qr-images")]
#[wasm_bindgen(js_name = readQrImage)]
pub fn read_qr_image(bytes: Vec<u8>) -> Result<Vec<String>, JsValue> {
    qr::read_image(&Zeroizing::new(bytes)).map_err(js_error)
}

/// [`read_qr_image`] for pixels the page already has: 8-bit greyscale, row by row.
#[wasm_bindgen(js_name = readQrPixels)]
pub fn read_qr_pixels(width: u32, height: u32, luma: Vec<u8>) -> Vec<String> {
    qr::read_luma(width, height, &Zeroizing::new(luma))
}

/// Says what scanned QR texts hold, joining the parts of a split Google Authenticator export.
/// Pass every text scanned so far.
#[wasm_bindgen(js_name = summarizeQrScans, unchecked_return_type = "QrScan")]
pub fn summarize_qr_scans(texts: Vec<String>) -> Result<JsValue, JsValue> {
    let texts = Zeroizing::new(texts);
    to_js(&qr::summarize(&texts))
}

/// The 5-character SHA-1 prefix to request from the Pwned Passwords range API.
#[wasm_bindgen(js_name = breachPrefix)]
pub fn breach_prefix(password: String) -> String {
    breach::sha1_range(&Zeroizing::new(password)).prefix
}

/// How many times the password appears in a range API response (0 = not found). The match is
/// done here, so the full hash never reaches JavaScript.
#[wasm_bindgen(js_name = breachCount)]
pub fn breach_count(
    password: String,
    #[wasm_bindgen(js_name = rangeResponse)] range_response: String,
) -> f64 {
    let range = breach::sha1_range(&Zeroizing::new(password));
    breach::count_in_range(&range.suffix, &range_response) as f64
}

/// Checks a typed Secret Key and returns it in canonical form (`OP1-XXXXXX-…`).
#[wasm_bindgen(js_name = normalizeSecretKey)]
pub fn normalize_secret_key(text: String) -> Result<String, JsValue> {
    let key = SecretKey::parse(&Zeroizing::new(text)).map_err(js_error)?;
    Ok(key.to_text().to_string())
}

/// The WebAuthn PRF input for device unlock (`extensions.prf.eval.first`):
/// `SHA-256("octapass/v1/device-unlock")`.
#[wasm_bindgen(js_name = deviceUnlockPrfInput)]
pub fn device_unlock_prf_input() -> Vec<u8> {
    device::prf_input().to_vec()
}

#[wasm_bindgen(typescript_custom_section)]
const SSH_TYPES: &str = r#"
export type SshKeyKind = "ed25519" | "ecdsaP256" | "ecdsaP384" | "rsa3072" | "rsa4096";
/** What can be shown without the private key. `usable` is false for DSA and FIDO (`sk-`) keys. */
export type SshPublicInfo = { keyType: string; bits: number; fingerprint: string; publicKey: string; comment: string; usable: boolean };
/** `privateKey`: OpenSSH, without a passphrase. */
export type SshKey = SshPublicInfo & { privateKey: string };
"#;

/// Makes a new SSH key on this device.
#[wasm_bindgen(js_name = generateSshKey, unchecked_return_type = "SshKey")]
pub fn generate_ssh_key(
    #[wasm_bindgen(unchecked_param_type = "SshKeyKind")] kind: JsValue,
    comment: String,
) -> Result<JsValue, JsValue> {
    let kind: ssh::SshKeyKind = from_js(kind, "SSH key kind")?;
    to_js(&ssh::generate(kind, &comment, &mut OsRng).map_err(js_error)?)
}

/// Reads a private key file (OpenSSH, PEM or PKCS#8). Throws `ssh_passphrase_required`,
/// `wrong_passphrase`, `ssh_public_key_only`, `unsupported_ssh_key` or `invalid_ssh_key`.
#[wasm_bindgen(js_name = readSshKey, unchecked_return_type = "SshKey")]
pub fn read_ssh_key(text: String, passphrase: Option<String>) -> Result<JsValue, JsValue> {
    let text = Zeroizing::new(text);
    let passphrase = passphrase.map(Zeroizing::new);
    to_js(
        &ssh::read_private_key(&text, passphrase.as_deref().map(String::as_str))
            .map_err(js_error)?,
    )
}

/// A public key line's type, size and fingerprint.
#[wasm_bindgen(js_name = readSshPublicKey, unchecked_return_type = "SshPublicInfo")]
pub fn read_ssh_public_key(line: String) -> Result<JsValue, JsValue> {
    to_js(&ssh::read_public_key(&line).map_err(js_error)?)
}

/// A stored key as an OpenSSH private key file with `comment`, protected by `passphrase` when it
/// isn't empty.
#[wasm_bindgen(js_name = writeSshKey)]
pub fn write_ssh_key(
    #[wasm_bindgen(js_name = privateKey)] private_key: String,
    comment: String,
    passphrase: Option<String>,
) -> Result<String, JsValue> {
    let private_key = Zeroizing::new(private_key);
    let passphrase = passphrase.map(Zeroizing::new);
    ssh::write_private_key(
        &private_key,
        &comment,
        passphrase.as_deref().map(String::as_str),
        &mut OsRng,
    )
    .map(|text| text.to_string())
    .map_err(js_error)
}

/// Runs a developer toolkit tool (plan 16): `op` is its name, `input` a JSON object, and the result a
/// JSON object. Everything runs in this worker, on this device.
#[cfg(feature = "toolkit")]
#[wasm_bindgen(js_name = toolRun)]
pub fn tool_run(op: String, input: String) -> Result<String, JsValue> {
    let input = Zeroizing::new(input);
    toolkit::run(&op, &input, crate::now_ms(), &mut OsRng)
        .map(|output| output.to_string())
        .map_err(js_error)
}

/// Hashes a file in chunks, so a big file never sits in WASM memory at once.
#[cfg(feature = "toolkit")]
#[wasm_bindgen]
pub struct StreamHasher {
    hashers: Vec<(toolkit::digest::Algorithm, toolkit::digest::Hasher)>,
}

#[cfg(feature = "toolkit")]
#[wasm_bindgen]
impl StreamHasher {
    /// `algorithms` are the hash names; all of them, when empty.
    #[wasm_bindgen(constructor)]
    pub fn new(algorithms: Vec<String>) -> Result<StreamHasher, JsValue> {
        use toolkit::digest::{Algorithm, Hasher};
        let chosen = if algorithms.is_empty() {
            Algorithm::ALL.to_vec()
        } else {
            algorithms
                .iter()
                .map(|name| Algorithm::parse(name))
                .collect::<Result<Vec<_>, _>>()
                .map_err(js_error)?
        };
        Ok(Self {
            hashers: chosen
                .into_iter()
                .map(|algorithm| (algorithm, Hasher::new(algorithm)))
                .collect(),
        })
    }

    pub fn update(&mut self, chunk: &[u8]) {
        for (_, hasher) in &mut self.hashers {
            hasher.update(chunk);
        }
    }

    /// `{ algorithm, hex, base64, legacy }` for each hash.
    pub fn finish(self) -> Result<String, JsValue> {
        let results: Vec<toolkit::HashResult> = self
            .hashers
            .into_iter()
            .map(|(algorithm, hasher)| toolkit::hash_result(algorithm, &hasher.finalize()))
            .collect();
        serde_json::to_string(&results).map_err(|_| crate::invalid_argument("hash results"))
    }
}
