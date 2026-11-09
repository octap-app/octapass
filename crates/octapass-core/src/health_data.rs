//! The health report's signed site lists (plan 06): which sites accept passkeys and which offer
//! two-step sign-in. The same format and checks as `packages/vault-client/src/tools/healthData.ts`.
//!
//! ```text
//! file      = { "payload": base64(payload), "signature": base64(Ed25519(context ‖ 0x00 ‖ payload)) }
//! context   = "openpass/v1/health-data"
//! payload   = { "format": 1, "version": n, "issuedAt": "…", "passkeyDomains": […], "twoFactorDomains": […] }
//! ```
//!
//! A file counts only when the pinned key signed it and its version is above the one in use, so
//! whoever serves it (the account's server, the project's site) can hold an update back but can't
//! forge one or roll the lists back. Nothing unsigned is parsed beyond the envelope.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

/// The project's key for the lists. The private half never enters the repository.
pub const PUBLIC_KEY: [u8; 32] = [
    0x37, 0xb6, 0x77, 0x51, 0x3e, 0xd9, 0x7e, 0x8c, 0x04, 0xcb, 0x6c, 0xe7, 0xd0, 0x8d, 0x0f, 0x68,
    0x73, 0x0e, 0x68, 0x43, 0x59, 0x10, 0x2c, 0x3d, 0x39, 0x2c, 0x99, 0x09, 0xa4, 0x52, 0x07, 0x51,
];
pub const CONTEXT: &str = "openpass/v1/health-data";
pub const FORMAT: u64 = 1;
/// The most a file may be. Today's is about 10 KB.
pub const MAX_BYTES: usize = 1 << 20;
/// How often a device asks for a newer file.
pub const CHECK_HOURS: i64 = 24;
/// The server path that serves the file.
pub const PATH: &str = "v1/health/data";
/// The file this build shipped with, signed like any update.
pub const BUNDLED: &str = include_str!("../../../packages/vault-client/src/data/health-data.json");

const MAX_DOMAINS: usize = 50_000;
/// JavaScript's largest safe integer, so the TypeScript client reads every version this one does.
const MAX_VERSION: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthData {
    /// Goes up with every signed file.
    pub version: u64,
    pub issued_at: String,
    /// Registrable domains of sites that accept passkeys.
    pub passkey_domains: BTreeSet<String>,
    /// Registrable domains of sites that offer an authenticator app or passkeys for two-step sign-in.
    pub two_factor_domains: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Rejected {
    #[error("the health data file is malformed")]
    Malformed,
    #[error("the health data file isn't signed by the project's key")]
    BadSignature,
    #[error("the health data file has a format this build doesn't know")]
    Unsupported,
    #[error("the health data file isn't newer than the lists in use")]
    Rollback,
}

/// Checks a downloaded file against the pinned key; `after` is the version in use.
pub fn verify(text: &str, after: u64) -> Result<HealthData, Rejected> {
    verify_with_key(text, after, &PUBLIC_KEY)
}

/// [`verify`] with another key, for tests of the code that fetches and keeps files.
pub fn verify_with_key(text: &str, after: u64, key: &[u8; 32]) -> Result<HealthData, Rejected> {
    let (payload, signature) = envelope(text)?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| Rejected::BadSignature)?;
    let mut message = Vec::with_capacity(CONTEXT.len() + 1 + payload.len());
    message.extend_from_slice(CONTEXT.as_bytes());
    message.push(0);
    message.extend_from_slice(&payload);
    key.verify(&message, &signature)
        .map_err(|_| Rejected::BadSignature)?;
    let data = parse_payload(&payload)?;
    if data.version <= after {
        return Err(Rejected::Rollback);
    }
    Ok(data)
}

/// The lists this build shipped with.
pub fn bundled() -> &'static HealthData {
    static DATA: OnceLock<HealthData> = OnceLock::new();
    DATA.get_or_init(|| verify(BUNDLED, 0).expect("the bundled health data is signed and valid"))
}

/// The bundled file, or `stored` when that's a valid, newer file. A stored copy is checked again
/// whenever it's read: it's no more trusted than a download.
pub fn newest(stored: Option<&str>) -> HealthData {
    let base = bundled();
    stored
        .and_then(|text| verify(text, base.version).ok())
        .unwrap_or_else(|| base.clone())
}

fn envelope(text: &str) -> Result<(Vec<u8>, Signature), Rejected> {
    if text.len() > MAX_BYTES {
        return Err(Rejected::Malformed);
    }
    let file: Value = serde_json::from_str(text).map_err(|_| Rejected::Malformed)?;
    let field = |name: &str| {
        file.get(name)
            .and_then(Value::as_str)
            .and_then(|text| STANDARD.decode(text).ok())
    };
    let payload = field("payload").ok_or(Rejected::Malformed)?;
    let signature: [u8; 64] = field("signature")
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Rejected::Malformed)?;
    Ok((payload, Signature::from_bytes(&signature)))
}

fn is_domain(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// `YYYY-MM-DDTHH:MM:SS`, then anything (fractions, `Z` or an offset): what the signing tool writes.
fn is_timestamp(text: &str) -> bool {
    let pattern = b"dddd-dd-ddTdd:dd:dd";
    let bytes = text.as_bytes();
    bytes.len() >= pattern.len()
        && bytes.len() <= 40
        && pattern.iter().zip(bytes).all(|(want, got)| match want {
            b'd' => got.is_ascii_digit(),
            _ => want == got,
        })
}

fn domains(value: Option<&Value>) -> Result<BTreeSet<String>, Rejected> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| list.len() <= MAX_DOMAINS)
        .ok_or(Rejected::Malformed)?;
    list.iter()
        .map(|name| {
            name.as_str()
                .filter(|name| is_domain(name))
                .map(str::to_owned)
                .ok_or(Rejected::Malformed)
        })
        .collect()
}

fn parse_payload(bytes: &[u8]) -> Result<HealthData, Rejected> {
    let text = std::str::from_utf8(bytes).map_err(|_| Rejected::Malformed)?;
    let payload: Value = serde_json::from_str(text).map_err(|_| Rejected::Malformed)?;
    let payload = payload.as_object().ok_or(Rejected::Malformed)?;
    let format = payload
        .get("format")
        .and_then(Value::as_u64)
        .ok_or(Rejected::Malformed)?;
    if format != FORMAT {
        return Err(Rejected::Unsupported);
    }
    let version = payload
        .get("version")
        .and_then(Value::as_u64)
        .filter(|version| (1..=MAX_VERSION).contains(version))
        .ok_or(Rejected::Malformed)?;
    let issued_at = payload
        .get("issuedAt")
        .and_then(Value::as_str)
        .filter(|date| is_timestamp(date))
        .ok_or(Rejected::Malformed)?
        .to_owned();
    Ok(HealthData {
        version,
        issued_at,
        passkey_domains: domains(payload.get("passkeyDomains"))?,
        two_factor_domains: domains(payload.get("twoFactorDomains"))?,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn signed_bytes(key: &SigningKey, payload: &[u8]) -> String {
        let mut message = CONTEXT.as_bytes().to_vec();
        message.push(0);
        message.extend_from_slice(payload);
        json!({
            "payload": STANDARD.encode(payload),
            "signature": STANDARD.encode(key.sign(&message).to_bytes()),
        })
        .to_string()
    }

    fn payload(fields: Value) -> Value {
        let mut payload = json!({
            "format": 1,
            "version": 5,
            "issuedAt": "2026-11-08T00:00:00.000Z",
            "passkeyDomains": ["example.com", "passkeys.example"],
            "twoFactorDomains": ["example.com"],
        });
        for (name, value) in fields.as_object().unwrap() {
            payload[name] = value.clone();
        }
        payload
    }

    fn signed(key: &SigningKey, payload: &Value) -> String {
        signed_bytes(key, payload.to_string().as_bytes())
    }

    fn check(text: &str, after: u64) -> Result<HealthData, Rejected> {
        verify_with_key(text, after, &key().verifying_key().to_bytes())
    }

    /// The lists the TypeScript data files hold, read the way `octapass-mobile` used to.
    fn ts_list(source: &str) -> BTreeSet<String> {
        let list = source.split_once("new Set([").map_or("", |(_, rest)| rest);
        list.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.split('\'').skip(1).step_by(2))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn the_bundled_file_is_signed_by_the_pinned_key_and_matches_the_lists() {
        let data = bundled();
        assert!(data.version >= 1);
        assert_eq!(
            data.passkey_domains,
            ts_list(include_str!(
                "../../../packages/vault-client/src/data/passkey-domains.ts"
            ))
        );
        assert_eq!(
            data.two_factor_domains,
            ts_list(include_str!(
                "../../../packages/vault-client/src/data/two-factor-domains.ts"
            ))
        );
        assert_eq!(verify(BUNDLED, data.version), Err(Rejected::Rollback));
    }

    #[test]
    fn accepts_a_newer_signed_file() {
        let data = check(&signed(&key(), &payload(json!({}))), 4).unwrap();
        assert_eq!(data.version, 5);
        assert!(data.passkey_domains.contains("passkeys.example"));
    }

    #[test]
    fn refuses_a_bad_signature() {
        let file: Value = serde_json::from_str(&signed(&key(), &payload(json!({})))).unwrap();
        let mut changed = file.clone();
        changed["payload"] = json!(
            STANDARD.encode(payload(json!({ "passkeyDomains": ["evil.example"] })).to_string())
        );
        assert_eq!(check(&changed.to_string(), 0), Err(Rejected::BadSignature));

        let mut flipped = file.clone();
        let mut signature = STANDARD
            .decode(file["signature"].as_str().unwrap())
            .unwrap();
        signature[0] ^= 1;
        flipped["signature"] = json!(STANDARD.encode(signature));
        assert_eq!(check(&flipped.to_string(), 0), Err(Rejected::BadSignature));

        // Another key, and the pinned key against a file the test key signed.
        let other = SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            check(&signed(&other, &payload(json!({}))), 0),
            Err(Rejected::BadSignature)
        );
        assert_eq!(verify(&file.to_string(), 0), Err(Rejected::BadSignature));

        // Signed without the context.
        let bytes = payload(json!({})).to_string();
        let bare = json!({
            "payload": STANDARD.encode(&bytes),
            "signature": STANDARD.encode(key().sign(bytes.as_bytes()).to_bytes()),
        });
        assert_eq!(check(&bare.to_string(), 0), Err(Rejected::BadSignature));
    }

    #[test]
    fn refuses_rolling_back() {
        assert_eq!(
            check(&signed(&key(), &payload(json!({}))), 5),
            Err(Rejected::Rollback)
        );
        assert_eq!(
            check(&signed(&key(), &payload(json!({ "version": 3 }))), 5),
            Err(Rejected::Rollback)
        );
    }

    #[test]
    fn refuses_malformed_files() {
        let key = key();
        let cases = [
            ("not JSON", "{".to_owned()),
            ("no signature", json!({ "payload": "e30=" }).to_string()),
            (
                "a short signature",
                json!({ "payload": "e30=", "signature": STANDARD.encode([0; 32]) }).to_string(),
            ),
            (
                "not base64",
                json!({ "payload": "%%%%", "signature": STANDARD.encode([0; 64]) }).to_string(),
            ),
            ("too large", "x".repeat(MAX_BYTES + 1)),
            ("a payload that isn't JSON", signed_bytes(&key, b"not json")),
            (
                "a payload that isn't UTF-8",
                signed_bytes(&key, &[0xff, 0xfe]),
            ),
            ("an array", signed_bytes(&key, b"[]")),
            (
                "no version",
                signed(&key, &payload(json!({ "version": null }))),
            ),
            ("version 0", signed(&key, &payload(json!({ "version": 0 })))),
            (
                "a fractional version",
                signed(&key, &payload(json!({ "version": 5.5 }))),
            ),
            (
                "a version JavaScript can't hold",
                signed(&key, &payload(json!({ "version": MAX_VERSION + 1 }))),
            ),
            (
                "a bad date",
                signed(&key, &payload(json!({ "issuedAt": "soon" }))),
            ),
            (
                "a list that isn't one",
                signed(&key, &payload(json!({ "passkeyDomains": "example.com" }))),
            ),
            (
                "a name that isn't a domain",
                signed(&key, &payload(json!({ "passkeyDomains": ["<script>"] }))),
            ),
            (
                "a single label",
                signed(&key, &payload(json!({ "twoFactorDomains": ["localhost"] }))),
            ),
            (
                "an empty label",
                signed(&key, &payload(json!({ "twoFactorDomains": ["a..com"] }))),
            ),
            (
                "upper case",
                signed(
                    &key,
                    &payload(json!({ "twoFactorDomains": ["Example.com"] })),
                ),
            ),
        ];
        for (what, text) in cases {
            assert_eq!(check(&text, 0), Err(Rejected::Malformed), "{what}");
        }
    }

    #[test]
    fn refuses_a_format_it_does_not_know() {
        assert_eq!(
            check(&signed(&key(), &payload(json!({ "format": 2 }))), 0),
            Err(Rejected::Unsupported)
        );
    }

    #[test]
    fn ignores_fields_it_does_not_know() {
        let data = check(
            &signed(&key(), &payload(json!({ "changePasswordUrls": {} }))),
            0,
        )
        .unwrap();
        assert_eq!(data.version, 5);
    }

    #[test]
    fn newest_falls_back_to_the_bundled_lists() {
        assert_eq!(newest(None), *bundled());
        assert_eq!(newest(Some("{")), *bundled());
        // Signed by a key the build doesn't pin.
        let other = signed(
            &key(),
            &payload(json!({ "version": bundled().version + 1 })),
        );
        assert_eq!(newest(Some(&other)), *bundled());
        assert_eq!(newest(Some(BUNDLED)), *bundled());
    }
}
