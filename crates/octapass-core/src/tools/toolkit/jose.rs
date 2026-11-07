//! JWT, JWS and JWE (plan 16 §1–2): a reader that explains a token in plain terms, signing,
//! verifying against a secret, a key or a JWKS, decrypting JWE, and new signing keys with their JWK
//! and JWKS.
//!
//! The rules of RFC 8725 hold throughout. The header never decides how a key is read: an HMAC
//! algorithm only takes a secret and a public-key algorithm only takes a public key, so a public
//! key can't be replayed as an HMAC secret. `alg: none` is never valid. Unknown `crit` headers fail.
//! RSA1_5 JWE is refused: it's the padding-oracle construction RFC 8725 §3.2 warns about.

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{AesGcm, Nonce};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use flate2::read::DeflateDecoder;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use rsa::Oaep;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::io::Read;
use zeroize::Zeroizing;

use super::encode::{decode_base64, hex_decode};
use super::keys::{self, KeyKind, ParsedKey, PrivateKey, PublicKey, SignatureAlgorithm};
use super::random::random_bytes;
use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};

/// RFC 8725 §3.5 asks for HMAC keys at least as long as the hash output, so a short human password
/// is flagged.
const MAX_PBKDF2_COUNT: u64 = 1_000_000;
/// A decompressed JWE payload may be at most this big: `zip` can otherwise expand a small token
/// into gigabytes.
const MAX_INFLATED: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacAlgorithm {
    Hs256,
    Hs384,
    Hs512,
}

impl HmacAlgorithm {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "HS256" => Some(Self::Hs256),
            "HS384" => Some(Self::Hs384),
            "HS512" => Some(Self::Hs512),
            _ => None,
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Hs256 => 32,
            Self::Hs384 => 48,
            Self::Hs512 => 64,
        }
    }

    fn mac(self, key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        macro_rules! compute {
            ($hash:ty) => {{
                let mut mac =
                    <Hmac<$hash> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
                Mac::update(&mut mac, message);
                Ok(mac.finalize().into_bytes().to_vec())
            }};
        }
        match self {
            Self::Hs256 => compute!(Sha256),
            Self::Hs384 => compute!(Sha384),
            Self::Hs512 => compute!(Sha512),
        }
    }

    fn verify(self, key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool> {
        macro_rules! check {
            ($hash:ty) => {{
                let mut mac =
                    <Hmac<$hash> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
                Mac::update(&mut mac, message);
                Ok(mac.verify_slice(tag).is_ok())
            }};
        }
        match self {
            Self::Hs256 => check!(Sha256),
            Self::Hs384 => check!(Sha384),
            Self::Hs512 => check!(Sha512),
        }
    }
}

/// A token split in its base64url parts. Flattened JSON is read as the compact form it stands for.
enum Parts {
    Jws {
        protected: String,
        payload: String,
        signature: String,
    },
    Jwe {
        protected: String,
        encrypted_key: String,
        iv: String,
        ciphertext: String,
        tag: String,
    },
}

fn split(token: &str) -> Result<Parts> {
    let token = token.trim();
    let token = token
        .strip_prefix("Bearer ")
        .or_else(|| token.strip_prefix("bearer "))
        .unwrap_or(token)
        .trim();
    if token.starts_with('{') {
        return split_flattened(token);
    }
    let parts: Vec<&str> = token.split('.').collect();
    match parts.as_slice() {
        [protected, payload, signature] => Ok(Parts::Jws {
            protected: (*protected).to_owned(),
            payload: (*payload).to_owned(),
            signature: (*signature).to_owned(),
        }),
        [protected, encrypted_key, iv, ciphertext, tag] => Ok(Parts::Jwe {
            protected: (*protected).to_owned(),
            encrypted_key: (*encrypted_key).to_owned(),
            iv: (*iv).to_owned(),
            ciphertext: (*ciphertext).to_owned(),
            tag: (*tag).to_owned(),
        }),
        _ => Err(Error::InvalidToken),
    }
}

fn split_flattened(token: &str) -> Result<Parts> {
    let value: Value = serde_json::from_str(token).map_err(|_| Error::InvalidToken)?;
    let field = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    let protected = field("protected").ok_or(Error::InvalidToken)?;
    if let Some(ciphertext) = field("ciphertext") {
        return Ok(Parts::Jwe {
            protected,
            encrypted_key: field("encrypted_key").unwrap_or_default(),
            iv: field("iv").ok_or(Error::InvalidToken)?,
            ciphertext,
            tag: field("tag").ok_or(Error::InvalidToken)?,
        });
    }
    Ok(Parts::Jws {
        protected,
        payload: field("payload").ok_or(Error::InvalidToken)?,
        signature: field("signature").ok_or(Error::InvalidToken)?,
    })
}

fn json_part(text: &str) -> Result<Value> {
    let bytes = b64_decode(text.trim_end_matches('=')).map_err(|_| Error::InvalidToken)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidToken)?;
    value
        .is_object()
        .then_some(value)
        .ok_or(Error::InvalidToken)
}

/// One registered claim, explained.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub name: String,
    pub value: Value,
    /// For time claims: seconds until that moment; negative once it's past.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_from_now: Option<i64>,
}

/// What can be said without any key.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decoded {
    /// `jws` or `jwe`.
    pub kind: String,
    pub header: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The payload as JSON, when it is JSON. JWE payloads need the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// The payload as text, when it's text but not JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_text: Option<String>,
    /// `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, in that order, when present.
    pub claims: Vec<Claim>,
    /// `algNone`, `expired`, `notYetValid`, `issuedInFuture`, `noExpiry`, `unknownCritical`.
    pub warnings: Vec<String>,
}

const TIME_CLAIMS: [&str; 3] = ["exp", "nbf", "iat"];

/// Reads a token without checking it. Nothing here is proof of anything until it's verified.
pub fn decode(token: &str, now_seconds: u64) -> Result<Decoded> {
    match split(token)? {
        Parts::Jws {
            protected, payload, ..
        } => {
            let header = json_part(&protected)?;
            let bytes =
                b64_decode(payload.trim_end_matches('=')).map_err(|_| Error::InvalidToken)?;
            let parsed: Option<Value> = serde_json::from_slice(&bytes).ok();
            let payload_text = if parsed.is_none() {
                String::from_utf8(bytes).ok()
            } else {
                None
            };
            Ok(describe(header, parsed, payload_text, "jws", now_seconds))
        }
        Parts::Jwe { protected, .. } => {
            let header = json_part(&protected)?;
            Ok(describe(header, None, None, "jwe", now_seconds))
        }
    }
}

fn describe(
    header: Value,
    payload: Option<Value>,
    payload_text: Option<String>,
    kind: &str,
    now_seconds: u64,
) -> Decoded {
    let text = |name: &str| header.get(name).and_then(Value::as_str).map(str::to_owned);
    let algorithm = text("alg");
    let mut warnings = Vec::new();
    if algorithm
        .as_deref()
        .is_some_and(|alg| alg.eq_ignore_ascii_case("none"))
    {
        warnings.push("algNone".to_owned());
    }
    if has_unknown_critical(&header) {
        warnings.push("unknownCritical".to_owned());
    }
    let (claims, time_warnings) = explain_claims(payload.as_ref(), now_seconds);
    warnings.extend(time_warnings);
    Decoded {
        kind: kind.to_owned(),
        algorithm,
        encryption: text("enc"),
        key_id: text("kid"),
        header,
        payload,
        payload_text,
        claims,
        warnings,
    }
}

fn explain_claims(payload: Option<&Value>, now_seconds: u64) -> (Vec<Claim>, Vec<String>) {
    let mut claims = Vec::new();
    let mut warnings = Vec::new();
    let Some(object) = payload.and_then(Value::as_object) else {
        return (claims, warnings);
    };
    for name in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
        let Some(value) = object.get(name) else {
            continue;
        };
        let seconds_from_now = TIME_CLAIMS
            .contains(&name)
            .then(|| value.as_f64())
            .flatten()
            .map(|time| time as i64 - now_seconds as i64);
        claims.push(Claim {
            name: name.to_owned(),
            value: value.clone(),
            seconds_from_now,
        });
        match (name, seconds_from_now) {
            ("exp", Some(seconds)) if seconds <= 0 => warnings.push("expired".to_owned()),
            ("nbf", Some(seconds)) if seconds > 0 => warnings.push("notYetValid".to_owned()),
            ("iat", Some(seconds)) if seconds > 60 => warnings.push("issuedInFuture".to_owned()),
            _ => {}
        }
    }
    if !object.contains_key("exp") {
        warnings.push("noExpiry".to_owned());
    }
    (claims, warnings)
}

/// RFC 7515 §4.1.11: `crit` lists extensions the reader must understand. This reader understands
/// none, so any token that has one can't be accepted.
fn has_unknown_critical(header: &Value) -> bool {
    header.get("crit").is_some()
}

/// A secret given as text, with how to read it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretInput {
    pub value: Zeroizing<String>,
    /// `utf8` (default), `base64`, `base64url` or `hex`.
    #[serde(default)]
    pub encoding: Option<String>,
}

impl SecretInput {
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let value = self.value.as_str();
        Ok(Zeroizing::new(match self.encoding.as_deref() {
            None | Some("utf8") => value.as_bytes().to_vec(),
            Some("base64") | Some("base64url") => decode_base64(value)?,
            Some("hex") => hex_decode(value)?,
            _ => return Err(Error::InvalidToolInput),
        }))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOptions {
    /// The claims or any other JSON payload.
    pub payload: Value,
    pub algorithm: String,
    /// For public-key algorithms: a private key in any format [`keys::parse`] reads.
    #[serde(default)]
    pub key: Option<Zeroizing<String>>,
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    /// For HS256, HS384 and HS512.
    #[serde(default)]
    pub secret: Option<SecretInput>,
    /// Goes in the header as `kid`.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Other header fields.
    #[serde(default)]
    pub header: Map<String, Value>,
    /// Adds `iat` set to now.
    #[serde(default)]
    pub issued_now: bool,
    /// Adds `exp` this long from now.
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signed {
    pub token: String,
    /// `shortSecret` when an HMAC secret is shorter than the hash.
    pub warnings: Vec<String>,
}

/// Creates a compact JWS from a payload. `none` isn't an algorithm here.
pub fn sign(
    options: &SignOptions,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Signed> {
    if options.algorithm.eq_ignore_ascii_case("none") {
        return Err(Error::UnsupportedAlgorithm);
    }
    let mut payload = options.payload.clone();
    if options.issued_now || options.expires_in_seconds.is_some() {
        let object = payload.as_object_mut().ok_or(Error::InvalidToolInput)?;
        if options.issued_now {
            object.insert("iat".to_owned(), json!(now_seconds));
        }
        if let Some(seconds) = options.expires_in_seconds {
            object.insert("exp".to_owned(), json!(now_seconds + seconds));
        }
    }
    let mut header = options.header.clone();
    header.insert("alg".to_owned(), json!(options.algorithm));
    header.entry("typ").or_insert_with(|| json!("JWT"));
    if let Some(key_id) = &options.key_id {
        header.insert("kid".to_owned(), json!(key_id));
    }
    let signing_input = format!(
        "{}.{}",
        b64_encode(Value::Object(header).to_string().as_bytes()),
        b64_encode(payload.to_string().as_bytes())
    );
    let mut warnings = Vec::new();
    let signature = match HmacAlgorithm::parse(&options.algorithm) {
        Some(hmac) => {
            let secret = options
                .secret
                .as_ref()
                .ok_or(Error::KeyAlgorithmMismatch)?
                .bytes()?;
            if secret.is_empty() {
                return Err(Error::InvalidKey);
            }
            if secret.len() < hmac.output_len() {
                warnings.push("shortSecret".to_owned());
            }
            hmac.mac(&secret, signing_input.as_bytes())?
        }
        None => {
            let algorithm = SignatureAlgorithm::parse(&options.algorithm)?;
            let text = options.key.as_ref().ok_or(Error::KeyAlgorithmMismatch)?;
            let key = match keys::parse(text, options.passphrase.as_ref().map(|p| p.as_str()))? {
                ParsedKey::Private(key) => key,
                ParsedKey::Public(_) => return Err(Error::PrivateKeyRequired),
            };
            key.sign(algorithm, signing_input.as_bytes(), rng)?
        }
    };
    Ok(Signed {
        token: format!("{signing_input}.{}", b64_encode(&signature)),
        warnings,
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOptions {
    pub token: String,
    /// A public or private key, a JWK or a JWKS.
    #[serde(default)]
    pub key: Option<Zeroizing<String>>,
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    pub secret: Option<SecretInput>,
    /// Allowed clock difference for `exp` and `nbf`.
    #[serde(default)]
    pub leeway_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verified {
    /// The signature is right, and the token is inside its time limits.
    pub valid: bool,
    pub signature_valid: bool,
    pub expired: bool,
    pub not_yet_valid: bool,
    /// The JWKS entry that matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_key_id: Option<String>,
    pub decoded: Decoded,
}

pub fn verify(options: &VerifyOptions, now_seconds: u64) -> Result<Verified> {
    let decoded = decode(&options.token, now_seconds)?;
    let Parts::Jws {
        protected,
        payload,
        signature,
    } = split(&options.token)?
    else {
        return Err(Error::InvalidToken);
    };
    let leeway = options.leeway_seconds.unwrap_or(0) as i64;
    let seconds = |name: &str| {
        decoded
            .claims
            .iter()
            .find(|claim| claim.name == name)
            .and_then(|claim| claim.seconds_from_now)
    };
    let expired = seconds("exp").is_some_and(|left| left + leeway <= 0);
    let not_yet_valid = seconds("nbf").is_some_and(|left| left - leeway > 0);
    let mut matched_key_id = None;
    let signature_valid = 'check: {
        // `alg: none` and critical extensions we can't honour fail, whatever key is given.
        let Some(algorithm) = decoded.algorithm.as_deref() else {
            break 'check false;
        };
        if algorithm.eq_ignore_ascii_case("none") || has_unknown_critical(&decoded.header) {
            break 'check false;
        }
        let signature =
            b64_decode(signature.trim_end_matches('=')).map_err(|_| Error::InvalidToken)?;
        let input = format!("{protected}.{payload}");
        if let Some(hmac) = HmacAlgorithm::parse(algorithm) {
            let secret = hmac_secret(options, decoded.key_id.as_deref())?;
            break 'check hmac.verify(&secret, input.as_bytes(), &signature)?;
        }
        let algorithm = SignatureAlgorithm::parse(algorithm)?;
        if options.secret.is_some() && options.key.is_none() {
            return Err(Error::KeyAlgorithmMismatch);
        }
        let text = options.key.as_ref().ok_or(Error::KeyAlgorithmMismatch)?;
        let passphrase = options.passphrase.as_ref().map(|p| p.as_str());
        let candidates = public_candidates(text, decoded.key_id.as_deref(), passphrase)?;
        let mut matched = false;
        for (kid, key) in candidates {
            // Keys in a set that can't do this algorithm just aren't candidates.
            match key.verify(algorithm, input.as_bytes(), &signature) {
                Ok(true) => {
                    matched_key_id = kid;
                    matched = true;
                    break;
                }
                Ok(false) | Err(Error::KeyAlgorithmMismatch) => {}
                Err(error) => return Err(error),
            }
        }
        matched
    };
    Ok(Verified {
        valid: signature_valid && !expired && !not_yet_valid,
        signature_valid,
        expired,
        not_yet_valid,
        matched_key_id,
        decoded,
    })
}

/// The HMAC secret: from `secret`, or an `oct` JWK or JWKS entry. Anything else (a PEM public key,
/// above all) is refused rather than tried as bytes.
fn hmac_secret(options: &VerifyOptions, key_id: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(secret) = &options.secret {
        return secret.bytes();
    }
    let text = options.key.as_ref().ok_or(Error::KeyAlgorithmMismatch)?;
    if !text.trim_start().starts_with('{') {
        return Err(Error::KeyAlgorithmMismatch);
    }
    let value: Value = serde_json::from_str(text).map_err(|_| Error::InvalidKeyFile)?;
    let keys: Vec<&Value> = match value.get("keys").and_then(Value::as_array) {
        Some(keys) => keys.iter().collect(),
        None => vec![&value],
    };
    keys.into_iter()
        .filter(|jwk| jwk.get("kty").and_then(Value::as_str) == Some("oct"))
        .find(|jwk| {
            key_id.is_none()
                || jwk
                    .get("kid")
                    .and_then(Value::as_str)
                    .is_none_or(|kid| Some(kid) == key_id)
        })
        .and_then(|jwk| jwk.get("k").and_then(Value::as_str))
        .ok_or(Error::NoMatchingKey)
        .and_then(|k| b64_decode(k.trim_end_matches('=')).map_err(|_| Error::InvalidKeyFile))
        .map(Zeroizing::new)
}

/// The public keys to try: one key, or the entries of a JWKS. With a `kid` in the token, a set is
/// narrowed to that entry; a set with no such entry is an error, not a pass over every key.
fn public_candidates(
    text: &str,
    key_id: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Vec<(Option<String>, PublicKey)>> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let value: Value = serde_json::from_str(trimmed).map_err(|_| Error::InvalidKeyFile)?;
        if let Some(keys) = value.get("keys").and_then(Value::as_array) {
            let entries: Vec<&Value> = keys
                .iter()
                .filter(|jwk| {
                    let kid = jwk.get("kid").and_then(Value::as_str);
                    key_id.is_none() || kid.is_none() || kid == key_id
                })
                .collect();
            if entries.is_empty() {
                return Err(Error::NoMatchingKey);
            }
            return entries
                .into_iter()
                .filter(|jwk| jwk.get("kty").and_then(Value::as_str) != Some("oct"))
                .map(|jwk| {
                    let kid = jwk.get("kid").and_then(Value::as_str).map(str::to_owned);
                    Ok((kid, keys::parse_jwk(jwk)?.public()))
                })
                .collect();
        }
    }
    Ok(vec![(None, keys::parse(trimmed, passphrase)?.public())])
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptOptions {
    pub token: String,
    /// A private key or a JWK (`oct` for symmetric algorithms).
    #[serde(default)]
    pub key: Option<Zeroizing<String>>,
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    /// The key as bytes for `dir`, AES key wrap and AES-GCM key wrap, or the password for PBES2.
    #[serde(default)]
    pub secret: Option<SecretInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decrypted {
    pub header: Value,
    /// The plaintext as text, when it's valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<Zeroizing<String>>,
    /// The plaintext as JSON, when it is JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// The plaintext as base64url.
    pub base64url: Zeroizing<String>,
    /// When the plaintext is itself a signed JWT (a nested token), what it says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested: Option<Decoded>,
    /// Claims of the plaintext, explained.
    pub claims: Vec<Claim>,
    pub warnings: Vec<String>,
}

/// Decrypts a JWE with a key you hold.
pub fn decrypt(
    options: &DecryptOptions,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Decrypted> {
    let Parts::Jwe {
        protected,
        encrypted_key,
        iv,
        ciphertext,
        tag,
    } = split(&options.token)?
    else {
        return Err(Error::InvalidToken);
    };
    let header = json_part(&protected)?;
    if has_unknown_critical(&header) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let text = |name: &str| header.get(name).and_then(Value::as_str);
    let algorithm = text("alg").ok_or(Error::InvalidToken)?;
    let encryption = text("enc").ok_or(Error::InvalidToken)?;
    let content = ContentAlgorithm::parse(encryption)?;
    let binary =
        |part: &str| b64_decode(part.trim_end_matches('=')).map_err(|_| Error::InvalidToken);
    let wrapped = binary(&encrypted_key)?;
    let cek = unwrap_key(options, &header, algorithm, content, &wrapped, rng)?;
    if cek.len() != content.key_len() {
        return Err(Error::DecryptionFailed);
    }
    let plaintext = content.decrypt(
        &cek,
        &binary(&iv)?,
        &binary(&ciphertext)?,
        &binary(&tag)?,
        protected.as_bytes(),
    )?;
    let plaintext = match text("zip") {
        None => plaintext,
        Some("DEF") => inflate(&plaintext)?,
        Some(_) => return Err(Error::UnsupportedAlgorithm),
    };
    let utf8 = std::str::from_utf8(&plaintext).ok();
    let payload: Option<Value> = serde_json::from_slice(&plaintext).ok();
    let (claims, warnings) = explain_claims(payload.as_ref(), now_seconds);
    let nested = utf8
        .filter(|text| text.split('.').count() == 3)
        .and_then(|text| decode(text, now_seconds).ok());
    Ok(Decrypted {
        text: utf8.map(|text| Zeroizing::new(text.to_owned())),
        base64url: Zeroizing::new(b64_encode(&plaintext)),
        header,
        payload,
        nested,
        claims,
        warnings,
    })
}

fn inflate(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    DeflateDecoder::new(data)
        .take(MAX_INFLATED + 1)
        .read_to_end(&mut out)
        .map_err(|_| Error::DecryptionFailed)?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(Error::DecryptionFailed);
    }
    Ok(out)
}

fn symmetric_key(options: &DecryptOptions) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(secret) = &options.secret {
        return secret.bytes();
    }
    let text = options.key.as_ref().ok_or(Error::KeyAlgorithmMismatch)?;
    let value: Value = serde_json::from_str(text).map_err(|_| Error::KeyAlgorithmMismatch)?;
    let k = value
        .get("k")
        .and_then(Value::as_str)
        .filter(|_| value.get("kty").and_then(Value::as_str) == Some("oct"))
        .ok_or(Error::KeyAlgorithmMismatch)?;
    b64_decode(k.trim_end_matches('='))
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidKeyFile)
}

fn private_key(options: &DecryptOptions) -> Result<PrivateKey> {
    let text = options.key.as_ref().ok_or(Error::KeyAlgorithmMismatch)?;
    match keys::parse(text, options.passphrase.as_ref().map(|p| p.as_str()))? {
        ParsedKey::Private(key) => Ok(key),
        ParsedKey::Public(_) => Err(Error::PrivateKeyRequired),
    }
}

fn aes_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let length = wrapped
        .len()
        .checked_sub(8)
        .ok_or(Error::DecryptionFailed)?;
    let mut out = Zeroizing::new(vec![0u8; length]);
    let result = match kek.len() {
        16 => aes_kw::KekAes128::try_from(kek)
            .map_err(|_| Error::InvalidKey)?
            .unwrap(wrapped, &mut out),
        24 => aes_kw::KekAes192::try_from(kek)
            .map_err(|_| Error::InvalidKey)?
            .unwrap(wrapped, &mut out),
        32 => aes_kw::KekAes256::try_from(kek)
            .map_err(|_| Error::InvalidKey)?
            .unwrap(wrapped, &mut out),
        _ => return Err(Error::KeyAlgorithmMismatch),
    };
    result.map_err(|_| Error::DecryptionFailed)?;
    Ok(out)
}

fn aes_gcm_open(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if iv.len() != 12 || tag.len() != 16 {
        return Err(Error::DecryptionFailed);
    }
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let nonce = Nonce::<U12>::from_slice(iv);
    let payload = Payload {
        msg: &combined,
        aad,
    };
    let opened = match key.len() {
        16 => AesGcm::<Aes128, U12>::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .decrypt(nonce, payload),
        24 => AesGcm::<Aes192, U12>::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .decrypt(nonce, payload),
        32 => AesGcm::<Aes256, U12>::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .decrypt(nonce, payload),
        _ => return Err(Error::KeyAlgorithmMismatch),
    };
    opened
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

fn unwrap_key(
    options: &DecryptOptions,
    header: &Value,
    algorithm: &str,
    content: ContentAlgorithm,
    wrapped: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<Vec<u8>>> {
    let header_bytes = |name: &str| -> Result<Vec<u8>> {
        header
            .get(name)
            .and_then(Value::as_str)
            .ok_or(Error::InvalidToken)
            .and_then(|text| {
                b64_decode(text.trim_end_matches('=')).map_err(|_| Error::InvalidToken)
            })
    };
    let sized = |key: Zeroizing<Vec<u8>>, length: usize| {
        if key.len() == length {
            Ok(key)
        } else {
            Err(Error::KeyAlgorithmMismatch)
        }
    };
    match algorithm {
        "dir" => {
            if !wrapped.is_empty() {
                return Err(Error::InvalidToken);
            }
            symmetric_key(options)
        }
        "A128KW" => aes_unwrap(&sized(symmetric_key(options)?, 16)?, wrapped),
        "A192KW" => aes_unwrap(&sized(symmetric_key(options)?, 24)?, wrapped),
        "A256KW" => aes_unwrap(&sized(symmetric_key(options)?, 32)?, wrapped),
        "A128GCMKW" | "A192GCMKW" | "A256GCMKW" => {
            let length = match algorithm {
                "A128GCMKW" => 16,
                "A192GCMKW" => 24,
                _ => 32,
            };
            let kek = sized(symmetric_key(options)?, length)?;
            aes_gcm_open(
                &kek,
                &header_bytes("iv")?,
                wrapped,
                &header_bytes("tag")?,
                b"",
            )
        }
        "RSA-OAEP" | "RSA-OAEP-256" => {
            let PrivateKey::Rsa(key) = private_key(options)? else {
                return Err(Error::KeyAlgorithmMismatch);
            };
            let padding = if algorithm == "RSA-OAEP" {
                Oaep::new::<Sha1>()
            } else {
                Oaep::new::<Sha256>()
            };
            key.decrypt_blinded(rng, padding, wrapped)
                .map(Zeroizing::new)
                .map_err(|_| Error::DecryptionFailed)
        }
        "RSA1_5" => Err(Error::UnsupportedAlgorithm),
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            let shared = ecdh_shared(&private_key(options)?, header)?;
            let apu = optional_bytes(header, "apu")?;
            let apv = optional_bytes(header, "apv")?;
            if algorithm == "ECDH-ES" {
                if !wrapped.is_empty() {
                    return Err(Error::InvalidToken);
                }
                return concat_kdf(&shared, content.name(), &apu, &apv, content.key_len());
            }
            let length = match algorithm {
                "ECDH-ES+A128KW" => 16,
                "ECDH-ES+A192KW" => 24,
                _ => 32,
            };
            let kek = concat_kdf(&shared, algorithm, &apu, &apv, length)?;
            aes_unwrap(&kek, wrapped)
        }
        "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW" => {
            let count = header
                .get("p2c")
                .and_then(Value::as_u64)
                .filter(|count| (1..=MAX_PBKDF2_COUNT).contains(count))
                .ok_or(Error::InvalidHashParameters)?;
            let mut salt = algorithm.as_bytes().to_vec();
            salt.push(0);
            salt.extend(header_bytes("p2s")?);
            let secret = options
                .secret
                .as_ref()
                .ok_or(Error::KeyAlgorithmMismatch)?
                .bytes()?;
            let mut kek = Zeroizing::new(vec![0u8; algorithm_key_len(algorithm)]);
            let rounds = count as u32;
            match algorithm {
                "PBES2-HS256+A128KW" => {
                    pbkdf2::pbkdf2_hmac::<Sha256>(&secret, &salt, rounds, &mut kek)
                }
                "PBES2-HS384+A192KW" => {
                    pbkdf2::pbkdf2_hmac::<Sha384>(&secret, &salt, rounds, &mut kek)
                }
                _ => pbkdf2::pbkdf2_hmac::<Sha512>(&secret, &salt, rounds, &mut kek),
            }
            aes_unwrap(&kek, wrapped)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn algorithm_key_len(algorithm: &str) -> usize {
    match algorithm {
        "PBES2-HS256+A128KW" => 16,
        "PBES2-HS384+A192KW" => 24,
        _ => 32,
    }
}

fn optional_bytes(header: &Value, name: &str) -> Result<Vec<u8>> {
    match header.get(name).and_then(Value::as_str) {
        Some(text) => b64_decode(text.trim_end_matches('=')).map_err(|_| Error::InvalidToken),
        None => Ok(Vec::new()),
    }
}

/// ECDH with the token's ephemeral key, which parsing checks is on the curve: an invalid-curve
/// `epk` would otherwise leak bits of the private key (RFC 8725 §3.4).
fn ecdh_shared(key: &PrivateKey, header: &Value) -> Result<Zeroizing<Vec<u8>>> {
    let epk = header.get("epk").ok_or(Error::InvalidToken)?;
    let ParsedKey::Public(public) = keys::parse_jwk(epk)? else {
        return Err(Error::InvalidToken);
    };
    Ok(Zeroizing::new(match (key, &public) {
        (PrivateKey::P256(key), PublicKey::P256(public)) => {
            p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), public.as_affine())
                .raw_secret_bytes()
                .to_vec()
        }
        (PrivateKey::P384(key), PublicKey::P384(public)) => {
            p384::ecdh::diffie_hellman(key.to_nonzero_scalar(), public.as_affine())
                .raw_secret_bytes()
                .to_vec()
        }
        (PrivateKey::P521(key), PublicKey::P521(public)) => {
            p521::ecdh::diffie_hellman(key.to_nonzero_scalar(), public.as_affine())
                .raw_secret_bytes()
                .to_vec()
        }
        _ => return Err(Error::KeyAlgorithmMismatch),
    }))
}

/// NIST SP 800-56A Concat KDF as RFC 7518 §4.6.2 sets it up.
fn concat_kdf(
    shared: &[u8],
    algorithm: &str,
    apu: &[u8],
    apv: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut info = Vec::new();
    for field in [algorithm.as_bytes(), apu, apv] {
        info.extend_from_slice(&(field.len() as u32).to_be_bytes());
        info.extend_from_slice(field);
    }
    info.extend_from_slice(&((key_len as u32) * 8).to_be_bytes());
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    concat_kdf::derive_key_into::<Sha256>(shared, &info, &mut key)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentAlgorithm {
    A128CbcHs256,
    A192CbcHs384,
    A256CbcHs512,
    A128Gcm,
    A192Gcm,
    A256Gcm,
}

impl ContentAlgorithm {
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "A128CBC-HS256" => Self::A128CbcHs256,
            "A192CBC-HS384" => Self::A192CbcHs384,
            "A256CBC-HS512" => Self::A256CbcHs512,
            "A128GCM" => Self::A128Gcm,
            "A192GCM" => Self::A192Gcm,
            "A256GCM" => Self::A256Gcm,
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::A128CbcHs256 | Self::A256Gcm => 32,
            Self::A192CbcHs384 => 48,
            Self::A256CbcHs512 => 64,
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
        }
    }

    fn decrypt(
        self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::A128Gcm | Self::A192Gcm | Self::A256Gcm => {
                aes_gcm_open(key, iv, ciphertext, tag, aad)
            }
            Self::A128CbcHs256 => cbc_hmac(key, iv, ciphertext, tag, aad, HmacAlgorithm::Hs256),
            Self::A192CbcHs384 => cbc_hmac(key, iv, ciphertext, tag, aad, HmacAlgorithm::Hs384),
            Self::A256CbcHs512 => cbc_hmac(key, iv, ciphertext, tag, aad, HmacAlgorithm::Hs512),
        }
    }
}

/// RFC 7518 §5.2: encrypt-then-MAC, so the MAC is checked before anything touches the padding.
fn cbc_hmac(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
    hmac: HmacAlgorithm,
) -> Result<Zeroizing<Vec<u8>>> {
    let half = key.len() / 2;
    let (mac_key, enc_key) = key.split_at(half);
    if iv.len() != 16 || tag.len() != half {
        return Err(Error::DecryptionFailed);
    }
    let mut message = Vec::with_capacity(aad.len() + iv.len() + ciphertext.len() + 8);
    message.extend_from_slice(aad);
    message.extend_from_slice(iv);
    message.extend_from_slice(ciphertext);
    message.extend_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    let expected = Zeroizing::new(hmac.mac(mac_key, &message)?);
    let same = expected[..half]
        .iter()
        .zip(tag)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b));
    if same != 0 {
        return Err(Error::DecryptionFailed);
    }
    macro_rules! open {
        ($aes:ty) => {
            cbc::Decryptor::<$aes>::new_from_slices(enc_key, iv)
                .map_err(|_| Error::InvalidKey)?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        };
    }
    let plaintext = match half {
        16 => open!(Aes128),
        24 => open!(Aes192),
        _ => open!(Aes256),
    };
    plaintext
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtKeyOptions {
    /// HS256/384/512, RS256/384/512, PS256/384/512, ES256/384 or EdDSA.
    pub algorithm: String,
    /// RSA modulus size. Default 3072.
    #[serde(default)]
    pub bits: Option<u32>,
}

/// A new JWT signing key.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtKey {
    pub algorithm: String,
    /// RFC 7638 thumbprint, ready to use as `kid`.
    pub key_id: String,
    /// HS*: the secret, base64url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Zeroizing<String>>,
    /// Others: the PKCS#8 private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The whole key as a JWK. Secret: guard it like the private key.
    pub jwk: Zeroizing<String>,
    /// `{"keys":[…]}` with only public parts, to publish. Absent for HMAC keys, which can't be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
}

fn with_key_metadata(mut jwk: Value, algorithm: &str, key_id: &str) -> Value {
    jwk["alg"] = json!(algorithm);
    jwk["use"] = json!("sig");
    jwk["kid"] = json!(key_id);
    jwk
}

pub fn generate_jwt_key(options: &JwtKeyOptions, rng: &mut impl CryptoRngCore) -> Result<JwtKey> {
    let name = options.algorithm.as_str();
    if let Some(hmac) = HmacAlgorithm::parse(name) {
        let secret = random_bytes(hmac.output_len(), rng)?;
        let k = b64_encode(&secret);
        let key_id = keys::jwk_thumbprint(&json!({ "kty": "oct", "k": k }));
        let jwk = with_key_metadata(json!({ "kty": "oct", "k": k }), name, &key_id);
        return Ok(JwtKey {
            algorithm: name.to_owned(),
            key_id,
            secret: Some(Zeroizing::new(k)),
            private_key: None,
            public_key: None,
            jwk: Zeroizing::new(jwk.to_string()),
            jwks: None,
        });
    }
    use SignatureAlgorithm as Alg;
    let algorithm = Alg::parse(name)?;
    let kind = match algorithm {
        Alg::Rs256 | Alg::Rs384 | Alg::Rs512 | Alg::Ps256 | Alg::Ps384 | Alg::Ps512 => {
            match options.bits.unwrap_or(3072) {
                2048 => KeyKind::Rsa2048,
                3072 => KeyKind::Rsa3072,
                4096 => KeyKind::Rsa4096,
                _ => return Err(Error::InvalidToolInput),
            }
        }
        Alg::Es256 => KeyKind::P256,
        Alg::Es384 => KeyKind::P384,
        Alg::EdDsa => KeyKind::Ed25519,
        Alg::Es512 => return Err(Error::UnsupportedAlgorithm),
    };
    let key = keys::generate(kind, rng)?;
    jwt_key_from(&key, name)
}

/// Exports an existing key as a JWT signing key.
pub fn jwt_key_from(key: &PrivateKey, algorithm: &str) -> Result<JwtKey> {
    let public = key.public();
    let key_id = public.jwk_thumbprint();
    let jwk = with_key_metadata(key.to_jwk()?, algorithm, &key_id);
    let public_jwk = with_key_metadata(public.to_jwk(), algorithm, &key_id);
    Ok(JwtKey {
        algorithm: algorithm.to_owned(),
        key_id,
        secret: None,
        private_key: Some(key.to_pkcs8_pem()?),
        public_key: Some(public.to_spki_pem()?),
        jwk: Zeroizing::new(jwk.to_string()),
        jwks: Some(json!({ "keys": [public_jwk] }).to_string()),
    })
}

/// A JWKS with the public parts of these keys. `oct` keys never go in: a JWKS is published.
pub fn public_jwks(jwks: &[Value]) -> Result<Value> {
    let mut keys = Vec::with_capacity(jwks.len());
    for jwk in jwks {
        if jwk.get("kty").and_then(Value::as_str) == Some("oct") {
            return Err(Error::KeyAlgorithmMismatch);
        }
        let public = keys::parse_jwk(jwk)?.public();
        let mut entry = public.to_jwk();
        for member in ["alg", "use", "kid"] {
            if let Some(value) = jwk.get(member) {
                entry[member] = value.clone();
            }
        }
        if entry.get("kid").is_none() {
            entry["kid"] = json!(public.jwk_thumbprint());
        }
        keys.push(entry);
    }
    Ok(json!({ "keys": keys }))
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, SeedableRng};

    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([5; 32])
    }

    fn secret(text: &str) -> SecretInput {
        SecretInput {
            value: Zeroizing::new(text.to_owned()),
            encoding: None,
        }
    }

    fn sign_hs(payload: Value, key: &str) -> String {
        sign(
            &SignOptions {
                payload,
                algorithm: "HS256".into(),
                key: None,
                passphrase: None,
                secret: Some(secret(key)),
                key_id: None,
                header: Map::new(),
                issued_now: false,
                expires_in_seconds: None,
            },
            NOW,
            &mut seeded(),
        )
        .unwrap()
        .token
    }

    #[test]
    fn decode_explains_claims_and_warns() {
        let token = sign_hs(
            json!({ "iss": "acme", "aud": "api", "exp": NOW + 720, "iat": NOW - 60 }),
            "a-long-enough-secret-for-hs256-32b",
        );
        let decoded = decode(&format!("Bearer {token}"), NOW).unwrap();
        assert_eq!(decoded.algorithm.as_deref(), Some("HS256"));
        let exp = decoded
            .claims
            .iter()
            .find(|claim| claim.name == "exp")
            .unwrap();
        assert_eq!(exp.seconds_from_now, Some(720));
        assert!(decoded.warnings.is_empty(), "{:?}", decoded.warnings);

        let expired = decode(&token, NOW + 721).unwrap();
        assert_eq!(expired.warnings, ["expired"]);
        let none = format!(
            "{}.{}.",
            b64_encode(br#"{"alg":"none"}"#),
            b64_encode(br#"{"sub":"x"}"#)
        );
        let decoded = decode(&none, NOW).unwrap();
        assert_eq!(decoded.warnings, ["algNone", "noExpiry"]);
    }

    #[test]
    fn alg_none_is_never_valid() {
        let token = format!(
            "{}.{}.",
            b64_encode(br#"{"alg":"none"}"#),
            b64_encode(br#"{"sub":"x","exp":99999999999}"#)
        );
        let verified = verify(
            &VerifyOptions {
                token,
                secret: Some(secret("x")),
                ..VerifyOptions::default()
            },
            NOW,
        )
        .unwrap();
        assert!(!verified.valid);
        assert!(!verified.signature_valid);
        assert!(matches!(
            sign(
                &SignOptions {
                    payload: json!({}),
                    algorithm: "none".into(),
                    key: None,
                    passphrase: None,
                    secret: None,
                    key_id: None,
                    header: Map::new(),
                    issued_now: false,
                    expires_in_seconds: None,
                },
                NOW,
                &mut seeded()
            ),
            Err(Error::UnsupportedAlgorithm)
        ));
    }

    /// The classic attack: sign with HS256, using the victim's public key as the secret.
    #[test]
    fn a_public_key_is_not_an_hmac_secret() {
        let key = keys::generate(KeyKind::P256, &mut seeded()).unwrap();
        let pem = key.public().to_spki_pem().unwrap();
        let forged = sign_hs(json!({ "admin": true }), &pem);
        let result = verify(
            &VerifyOptions {
                token: forged,
                key: Some(Zeroizing::new(pem)),
                ..VerifyOptions::default()
            },
            NOW,
        );
        assert_eq!(result.err(), Some(Error::KeyAlgorithmMismatch));
    }

    #[test]
    fn unknown_critical_header_fails() {
        let input = format!(
            "{}.{}",
            b64_encode(br#"{"alg":"HS256","crit":["exp2"],"exp2":1}"#),
            b64_encode(b"{}")
        );
        let tag = HmacAlgorithm::Hs256.mac(b"key", input.as_bytes()).unwrap();
        let verified = verify(
            &VerifyOptions {
                token: format!("{input}.{}", b64_encode(&tag)),
                secret: Some(secret("key")),
                ..VerifyOptions::default()
            },
            NOW,
        )
        .unwrap();
        assert!(!verified.signature_valid);
        assert!(
            verified
                .decoded
                .warnings
                .contains(&"unknownCritical".to_owned())
        );
    }

    #[test]
    fn time_limits_and_leeway() {
        let token = sign_hs(json!({ "exp": NOW - 10, "nbf": NOW - 100 }), "k");
        let options = |leeway| VerifyOptions {
            token: token.clone(),
            secret: Some(secret("k")),
            leeway_seconds: leeway,
            ..VerifyOptions::default()
        };
        let strict = verify(&options(None), NOW).unwrap();
        assert!(strict.signature_valid && strict.expired && !strict.valid);
        assert!(verify(&options(Some(30)), NOW).unwrap().valid);
        let later = sign_hs(json!({ "nbf": NOW + 10 }), "k");
        let verified = verify(
            &VerifyOptions {
                token: later,
                secret: Some(secret("k")),
                ..VerifyOptions::default()
            },
            NOW,
        )
        .unwrap();
        assert!(verified.not_yet_valid && !verified.valid);
    }

    #[test]
    fn jwt_keys_sign_and_verify_through_their_jwks() {
        for name in ["ES256", "ES384", "EdDSA", "RS256", "PS256"] {
            let options = JwtKeyOptions {
                algorithm: name.into(),
                bits: Some(2048),
            };
            let made = generate_jwt_key(&options, &mut seeded()).unwrap();
            let signed = sign(
                &SignOptions {
                    payload: json!({ "sub": "ada" }),
                    algorithm: name.into(),
                    key: made.private_key.clone(),
                    passphrase: None,
                    secret: None,
                    key_id: Some(made.key_id.clone()),
                    header: Map::new(),
                    issued_now: true,
                    expires_in_seconds: Some(60),
                },
                NOW,
                &mut OsRng,
            )
            .unwrap();
            let check = |key: &str| {
                verify(
                    &VerifyOptions {
                        token: signed.token.clone(),
                        key: Some(Zeroizing::new(key.to_owned())),
                        ..VerifyOptions::default()
                    },
                    NOW,
                )
                .unwrap()
            };
            let jwks = made.jwks.as_deref().unwrap();
            let verified = check(jwks);
            assert!(verified.valid, "{name}");
            assert_eq!(
                verified.matched_key_id.as_deref(),
                Some(made.key_id.as_str())
            );
            assert!(check(made.public_key.as_deref().unwrap()).valid, "{name}");
            assert!(check(made.jwk.as_str()).valid, "{name}");
            assert!(!jwks.contains("\"d\""), "{name}");
        }
    }

    #[test]
    fn hmac_keys_never_go_in_a_jwks() {
        let made = generate_jwt_key(
            &JwtKeyOptions {
                algorithm: "HS384".into(),
                bits: None,
            },
            &mut seeded(),
        )
        .unwrap();
        assert!(made.jwks.is_none());
        assert_eq!(
            decode_base64(made.secret.as_ref().unwrap()).unwrap().len(),
            48
        );
        let jwk: Value = serde_json::from_str(&made.jwk).unwrap();
        assert_eq!(
            public_jwks(std::slice::from_ref(&jwk)).err(),
            Some(Error::KeyAlgorithmMismatch)
        );

        // Verifying with an `oct` JWK works.
        let signed = sign(
            &SignOptions {
                payload: json!({}),
                algorithm: "HS384".into(),
                key: None,
                passphrase: None,
                secret: Some(SecretInput {
                    value: made.secret.clone().unwrap(),
                    encoding: Some("base64url".into()),
                }),
                key_id: None,
                header: Map::new(),
                issued_now: false,
                expires_in_seconds: None,
            },
            NOW,
            &mut seeded(),
        )
        .unwrap();
        assert!(signed.warnings.is_empty());
        let verified = verify(
            &VerifyOptions {
                token: signed.token,
                key: Some(made.jwk),
                ..VerifyOptions::default()
            },
            NOW,
        )
        .unwrap();
        assert!(verified.signature_valid);
    }

    #[test]
    fn a_jwks_without_the_tokens_kid_doesnt_match() {
        let one = generate_jwt_key(
            &JwtKeyOptions {
                algorithm: "ES256".into(),
                bits: None,
            },
            &mut seeded(),
        )
        .unwrap();
        let signed = sign(
            &SignOptions {
                payload: json!({}),
                algorithm: "ES256".into(),
                key: one.private_key.clone(),
                passphrase: None,
                secret: None,
                key_id: Some("not-in-the-set".into()),
                header: Map::new(),
                issued_now: false,
                expires_in_seconds: None,
            },
            NOW,
            &mut seeded(),
        )
        .unwrap();
        let result = verify(
            &VerifyOptions {
                token: signed.token,
                key: Some(Zeroizing::new(one.jwks.unwrap())),
                ..VerifyOptions::default()
            },
            NOW,
        );
        assert_eq!(result.err(), Some(Error::NoMatchingKey));
    }

    #[test]
    fn short_hmac_secrets_are_flagged() {
        let signed = sign(
            &SignOptions {
                payload: json!({}),
                algorithm: "HS256".into(),
                key: None,
                passphrase: None,
                secret: Some(secret("short")),
                key_id: None,
                header: Map::new(),
                issued_now: false,
                expires_in_seconds: None,
            },
            NOW,
            &mut seeded(),
        )
        .unwrap();
        assert_eq!(signed.warnings, ["shortSecret"]);
    }

    // RFC 7518 Appendix C.
    #[test]
    fn concat_kdf_vector() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let key = concat_kdf(&z, "A128GCM", b"Alice", b"Bob", 16).unwrap();
        assert_eq!(b64_encode(&key), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn bad_tokens() {
        for token in [
            "",
            "a",
            "a.b",
            "a.b.c.d",
            "a.b.c",
            "e30.!!.c",
            "eyJhIjoxfQ.e30",
        ] {
            assert!(decode(token, NOW).is_err(), "{token}");
        }
    }
}
