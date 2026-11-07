//! Random bytes, tokens and identifiers (plan 16 §1–2): API keys in common shapes, UUID v4/v7, ULID
//! and NanoID, and new TOTP secrets for people adding 2FA to their own apps.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::encode::{self, Format};
use crate::encoding::base32_encode;
use crate::error::{Error, Result};
use crate::tools::otpauth::{OtpAlgorithm, OtpKind, OtpParams};

/// Most random data one call makes, so a mistyped size can't eat the memory of a phone.
pub const MAX_RANDOM_BYTES: usize = 1 << 20;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const NANOID: &[u8] = b"_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn random_bytes(length: usize, rng: &mut impl CryptoRngCore) -> Result<Zeroizing<Vec<u8>>> {
    if length == 0 || length > MAX_RANDOM_BYTES {
        return Err(Error::InvalidToolInput);
    }
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// `length` characters drawn evenly from `alphabet`, by rejection, so none is more likely.
pub fn random_from(
    alphabet: &[u8],
    length: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    if !(2..=256).contains(&alphabet.len()) || length == 0 || length > MAX_RANDOM_BYTES {
        return Err(Error::InvalidToolInput);
    }
    let size = alphabet.len();
    let limit = 256 - (256 % size);
    let mut text = Zeroizing::new(String::with_capacity(length));
    let mut buffer = Zeroizing::new([0u8; 64]);
    while text.len() < length {
        rng.fill_bytes(&mut buffer[..]);
        for &byte in buffer.iter() {
            if (byte as usize) < limit && text.len() < length {
                text.push(alphabet[byte as usize % size] as char);
            }
        }
    }
    Ok(text)
}

/// A random (version 4) UUID.
pub fn uuid_v4(rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

/// A time-ordered (version 7, RFC 9562) UUID.
pub fn uuid_v7(now_ms: u64, rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; 10];
    rng.fill_bytes(&mut bytes);
    uuid::Builder::from_unix_timestamp_millis(now_ms, &bytes)
        .into_uuid()
        .to_string()
}

/// A ULID: 48 bits of milliseconds and 80 random bits, in Crockford base32.
pub fn ulid(now_ms: u64, rng: &mut impl CryptoRngCore) -> Result<String> {
    if now_ms >= 1 << 48 {
        return Err(Error::InvalidToolInput);
    }
    let mut random = [0u8; 10];
    rng.fill_bytes(&mut random);
    Ok(ulid_from(now_ms, &random))
}

fn ulid_from(now_ms: u64, random: &[u8; 10]) -> String {
    let mut value = u128::from(now_ms) << 80;
    for (index, byte) in random.iter().enumerate() {
        value |= u128::from(*byte) << (8 * (9 - index));
    }
    (0..26)
        .rev()
        .map(|digit| CROCKFORD[((value >> (5 * digit)) & 31) as usize] as char)
        .collect()
}

pub fn is_uuid(text: &str) -> bool {
    text.len() == 36 && Uuid::try_parse(text).is_ok()
}

pub fn is_ulid(text: &str) -> bool {
    text.len() == 26
        // The first character carries only three bits.
        && matches!(text.as_bytes()[0], b'0'..=b'7')
        && text
            .bytes()
            .all(|byte| CROCKFORD.contains(&byte.to_ascii_uppercase()))
}

/// The shapes a new API key can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenShape {
    Hex,
    Base64url,
    Base62,
    Uuid4,
    Uuid7,
    Ulid,
    Nanoid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenOptions {
    pub shape: TokenShape,
    /// Bytes of randomness for hex and base64url, characters for base62 and NanoID. Default: 32
    /// bytes, or a length that holds 256 bits.
    #[serde(default)]
    pub length: Option<usize>,
    /// Put in front, as in `sk_live_…`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// For base62 and NanoID: a custom alphabet of ASCII characters.
    #[serde(default)]
    pub alphabet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub value: Zeroizing<String>,
    /// Bits of randomness in the value, not counting the prefix.
    pub entropy_bits: f64,
}

/// Tokens below this strength can be guessed by a determined attacker.
pub const MIN_TOKEN_BITS: f64 = 128.0;

pub fn token(options: &TokenOptions, now_ms: u64, rng: &mut impl CryptoRngCore) -> Result<Token> {
    let (body, entropy_bits) = match options.shape {
        TokenShape::Hex | TokenShape::Base64url => {
            let length = options.length.unwrap_or(32);
            let bytes = random_bytes(length, rng)?;
            let format = if options.shape == TokenShape::Hex {
                Format::Hex
            } else {
                Format::Base64url
            };
            (
                Zeroizing::new(encode::encode(format, &bytes)?),
                length as f64 * 8.0,
            )
        }
        TokenShape::Base62 | TokenShape::Nanoid => {
            let default = if options.shape == TokenShape::Base62 {
                BASE62
            } else {
                NANOID
            };
            let alphabet = options.alphabet.as_deref().map_or(default, str::as_bytes);
            if !alphabet.is_ascii() {
                return Err(Error::InvalidToolInput);
            }
            let bits_per_char = (distinct(alphabet) as f64).log2();
            let length = options
                .length
                .unwrap_or_else(|| (256.0 / bits_per_char).ceil() as usize);
            (
                random_from(alphabet, length, rng)?,
                bits_per_char * length as f64,
            )
        }
        TokenShape::Uuid4 => (Zeroizing::new(uuid_v4(rng)), 122.0),
        TokenShape::Uuid7 => (Zeroizing::new(uuid_v7(now_ms, rng)), 74.0),
        TokenShape::Ulid => (Zeroizing::new(ulid(now_ms, rng)?), 80.0),
    };
    let mut value = Zeroizing::new(options.prefix.clone().unwrap_or_default());
    value.push_str(&body);
    Ok(Token {
        value,
        entropy_bits,
    })
}

fn distinct(alphabet: &[u8]) -> usize {
    let mut seen = [false; 256];
    alphabet.iter().for_each(|&byte| seen[byte as usize] = true);
    seen.iter().filter(|seen| **seen).count()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSecretOptions {
    /// Bytes of secret. RFC 4226 asks for at least 20.
    #[serde(default)]
    pub bytes: Option<usize>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    /// `sha1` (what most authenticator apps read), `sha256` or `sha512`.
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub digits: Option<u32>,
    #[serde(default)]
    pub period: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSecret {
    pub secret: Zeroizing<String>,
    /// The `otpauth://` URI: the content of the QR code, and what an item's `totp` field holds.
    pub uri: Zeroizing<String>,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
}

pub fn totp_secret(
    options: &TotpSecretOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<TotpSecret> {
    let length = options.bytes.unwrap_or(20);
    if !(16..=64).contains(&length) {
        return Err(Error::InvalidToolInput);
    }
    let digits = options.digits.unwrap_or(6);
    let period = options.period.unwrap_or(30);
    if !(6..=8).contains(&digits) || !(15..=120).contains(&period) {
        return Err(Error::InvalidToolInput);
    }
    let (algorithm, name) = match options.algorithm.as_deref().unwrap_or("sha1") {
        "sha1" => (OtpAlgorithm::Sha1, "sha1"),
        "sha256" => (OtpAlgorithm::Sha256, "sha256"),
        "sha512" => (OtpAlgorithm::Sha512, "sha512"),
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    let secret = random_bytes(length, rng)?;
    let params = OtpParams {
        kind: OtpKind::Totp { period },
        secret: Zeroizing::new(secret.to_vec()),
        algorithm,
        digits,
        issuer: options.issuer.clone().filter(|issuer| !issuer.is_empty()),
        account: options
            .account
            .clone()
            .filter(|account| !account.is_empty()),
    };
    Ok(TotpSecret {
        secret: Zeroizing::new(base32_encode(&secret)),
        uri: params.to_uri(),
        algorithm: name.to_owned(),
        digits,
        period,
    })
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, SeedableRng};

    use super::*;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([7; 32])
    }

    // The ULID spec's example timestamp: 1469918176385 is `01ARYZ6S41`.
    #[test]
    fn ulid_timestamp_encoding() {
        let text = ulid_from(1469918176385, &[0; 10]);
        assert_eq!(&text[..10], "01ARYZ6S41");
        assert_eq!(&text[10..], "0000000000000000");
        assert_eq!(
            ulid_from(1469918176385, &[255; 10])[10..],
            *"ZZZZZZZZZZZZZZZZ"
        );
        assert!(is_ulid(&text));
        assert_eq!(ulid(1 << 48, &mut seeded()), Err(Error::InvalidToolInput));
    }

    #[test]
    fn uuids() {
        let v4 = uuid_v4(&mut seeded());
        assert_eq!(&v4[14..15], "4");
        assert!(matches!(&v4[19..20], "8" | "9" | "a" | "b"));
        assert!(is_uuid(&v4));
        // RFC 9562 appendix A.6's timestamp: 2022-02-22 19:22:22 UTC.
        let v7 = uuid_v7(0x017F22E279B0, &mut seeded());
        assert!(v7.starts_with("017f22e2-79b0-7"), "{v7}");
    }

    #[test]
    fn tokens_have_the_shape_asked_for() {
        let mut rng = seeded();
        let option = |shape, length, prefix: Option<&str>| TokenOptions {
            shape,
            length,
            prefix: prefix.map(str::to_owned),
            alphabet: None,
        };
        let hex = token(&option(TokenShape::Hex, Some(16), None), 0, &mut rng).unwrap();
        assert_eq!(hex.value.len(), 32);
        assert_eq!(hex.entropy_bits, 128.0);
        let url = token(&option(TokenShape::Base64url, None, None), 0, &mut rng).unwrap();
        assert_eq!(url.value.len(), 43);
        let prefixed = token(
            &option(TokenShape::Base62, None, Some("sk_live_")),
            0,
            &mut rng,
        )
        .unwrap();
        assert!(prefixed.value.starts_with("sk_live_"));
        assert_eq!(prefixed.value.len(), 8 + 43);
        assert!(prefixed.entropy_bits >= 256.0);
        let nano = token(&option(TokenShape::Nanoid, Some(21), None), 0, &mut rng).unwrap();
        assert_eq!(nano.value.len(), 21);
        assert!((nano.entropy_bits - 126.0).abs() < 0.001);
    }

    #[test]
    fn random_alphabet_is_even() {
        let text = random_from(b"abc", 90_000, &mut OsRng).unwrap();
        for letter in ['a', 'b', 'c'] {
            let count = text.chars().filter(|c| *c == letter).count();
            assert!((29_000..31_000).contains(&count), "{letter}: {count}");
        }
    }

    #[test]
    fn limits() {
        assert!(random_bytes(0, &mut OsRng).is_err());
        assert!(random_bytes(MAX_RANDOM_BYTES + 1, &mut OsRng).is_err());
        assert!(random_from(b"a", 4, &mut OsRng).is_err());
    }

    #[test]
    fn totp_secret_is_an_authenticator_uri_the_core_reads_back() {
        let made = totp_secret(
            &TotpSecretOptions {
                issuer: Some("Acme".into()),
                account: Some("ada@example.com".into()),
                ..Default::default()
            },
            &mut seeded(),
        )
        .unwrap();
        assert_eq!(made.secret.len(), 32);
        assert!(made.uri.starts_with("otpauth://totp/"));
        let parsed = OtpParams::parse(&made.uri).unwrap();
        assert_eq!(parsed.secret.len(), 20);
        assert_eq!(parsed.issuer.as_deref(), Some("Acme"));
        assert_eq!(parsed.digits, 6);
        assert!(crate::tools::totp::totp_code(&made.uri, 59).is_ok());
        assert!(
            totp_secret(
                &TotpSecretOptions {
                    bytes: Some(8),
                    ..Default::default()
                },
                &mut OsRng
            )
            .is_err()
        );
    }
}
