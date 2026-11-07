//! Password hashes for people's own apps (plan 16 §1): Argon2id, bcrypt, scrypt and PBKDF2, in the
//! formats libraries store them in (PHC strings, and `$2b$` for bcrypt), with a verify mode.
//!
//! Costs are bounded both ways: below the floors the hash protects nothing, and a hash pasted in to
//! verify can ask for any cost, so the ceilings stop it freezing the device.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use pbkdf2::Pbkdf2;
use rand_core::CryptoRngCore;
use scrypt::Scrypt;
use serde::{Deserialize, Serialize};
use subtle_compare::constant_time_eq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Lower bounds are OWASP's minimums from the password storage cheat sheet, except that a hash can
/// be verified at any cost that isn't absurd: old hashes need checking too.
const ARGON2_MIN_KIB: u32 = 7 * 1024;
const ARGON2_MAX_KIB: u32 = 1024 * 1024;
const ARGON2_MAX_TIME: u32 = 64;
const BCRYPT_MIN_COST: u32 = 10;
const BCRYPT_MAX_COST: u32 = 18;
const SCRYPT_MIN_LOG_N: u8 = 15;
const SCRYPT_MAX_LOG_N: u8 = 22;
const PBKDF2_MIN_ROUNDS: u32 = 210_000;
const PBKDF2_MAX_ROUNDS: u32 = 20_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Argon2id,
    Bcrypt,
    Scrypt,
    Pbkdf2,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashOptions {
    /// Argon2id: memory in KiB. Default 65536.
    #[serde(default)]
    pub memory_kib: Option<u32>,
    /// Argon2id: passes. Default 3. PBKDF2: rounds. Default 600000.
    #[serde(default)]
    pub iterations: Option<u32>,
    /// Argon2id and scrypt: lanes. Default 1.
    #[serde(default)]
    pub parallelism: Option<u32>,
    /// bcrypt: cost. Default 12.
    #[serde(default)]
    pub cost: Option<u32>,
    /// scrypt: log2 of N. Default 17.
    #[serde(default)]
    pub log_n: Option<u8>,
    /// scrypt: block size. Default 8.
    #[serde(default)]
    pub block_size: Option<u32>,
    /// PBKDF2: `sha256` (default) or `sha512`.
    #[serde(default)]
    pub digest: Option<String>,
}

/// What a hash string says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashInfo {
    pub scheme: Scheme,
    pub parameters: String,
}

fn salt(rng: &mut impl CryptoRngCore) -> Result<SaltString> {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    SaltString::encode_b64(&bytes).map_err(|_| Error::InvalidToolInput)
}

/// Hashes `password` with a new random salt.
pub fn hash(
    scheme: Scheme,
    password: &str,
    options: &HashOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    if password.is_empty() {
        return Err(Error::InvalidToolInput);
    }
    match scheme {
        Scheme::Argon2id => {
            let memory = options.memory_kib.unwrap_or(65536);
            let time = options.iterations.unwrap_or(3);
            let lanes = options.parallelism.unwrap_or(1);
            if !(ARGON2_MIN_KIB..=ARGON2_MAX_KIB).contains(&memory)
                || !(1..=ARGON2_MAX_TIME).contains(&time)
                || !(1..=16).contains(&lanes)
            {
                return Err(Error::InvalidHashParameters);
            }
            let params =
                Params::new(memory, time, lanes, None).map_err(|_| Error::InvalidHashParameters)?;
            let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = salt(rng)?;
            hasher
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| Error::KdfFailed)
        }
        Scheme::Bcrypt => {
            let cost = options.cost.unwrap_or(12);
            if !(BCRYPT_MIN_COST..=BCRYPT_MAX_COST).contains(&cost) {
                return Err(Error::InvalidHashParameters);
            }
            // bcrypt keeps only the first 72 bytes: longer passwords would silently match on their
            // beginning alone.
            if password.len() > 72 {
                return Err(Error::InvalidToolInput);
            }
            let mut salt = [0u8; 16];
            rng.fill_bytes(&mut salt);
            Ok(bcrypt_string(cost, salt, password))
        }
        Scheme::Scrypt => {
            let log_n = options.log_n.unwrap_or(17);
            let r = options.block_size.unwrap_or(8);
            let p = options.parallelism.unwrap_or(1);
            if !(SCRYPT_MIN_LOG_N..=SCRYPT_MAX_LOG_N).contains(&log_n) {
                return Err(Error::InvalidHashParameters);
            }
            let params = scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
                .map_err(|_| Error::InvalidHashParameters)?;
            let salt = salt(rng)?;
            Scrypt
                .hash_password_customized(password.as_bytes(), None, None, params, &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| Error::KdfFailed)
        }
        Scheme::Pbkdf2 => {
            let rounds = options.iterations.unwrap_or(600_000);
            if !(PBKDF2_MIN_ROUNDS..=PBKDF2_MAX_ROUNDS).contains(&rounds) {
                return Err(Error::InvalidHashParameters);
            }
            let (algorithm, output_length) = match options.digest.as_deref().unwrap_or("sha256") {
                "sha256" => (pbkdf2::Algorithm::Pbkdf2Sha256, 32),
                "sha512" => (pbkdf2::Algorithm::Pbkdf2Sha512, 64),
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            let params = pbkdf2::Params {
                rounds,
                output_length,
            };
            let salt = salt(rng)?;
            Pbkdf2
                .hash_password_customized(
                    password.as_bytes(),
                    Some(algorithm.ident()),
                    None,
                    params,
                    &salt,
                )
                .map(|hash| hash.to_string())
                .map_err(|_| Error::KdfFailed)
        }
    }
}

const BCRYPT_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::BCRYPT,
    base64::engine::general_purpose::NO_PAD,
);

fn bcrypt_string(cost: u32, salt: [u8; 16], password: &str) -> String {
    let output = bcrypt_raw(cost, salt, password);
    format!(
        "$2b${cost:02}${}{}",
        BCRYPT_ENGINE.encode(salt),
        BCRYPT_ENGINE.encode(&output[..23])
    )
}

/// bcrypt over `password` and a terminating NUL, as the C implementation hashes it, cut at 72 bytes.
fn bcrypt_raw(cost: u32, salt: [u8; 16], password: &str) -> [u8; 24] {
    let mut key = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    key.extend_from_slice(password.as_bytes());
    key.push(0);
    key.truncate(72);
    bcrypt::bcrypt(cost, salt, &key)
}

/// Whether `password` matches `hash`, whichever scheme wrote it.
pub fn verify(password: &str, hash: &str) -> Result<bool> {
    let hash = hash.trim();
    if hash.starts_with("$2") {
        return verify_bcrypt(password, hash);
    }
    let parsed = PasswordHash::new(hash).map_err(|_| Error::InvalidHashParameters)?;
    check_ceiling(&parsed)?;
    let result = match parsed.algorithm.as_str() {
        "argon2id" | "argon2i" | "argon2d" => {
            Argon2::default().verify_password(password.as_bytes(), &parsed)
        }
        "scrypt" => Scrypt.verify_password(password.as_bytes(), &parsed),
        "pbkdf2" | "pbkdf2-sha256" | "pbkdf2-sha512" => {
            Pbkdf2.verify_password(password.as_bytes(), &parsed)
        }
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    match result {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(Error::InvalidHashParameters),
    }
}

fn param(hash: &PasswordHash<'_>, name: &str) -> Option<u32> {
    hash.params.get(name).and_then(|value| value.decimal().ok())
}

fn check_ceiling(hash: &PasswordHash<'_>) -> Result<()> {
    let within = match hash.algorithm.as_str() {
        "argon2id" | "argon2i" | "argon2d" => {
            param(hash, "m").is_none_or(|m| m <= ARGON2_MAX_KIB)
                && param(hash, "t").is_none_or(|t| t <= ARGON2_MAX_TIME)
                && param(hash, "p").is_none_or(|p| p <= 64)
        }
        "scrypt" => {
            param(hash, "ln").is_none_or(|ln| ln <= u32::from(SCRYPT_MAX_LOG_N))
                && param(hash, "r").is_none_or(|r| r <= 32)
                && param(hash, "p").is_none_or(|p| p <= 16)
        }
        _ => param(hash, "i").is_none_or(|rounds| rounds <= PBKDF2_MAX_ROUNDS),
    };
    within.then_some(()).ok_or(Error::InvalidHashParameters)
}

fn verify_bcrypt(password: &str, hash: &str) -> Result<bool> {
    let mut parts = hash.split('$').skip(1);
    let version = parts.next().ok_or(Error::InvalidHashParameters)?;
    let cost = parts.next().ok_or(Error::InvalidHashParameters)?;
    let rest = parts.next().ok_or(Error::InvalidHashParameters)?;
    if !matches!(version, "2a" | "2b" | "2y") || rest.len() != 53 {
        return Err(Error::InvalidHashParameters);
    }
    let cost: u32 = cost.parse().map_err(|_| Error::InvalidHashParameters)?;
    if !(4..=BCRYPT_MAX_COST).contains(&cost) {
        return Err(Error::InvalidHashParameters);
    }
    let salt = BCRYPT_ENGINE
        .decode(&rest[..22])
        .map_err(|_| Error::InvalidHashParameters)?;
    let expected = BCRYPT_ENGINE
        .decode(&rest[22..])
        .map_err(|_| Error::InvalidHashParameters)?;
    let salt: [u8; 16] = salt.try_into().map_err(|_| Error::InvalidHashParameters)?;
    let actual = bcrypt_raw(cost, salt, password);
    Ok(constant_time_eq(&actual[..23], &expected))
}

/// The scheme and costs a hash string carries.
pub fn inspect(hash: &str) -> Result<HashInfo> {
    let hash = hash.trim();
    if hash.starts_with("$2") {
        let cost = hash.split('$').nth(2).ok_or(Error::InvalidHashParameters)?;
        return Ok(HashInfo {
            scheme: Scheme::Bcrypt,
            parameters: format!("cost={cost}"),
        });
    }
    let parsed = PasswordHash::new(hash).map_err(|_| Error::InvalidHashParameters)?;
    let scheme = match parsed.algorithm.as_str() {
        "argon2id" | "argon2i" | "argon2d" => Scheme::Argon2id,
        "scrypt" => Scheme::Scrypt,
        "pbkdf2" | "pbkdf2-sha256" | "pbkdf2-sha512" => Scheme::Pbkdf2,
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    Ok(HashInfo {
        scheme,
        parameters: parsed.params.to_string(),
    })
}

mod subtle_compare {
    /// Compares without stopping at the first difference.
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn known_hashes_from_other_implementations_verify() {
        // bcrypt: written by Apache's `htpasswd -nbBC 5`.
        assert!(
            verify(
                "U*U",
                "$2y$05$JcKbLZCMJBhOCVk.qtHlH.XrAdEo4V4pdAevlo.RgLWW8xwgr4DEq"
            )
            .unwrap()
        );
        assert!(
            !verify(
                "U*V",
                "$2y$05$JcKbLZCMJBhOCVk.qtHlH.XrAdEo4V4pdAevlo.RgLWW8xwgr4DEq"
            )
            .unwrap()
        );
        // The Argon2 reference implementation's `argon2 somesalt -id -t 2 -m 16 -p 4 -l 24`.
        assert!(
            verify(
                "password",
                "$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo"
            )
            .is_ok()
        );
    }

    #[test]
    fn each_scheme_round_trips() {
        for (scheme, options, prefix) in [
            (
                Scheme::Argon2id,
                HashOptions {
                    memory_kib: Some(ARGON2_MIN_KIB),
                    iterations: Some(1),
                    ..Default::default()
                },
                "$argon2id$v=19$m=7168,t=1,p=1$",
            ),
            (
                Scheme::Bcrypt,
                HashOptions {
                    cost: Some(10),
                    ..Default::default()
                },
                "$2b$10$",
            ),
            (
                Scheme::Scrypt,
                HashOptions {
                    log_n: Some(15),
                    ..Default::default()
                },
                "$scrypt$ln=15,r=8,p=1$",
            ),
            (
                Scheme::Pbkdf2,
                HashOptions {
                    iterations: Some(PBKDF2_MIN_ROUNDS),
                    ..Default::default()
                },
                "$pbkdf2-sha256$i=210000,l=32$",
            ),
            (
                Scheme::Pbkdf2,
                HashOptions {
                    iterations: Some(PBKDF2_MIN_ROUNDS),
                    digest: Some("sha512".into()),
                    ..Default::default()
                },
                "$pbkdf2-sha512$i=210000,l=64$",
            ),
        ] {
            let text = hash(scheme, "correct horse", &options, &mut OsRng).unwrap();
            assert!(text.starts_with(prefix), "{text}");
            assert!(verify("correct horse", &text).unwrap(), "{text}");
            assert!(!verify("wrong horse", &text).unwrap(), "{text}");
            assert_eq!(inspect(&text).unwrap().scheme, scheme);
        }
    }

    #[test]
    fn unsafe_costs_are_refused() {
        let weak = HashOptions {
            cost: Some(4),
            ..Default::default()
        };
        assert_eq!(
            hash(Scheme::Bcrypt, "p", &weak, &mut OsRng),
            Err(Error::InvalidHashParameters)
        );
        let weak = HashOptions {
            iterations: Some(1000),
            ..Default::default()
        };
        assert_eq!(
            hash(Scheme::Pbkdf2, "p", &weak, &mut OsRng),
            Err(Error::InvalidHashParameters)
        );
        let weak = HashOptions {
            memory_kib: Some(1024),
            ..Default::default()
        };
        assert_eq!(
            hash(Scheme::Argon2id, "p", &weak, &mut OsRng),
            Err(Error::InvalidHashParameters)
        );
        assert_eq!(
            hash(
                Scheme::Bcrypt,
                &"x".repeat(73),
                &HashOptions::default(),
                &mut OsRng
            ),
            Err(Error::InvalidToolInput)
        );
    }

    #[test]
    fn pasted_hashes_cant_freeze_the_device() {
        for text in [
            "$2b$31$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMKKfYWoW",
            "$argon2id$v=19$m=4294967295,t=1,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/6g",
            "$pbkdf2-sha256$i=4294967295,l=32$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/6g",
            "$scrypt$ln=40,r=8,p=1$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/6g",
        ] {
            assert_eq!(
                verify("p", text),
                Err(Error::InvalidHashParameters),
                "{text}"
            );
        }
        assert!(verify("p", "not a hash").is_err());
    }
}
