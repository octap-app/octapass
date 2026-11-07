//! From master password + Secret Key to the Account Unlock Key (AUK) and the OPAQUE password
//! input (`auth_secret`).
//!
//! ```text
//! pw_key      = Argon2id(NFKD(password), salt = HKDF(account_salt, "octapass/v1", email)[0..16])
//! sk_key      = HKDF(ikm = secret_key, salt = account_salt, info = "octapass/v1/secret-key")
//! AUK         = HKDF(ikm = pw_key ‖ sk_key, salt = "", info = "octapass/v1/auk")
//! auth_secret = HKDF(ikm = pw_key ‖ sk_key, salt = "", info = "octapass/v1/auth")
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{KEY_LEN, SymmetricKey, hkdf_key};
use crate::secret_key::SecretKey;

pub const ACCOUNT_SALT_LEN: usize = 16;
const ARGON2_SALT_LEN: usize = 16;

/// Argon2id parameters, stored per account and returned by `prelogin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2id,
}

impl KdfParams {
    /// The parameters every new account gets: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// The parameters come from the server, so they are checked before use: weaker than the
    /// defaults would let a malicious server cheapen offline guessing, and absurdly large values
    /// would freeze or crash the client.
    pub fn validate(&self) -> Result<()> {
        let ok = (Self::DEFAULT.memory_kib..=1_048_576).contains(&self.memory_kib)
            && (Self::DEFAULT.iterations..=16).contains(&self.iterations)
            && (1..=4).contains(&self.parallelism);
        ok.then_some(()).ok_or(Error::UnsupportedKdf)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Emails are trimmed and lower-cased everywhere: in the Argon2 salt, as the OPAQUE credential
/// identifier and in the account bundle.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Master passwords are NFKD-normalised so the same password typed on different keyboards and
/// platforms derives the same key. They are deliberately not trimmed.
pub fn normalize_password(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfkd().collect())
}

pub fn generate_account_salt(rng: &mut impl CryptoRngCore) -> [u8; ACCOUNT_SALT_LEN] {
    let mut salt = [0u8; ACCOUNT_SALT_LEN];
    rng.fill_bytes(&mut salt);
    salt
}

/// `HKDF-SHA256(ikm = account_salt, salt = "octapass/v1", info = email)[0..16]`.
pub fn argon2_salt(account_salt: &[u8], email: &str) -> [u8; ARGON2_SALT_LEN] {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    Hkdf::<Sha256>::new(Some(b"octapass/v1"), account_salt)
        .expand(normalize_email(email).as_bytes(), &mut salt)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    salt
}

/// The password half of the AUK: Argon2id over the NFKD-normalised password.
pub fn password_key(
    password: &str,
    email: &str,
    account_salt: &[u8],
    params: &KdfParams,
) -> Result<SymmetricKey> {
    argon2id(password, &argon2_salt(account_salt, email), params)
}

/// Argon2id v1.3 over the NFKD-normalised password, after checking `params` with
/// [`KdfParams::validate`]. Local vaults, backups and encrypted exports use it with their own salt.
pub fn argon2id(password: &str, salt: &[u8], params: &KdfParams) -> Result<SymmetricKey> {
    params.validate()?;
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::UnsupportedKdf)?,
    );
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(normalize_password(password).as_bytes(), salt, &mut out)
        .map_err(|_| Error::KdfFailed)?;
    let key = SymmetricKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// The Secret Key half of the AUK.
pub fn secret_key_key(secret_key: &SecretKey, account_salt: &[u8]) -> SymmetricKey {
    hkdf_key(
        secret_key.as_bytes(),
        account_salt,
        b"octapass/v1/secret-key",
    )
}

/// The two keys derived from password + Secret Key.
#[derive(Clone, Debug)]
pub struct AccountKeys {
    /// Account Unlock Key: unwraps the ASK. Never leaves the device.
    pub auk: SymmetricKey,
    /// The OPAQUE password input. Never leaves the device either; OPAQUE only proves knowledge.
    pub auth_secret: SymmetricKey,
}

impl AccountKeys {
    /// Runs the full derivation (Argon2id, so this is the slow step: about a second).
    pub fn derive(
        password: &str,
        secret_key: &SecretKey,
        email: &str,
        account_salt: &[u8],
        params: &KdfParams,
    ) -> Result<Self> {
        let pw_key = password_key(password, email, account_salt, params)?;
        let sk_key = secret_key_key(secret_key, account_salt);
        Ok(Self::combine(&pw_key, &sk_key))
    }

    pub fn combine(pw_key: &SymmetricKey, sk_key: &SymmetricKey) -> Self {
        let mut combined = Zeroizing::new([0u8; 2 * KEY_LEN]);
        combined[..KEY_LEN].copy_from_slice(pw_key.as_bytes());
        combined[KEY_LEN..].copy_from_slice(sk_key.as_bytes());
        Self {
            auk: hkdf_key(combined.as_ref(), b"", b"octapass/v1/auk"),
            auth_secret: hkdf_key(combined.as_ref(), b"", b"octapass/v1/auth"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalisation() {
        assert_eq!(
            normalize_email("  Alice@Example.COM\n"),
            "alice@example.com"
        );
    }

    #[test]
    fn password_normalisation_is_nfkd_without_trimming() {
        // "é" precomposed (U+00E9) and decomposed (e + U+0301) normalise to the same bytes.
        assert_eq!(
            *normalize_password("caf\u{e9} "),
            *normalize_password("cafe\u{301} ")
        );
        assert_eq!(normalize_password(" pw ").as_str(), " pw ");
        // Compatibility characters fold too: the "ﬁ" ligature becomes "fi".
        assert_eq!(normalize_password("\u{fb01}").as_str(), "fi");
    }

    #[test]
    fn argon2_salt_uses_normalised_email() {
        let salt = [5u8; 16];
        assert_eq!(argon2_salt(&salt, "A@B.c "), argon2_salt(&salt, "a@b.c"));
        assert_ne!(
            argon2_salt(&salt, "a@b.c"),
            argon2_salt(&[6u8; 16], "a@b.c")
        );
    }

    #[test]
    fn kdf_params_validation() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        let weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::DEFAULT
        };
        assert_eq!(weak.validate().unwrap_err(), Error::UnsupportedKdf);
        let few = KdfParams {
            iterations: 1,
            ..KdfParams::DEFAULT
        };
        assert_eq!(few.validate().unwrap_err(), Error::UnsupportedKdf);
        let huge = KdfParams {
            memory_kib: 8 << 20,
            ..KdfParams::DEFAULT
        };
        assert_eq!(huge.validate().unwrap_err(), Error::UnsupportedKdf);
        let json = serde_json::to_string(&KdfParams::DEFAULT).unwrap();
        assert_eq!(
            json,
            r#"{"algorithm":"argon2id","memoryKib":65536,"iterations":3,"parallelism":1}"#
        );
    }

    #[test]
    fn auk_and_auth_secret_are_independent() {
        let keys = AccountKeys::combine(
            &SymmetricKey::from_bytes([1; 32]),
            &SymmetricKey::from_bytes([2; 32]),
        );
        assert_ne!(keys.auk, keys.auth_secret);
        let other = AccountKeys::combine(
            &SymmetricKey::from_bytes([1; 32]),
            &SymmetricKey::from_bytes([3; 32]),
        );
        assert_ne!(keys.auk, other.auk, "the Secret Key changes the AUK");
    }
}
