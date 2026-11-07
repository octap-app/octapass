//! OpenPGP keys for signing commits and email (plan 16 §1), on rPGP: an Ed25519 primary key for
//! certifying and signing with a Curve25519 encryption subkey, or RSA with an RSA subkey. These are
//! version 4 keys, the ones `gpg` and Git read today.

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, KeyDetails as _, Timestamp};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPgpOptions {
    /// `Name <email>`.
    pub user_id: String,
    /// `ed25519` (default) or `rsa4096`.
    #[serde(default)]
    pub key_type: Option<String>,
    /// Protects the armored private key. The vault encrypts its copy anyway.
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPgpKey {
    pub user_id: String,
    pub fingerprint: String,
    /// The last 16 hex characters: what `gpg --list-keys --keyid-format long` shows.
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub private_key: Zeroizing<String>,
}

pub fn generate(
    options: &OpenPgpOptions,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<OpenPgpKey> {
    let user_id = options.user_id.trim();
    if user_id.is_empty() || user_id.contains(['\r', '\n']) {
        return Err(Error::InvalidToolInput);
    }
    let (primary, subkey, algorithm) = match options.key_type.as_deref().unwrap_or("ed25519") {
        "ed25519" => (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
            "ed25519",
        ),
        "rsa4096" => (KeyType::Rsa(4096), KeyType::Rsa(4096), "rsa4096"),
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    let created =
        Timestamp::from_secs(u32::try_from(now_seconds).map_err(|_| Error::InvalidToolInput)?);
    let passphrase = options
        .passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str().to_owned())
        .filter(|passphrase| !passphrase.is_empty());
    let subkey = SubkeyParamsBuilder::default()
        .key_type(subkey)
        .can_encrypt(EncryptionCaps::All)
        .passphrase(passphrase.clone())
        .created_at(created)
        .build()
        .map_err(|_| Error::InvalidToolInput)?;
    let params = SecretKeyParamsBuilder::default()
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id.to_owned())
        .passphrase(passphrase)
        .created_at(created)
        .preferred_symmetric_algorithms(
            vec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ]
            .into(),
        )
        .preferred_hash_algorithms(
            vec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ]
            .into(),
        )
        .preferred_compression_algorithms(
            vec![CompressionAlgorithm::ZLIB, CompressionAlgorithm::ZIP].into(),
        )
        .subkey(subkey)
        .build()
        .map_err(|_| Error::InvalidToolInput)?;
    let secret: SignedSecretKey = params.generate(rng).map_err(|_| Error::InvalidKey)?;
    let private_key = secret
        .to_armored_string(None.into())
        .map_err(|_| Error::InvalidKey)?;
    describe(
        &secret.to_public_key(),
        Zeroizing::new(private_key),
        user_id,
        algorithm,
    )
}

fn describe(
    public: &SignedPublicKey,
    private_key: Zeroizing<String>,
    user_id: &str,
    algorithm: &str,
) -> Result<OpenPgpKey> {
    let fingerprint = hex_upper(public.fingerprint().as_bytes());
    Ok(OpenPgpKey {
        user_id: user_id.to_owned(),
        key_id: fingerprint[fingerprint.len() - 16..].to_owned(),
        fingerprint,
        algorithm: algorithm.to_owned(),
        public_key: public
            .to_armored_string(None.into())
            .map_err(|_| Error::InvalidKey)?,
        private_key,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// A public key's fingerprint and user IDs, from armored text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPgpInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
}

pub fn inspect(armored: &str) -> Result<OpenPgpInfo> {
    let (public, _) = SignedPublicKey::from_string(armored)
        .or_else(|_| {
            SignedSecretKey::from_string(armored)
                .map(|(secret, headers)| (secret.to_public_key(), headers))
        })
        .map_err(|_| Error::InvalidKeyFile)?;
    public
        .verify_bindings()
        .map_err(|_| Error::InvalidKeyFile)?;
    let fingerprint = hex_upper(public.fingerprint().as_bytes());
    Ok(OpenPgpInfo {
        key_id: fingerprint[fingerprint.len() - 16..].to_owned(),
        fingerprint,
        user_ids: public
            .details
            .users
            .iter()
            .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;

    const NOW: u64 = 1_793_000_000;

    #[test]
    fn generated_key_reads_back_with_valid_bindings() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([3; 32]);
        let key = generate(
            &OpenPgpOptions {
                user_id: "Ada <ada@example.test>".into(),
                key_type: None,
                passphrase: None,
            },
            NOW,
            &mut rng,
        )
        .unwrap();
        assert!(key.public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(key.private_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert_eq!(key.fingerprint.len(), 40);
        let info = inspect(&key.public_key).unwrap();
        assert_eq!(info.fingerprint, key.fingerprint);
        assert_eq!(info.user_ids, ["Ada <ada@example.test>"]);
        assert_eq!(
            inspect(&key.private_key).unwrap().fingerprint,
            key.fingerprint
        );
    }

    #[test]
    fn user_ids_stay_on_one_line() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([3; 32]);
        for user_id in ["", "a\nb"] {
            let options = OpenPgpOptions {
                user_id: user_id.into(),
                key_type: None,
                passphrase: None,
            };
            assert!(generate(&options, NOW, &mut rng).is_err());
        }
    }
}
