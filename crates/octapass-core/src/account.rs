//! Creating an account: every key and the `AccountBundle` the server stores.

use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::encoding::{b64_decode, b64_decode_array, b64_encode};
use crate::envelope::{Context, open_b64, seal_b64, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::kdf::{AccountKeys, KdfParams, generate_account_salt, normalize_email};
use crate::keys::SymmetricKey;
use crate::recovery::RecoveryCode;
use crate::secret_key::SecretKey;
use crate::sharing::pq::PqKeyPair;
use crate::transparency::record::KeyRecord;

/// What the server stores per account. Everything in it is either public or encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBundle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub email: String,
    pub kdf: KdfParams,
    pub account_salt: String,
    /// ASK sealed by the AUK (context `ask`).
    pub wrapped_ask: String,
    /// X25519 public key, for sharing.
    pub public_enc_key: String,
    /// Ed25519 public key, for signatures.
    pub public_sign_key: String,
    /// `x25519_secret (32) ‖ ed25519_seed (32)` sealed by the ASK (context `privkeys`).
    pub wrapped_private_keys: String,
    /// ASK sealed by the recovery code's wrapping key (context `recovery`).
    pub recovery_wrapped_ask: String,
    /// The ML-KEM-768 seed sealed by the ASK (context `pqprivkey`). Accounts get one the first
    /// time a client unlocks them, together with `key_record`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_pq_private_key: Option<String>,
    /// The account's signed statement of its public keys, as published in the key log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
}

impl AccountBundle {
    pub fn account_salt_bytes(&self) -> Result<Vec<u8>> {
        b64_decode(&self.account_salt)
    }

    /// Unwraps the ASK with the AUK (normal unlock).
    pub fn unwrap_ask(&self, auk: &SymmetricKey) -> Result<SymmetricKey> {
        unwrap_key(auk, &Context::Ask, &self.wrapped_ask)
    }

    /// Unwraps the ASK with the recovery code (lost password or Secret Key).
    pub fn unwrap_ask_with_recovery(&self, code: &RecoveryCode) -> Result<SymmetricKey> {
        unwrap_key(
            &code.wrapping_key(),
            &Context::Recovery,
            &self.recovery_wrapped_ask,
        )
    }

    /// Opens the private keys and checks they match the public keys in the bundle, so a server
    /// can't pair our private keys with public keys of its choosing.
    pub fn open_key_pairs(&self, ask: &SymmetricKey) -> Result<AccountKeyPairs> {
        let pairs = AccountKeyPairs::from_bytes(&open_b64(
            ask,
            &Context::PrivateKeys,
            &self.wrapped_private_keys,
        )?)?;
        let enc: [u8; 32] =
            b64_decode_array(&self.public_enc_key).map_err(|_| Error::InvalidAccountBundle)?;
        let sign: [u8; 32] =
            b64_decode_array(&self.public_sign_key).map_err(|_| Error::InvalidAccountBundle)?;
        if pairs.public_enc_key() != enc || pairs.public_sign_key() != sign {
            return Err(Error::KeyMismatch);
        }
        Ok(pairs)
    }

    /// Opens the ML-KEM key, if the account has one, and checks it against the signed key record
    /// and the account's own signing key: the server can't substitute either.
    pub fn open_pq_keys(&self, ask: &SymmetricKey) -> Result<Option<PqKeyPair>> {
        let (Some(wrapped), Some(record)) = (&self.wrapped_pq_private_key, &self.key_record) else {
            return Ok(None);
        };
        let pair = PqKeyPair::from_seed(&open_b64(ask, &Context::PqPrivateKey, wrapped)?)?;
        record.verify()?;
        if record.public_sign_key != self.public_sign_key
            || record.public_enc_key != self.public_enc_key
            || record.public_pq_key != pair.public_key().to_b64()
        {
            return Err(Error::KeyMismatch);
        }
        Ok(Some(pair))
    }
}

/// The account's X25519 (encryption) and Ed25519 (signing) private keys. Both zero themselves on
/// drop.
pub struct AccountKeyPairs {
    encryption: StaticSecret,
    signing: SigningKey,
}

impl AccountKeyPairs {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        Self {
            encryption: StaticSecret::random_from_rng(&mut *rng),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_enc_key(&self) -> [u8; 32] {
        PublicKey::from(&self.encryption).to_bytes()
    }

    pub fn public_sign_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn encryption_key(&self) -> &StaticSecret {
        &self.encryption
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.encryption.as_bytes());
        out[32..].copy_from_slice(self.signing.as_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidKey);
        }
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut seed = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&bytes[..32]);
        seed.copy_from_slice(&bytes[32..]);
        Ok(Self {
            encryption: StaticSecret::from(*enc),
            signing: SigningKey::from_bytes(&seed),
        })
    }
}

/// The personal vault created at sign-up: `{ id, wrappedVaultKey }` in `register/finish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVault {
    pub id: String,
    pub wrapped_vault_key: String,
}

/// Everything sign-up produces. The secrets in it are shown once (Secret Key, recovery code) or
/// kept only in memory.
pub struct NewAccount {
    pub secret_key: SecretKey,
    pub recovery_code: RecoveryCode,
    pub keys: AccountKeys,
    pub ask: SymmetricKey,
    pub key_pairs: AccountKeyPairs,
    pub bundle: AccountBundle,
    pub personal_vault: NewVault,
    pub personal_vault_key: SymmetricKey,
}

impl NewAccount {
    /// Generates a new account. Runs Argon2id, so it takes about a second.
    ///
    /// `now_ms` (Unix milliseconds) only feeds the UUIDv7 of the personal vault.
    pub fn create(
        email: &str,
        password: &str,
        kdf: KdfParams,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let email = normalize_email(email);
        let secret_key = SecretKey::generate(rng);
        let account_salt = generate_account_salt(rng);
        let keys = AccountKeys::derive(password, &secret_key, &email, &account_salt, &kdf)?;

        let ask = SymmetricKey::generate(rng);
        let key_pairs = AccountKeyPairs::generate(rng);
        let recovery_code = RecoveryCode::generate(rng);
        let personal_vault_key = SymmetricKey::generate(rng);
        let vault_id = new_id(now_ms, rng);

        let bundle = AccountBundle {
            account_id: None,
            email,
            kdf,
            account_salt: b64_encode(&account_salt),
            wrapped_ask: wrap_key(&keys.auk, &Context::Ask, &ask, rng)?,
            public_enc_key: b64_encode(&key_pairs.public_enc_key()),
            public_sign_key: b64_encode(&key_pairs.public_sign_key()),
            wrapped_private_keys: seal_b64(
                &ask,
                &Context::PrivateKeys,
                key_pairs.to_bytes().as_ref(),
                rng,
            )?,
            recovery_wrapped_ask: wrap_key(
                &recovery_code.wrapping_key(),
                &Context::Recovery,
                &ask,
                rng,
            )?,
            wrapped_pq_private_key: None,
            key_record: None,
        };
        let personal_vault = NewVault {
            wrapped_vault_key: wrap_key(
                &ask,
                &Context::VaultKey {
                    vault_id: &vault_id,
                },
                &personal_vault_key,
                rng,
            )?,
            id: vault_id,
        };

        Ok(Self {
            secret_key,
            recovery_code,
            keys,
            ask,
            key_pairs,
            bundle,
            personal_vault,
            personal_vault_key,
        })
    }
}

/// A new UUIDv7 (time-ordered) id for a vault or item, as clients generate them.
pub fn new_id(now_ms: u64, rng: &mut impl CryptoRngCore) -> String {
    let mut random = [0u8; 10];
    rng.fill_bytes(&mut random);
    uuid::Builder::from_unix_timestamp_millis(now_ms, &random)
        .into_uuid()
        .hyphenated()
        .to_string()
}

/// Parses a vault or item id, normalising it to lower-case hyphenated form so it is spelled the
/// same in every associated-data context. Requiring a UUID also keeps `:` out of contexts, so
/// `itemkey:<vault>:<item>` can't be made ambiguous by a crafted id.
pub fn parse_id(id: &str) -> Result<String> {
    Uuid::try_parse(id)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| Error::InvalidId)
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn ids_are_uuid_v7() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let id = new_id(1_761_177_600_000, &mut rng);
        let uuid = Uuid::parse_str(&id).unwrap();
        assert_eq!(uuid.get_version_num(), 7);
        assert_eq!(parse_id(&id.to_uppercase()).unwrap(), id);
        assert!(parse_id("nope").is_err());
    }

    #[test]
    fn key_pairs_round_trip_and_mismatch_is_detected() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let pairs = AccountKeyPairs::generate(&mut rng);
        let again = AccountKeyPairs::from_bytes(pairs.to_bytes().as_ref()).unwrap();
        assert_eq!(again.public_enc_key(), pairs.public_enc_key());
        assert_eq!(again.public_sign_key(), pairs.public_sign_key());

        let ask = SymmetricKey::generate(&mut rng);
        let other = AccountKeyPairs::generate(&mut rng);
        let bundle = AccountBundle {
            account_id: None,
            email: "a@b.c".into(),
            kdf: KdfParams::DEFAULT,
            account_salt: b64_encode(&[0; 16]),
            wrapped_ask: String::new(),
            public_enc_key: b64_encode(&pairs.public_enc_key()),
            public_sign_key: b64_encode(&other.public_sign_key()),
            wrapped_private_keys: seal_b64(
                &ask,
                &Context::PrivateKeys,
                pairs.to_bytes().as_ref(),
                &mut rng,
            )
            .unwrap(),
            recovery_wrapped_ask: String::new(),
            wrapped_pq_private_key: None,
            key_record: None,
        };
        assert_eq!(bundle.open_key_pairs(&ask).err(), Some(Error::KeyMismatch));
    }
}
