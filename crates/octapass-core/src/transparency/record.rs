//! The key record: what an account says about its own public keys, signed by its Ed25519 key.
//!
//! ```text
//! message     = "openpass/v1/key-record" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
//! fields      = logId, accountId, label, publicEncKey, publicSignKey, publicPqKey, createdAt
//! record_hash = SHA-256("openpass/v1/key-record-hash" ‖ 0x00 ‖ message ‖ signature)
//! leaf        = label (32) ‖ record_hash (32)
//! ```
//!
//! The record is also what carries the ML-KEM key: signed by the key the fingerprint covers, so
//! the fingerprint vouches for it too.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::account::parse_id;
use crate::encoding::{b64_decode_array, b64_encode};
use crate::error::{Error, Result};
use crate::sharing::pq::PqPublicKey;
use crate::transparency::merkle::{Hash, leaf_hash};

pub const LEAF_LEN: usize = 64;

const SIGNATURE_LABEL: &[u8] = b"openpass/v1/key-record\0";

/// The fields of a key record; every one is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRecord {
    /// base64url id of the log this record is for.
    pub log_id: String,
    pub account_id: String,
    /// base64url label of the account's email.
    pub label: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    /// base64url ML-KEM-768 encapsulation key (1,184 bytes).
    pub public_pq_key: String,
    /// Unix milliseconds.
    pub created_at: u64,
    /// base64url Ed25519 signature by `public_sign_key` over the fields above.
    pub signature: String,
}

/// The public keys a server offered for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedKeys<'a> {
    pub account_id: &'a str,
    pub public_enc_key: &'a str,
    pub public_sign_key: &'a str,
}

impl KeyRecord {
    /// A signed record, with `signature` filled in.
    pub fn signed(mut self, key: &SigningKey) -> Self {
        self.signature = b64_encode(&key.sign(&self.message()).to_bytes());
        self
    }

    /// The exact bytes the signature covers.
    pub fn message(&self) -> Vec<u8> {
        let created_at = self.created_at.to_string();
        let fields = [
            self.log_id.as_str(),
            &self.account_id,
            &self.label,
            &self.public_enc_key,
            &self.public_sign_key,
            &self.public_pq_key,
            &created_at,
        ];
        let mut message = SIGNATURE_LABEL.to_vec();
        for field in fields {
            let len = u32::try_from(field.len()).expect("record fields are short");
            message.extend_from_slice(&len.to_be_bytes());
            message.extend_from_slice(field.as_bytes());
        }
        message
    }

    /// Checks the signature against the record's own signing key. That says the holder of that
    /// key made it; whether the key is the right one is for the fingerprint and the log.
    pub fn verify(&self) -> Result<()> {
        let invalid = |_| Error::KeyLogMismatch;
        let key: [u8; 32] = b64_decode_array(&self.public_sign_key).map_err(invalid)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::KeyLogMismatch)?;
        let signature: [u8; 64] = b64_decode_array(&self.signature).map_err(invalid)?;
        key.verify_strict(&self.message(), &Signature::from_bytes(&signature))
            .map_err(|_| Error::KeyLogMismatch)
    }

    /// Whether the record is about exactly these keys, and validly signed.
    pub fn verify_for(&self, offered: &OfferedKeys<'_>) -> Result<()> {
        if parse_id(&self.account_id)? != parse_id(offered.account_id)?
            || self.public_enc_key != offered.public_enc_key
            || self.public_sign_key != offered.public_sign_key
        {
            return Err(Error::KeyLogMismatch);
        }
        self.verify()
    }

    /// The ML-KEM key to seal to: `None` for an account with no record, an error for a record
    /// that isn't validly about these keys. Use this, never a key from anywhere else.
    pub fn pq_key_of(
        record: Option<&Self>,
        offered: &OfferedKeys<'_>,
    ) -> Result<Option<PqPublicKey>> {
        let Some(record) = record else {
            return Ok(None);
        };
        record.verify_for(offered)?;
        PqPublicKey::from_b64(&record.public_pq_key)
            .map(Some)
            .map_err(|_| Error::KeyLogMismatch)
    }

    pub fn record_hash(&self) -> Hash {
        Sha256::new()
            .chain_update(b"openpass/v1/key-record-hash\0")
            .chain_update(self.message())
            .chain_update(self.signature.as_bytes())
            .finalize()
            .into()
    }

    pub fn leaf(&self) -> Result<[u8; LEAF_LEN]> {
        let label: [u8; 32] = b64_decode_array(&self.label).map_err(|_| Error::KeyLogMismatch)?;
        let mut leaf = [0u8; LEAF_LEN];
        leaf[..32].copy_from_slice(&label);
        leaf[32..].copy_from_slice(&self.record_hash());
        Ok(leaf)
    }

    /// The Merkle tree's hash of this record's leaf.
    pub fn leaf_hash(&self) -> Result<Hash> {
        Ok(leaf_hash(&self.leaf()?))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use rand_core::CryptoRngCore;

    use super::*;
    use crate::sharing::pq::PqKeyPair;

    pub const ACCOUNT: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";

    pub fn record(signing: &SigningKey, rng: &mut impl CryptoRngCore) -> KeyRecord {
        KeyRecord {
            log_id: b64_encode(&[1; 32]),
            account_id: ACCOUNT.into(),
            label: b64_encode(&[2; 32]),
            public_enc_key: b64_encode(&[3; 32]),
            public_sign_key: b64_encode(signing.verifying_key().as_bytes()),
            public_pq_key: PqKeyPair::generate(rng).public_key().to_b64(),
            created_at: 1_000,
            signature: String::new(),
        }
        .signed(signing)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::test_support::{ACCOUNT, record};
    use super::*;

    fn offered(record: &KeyRecord) -> OfferedKeys<'_> {
        OfferedKeys {
            account_id: &record.account_id,
            public_enc_key: &record.public_enc_key,
            public_sign_key: &record.public_sign_key,
        }
    }

    #[test]
    fn every_field_is_signed() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let signing = SigningKey::from_bytes(&[9; 32]);
        let record = record(&signing, &mut rng);
        record.verify().unwrap();
        let other_pq = crate::sharing::pq::PqKeyPair::generate(&mut rng);
        let tampered = [
            KeyRecord {
                log_id: b64_encode(&[8; 32]),
                ..record.clone()
            },
            KeyRecord {
                account_id: "0192f0c8-1c2d-7a00-8000-0000000000b1".into(),
                ..record.clone()
            },
            KeyRecord {
                label: b64_encode(&[8; 32]),
                ..record.clone()
            },
            KeyRecord {
                public_enc_key: b64_encode(&[8; 32]),
                ..record.clone()
            },
            KeyRecord {
                public_pq_key: other_pq.public_key().to_b64(),
                ..record.clone()
            },
            KeyRecord {
                created_at: 1_001,
                ..record.clone()
            },
        ];
        for bad in tampered {
            assert_eq!(bad.verify().err(), Some(Error::KeyLogMismatch));
        }
    }

    #[test]
    fn the_ml_kem_key_comes_only_from_a_record_about_these_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let signing = SigningKey::from_bytes(&[9; 32]);
        let record = record(&signing, &mut rng);
        let key = KeyRecord::pq_key_of(Some(&record), &offered(&record))
            .unwrap()
            .unwrap();
        assert_eq!(key.to_b64(), record.public_pq_key);
        assert_eq!(KeyRecord::pq_key_of(None, &offered(&record)), Ok(None));

        // The server offers a different encryption key with the real record.
        let swapped = OfferedKeys {
            public_enc_key: "AAAA",
            ..offered(&record)
        };
        assert_eq!(
            KeyRecord::pq_key_of(Some(&record), &swapped).err(),
            Some(Error::KeyLogMismatch)
        );
        // Or signs a record of its own for someone else's keys.
        let forged = record.clone().signed(&SigningKey::from_bytes(&[10; 32]));
        assert_eq!(
            KeyRecord::pq_key_of(Some(&forged), &offered(&record)).err(),
            Some(Error::KeyLogMismatch)
        );
    }

    #[test]
    fn leaves_are_a_label_and_a_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let signing = SigningKey::from_bytes(&[9; 32]);
        let record = record(&signing, &mut rng);
        let leaf = record.leaf().unwrap();
        assert_eq!(leaf[..32], [2; 32]);
        assert_eq!(leaf[32..], record.record_hash());
        assert_eq!(record.account_id, ACCOUNT);
    }
}
