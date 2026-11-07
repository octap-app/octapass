//! Signed tree heads and the log's identity.
//!
//! ```text
//! logId   = SHA-256("openpass/v1/key-log-id" ‖ 0x00 ‖ log_public_key ‖ oprf_public_key)
//! message = "openpass/v1/key-log-head" ‖ 0x00 ‖ logId ‖ size (u64 BE) ‖ timestamp ms (u64 BE) ‖ root
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64_decode_array, b64_encode};
use crate::error::{Error, Result};
use crate::transparency::merkle::Hash;

/// The log's public keys, which clients pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogIdentity {
    /// base64url Ed25519 public key that signs heads.
    pub sign_key: String,
    /// base64url ristretto255 element: the VOPRF public key behind labels.
    pub oprf_key: String,
}

impl LogIdentity {
    pub fn log_id(&self) -> Result<[u8; 32]> {
        let sign: [u8; 32] = b64_decode_array(&self.sign_key)?;
        let oprf: [u8; 32] = b64_decode_array(&self.oprf_key)?;
        Ok(Sha256::new()
            .chain_update(b"openpass/v1/key-log-id\0")
            .chain_update(sign)
            .chain_update(oprf)
            .finalize()
            .into())
    }

    pub fn log_id_b64(&self) -> Result<String> {
        Ok(b64_encode(&self.log_id()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedHead {
    pub tree_size: u64,
    /// base64url SHA-256.
    pub root_hash: String,
    /// Unix milliseconds.
    pub timestamp: u64,
    /// base64url Ed25519 signature.
    pub signature: String,
}

fn message(log_id: &[u8; 32], size: u64, timestamp: u64, root: &Hash) -> Vec<u8> {
    let mut message = b"openpass/v1/key-log-head\0".to_vec();
    message.extend_from_slice(log_id);
    message.extend_from_slice(&size.to_be_bytes());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(root);
    message
}

impl SignedHead {
    pub fn sign(
        key: &SigningKey,
        log_id: &[u8; 32],
        tree_size: u64,
        root: &Hash,
        timestamp: u64,
    ) -> Self {
        let signature = key.sign(&message(log_id, tree_size, timestamp, root));
        Self {
            tree_size,
            root_hash: b64_encode(root),
            timestamp,
            signature: b64_encode(&signature.to_bytes()),
        }
    }

    pub fn root(&self) -> Result<Hash> {
        b64_decode_array(&self.root_hash).map_err(|_| Error::KeyLogMismatch)
    }

    pub fn verify(&self, log: &LogIdentity) -> Result<()> {
        let invalid = |_| Error::KeyLogMismatch;
        let key: [u8; 32] = b64_decode_array(&log.sign_key).map_err(invalid)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::KeyLogMismatch)?;
        let signature: [u8; 64] = b64_decode_array(&self.signature).map_err(invalid)?;
        let message = message(
            &log.log_id().map_err(invalid)?,
            self.tree_size,
            self.timestamp,
            &self.root()?,
        );
        key.verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::KeyLogMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, LogIdentity) {
        let key = SigningKey::from_bytes(&[1; 32]);
        let log = LogIdentity {
            sign_key: b64_encode(key.verifying_key().as_bytes()),
            oprf_key: b64_encode(&[2; 32]),
        };
        (key, log)
    }

    #[test]
    fn heads_verify_and_every_field_is_signed() {
        let (key, log) = fixture();
        let id = log.log_id().unwrap();
        let head = SignedHead::sign(&key, &id, 7, &[3; 32], 1_000);
        head.verify(&log).unwrap();
        let tampered = [
            SignedHead {
                tree_size: 8,
                ..head.clone()
            },
            SignedHead {
                timestamp: 1_001,
                ..head.clone()
            },
            SignedHead {
                root_hash: b64_encode(&[4; 32]),
                ..head.clone()
            },
        ];
        for head in tampered {
            assert_eq!(head.verify(&log).err(), Some(Error::KeyLogMismatch));
        }
    }

    #[test]
    fn a_head_is_bound_to_both_log_keys() {
        let (key, log) = fixture();
        let head = SignedHead::sign(&key, &log.log_id().unwrap(), 7, &[3; 32], 1_000);
        let other_oprf = LogIdentity {
            oprf_key: b64_encode(&[5; 32]),
            ..log
        };
        assert_eq!(head.verify(&other_oprf).err(), Some(Error::KeyLogMismatch));
    }
}
