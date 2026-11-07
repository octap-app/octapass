//! The server's half of the key log: its two keys, both derived from the server secret, so they
//! live and die with the data directory's backup. Losing them starts a new log, which clients
//! report (plan 03).

use ed25519_dalek::SigningKey;
use octapass_core::transparency::head::{LogIdentity, SignedHead};
use octapass_core::transparency::label::LabelKey;
use octapass_core::transparency::merkle::Hash;

use crate::crypto::keyed_hash;

pub struct KeyLog {
    sign_key: SigningKey,
    pub label_key: LabelKey,
    pub identity: LogIdentity,
    log_id: [u8; 32],
    pub log_id_b64: String,
}

impl KeyLog {
    pub fn new(server_secret: &[u8]) -> Self {
        let sign_key =
            SigningKey::from_bytes(&keyed_hash(server_secret, "openpass/key-log-sign", &[]));
        let label_key =
            LabelKey::from_seed(&keyed_hash(server_secret, "openpass/key-log-oprf", &[]))
                .expect("a 32-byte seed always gives a key");
        let identity = LogIdentity {
            sign_key: crate::crypto::base64url(sign_key.verifying_key().as_bytes()),
            oprf_key: label_key.public_key(),
        };
        let log_id = identity.log_id().expect("our own keys are well formed");
        Self {
            log_id_b64: crate::crypto::base64url(log_id),
            sign_key,
            label_key,
            identity,
            log_id,
        }
    }

    pub fn sign_head(&self, tree_size: u64, root: &Hash, timestamp: u64) -> SignedHead {
        SignedHead::sign(&self.sign_key, &self.log_id, tree_size, root, timestamp)
    }
}
