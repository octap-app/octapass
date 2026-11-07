//! Sharing (plan 06): shared and family vaults, key fingerprints, one-time share links and
//! emergency access. Everything is end-to-end encrypted; the server routes sealed keys between
//! accounts but can't open them.
//!
//! - [`seal`]: the sealed box that carries a key to another account, hybrid when the recipient has
//!   an ML-KEM key.
//! - [`pq`]: ML-KEM-768 key pairs.
//! - [`grant`]: signed grants, a member's sealed copy of a vault key.
//! - [`vault`]: creating, granting, opening and rotating shared vaults on a [`Session`].
//! - [`fingerprint`]: short codes for comparing public keys out of band.
//! - [`share_link`]: item snapshots for people without an account.
//! - [`emergency`]: sealing the account key (or one vault's key) for a trusted contact.
//!
//! [`Session`]: crate::session::Session

pub mod emergency;
pub mod fingerprint;
pub mod grant;
pub mod pq;
pub mod seal;
pub mod share_link;
pub mod vault;

use serde::{Deserialize, Serialize};

/// A member's role in a shared vault. Each role can do everything the ones below it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// View, copy and fill items.
    Read,
    /// Also create, edit and delete items.
    Write,
    /// Also add and remove members, and rotate the vault key.
    Manage,
    /// Also grant and remove owners. A vault is deleted with its last owner.
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Write => "write",
            Role::Manage => "manage",
            Role::Owner => "owner",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_ordered_by_power() {
        assert!(
            Role::Read < Role::Write && Role::Write < Role::Manage && Role::Manage < Role::Owner
        );
        assert_eq!(serde_json::to_value(Role::Manage).unwrap(), "manage");
        assert_eq!(Role::Owner.as_str(), "owner");
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use rand_core::CryptoRngCore;

    use crate::account::{AccountBundle, AccountKeyPairs, new_id};
    use crate::encoding::b64_encode;
    use crate::envelope::{Context, seal_b64};
    use crate::kdf::KdfParams;
    use crate::keys::SymmetricKey;
    use crate::session::Session;

    /// An unlocked account with a server-assigned id, built directly from keys (no Argon2id).
    pub fn account(rng: &mut impl CryptoRngCore) -> Session {
        let ask = SymmetricKey::generate(rng);
        let pairs = AccountKeyPairs::generate(rng);
        let bundle = AccountBundle {
            account_id: Some(new_id(1_761_177_600_000, rng)),
            email: "member@example.com".into(),
            kdf: KdfParams::DEFAULT,
            account_salt: b64_encode(&[0; 16]),
            wrapped_ask: String::new(),
            public_enc_key: b64_encode(&pairs.public_enc_key()),
            public_sign_key: b64_encode(&pairs.public_sign_key()),
            wrapped_private_keys: seal_b64(
                &ask,
                &Context::PrivateKeys,
                pairs.to_bytes().as_ref(),
                rng,
            )
            .unwrap(),
            recovery_wrapped_ask: String::new(),
            wrapped_pq_private_key: None,
            key_record: None,
        };
        Session::with_ask(bundle, ask).unwrap()
    }
}
