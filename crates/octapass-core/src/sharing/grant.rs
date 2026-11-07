//! Signed grants: a member's sealed copy of a shared vault's key, signed by whoever gave it.
//!
//! The signature covers every field, so the server can't change a member's role, swap in a
//! sealed key of its own, or move a grant to another vault or account. Recipients check it
//! against the granter's Ed25519 public key (whose fingerprint they can compare out of band)
//! before they use the vault key.
//!
//! ```text
//! message = "octapass/v1/grant" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
//! fields  = vaultId, recipientAccountId, role, wrappedVaultKey, grantedBy, grantedAt (decimal ms)
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::account::parse_id;
use crate::encoding::{b64_decode_array, b64_encode};
use crate::error::{Error, Result};
use crate::keys::SymmetricKey;
use crate::sharing::Role;
use crate::sharing::pq::PqPublicKey;
use crate::sharing::seal::{Opener, SealContext, open_key, seal_for};

const SIGNATURE_LABEL: &[u8] = b"octapass/v1/grant\0";

/// A grant as sent to and returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedGrant {
    pub vault_id: String,
    pub recipient_account_id: String,
    pub role: Role,
    /// The vault key sealed to the recipient (context `vaultkey:<vaultId>:<recipientAccountId>`).
    pub wrapped_vault_key: String,
    /// The account that signed the grant.
    pub granted_by: String,
    /// Unix milliseconds.
    pub granted_at: u64,
    /// base64url Ed25519 signature (64 bytes) over the fields above.
    pub signature: String,
}

/// Who receives a grant: an account id and its X25519 public key, as `GET /v1/accounts/lookup`
/// or the member list return them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub account_id: String,
    pub public_enc_key: [u8; 32],
    /// The ML-KEM key from the account's verified key record
    /// ([`crate::transparency::record::KeyRecord::pq_key_of`]). With it the grant is hybrid.
    pub public_pq_key: Option<PqPublicKey>,
    pub role: Role,
}

impl SignedGrant {
    /// Seals `vault_key` to the recipient and signs the grant.
    pub fn create(
        vault_id: &str,
        vault_key: &SymmetricKey,
        recipient: &Recipient,
        granter_account_id: &str,
        granter: &SigningKey,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let vault_id = parse_id(vault_id)?;
        let recipient_account_id = parse_id(&recipient.account_id)?;
        let context = SealContext::VaultKey {
            vault_id: &vault_id,
            recipient_account_id: &recipient_account_id,
        };
        let wrapped_vault_key = seal_for(
            &recipient.public_enc_key,
            recipient.public_pq_key.as_ref(),
            &context,
            vault_key,
            rng,
        )?;
        let mut grant = Self {
            vault_id,
            recipient_account_id,
            role: recipient.role,
            wrapped_vault_key,
            granted_by: parse_id(granter_account_id)?,
            granted_at: now_ms,
            signature: String::new(),
        };
        grant.signature = b64_encode(&granter.sign(&grant.message()).to_bytes());
        Ok(grant)
    }

    /// The exact bytes the signature covers.
    pub fn message(&self) -> Vec<u8> {
        let granted_at = self.granted_at.to_string();
        let fields = [
            self.vault_id.as_str(),
            &self.recipient_account_id,
            self.role.as_str(),
            &self.wrapped_vault_key,
            &self.granted_by,
            &granted_at,
        ];
        let mut message = SIGNATURE_LABEL.to_vec();
        for field in fields {
            let len = u32::try_from(field.len()).expect("grant fields are short");
            message.extend_from_slice(&len.to_be_bytes());
            message.extend_from_slice(field.as_bytes());
        }
        message
    }

    /// Checks the signature against the granter's Ed25519 public key.
    pub fn verify(&self, granter_public_sign_key: &[u8; 32]) -> Result<()> {
        let key =
            VerifyingKey::from_bytes(granter_public_sign_key).map_err(|_| Error::InvalidKey)?;
        let signature: [u8; 64] =
            b64_decode_array(&self.signature).map_err(|_| Error::InvalidSignature)?;
        // Strict verification also rejects small-order keys and non-canonical signatures.
        key.verify_strict(&self.message(), &Signature::from_bytes(&signature))
            .map_err(|_| Error::InvalidSignature)
    }

    /// Verifies the grant and opens the vault key with the recipient's X25519 private key.
    /// Fails with [`Error::InvalidGrant`] when the grant isn't for `vault_id` and
    /// `recipient_account_id`, so a server can't pass off one grant as another.
    pub fn open<'a>(
        &self,
        vault_id: &str,
        recipient_account_id: &str,
        recipient: impl Into<Opener<'a>>,
        granter_public_sign_key: &[u8; 32],
    ) -> Result<SymmetricKey> {
        if parse_id(vault_id)? != self.vault_id
            || parse_id(recipient_account_id)? != self.recipient_account_id
        {
            return Err(Error::InvalidGrant);
        }
        self.verify(granter_public_sign_key)?;
        let context = SealContext::VaultKey {
            vault_id: &self.vault_id,
            recipient_account_id: &self.recipient_account_id,
        };
        open_key(recipient, &context, &self.wrapped_vault_key)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::sharing::pq::PqKeyPair;
    use crate::sharing::seal::seal_key;

    const VAULT: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
    const OWNER: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";
    const MEMBER: &str = "0192f0c8-1c2d-7a00-8000-0000000000b1";

    struct Fixture {
        rng: ChaCha20Rng,
        owner: SigningKey,
        member: StaticSecret,
        vault_key: SymmetricKey,
        grant: SignedGrant,
    }

    fn fixture() -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let owner = SigningKey::from_bytes(&[4; 32]);
        let member = StaticSecret::random_from_rng(&mut rng);
        let vault_key = SymmetricKey::generate(&mut rng);
        let recipient = Recipient {
            account_id: MEMBER.into(),
            public_enc_key: PublicKey::from(&member).to_bytes(),
            public_pq_key: None,
            role: Role::Write,
        };
        let grant = SignedGrant::create(
            VAULT, &vault_key, &recipient, OWNER, &owner, 1_000, &mut rng,
        )
        .unwrap();
        Fixture {
            rng,
            owner,
            member,
            vault_key,
            grant,
        }
    }

    fn owner_public(f: &Fixture) -> [u8; 32] {
        f.owner.verifying_key().to_bytes()
    }

    #[test]
    fn the_recipient_opens_a_valid_grant() {
        let f = fixture();
        let key = f
            .grant
            .open(VAULT, MEMBER, &f.member, &owner_public(&f))
            .unwrap();
        assert_eq!(key, f.vault_key);
        assert_eq!(f.grant.granted_by, OWNER);
        assert_eq!(f.grant.granted_at, 1_000);
    }

    #[test]
    fn a_member_with_an_ml_kem_key_gets_a_hybrid_grant() {
        let mut f = fixture();
        let pq = PqKeyPair::generate(&mut f.rng);
        let recipient = Recipient {
            account_id: MEMBER.into(),
            public_enc_key: PublicKey::from(&f.member).to_bytes(),
            public_pq_key: Some(pq.public_key().clone()),
            role: Role::Write,
        };
        let grant = SignedGrant::create(
            VAULT,
            &f.vault_key,
            &recipient,
            OWNER,
            &f.owner,
            1_000,
            &mut f.rng,
        )
        .unwrap();
        let opener = Opener {
            x25519: &f.member,
            pq: Some(&pq),
        };
        let key = grant
            .open(VAULT, MEMBER, opener, &owner_public(&f))
            .unwrap();
        assert_eq!(key, f.vault_key);
        // The older grant opens with the same keys.
        let key = f
            .grant
            .open(VAULT, MEMBER, opener, &owner_public(&f))
            .unwrap();
        assert_eq!(key, f.vault_key);
    }

    #[test]
    fn every_field_is_signed() {
        let f = fixture();
        let public = owner_public(&f);
        let mut other_key = f.grant.clone();
        other_key.wrapped_vault_key = seal_key(
            &PublicKey::from(&f.member).to_bytes(),
            &SealContext::VaultKey {
                vault_id: VAULT,
                recipient_account_id: MEMBER,
            },
            &SymmetricKey::from_bytes([9; 32]),
            &mut f.rng.clone(),
        )
        .unwrap();
        let tampered = [
            SignedGrant {
                role: Role::Manage,
                ..f.grant.clone()
            },
            SignedGrant {
                granted_at: 1_001,
                ..f.grant.clone()
            },
            SignedGrant {
                granted_by: MEMBER.into(),
                ..f.grant.clone()
            },
            other_key,
        ];
        for grant in tampered {
            assert_eq!(grant.verify(&public).err(), Some(Error::InvalidSignature));
        }
        let stranger = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        assert_eq!(
            f.grant.verify(&stranger).err(),
            Some(Error::InvalidSignature)
        );
    }

    #[test]
    fn a_grant_only_opens_for_its_vault_and_recipient() {
        let f = fixture();
        let public = owner_public(&f);
        let other = "0192f0c8-1c2d-7a00-8000-0000000000ff";
        assert_eq!(
            f.grant.open(other, MEMBER, &f.member, &public).err(),
            Some(Error::InvalidGrant)
        );
        assert_eq!(
            f.grant.open(VAULT, other, &f.member, &public).err(),
            Some(Error::InvalidGrant)
        );
        // Re-labelled and re-signed by someone else, the sealed key still refuses to open.
        let mut moved = f.grant.clone();
        moved.recipient_account_id = other.into();
        let mallory = SigningKey::from_bytes(&[6; 32]);
        moved.signature = b64_encode(&mallory.sign(&moved.message()).to_bytes());
        assert_eq!(
            moved
                .open(VAULT, other, &f.member, &mallory.verifying_key().to_bytes())
                .err(),
            Some(Error::DecryptionFailed)
        );
    }

    #[test]
    fn message_layout() {
        let f = fixture();
        let message = f.grant.message();
        assert!(message.starts_with(b"octapass/v1/grant\0\0\0\0\x24"));
        assert!(message.ends_with(b"\0\0\0\x041000"));
    }

    #[test]
    fn serialises_as_camel_case() {
        let f = fixture();
        let json = serde_json::to_value(&f.grant).unwrap();
        assert_eq!(json["role"], "write");
        assert_eq!(json["recipientAccountId"], MEMBER);
        assert_eq!(json["grantedAt"], 1_000);
        let back: SignedGrant = serde_json::from_value(json).unwrap();
        assert_eq!(back, f.grant);
    }
}
