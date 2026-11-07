//! The sealed box: seals a 32-byte key to an account's public keys.
//!
//! Version 2 is hybrid, safe while either X25519 or ML-KEM-768 holds. Version 1, X25519 alone, is
//! for accounts with no ML-KEM key yet; every box made with it keeps opening.
//!
//! ```text
//! ephemeral   = fresh X25519 key pair
//! ss_x        = X25519(ephemeral_secret, recipient_public)
//! aad         = "openpass/v1|" + context
//!
//! version 1
//! wrap_key    = HKDF-SHA256(ikm = ss_x, salt = ephemeral_public ‖ recipient_public,
//!                           info = "openpass/v1/seal")
//! sealed      = 0x01 ‖ ephemeral_public (32) ‖ nonce (24) ‖ XChaCha20-Poly1305(wrap_key, key, aad)
//!
//! version 2
//! ct_m, ss_m  = ML-KEM-768.Encaps(recipient_pq_public)
//! transcript  = SHA-256("openpass/v2/seal-transcript" ‖ 0x00 ‖ ephemeral_public ‖ recipient_public
//!                       ‖ ct_m ‖ recipient_pq_public)
//! wrap_key    = HKDF-SHA256(ikm = ss_m ‖ ss_x, salt = transcript, info = "openpass/v2/seal")
//! sealed      = 0x02 ‖ ephemeral_public (32) ‖ ct_m (1088) ‖ nonce (24)
//!               ‖ XChaCha20-Poly1305(wrap_key, key, aad)
//! ```
//!
//! Not audited: the combiner needs the external review plan 09's risks table calls for.
//!
//! The context names what the key is and who it is for, so the server can't hand one member's
//! sealed vault key to another member, or present it as another vault's key.

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::encoding::{b64_decode, b64_encode};
use crate::envelope::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::keys::{KEY_LEN, SymmetricKey, hkdf_key};
use crate::sharing::pq::{self, PqKeyPair, PqPublicKey};

pub const VERSION: u8 = 0x01;
pub const HYBRID_VERSION: u8 = 0x02;
const PUBLIC_KEY_LEN: usize = 32;
const HEADER_LEN: usize = 1 + PUBLIC_KEY_LEN + NONCE_LEN;
/// Every version 1 box is exactly this long: 105 bytes.
pub const SEALED_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;
const HYBRID_HEADER_LEN: usize = 1 + PUBLIC_KEY_LEN + pq::CIPHERTEXT_LEN + NONCE_LEN;
/// Every version 2 box is exactly this long: 1,193 bytes.
pub const HYBRID_SEALED_LEN: usize = HYBRID_HEADER_LEN + KEY_LEN + TAG_LEN;

/// What a sealed key is and who it is for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SealContext<'a> {
    /// A shared vault's key in a member's grant.
    VaultKey {
        vault_id: &'a str,
        recipient_account_id: &'a str,
    },
    /// A grantor's account key (ASK), held for an emergency contact.
    EmergencyAccount {
        grantor_account_id: &'a str,
        contact_account_id: &'a str,
    },
    /// One of the grantor's vault keys, held for an emergency contact.
    EmergencyVault {
        grantor_account_id: &'a str,
        contact_account_id: &'a str,
        vault_id: &'a str,
    },
    /// The key of one entry in a vault's save inbox (see [`crate::inbox`]), sealed by the device
    /// that saved it while the vault was locked. `owner` is the account id, or a local vault's id.
    Inbox { owner: &'a str },
}

impl fmt::Display for SealContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealContext::VaultKey {
                vault_id,
                recipient_account_id,
            } => write!(f, "vaultkey:{vault_id}:{recipient_account_id}"),
            SealContext::EmergencyAccount {
                grantor_account_id,
                contact_account_id,
            } => write!(f, "emergency:{grantor_account_id}:{contact_account_id}:ask"),
            SealContext::EmergencyVault {
                grantor_account_id,
                contact_account_id,
                vault_id,
            } => write!(
                f,
                "emergency:{grantor_account_id}:{contact_account_id}:vault:{vault_id}"
            ),
            SealContext::Inbox { owner } => write!(f, "inbox:{owner}"),
        }
    }
}

impl SealContext<'_> {
    pub fn associated_data(&self) -> Vec<u8> {
        format!("openpass/v1|{self}").into_bytes()
    }
}

/// The private keys that open a box. The ML-KEM key is absent for an account that has none yet.
#[derive(Clone, Copy)]
pub struct Opener<'a> {
    pub x25519: &'a StaticSecret,
    pub pq: Option<&'a PqKeyPair>,
}

impl<'a> From<&'a StaticSecret> for Opener<'a> {
    fn from(x25519: &'a StaticSecret) -> Self {
        Self { x25519, pq: None }
    }
}

/// Seals `key` to `recipient_public` (an X25519 public key), adding `recipient_pq` when the
/// recipient has an ML-KEM key. Returns base64url.
pub fn seal_for(
    recipient_public: &[u8; 32],
    recipient_pq: Option<&PqPublicKey>,
    context: &SealContext<'_>,
    key: &SymmetricKey,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    match recipient_pq {
        Some(pq) => seal_key_hybrid(recipient_public, pq, context, key, rng),
        None => seal_key(recipient_public, context, key, rng),
    }
}

/// Seals `key` with the hybrid box (version 2). Returns base64url.
pub fn seal_key_hybrid(
    recipient_public: &[u8; 32],
    recipient_pq: &PqPublicKey,
    context: &SealContext<'_>,
    key: &SymmetricKey,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    let recipient = PublicKey::from(*recipient_public);
    let ephemeral = StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let (ciphertext, pq_shared) = recipient_pq.encapsulate(rng);
    let wrap_key = hybrid_wrap_key(
        shared.as_bytes(),
        &pq_shared,
        &ephemeral_public,
        &recipient,
        &ciphertext,
        recipient_pq,
    );
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = context.associated_data();
    let body = XChaCha20Poly1305::new(wrap_key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    let mut sealed = Vec::with_capacity(HYBRID_SEALED_LEN);
    sealed.push(HYBRID_VERSION);
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&body);
    Ok(b64_encode(&sealed))
}

/// Seals `key` to `recipient_public` (an X25519 public key) with the version 1 box. Returns
/// base64url.
pub fn seal_key(
    recipient_public: &[u8; 32],
    context: &SealContext<'_>,
    key: &SymmetricKey,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    let recipient = PublicKey::from(*recipient_public);
    let ephemeral = StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    // A low-order "public key" would make the shared secret predictable.
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let wrap_key = wrap_key(shared.as_bytes(), &ephemeral_public, &recipient);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = context.associated_data();
    let ciphertext = XChaCha20Poly1305::new(wrap_key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    let mut sealed = Vec::with_capacity(SEALED_LEN);
    sealed.push(VERSION);
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(b64_encode(&sealed))
}

/// Opens a key sealed by any version of the box.
pub fn open_key<'a>(
    recipient: impl Into<Opener<'a>>,
    context: &SealContext<'_>,
    sealed: &str,
) -> Result<SymmetricKey> {
    let recipient = recipient.into();
    let sealed = b64_decode(sealed)?;
    let (expected, opened) = match sealed.len() {
        SEALED_LEN => (VERSION, open_classical as Opening),
        HYBRID_SEALED_LEN => (HYBRID_VERSION, open_hybrid as Opening),
        _ => return Err(Error::MalformedCiphertext),
    };
    if sealed[0] != expected {
        return Err(Error::UnsupportedVersion);
    }
    opened(recipient, context, &sealed)
}

type Opening = fn(Opener<'_>, &SealContext<'_>, &[u8]) -> Result<SymmetricKey>;

fn open_hybrid(
    recipient: Opener<'_>,
    context: &SealContext<'_>,
    sealed: &[u8],
) -> Result<SymmetricKey> {
    // Sealed to an ML-KEM key this account doesn't hold.
    let pq = recipient.pq.ok_or(Error::DecryptionFailed)?;
    let (ephemeral, rest) = sealed[1..].split_at(PUBLIC_KEY_LEN);
    let (ciphertext, rest) = rest.split_at(pq::CIPHERTEXT_LEN);
    let (nonce, body) = rest.split_at(NONCE_LEN);
    let ephemeral: [u8; 32] = ephemeral.try_into().expect("length checked");
    let ephemeral = PublicKey::from(ephemeral);
    let shared = recipient.x25519.diffie_hellman(&ephemeral);
    if !shared.was_contributory() {
        return Err(Error::DecryptionFailed);
    }
    let ciphertext: &[u8; pq::CIPHERTEXT_LEN] = ciphertext.try_into().expect("length checked");
    let pq_shared = pq.decapsulate(ciphertext);
    let wrap_key = hybrid_wrap_key(
        shared.as_bytes(),
        &pq_shared,
        &ephemeral,
        &PublicKey::from(recipient.x25519),
        ciphertext,
        pq.public_key(),
    );
    let aad = context.associated_data();
    let plaintext = XChaCha20Poly1305::new(wrap_key.as_bytes().into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)?;
    SymmetricKey::from_slice(&plaintext)
}

fn open_classical(
    recipient: Opener<'_>,
    context: &SealContext<'_>,
    sealed: &[u8],
) -> Result<SymmetricKey> {
    let recipient = recipient.x25519;
    let ephemeral: [u8; 32] = sealed[1..1 + PUBLIC_KEY_LEN]
        .try_into()
        .expect("length checked");
    let ephemeral = PublicKey::from(ephemeral);
    let shared = recipient.diffie_hellman(&ephemeral);
    if !shared.was_contributory() {
        return Err(Error::DecryptionFailed);
    }
    let wrap_key = wrap_key(shared.as_bytes(), &ephemeral, &PublicKey::from(recipient));
    let aad = context.associated_data();
    let plaintext = XChaCha20Poly1305::new(wrap_key.as_bytes().into())
        .decrypt(
            XNonce::from_slice(&sealed[1 + PUBLIC_KEY_LEN..HEADER_LEN]),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)?;
    SymmetricKey::from_slice(&plaintext)
}

fn hybrid_wrap_key(
    shared: &[u8; 32],
    pq_shared: &[u8; 32],
    ephemeral: &PublicKey,
    recipient: &PublicKey,
    ciphertext: &[u8; pq::CIPHERTEXT_LEN],
    recipient_pq: &PqPublicKey,
) -> SymmetricKey {
    let transcript = Sha256::new()
        .chain_update(b"openpass/v2/seal-transcript\0")
        .chain_update(ephemeral.as_bytes())
        .chain_update(recipient.as_bytes())
        .chain_update(ciphertext)
        .chain_update(recipient_pq.as_bytes())
        .finalize();
    let mut secret = Zeroizing::new([0u8; 2 * KEY_LEN]);
    secret[..KEY_LEN].copy_from_slice(pq_shared);
    secret[KEY_LEN..].copy_from_slice(shared);
    hkdf_key(secret.as_ref(), &transcript, b"openpass/v2/seal")
}

fn wrap_key(shared: &[u8; 32], ephemeral: &PublicKey, recipient: &PublicKey) -> SymmetricKey {
    let mut salt = [0u8; 2 * PUBLIC_KEY_LEN];
    salt[..PUBLIC_KEY_LEN].copy_from_slice(ephemeral.as_bytes());
    salt[PUBLIC_KEY_LEN..].copy_from_slice(recipient.as_bytes());
    hkdf_key(shared, &salt, b"openpass/v1/seal")
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    const V: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
    const A: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";
    const B: &str = "0192f0c8-1c2d-7a00-8000-0000000000b1";

    fn vault_key(recipient: &str) -> SealContext<'_> {
        SealContext::VaultKey {
            vault_id: V,
            recipient_account_id: recipient,
        }
    }

    fn setup() -> (ChaCha20Rng, StaticSecret, [u8; 32], SymmetricKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let private = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&private).to_bytes();
        let key = SymmetricKey::generate(&mut rng);
        (rng, private, public, key)
    }

    #[test]
    fn context_strings_match_the_contract() {
        assert_eq!(vault_key(A).to_string(), format!("vaultkey:{V}:{A}"));
        let account = SealContext::EmergencyAccount {
            grantor_account_id: A,
            contact_account_id: B,
        };
        assert_eq!(account.to_string(), format!("emergency:{A}:{B}:ask"));
        let vault = SealContext::EmergencyVault {
            grantor_account_id: A,
            contact_account_id: B,
            vault_id: V,
        };
        assert_eq!(vault.to_string(), format!("emergency:{A}:{B}:vault:{V}"));
        assert_eq!(
            vault_key(A).associated_data(),
            format!("openpass/v1|vaultkey:{V}:{A}").into_bytes()
        );
    }

    #[test]
    fn round_trips() {
        let (mut rng, private, public, key) = setup();
        let sealed = seal_key(&public, &vault_key(A), &key, &mut rng).unwrap();
        let bytes = b64_decode(&sealed).unwrap();
        assert_eq!(bytes.len(), SEALED_LEN);
        assert_eq!(bytes[0], VERSION);
        assert_eq!(open_key(&private, &vault_key(A), &sealed).unwrap(), key);
        assert_ne!(
            sealed,
            seal_key(&public, &vault_key(A), &key, &mut rng).unwrap(),
            "every seal uses a fresh ephemeral key"
        );
    }

    #[test]
    fn opens_only_for_its_context_and_recipient() {
        let (mut rng, private, public, key) = setup();
        let sealed = seal_key(&public, &vault_key(A), &key, &mut rng).unwrap();
        let other_vault = SealContext::VaultKey {
            vault_id: "0192f0c8-1c2d-7a00-8000-0000000000ff",
            recipient_account_id: A,
        };
        for context in [vault_key(B), other_vault] {
            assert_eq!(
                open_key(&private, &context, &sealed).err(),
                Some(Error::DecryptionFailed)
            );
        }
        let stranger = StaticSecret::random_from_rng(&mut rng);
        assert_eq!(
            open_key(&stranger, &vault_key(A), &sealed).err(),
            Some(Error::DecryptionFailed)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        let (mut rng, private, public, key) = setup();
        let mut bytes =
            b64_decode(&seal_key(&public, &vault_key(A), &key, &mut rng).unwrap()).unwrap();
        let open = |bytes: &[u8]| open_key(&private, &vault_key(A), &b64_encode(bytes)).err();
        assert_eq!(open(&bytes[1..]), Some(Error::MalformedCiphertext));
        bytes[50] ^= 1;
        assert_eq!(open(&bytes), Some(Error::DecryptionFailed));
        bytes[50] ^= 1;
        bytes[0] = 2;
        assert_eq!(open(&bytes), Some(Error::UnsupportedVersion));
        assert_eq!(
            open_key(&private, &vault_key(A), "not base64!").err(),
            Some(Error::InvalidBase64)
        );
    }

    fn hybrid_setup() -> (ChaCha20Rng, StaticSecret, [u8; 32], PqKeyPair, SymmetricKey) {
        let (mut rng, private, public, key) = setup();
        let pq = PqKeyPair::generate(&mut rng);
        (rng, private, public, pq, key)
    }

    fn opener<'a>(x25519: &'a StaticSecret, pq: &'a PqKeyPair) -> Opener<'a> {
        Opener {
            x25519,
            pq: Some(pq),
        }
    }

    #[test]
    fn hybrid_boxes_round_trip() {
        let (mut rng, private, public, pq, key) = hybrid_setup();
        let sealed =
            seal_key_hybrid(&public, pq.public_key(), &vault_key(A), &key, &mut rng).unwrap();
        let bytes = b64_decode(&sealed).unwrap();
        assert_eq!(bytes.len(), HYBRID_SEALED_LEN);
        assert_eq!(HYBRID_SEALED_LEN, 1193);
        assert_eq!(bytes[0], HYBRID_VERSION);
        assert_eq!(
            open_key(opener(&private, &pq), &vault_key(A), &sealed).unwrap(),
            key
        );
    }

    #[test]
    fn version_one_boxes_keep_opening_for_accounts_with_an_ml_kem_key() {
        let (mut rng, private, public, pq, key) = hybrid_setup();
        let sealed = seal_key(&public, &vault_key(A), &key, &mut rng).unwrap();
        assert_eq!(
            open_key(opener(&private, &pq), &vault_key(A), &sealed).unwrap(),
            key
        );
    }

    #[test]
    fn seal_for_picks_the_box_the_recipient_can_open() {
        let (mut rng, _, public, pq, key) = hybrid_setup();
        let version = |sealed: String| b64_decode(&sealed).unwrap()[0];
        let classical = seal_for(&public, None, &vault_key(A), &key, &mut rng).unwrap();
        assert_eq!(version(classical), VERSION);
        let hybrid = seal_for(
            &public,
            Some(pq.public_key()),
            &vault_key(A),
            &key,
            &mut rng,
        )
        .unwrap();
        assert_eq!(version(hybrid), HYBRID_VERSION);
    }

    #[test]
    fn a_hybrid_box_needs_both_private_keys() {
        let (mut rng, private, public, pq, key) = hybrid_setup();
        let sealed =
            seal_key_hybrid(&public, pq.public_key(), &vault_key(A), &key, &mut rng).unwrap();
        let wrong_pq = PqKeyPair::generate(&mut rng);
        let wrong_x = StaticSecret::random_from_rng(&mut rng);
        for (x25519, pq_key) in [
            (&private, Some(&wrong_pq)),
            (&wrong_x, Some(&pq)),
            (&private, None),
        ] {
            let keys = Opener { x25519, pq: pq_key };
            assert_eq!(
                open_key(keys, &vault_key(A), &sealed).err(),
                Some(Error::DecryptionFailed)
            );
        }
    }

    #[test]
    fn hybrid_boxes_open_only_for_their_context_and_stay_whole() {
        let (mut rng, private, public, pq, key) = hybrid_setup();
        let sealed =
            seal_key_hybrid(&public, pq.public_key(), &vault_key(A), &key, &mut rng).unwrap();
        assert_eq!(
            open_key(opener(&private, &pq), &vault_key(B), &sealed).err(),
            Some(Error::DecryptionFailed)
        );
        // A change anywhere: version aside, every part feeds the key or the tag.
        let bytes = b64_decode(&sealed).unwrap();
        for position in [1, 33, 500, 1120, 1121, 1145, 1192] {
            let mut tampered = bytes.clone();
            tampered[position] ^= 1;
            assert_eq!(
                open_key(opener(&private, &pq), &vault_key(A), &b64_encode(&tampered)).err(),
                Some(Error::DecryptionFailed),
                "byte {position}"
            );
        }
        let mut relabelled = bytes.clone();
        relabelled[0] = VERSION;
        assert_eq!(
            open_key(
                opener(&private, &pq),
                &vault_key(A),
                &b64_encode(&relabelled)
            )
            .err(),
            Some(Error::UnsupportedVersion)
        );
        assert_eq!(
            open_key(
                opener(&private, &pq),
                &vault_key(A),
                &b64_encode(&bytes[1..])
            )
            .err(),
            Some(Error::MalformedCiphertext)
        );
    }

    #[test]
    fn hybrid_boxes_refuse_low_order_public_keys() {
        let (mut rng, _, _, pq, key) = hybrid_setup();
        assert_eq!(
            seal_key_hybrid(&[0u8; 32], pq.public_key(), &vault_key(A), &key, &mut rng).err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn refuses_low_order_public_keys() {
        let (mut rng, _, _, key) = setup();
        assert_eq!(
            seal_key(&[0u8; 32], &vault_key(A), &key, &mut rng).err(),
            Some(Error::InvalidKey)
        );
    }
}
