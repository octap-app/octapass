//! The key exchange that hands a secret to the browser extension or the CLI without it ever
//! being readable on the way (plan 13, J): the peer sends a fresh X25519 public key, the app
//! answers with its own ephemeral public key and the secret wrapped under
//!
//! ```text
//! shared    = X25519(app_ephemeral, peer_public)
//! wrap_key  = HKDF-SHA256(ikm = shared, salt = app_ephemeral_public ‖ peer_public, info)
//! ```
//!
//! The account key is wrapped exactly as for device unlock (`octapass_core::device`), with
//! `wrap_key` as the 32-byte device secret; the peer derives the same key and calls
//! `Session.unlockWithDeviceKey`. The same as the Tauri app's (`octapass_desktop_vault::bridge`).

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const WRAP_INFO: &[u8] = b"openpass/v1/native-messaging";
/// For the chip secret of the extension's own local vault, so the two keys never coincide.
pub const CHIP_WRAP_INFO: &[u8] = b"openpass/v1/native-messaging-chip";

/// Both sides derive the wrapping key the same way.
pub fn wrap_key(
    shared_secret: &[u8; 32],
    app_public: &[u8; 32],
    peer_public: &[u8; 32],
    info: &[u8],
) -> Zeroizing<[u8; 32]> {
    let salt = [app_public.as_slice(), peer_public.as_slice()].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared_secret)
        .expand(info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

/// A fresh ephemeral key against `peer_public`: the app's public key to send back, and the
/// wrapping key.
pub(crate) fn exchange(
    peer_public: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], Zeroizing<[u8; 32]>)> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let app_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(VaultError::unexpected("invalid peer public key"));
    }
    let key = wrap_key(shared.as_bytes(), app_public.as_bytes(), peer_public, info);
    Ok((*app_public.as_bytes(), key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_key() {
        let peer = StaticSecret::random_from_rng(OsRng);
        let peer_public = *PublicKey::from(&peer).as_bytes();
        let (app_public, key) = exchange(&peer_public, WRAP_INFO).unwrap();
        let shared = peer.diffie_hellman(&PublicKey::from(app_public));
        assert_eq!(
            *wrap_key(shared.as_bytes(), &app_public, &peer_public, WRAP_INFO),
            *key
        );
        assert_ne!(
            *wrap_key(shared.as_bytes(), &app_public, &peer_public, CHIP_WRAP_INFO),
            *key,
            "the chip's key is another key"
        );
    }

    #[test]
    fn a_low_order_key_is_refused() {
        assert!(exchange(&[0; 32], WRAP_INFO).is_err());
    }

    /// The extension's `deriveWrapKey` (`apps/extension/src/background/desktop.ts`) and the
    /// Tauri app compute this: HKDF-SHA256 over the X25519 output, salted with both public keys,
    /// the app's first.
    #[test]
    fn the_derivation_is_the_documented_one() {
        let key = wrap_key(&[1; 32], &[2; 32], &[3; 32], WRAP_INFO);
        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&[[2u8; 32], [3u8; 32]].concat()), &[1; 32])
            .expand(b"openpass/v1/native-messaging", &mut expected)
            .unwrap();
        assert_eq!(*key, expected);
    }
}
