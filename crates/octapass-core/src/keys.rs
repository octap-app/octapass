//! 256-bit symmetric keys and their key ids.

use core::fmt;

use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const KEY_ID_LEN: usize = 16;

/// A 256-bit symmetric key (AUK, ASK, vault key, item key, recovery key …).
///
/// Zeroed on drop and redacted in `Debug` output.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidKey)?))
    }

    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// `SHA-256("octapass/v1/keyid" ‖ key)[0..16]`: identifies a key without revealing it.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let digest = Sha256::new()
            .chain_update(b"octapass/v1/keyid")
            .chain_update(self.0)
            .finalize();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        id
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

/// `HKDF-SHA256(ikm, salt, info)` expanded to 32 bytes.
pub(crate) fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> SymmetricKey {
    let mut out = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymmetricKey(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let key = SymmetricKey::from_bytes([7; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SymmetricKey(<redacted>)");
    }

    #[test]
    fn key_ids_differ_per_key() {
        let a = SymmetricKey::from_bytes([1; KEY_LEN]);
        let b = SymmetricKey::from_bytes([2; KEY_LEN]);
        assert_ne!(a.key_id(), b.key_id());
        assert_eq!(a.key_id(), a.clone().key_id());
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        // RFC 5869 A.1, truncated to the first 32 bytes of OKM.
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let key = hkdf_key(&ikm, &salt, &info);
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf,
        ];
        assert_eq!(key.as_bytes(), &expected);
    }
}
