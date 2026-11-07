//! Device unlock: the account key (ASK) wrapped by a key only this device can produce, for unlock
//! with Touch ID, Windows Hello or the device passcode instead of the master password.
//!
//! In the browser the device secret is the 32-byte output of a platform passkey's WebAuthn PRF
//! extension, evaluated on [`PRF_INPUT_LABEL`] hashed with SHA-256.
//!
//! ```text
//! device_key = HKDF-SHA256(ikm = prf_output, salt = device_salt (16 random bytes), info = "octapass/v1/device-unlock")
//! wrappedAsk = AEAD(device_key, ASK, context "device-unlock")
//! ```
//!
//! Nothing here goes to the server: the salt and wrapped ASK stay on the device.

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{SymmetricKey, hkdf_key};

pub const PRF_OUTPUT_LEN: usize = 32;
pub const DEVICE_SALT_LEN: usize = 16;
/// The PRF is evaluated on `SHA-256` of this label (`extensions.prf.eval.first`).
pub const PRF_INPUT_LABEL: &[u8] = b"octapass/v1/device-unlock";

/// What a device stores to unlock later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceUnlock {
    pub device_salt: [u8; DEVICE_SALT_LEN],
    /// ASK sealed by the device key (context `device-unlock`), base64url.
    pub wrapped_ask: String,
}

/// `SHA-256("octapass/v1/device-unlock")`: the PRF input for every account and device.
pub fn prf_input() -> [u8; 32] {
    Sha256::digest(PRF_INPUT_LABEL).into()
}

/// Derives the device key from the PRF output and the device salt.
pub fn device_key(prf_output: &[u8], device_salt: &[u8]) -> Result<SymmetricKey> {
    if prf_output.len() != PRF_OUTPUT_LEN || device_salt.len() != DEVICE_SALT_LEN {
        return Err(Error::InvalidKey);
    }
    Ok(hkdf_key(
        prf_output,
        device_salt,
        b"octapass/v1/device-unlock",
    ))
}

pub fn generate_device_salt(rng: &mut impl CryptoRngCore) -> [u8; DEVICE_SALT_LEN] {
    let mut salt = Zeroizing::new([0u8; DEVICE_SALT_LEN]);
    rng.fill_bytes(salt.as_mut());
    *salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_input_is_the_hashed_label() {
        assert_eq!(
            prf_input().as_slice(),
            Sha256::digest(b"octapass/v1/device-unlock").as_slice()
        );
    }

    #[test]
    fn device_key_needs_exact_lengths() {
        assert!(device_key(&[1; 32], &[2; 16]).is_ok());
        assert_eq!(
            device_key(&[1; 31], &[2; 16]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            device_key(&[1; 32], &[2; 15]).unwrap_err(),
            Error::InvalidKey
        );
        assert_ne!(
            device_key(&[1; 32], &[2; 16]).unwrap(),
            device_key(&[1; 32], &[3; 16]).unwrap()
        );
    }
}
