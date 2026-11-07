//! Keys from the master password alone (no Secret Key, no email): the Local Unlock Key and the
//! backup key.
//!
//! ```text
//! pw_key = Argon2id v1.3(NFKD(password), local_salt (16 bytes), m = 256 MiB (or 64 MiB), t = 3, p = 1)
//! LUK    = HKDF-SHA256(ikm = pw_key ‖ hw_secret (32 bytes, if the device has a chip), salt = "", info = "openpass/v1/local-unlock")
//! ```
//!
//! The browser extension has no chip of its own. With the desktop app installed it borrows the
//! app's: the app seals `hw_secret` to it over native messaging ([`seal_chip_secret`]).

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::envelope::{Context, open_b64, seal_b64};
use crate::error::{Error, Result};
use crate::kdf::{KdfAlgorithm, KdfParams};
use crate::keys::{SymmetricKey, hkdf_key};
use crate::tools::strength;

pub const SALT_LEN: usize = 16;
pub const HARDWARE_SECRET_LEN: usize = 32;

/// Local vaults use 256 MiB where the device allows it.
pub const LOCAL_KDF: KdfParams = KdfParams {
    algorithm: KdfAlgorithm::Argon2id,
    memory_kib: 262_144,
    iterations: 3,
    parallelism: 1,
};

/// For devices that can't spare 256 MiB (some phones, the browser extension on low memory).
pub const LOCAL_KDF_LOW_MEMORY: KdfParams = KdfParams::DEFAULT;

/// `pw_key`: Argon2id over the NFKD-normalised password. `params` must pass
/// [`KdfParams::validate`]. Backups use it too, with their own salt and parameters.
pub fn password_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<SymmetricKey> {
    crate::kdf::argon2id(password, salt, params)
}

/// The Local Unlock Key. Runs Argon2id.
pub fn local_unlock_key(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
    hardware_secret: Option<&[u8]>,
) -> Result<SymmetricKey> {
    let pw_key = password_key(password, salt, params)?;
    let mut ikm = Zeroizing::new(pw_key.as_bytes().to_vec());
    if let Some(secret) = hardware_secret {
        if secret.len() != HARDWARE_SECRET_LEN {
            return Err(Error::InvalidKey);
        }
        ikm.extend_from_slice(secret);
    }
    Ok(hkdf_key(&ikm, b"", b"openpass/v1/local-unlock"))
}

/// A chip's secret for the trip from the desktop app to the extension, under the key both sides
/// derive from their X25519 exchange (context `chip-secret`).
pub fn seal_chip_secret(
    key: &SymmetricKey,
    secret: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    if secret.len() != HARDWARE_SECRET_LEN {
        return Err(Error::InvalidKey);
    }
    seal_b64(key, &Context::ChipSecret, secret, rng)
}

/// Opens [`seal_chip_secret`]'s output.
pub fn open_chip_secret(key: &SymmetricKey, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
    let secret = Zeroizing::new(open_b64(key, &Context::ChipSecret, sealed)?.to_vec());
    if secret.len() != HARDWARE_SECRET_LEN {
        return Err(Error::InvalidKey);
    }
    Ok(secret)
}

/// Without a device chip, a copied vault file is only as strong as the master password, so it
/// must score 4 (the top) with zxcvbn (plan 03).
pub(crate) fn check_strength(password: &str, hardware_bound: bool) -> Result<()> {
    if hardware_bound || strength::estimate(password, &[]).score == 4 {
        Ok(())
    } else {
        Err(Error::WeakMasterPassword)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hardware_secret_changes_the_key() {
        let salt = [1u8; SALT_LEN];
        let plain = local_unlock_key("pw", &salt, &KdfParams::DEFAULT, None).unwrap();
        let bound = local_unlock_key("pw", &salt, &KdfParams::DEFAULT, Some(&[2; 32])).unwrap();
        assert_ne!(plain, bound);
        assert_eq!(
            local_unlock_key("pw", &salt, &KdfParams::DEFAULT, Some(&[2; 16])).unwrap_err(),
            Error::InvalidKey
        );
        let weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::DEFAULT
        };
        assert_eq!(
            local_unlock_key("pw", &salt, &weak, None).unwrap_err(),
            Error::UnsupportedKdf
        );
    }

    #[test]
    fn a_chip_secret_opens_only_with_its_key() {
        use rand_core::OsRng;
        let key = SymmetricKey::generate(&mut OsRng);
        let sealed = seal_chip_secret(&key, &[7; 32], &mut OsRng).unwrap();
        assert_eq!(
            open_chip_secret(&key, &sealed).unwrap().as_slice(),
            &[7; 32]
        );
        assert!(open_chip_secret(&SymmetricKey::generate(&mut OsRng), &sealed).is_err());
        assert_eq!(
            seal_chip_secret(&key, &[7; 16], &mut OsRng).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn unbound_vaults_need_a_strong_password() {
        assert_eq!(
            check_strength("password123", false).unwrap_err(),
            Error::WeakMasterPassword
        );
        assert!(check_strength("password123", true).is_ok());
        assert!(check_strength("vexed-kiwi-trumpet-galaxy-oboe", false).is_ok());
        assert!(LOCAL_KDF.validate().is_ok() && LOCAL_KDF_LOW_MEMORY.validate().is_ok());
    }
}
