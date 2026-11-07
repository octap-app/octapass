//! The `.octapass-backup` file: a local vault encrypted with a key from the master password alone
//! (no device chip), so it can be restored on any device (plan 03, *Local mode keys*).
//!
//! ```text
//! offset  size  field
//! 0       4     magic "OPBK"
//! 4       1     version (0x01)
//! 5       4     Argon2id memory in KiB (u32, big-endian)
//! 9       4     Argon2id iterations (u32, big-endian)
//! 13      4     Argon2id parallelism (u32, big-endian)
//! 17      16    salt
//! 33      89    backup key sealed by the backup recovery code (envelope, context "backup-recovery")
//! 122     24    nonce
//! 146     …     XChaCha20-Poly1305 ciphertext ‖ tag, associated data = bytes 0..146
//!
//! backup_key   = Argon2id v1.3(NFKD(password), salt, m = 256 MiB, t = 4, p = 1)
//! recovery_key = HKDF-SHA256(ikm = backup recovery code (32 bytes), salt = "", info = "octapass/v1/backup-recovery")
//! ```
//!
//! The whole header is authenticated, so changing the parameters or the salt makes the file fail
//! to open rather than weakening it. The plaintext is the vault itself (see [`crate::local`]).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::envelope::{self, Context, NONCE_LEN};
use crate::error::{Error, Result};
use crate::kdf::{KdfAlgorithm, KdfParams};
use crate::keys::{SymmetricKey, hkdf_key};
use crate::local::keys::{SALT_LEN, password_key};
use crate::recovery::RecoveryCode;

pub const MAGIC: &[u8; 4] = b"OPBK";
pub const VERSION: u8 = 0x01;

pub const BACKUP_KDF: KdfParams = KdfParams {
    algorithm: KdfAlgorithm::Argon2id,
    memory_kib: 262_144,
    iterations: 4,
    parallelism: 1,
};

const WRAPPED_KEY_LEN: usize = 1 + 16 + NONCE_LEN + 32 + envelope::TAG_LEN;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN + WRAPPED_KEY_LEN + NONCE_LEN;

/// What a backup is keyed by: the password-derived key, its salt and parameters.
pub(crate) struct BackupKey {
    pub key: SymmetricKey,
    pub salt: [u8; SALT_LEN],
    pub kdf: KdfParams,
}

impl BackupKey {
    /// Derives a fresh backup key (new salt). Runs Argon2id.
    pub fn derive(password: &str, kdf: KdfParams, rng: &mut impl CryptoRngCore) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        Ok(Self {
            key: password_key(password, &salt, &kdf)?,
            salt,
            kdf,
        })
    }
}

/// `HKDF(code, info = "octapass/v1/backup-recovery")`, separate from the account recovery key.
fn recovery_key(code: &RecoveryCode) -> SymmetricKey {
    hkdf_key(code.as_bytes(), b"", b"octapass/v1/backup-recovery")
}

/// Encrypts `plaintext` into a backup file.
pub(crate) fn seal(
    plaintext: &[u8],
    key: &BackupKey,
    code: &RecoveryCode,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let wrapped = envelope::seal(
        &recovery_key(code),
        &Context::BackupRecovery,
        key.key.as_bytes(),
        rng,
    )?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + envelope::TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    for value in [key.kdf.memory_kib, key.kdf.iterations, key.kdf.parallelism] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&key.salt);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);
    let ciphertext = XChaCha20Poly1305::new(key.key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The parsed header of a backup file.
struct Header<'a> {
    kdf: KdfParams,
    salt: &'a [u8],
    wrapped_key: &'a [u8],
}

fn header(file: &[u8]) -> Result<Header<'_>> {
    if file.len() < HEADER_LEN + envelope::TAG_LEN || &file[..4] != MAGIC {
        return Err(Error::InvalidBackup);
    }
    if file[4] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let u32_at =
        |offset: usize| u32::from_be_bytes(file[offset..offset + 4].try_into().expect("4 bytes"));
    Ok(Header {
        kdf: KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: u32_at(5),
            iterations: u32_at(9),
            parallelism: u32_at(13),
        },
        salt: &file[17..17 + SALT_LEN],
        wrapped_key: &file[17 + SALT_LEN..17 + SALT_LEN + WRAPPED_KEY_LEN],
    })
}

/// Opens a backup with the master password. Returns the plaintext and the backup key, so a
/// restored vault keeps backing up with the same key. Wrong password: [`Error::LoginFailed`].
pub(crate) fn open_with_password(
    file: &[u8],
    password: &str,
) -> Result<(Zeroizing<Vec<u8>>, BackupKey)> {
    let header = header(file)?;
    // The parameters are checked before running Argon2id, so a crafted file can't freeze the device.
    let key = password_key(password, header.salt, &header.kdf)?;
    let plaintext = decrypt(file, &key).map_err(|_| Error::LoginFailed)?;
    let salt = header.salt.try_into().expect("16 bytes");
    Ok((
        plaintext,
        BackupKey {
            key,
            salt,
            kdf: header.kdf,
        },
    ))
}

/// Opens a backup with the backup recovery code. Wrong code: [`Error::InvalidRecoveryCode`].
pub(crate) fn open_with_recovery_code(
    file: &[u8],
    code: &RecoveryCode,
) -> Result<Zeroizing<Vec<u8>>> {
    let header = header(file)?;
    let key = envelope::open(
        &recovery_key(code),
        &Context::BackupRecovery,
        header.wrapped_key,
    )
    .map_err(|error| match error {
        Error::WrongKey | Error::DecryptionFailed => Error::InvalidRecoveryCode,
        _ => Error::InvalidBackup,
    })?;
    decrypt(file, &SymmetricKey::from_slice(&key)?).map_err(|_| Error::InvalidBackup)
}

fn decrypt(file: &[u8], key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
    let (aad, ciphertext) = file.split_at(HEADER_LEN);
    let nonce = XNonce::from_slice(&aad[HEADER_LEN - NONCE_LEN..]);
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(7)
    }

    fn backup(rng: &mut ChaCha20Rng) -> (Vec<u8>, RecoveryCode) {
        let key = BackupKey::derive("pw", KdfParams::DEFAULT, rng).unwrap();
        let code = RecoveryCode::generate(rng);
        (seal(b"the vault", &key, &code, rng).unwrap(), code)
    }

    #[test]
    fn layout() {
        let (file, _) = backup(&mut rng());
        assert_eq!(&file[..5], b"OPBK\x01");
        assert_eq!(&file[5..9], &65_536u32.to_be_bytes());
        assert_eq!(&file[9..13], &3u32.to_be_bytes());
        assert_eq!(&file[13..17], &1u32.to_be_bytes());
        assert_eq!(file[33], envelope::VERSION);
        assert_eq!(file.len(), HEADER_LEN + 9 + 16);
        assert_eq!(HEADER_LEN, 146);
    }

    #[test]
    fn opens_with_the_password_or_the_recovery_code() {
        let mut rng = rng();
        let (file, code) = backup(&mut rng);
        let (plaintext, key) = open_with_password(&file, "pw").unwrap();
        assert_eq!(plaintext.as_slice(), b"the vault");
        assert_eq!(key.kdf, KdfParams::DEFAULT);
        assert_eq!(
            open_with_recovery_code(&file, &code).unwrap().as_slice(),
            b"the vault"
        );

        assert_eq!(
            open_with_password(&file, "wrong").err(),
            Some(Error::LoginFailed)
        );
        let other = RecoveryCode::generate(&mut rng);
        assert_eq!(
            open_with_recovery_code(&file, &other).err(),
            Some(Error::InvalidRecoveryCode)
        );
    }

    #[test]
    fn the_header_is_authenticated() {
        let (file, code) = backup(&mut rng());
        // Another salt, other parameters or a swapped nonce: nothing opens.
        for offset in [20, 125, 140] {
            let mut tampered = file.clone();
            tampered[offset] ^= 1;
            assert!(
                open_with_recovery_code(&tampered, &code).is_err(),
                "{offset}"
            );
        }
        let mut cheaper = file.clone();
        cheaper[9..13].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            open_with_recovery_code(&cheaper, &code).err(),
            Some(Error::InvalidBackup)
        );
        let mut weak = file.clone();
        weak[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            open_with_password(&weak, "pw").err(),
            Some(Error::UnsupportedKdf)
        );
    }

    #[test]
    fn rejects_other_files() {
        let (file, code) = backup(&mut rng());
        assert_eq!(
            open_with_recovery_code(b"OPBK", &code).err(),
            Some(Error::InvalidBackup)
        );
        let mut other = file.clone();
        other[..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(
            open_with_recovery_code(&other, &code).err(),
            Some(Error::InvalidBackup)
        );
        let mut future = file;
        future[4] = 2;
        assert_eq!(
            open_with_recovery_code(&future, &code).err(),
            Some(Error::UnsupportedVersion)
        );
    }
}
