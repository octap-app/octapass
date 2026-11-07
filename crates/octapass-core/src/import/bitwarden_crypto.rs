//! Decrypting Bitwarden's password-protected JSON export (`.json (Encrypted)`, "Password
//! protected").
//!
//! ```text
//! key     = PBKDF2-SHA256(password, salt, kdfIterations)                       (kdfType 0)
//!         | Argon2id(password, SHA-256(salt), kdfIterations, kdfMemory MiB, kdfParallelism)  (kdfType 1)
//! enc_key = HKDF-Expand(key, "enc", 32);  mac_key = HKDF-Expand(key, "mac", 32)
//! "2.<iv>|<ciphertext>|<mac>"  =  AES-256-CBC (PKCS#7) with HMAC-SHA256(mac_key, iv ‖ ciphertext)
//! ```
//!
//! `salt` is used as the UTF-8 of the base64 string in the file, as Bitwarden does. The MAC is
//! checked before anything is decrypted; a wrong password fails it.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ImportError;
use crate::error::Error;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProtectedExport {
    salt: String,
    kdf_type: u32,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    key_validation: String,
    data: String,
}

struct Keys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

/// The plaintext JSON inside a password-protected export.
pub(super) fn decrypt(
    export: &ProtectedExport,
    password: &str,
) -> Result<Zeroizing<String>, ImportError> {
    let keys = derive(export, password)?;
    let wrong = || {
        ImportError::new(
            Error::WrongImportPassword,
            "Wrong password for this export.",
        )
    };
    decrypt_string(&keys, &export.key_validation).map_err(|_| wrong())?;
    let data = decrypt_string(&keys, &export.data).map_err(|_| wrong())?;
    String::from_utf8(data.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| malformed())
}

fn derive(export: &ProtectedExport, password: &str) -> Result<Keys, ImportError> {
    let mut key = Zeroizing::new([0u8; 32]);
    match export.kdf_type {
        0 => {
            // Bitwarden's minimum is 5,000; the cap keeps a crafted file from freezing the device.
            if !(5_000..=10_000_000).contains(&export.kdf_iterations) {
                return Err(unsupported_kdf());
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                export.salt.as_bytes(),
                export.kdf_iterations,
                key.as_mut(),
            );
        }
        1 => {
            let memory_mib = export.kdf_memory.ok_or_else(malformed)?;
            let parallelism = export.kdf_parallelism.ok_or_else(malformed)?;
            if !(16..=1024).contains(&memory_mib)
                || !(2..=16).contains(&export.kdf_iterations)
                || !(1..=16).contains(&parallelism)
            {
                return Err(unsupported_kdf());
            }
            let params = argon2::Params::new(
                memory_mib * 1024,
                export.kdf_iterations,
                parallelism,
                Some(32),
            )
            .map_err(|_| unsupported_kdf())?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(
                    password.as_bytes(),
                    &Sha256::digest(export.salt.as_bytes()),
                    key.as_mut(),
                )
                .map_err(|_| unsupported_kdf())?;
        }
        _ => return Err(unsupported_kdf()),
    }
    let hkdf = Hkdf::<Sha256>::from_prk(key.as_ref()).expect("32 bytes is a valid PRK");
    let mut keys = Keys {
        enc: Zeroizing::new([0u8; 32]),
        mac: Zeroizing::new([0u8; 32]),
    };
    hkdf.expand(b"enc", keys.enc.as_mut())
        .and_then(|()| hkdf.expand(b"mac", keys.mac.as_mut()))
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(keys)
}

/// Opens a type 2 cipher string, `2.<iv>|<ciphertext>|<mac>` in standard base64.
fn decrypt_string(keys: &Keys, cipher: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let body = cipher.strip_prefix("2.").ok_or_else(malformed)?;
    let parts: Vec<Vec<u8>> = body
        .split('|')
        .map(|part| STANDARD.decode(part))
        .collect::<Result<_, _>>()
        .map_err(|_| malformed())?;
    let [iv, ciphertext, tag] = parts.as_slice() else {
        return Err(malformed());
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(keys.mac.as_ref())
        .expect("HMAC takes any key length");
    mac.update(iv);
    mac.update(ciphertext);
    mac.verify_slice(tag).map_err(|_| {
        ImportError::new(
            Error::WrongImportPassword,
            "Wrong password for this export.",
        )
    })?;
    let iv: [u8; 16] = iv.as_slice().try_into().map_err(|_| malformed())?;
    let mut buffer = Zeroizing::new(ciphertext.clone());
    let plaintext_len = cbc::Decryptor::<Aes256>::new((&*keys.enc).into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| malformed())?
        .len();
    buffer.truncate(plaintext_len);
    Ok(buffer)
}

fn malformed() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted Bitwarden export is damaged.",
    )
}

fn unsupported_kdf() -> ImportError {
    ImportError::new(
        Error::UnsupportedImport,
        "This encrypted Bitwarden export uses key derivation settings Octa Pass doesn't accept.",
    )
}
