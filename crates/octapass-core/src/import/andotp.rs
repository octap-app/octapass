//! andOTP backups: the plain JSON array (`otp_accounts_….json`), or the password-encrypted
//! `.json.aes`.
//!
//! ```text
//! file = iterations (4 bytes, big-endian) ‖ salt (12) ‖ nonce (12) ‖ ciphertext ‖ tag (16)
//! key  = PBKDF2-HMAC-SHA1(password, salt, iterations, 32 bytes);  AES-256-GCM
//! ```
//!
//! Older andOTP versions wrote `nonce (12) ‖ ciphertext ‖ tag` with SHA-256(password) as the key;
//! that layout is tried when the first one doesn't open. Tags carry over, and `last_used`
//! (milliseconds) becomes the last-used date; thumbnails and usage counts don't. Entries have no
//! id, so importing a backup again recognises codes by their secret. Backups encrypted with OpenPGP aren't supported.

use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::authenticator::{Codes, Entry, number, open_gcm, text};
use super::build::{ItemMeta, clean, unix_time};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;

/// andOTP picks 140,000 to 160,000; the cap keeps a crafted file from freezing the device.
const MAX_ITERATIONS: u32 = 1_000_000;
const SALT: usize = 12;
const NONCE: usize = 12;
const TAG: usize = 16;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let contents = decode_text(bytes).ok();
    let starts_like_json = contents
        .as_deref()
        .is_some_and(|c| c.trim_start().starts_with('['))
        || bytes.trim_ascii_start().starts_with(b"[");
    if starts_like_json {
        if let Some(result) = contents.as_deref().and_then(|c| entries(c, options)) {
            return Ok(result);
        }
        // An older encrypted backup starts with a random nonce, which can be "[" by chance.
        if let Some(password) = &options.password
            && let Ok(result) = decrypted(bytes, password, options)
        {
            return Ok(result);
        }
        return Err(not_andotp());
    }
    // Encrypted backups are binary; other text is some other file.
    if bytes.len() < NONCE + TAG || (contents.is_some() && current_layout(bytes).is_none()) {
        return Err(not_andotp());
    }
    let password = options.password.as_ref().ok_or(ImportError::new(
        Error::ImportPasswordRequired,
        "This andOTP backup is protected by a password.",
    ))?;
    decrypted(bytes, password, options)
}

fn decrypted(
    bytes: &[u8],
    password: &str,
    options: &ImportOptions,
) -> Result<ImportResult, ImportError> {
    let plain = decrypt(bytes, password)?;
    let contents = std::str::from_utf8(&plain).map_err(|_| damaged())?;
    entries(contents, options).ok_or_else(damaged)
}

/// The iterations, and the salt, nonce and sealed data after them, when the header fits a
/// current backup.
fn current_layout(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (iterations, rest) = bytes.split_first_chunk::<4>()?;
    let iterations = u32::from_be_bytes(*iterations);
    ((1..=MAX_ITERATIONS).contains(&iterations) && rest.len() >= SALT + NONCE + TAG)
        .then_some((iterations, rest))
}

fn decrypt(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    if let Some((iterations, rest)) = current_layout(bytes) {
        let (salt, rest) = rest.split_at(SALT);
        let (nonce, sealed) = rest.split_at(NONCE);
        let mut key = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, key.as_mut());
        if let Some(plain) = open_gcm(&key, nonce, sealed) {
            return Ok(plain);
        }
    }
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(password.as_bytes()).into());
    let (nonce, sealed) = bytes.split_at(NONCE.min(bytes.len()));
    open_gcm(&key, nonce, sealed).ok_or(ImportError::new(
        Error::WrongImportPassword,
        "Wrong password for this andOTP backup.",
    ))
}

fn entries(contents: &str, options: &ImportOptions) -> Option<ImportResult> {
    let list: Value = serde_json::from_str(contents).ok()?;
    let list = list.as_array()?;
    let mut codes = Codes::new(&options.existing_logins);
    for (index, entry) in list.iter().enumerate() {
        let number_in_file = index + 1;
        if !entry.is_object() {
            codes.skip(format!(
                "Entry {number_in_file} skipped: not an andOTP entry."
            ));
            continue;
        }
        let mut issuer = text(entry, "issuer");
        let mut account = text(entry, "label");
        // Backups from before andOTP had an issuer field: "Issuer:account" in the label.
        if issuer.is_none()
            && let Some((head, tail)) = account.as_deref().and_then(|l| l.split_once(':'))
        {
            (issuer, account) = (clean(Some(head)), clean(Some(tail)));
        }
        codes.add(
            number_in_file,
            Entry {
                kind: text(entry, "type").unwrap_or_else(|| "totp".into()),
                secret: Zeroizing::new(text(entry, "secret").unwrap_or_default()),
                algorithm: text(entry, "algorithm"),
                digits: number(entry, "digits"),
                period: number(entry, "period"),
                counter: number(entry, "counter"),
                pin: text(entry, "pin").map(Zeroizing::new),
                title: None,
                issuer,
                account,
                notes: None,
                tags: entry
                    .get("tags")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|tag| clean(tag.as_str()))
                    .collect(),
                favorite: false,
                meta: ItemMeta {
                    last_used_at: number(entry, "last_used")
                        .and_then(|ms| unix_time(i64::try_from(ms).ok()?)),
                    ..ItemMeta::default()
                },
            },
        );
    }
    Some(codes.finish())
}

fn not_andotp() -> ImportError {
    ImportError::new(Error::InvalidImportFile, "This is not an andOTP backup.")
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted andOTP backup is damaged.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    const PLAIN: &[u8] =
        br#"[{"secret":"JBSWY3DPEHPK3PXP","issuer":"","label":"Shop:me","type":"TOTP"}]"#;

    fn seal(key: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
        let mut out = nonce.to_vec();
        out.extend(
            Aes256Gcm::new(key.into())
                .encrypt(Nonce::from_slice(&nonce), PLAIN)
                .unwrap(),
        );
        out
    }

    #[test]
    fn both_encrypted_layouts() {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"pw", &[5u8; 12], 1000, &mut key);
        let mut current = 1000u32.to_be_bytes().to_vec();
        current.extend([5u8; 12]);
        current.extend(seal(&key, [6u8; 12]));
        assert_eq!(decrypt(&current, "pw").unwrap().as_slice(), PLAIN);
        assert_eq!(
            decrypt(&current, "other").unwrap_err().code,
            Error::WrongImportPassword
        );

        let legacy = seal(&Sha256::digest(b"pw").into(), [0xa7; 12]);
        assert_eq!(decrypt(&legacy, "pw").unwrap().as_slice(), PLAIN);
    }

    #[test]
    fn issuer_from_old_labels() {
        let result = parse(PLAIN, &ImportOptions::default()).unwrap();
        assert_eq!(result.items[0].overview.title, "Shop");
        assert_eq!(result.items[0].overview.subtitle.as_deref(), Some("me"));
    }

    #[test]
    fn text_that_isnt_a_backup() {
        for bytes in [
            &b"name,url\nsite,https://example.com\n"[..],
            b"[1",
            b"{}",
            b"",
        ] {
            assert_eq!(
                parse(bytes, &ImportOptions::default()).unwrap_err().code,
                Error::InvalidImportFile
            );
        }
    }
}
