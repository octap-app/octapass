//! 2FAS Authenticator backups (`.2fas`, from the Android and iOS apps), plain or encrypted with a
//! password.
//!
//! ```text
//! servicesEncrypted = base64(ciphertext ‖ tag) ":" base64(salt) ":" base64(iv)
//! key               = PBKDF2-HMAC-SHA256(password, salt, 10,000 iterations, 32 bytes)
//! services          = AES-256-GCM(key, iv)  →  the JSON array that `services` holds in a plain backup
//! ```
//!
//! `reference` is a known text encrypted the same way; the tag on `servicesEncrypted` already
//! tells a wrong password apart, so it isn't needed. Groups become tags; 2FAS has no notes. A
//! service's `updatedAt` (milliseconds) is its last-changed date. Services have no id of their
//! own, so importing the backup again recognises codes by their secret.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::authenticator::{Codes, Entry, number, open_gcm, text};
use super::build::{ItemMeta, clean, unix_time};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;

const ITERATIONS: u32 = 10_000;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let contents = decode_text(bytes).map_err(|_| not_2fas())?;
    let file: Value = serde_json::from_str(&contents).map_err(|_| not_2fas())?;
    if !file.get("schemaVersion").is_some_and(Value::is_u64) {
        return Err(not_2fas());
    }
    let groups: HashMap<&str, String> = file
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| Some((group.get("id")?.as_str()?, text(group, "name")?)))
        .collect();
    let encrypted = file
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());
    let decrypted: Value;
    let services = match encrypted {
        Some(encrypted) => {
            let password = options.password.as_ref().ok_or(ImportError::new(
                Error::ImportPasswordRequired,
                "This 2FAS backup is protected by a password.",
            ))?;
            let plain = decrypt(encrypted, password)?;
            decrypted = serde_json::from_slice(&plain).map_err(|_| damaged())?;
            decrypted.as_array().ok_or_else(damaged)?
        }
        None => file
            .get("services")
            .and_then(Value::as_array)
            .ok_or_else(not_2fas)?,
    };

    let mut codes = Codes::new(&options.existing_logins);
    for (index, service) in services.iter().enumerate() {
        let number_in_file = index + 1;
        if !service.is_object() {
            codes.skip(format!(
                "Entry {number_in_file} skipped: not a 2FAS service."
            ));
            continue;
        }
        let otp = service.get("otp").unwrap_or(&Value::Null);
        let name = text(service, "name");
        // "Issuer:account" when the account isn't given on its own (older backups).
        let label = text(otp, "label");
        let account = text(otp, "account").or_else(|| {
            label
                .as_deref()
                .and_then(|l| l.split_once(':'))
                .and_then(|(_, account)| clean(Some(account)))
        });
        codes.add(
            number_in_file,
            Entry {
                kind: text(otp, "tokenType").unwrap_or_else(|| "totp".into()),
                secret: Zeroizing::new(text(service, "secret").unwrap_or_default()),
                algorithm: text(otp, "algorithm"),
                digits: number(otp, "digits"),
                period: number(otp, "period"),
                counter: number(otp, "counter"),
                pin: None,
                issuer: text(otp, "issuer").or_else(|| name.clone()),
                title: name,
                account,
                notes: None,
                tags: text(service, "groupId")
                    .and_then(|id| groups.get(id.as_str()).cloned())
                    .into_iter()
                    .collect(),
                favorite: false,
                meta: ItemMeta {
                    updated_at: number(service, "updatedAt")
                        .and_then(|ms| unix_time(i64::try_from(ms).ok()?)),
                    ..ItemMeta::default()
                },
            },
        );
    }
    Ok(codes.finish())
}

fn decrypt(encrypted: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let parts: Vec<Vec<u8>> = encrypted
        .split(':')
        .map(|part| STANDARD.decode(part.trim()))
        .collect::<Result<_, _>>()
        .map_err(|_| damaged())?;
    let [sealed, salt, iv] = parts.as_slice() else {
        return Err(damaged());
    };
    if iv.len() != 12 {
        return Err(damaged());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, key.as_mut());
    open_gcm(&key, iv, sealed).ok_or(ImportError::new(
        Error::WrongImportPassword,
        "Wrong password for this 2FAS backup.",
    ))
}

fn not_2fas() -> ImportError {
    ImportError::new(Error::InvalidImportFile, "This is not a 2FAS backup.")
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted 2FAS backup is damaged.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    fn seal(password: &str, plain: &[u8]) -> String {
        let (salt, iv) = ([3u8; 32], [4u8; 12]);
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut key);
        let sealed = Aes256Gcm::new((&key).into())
            .encrypt(Nonce::from_slice(&iv), plain)
            .unwrap();
        [&sealed[..], &salt, &iv]
            .map(|part| STANDARD.encode(part))
            .join(":")
    }

    #[test]
    fn encrypted_services() {
        let services = br#"[{"name":"Shop","secret":"JBSWY3DPEHPK3PXP","otp":{"label":"Shop:me@example.com","tokenType":"TOTP"}}]"#;
        let plain = decrypt(&seal("pw", services), "pw").unwrap();
        assert_eq!(plain.as_slice(), services);
        assert_eq!(
            decrypt(&seal("pw", services), "other").unwrap_err().code,
            Error::WrongImportPassword
        );
        for broken in ["", "a:b", "AAAA:AAAA:AAAA", "!!:AA==:AA=="] {
            assert_eq!(
                decrypt(broken, "pw").unwrap_err().code,
                Error::InvalidImportFile
            );
        }
    }

    #[test]
    fn account_from_the_label() {
        let file = br#"{"schemaVersion":4,"services":[{"name":"Shop","secret":"JBSWY3DPEHPK3PXP","otp":{"label":"Shop:me@example.com","tokenType":"TOTP"}}]}"#;
        let result = parse(file, &ImportOptions::default()).unwrap();
        assert_eq!(
            result.items[0].overview.subtitle.as_deref(),
            Some("me@example.com")
        );
    }
}
