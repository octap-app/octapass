//! Raivo OTP exports (iOS): `raivo-otp-export.zip`, protected with a password, holding
//! `raivo-otp-export.json` (and an HTML page with QR codes, which isn't read), or that JSON on its
//! own once unzipped.
//!
//! As Raivo's `DataExportFeature.swift` writes it: SSZipArchive with `aes: true` (WinZip AE-2
//! encryption, AES-256) and no compression; the JSON is an array of objects whose values are all
//! text: `issuer`, `account`, `secret`, `algorithm`, `digits`, `kind` (`TOTP` or `HOTP`),
//! `timer`, `counter`, `pinned` and the icon's `iconType` and `iconValue`. Pinned codes become
//! favourites; icons aren't kept. The export has no ids or dates, so importing it again
//! recognises codes by their secret.
//!
//! ```text
//! entry data = salt (8, 12 or 16 bytes) ‖ password check (2) ‖ ciphertext ‖ HMAC-SHA1 (first 10 bytes)
//! keys       = PBKDF2-HMAC-SHA1(password, salt, 1000, 2 × key length + 2): AES key ‖ HMAC key ‖ check
//! ciphertext = AES-CTR (128-bit little-endian counter from 1), the MAC over the ciphertext
//! ```

use std::io::{Cursor, Read};

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use zeroize::Zeroizing;

use super::authenticator::{Codes, Entry, number, text};
use super::build::is_true;
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;

const FILE_NAME: &str = "raivo-otp-export.json";
/// The JSON is a few hundred bytes per code; this stops a ZIP bomb.
const MAX_JSON_LEN: u64 = 64 << 20;
const AES_EXTRA_FIELD: u16 = 0x9901;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const WINZIP_AES: u16 = 99;
const ITERATIONS: u32 = 1000;
const MAC_LEN: usize = 10;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let json = if bytes.starts_with(b"PK\x03\x04") {
        let password = options.password.as_ref().map(|p| p.as_str());
        decode_text(&read_zip(bytes, password)?).map_err(|_| damaged())?
    } else {
        decode_text(bytes).map_err(|_| not_raivo())?
    };
    let list: Value = serde_json::from_str(&json).map_err(|_| not_raivo())?;
    let list = list.as_array().ok_or_else(not_raivo)?;
    let mut codes = Codes::new(&options.existing_logins);
    for (index, entry) in list.iter().enumerate() {
        let number_in_file = index + 1;
        if entry.get("secret").is_none() {
            codes.skip(format!("Entry {number_in_file} skipped: not a Raivo code."));
            continue;
        }
        codes.add(
            number_in_file,
            Entry {
                kind: text(entry, "kind").unwrap_or_else(|| "totp".into()),
                secret: Zeroizing::new(text(entry, "secret").unwrap_or_default()),
                algorithm: text(entry, "algorithm"),
                digits: number(entry, "digits"),
                period: number(entry, "timer"),
                counter: number(entry, "counter"),
                issuer: text(entry, "issuer"),
                account: text(entry, "account"),
                favorite: is_true(text(entry, "pinned").as_deref()),
                ..Entry::default()
            },
        );
    }
    Ok(codes.finish())
}

/// The JSON file from the archive, decrypted when it's encrypted.
fn read_zip(bytes: &[u8], password: Option<&str>) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| not_raivo())?;
    let index = (0..archive.len())
        .find(|&i| {
            archive.name_for_index(i).is_some_and(|name| {
                name.is_ok_and(|name| name == FILE_NAME || name.ends_with(&format!("/{FILE_NAME}")))
            })
        })
        .ok_or_else(not_raivo)?;
    let file = archive.by_index_raw(index).map_err(|_| not_raivo())?;
    let (header, start, size) = (
        file.header_start(),
        file.data_start().ok_or_else(damaged)?,
        file.compressed_size(),
    );
    let encrypted = file.encrypted();
    drop(file);
    if !encrypted {
        let mut json = Zeroizing::new(Vec::new());
        archive
            .by_index(index)
            .map_err(|_| damaged())?
            .take(MAX_JSON_LEN)
            .read_to_end(&mut json)
            .map_err(|_| damaged())?;
        return Ok(json);
    }
    let (strength, method) = aes_settings(bytes, header).ok_or(ImportError::new(
        Error::UnsupportedImport,
        "This ZIP uses an old kind of encryption Octa Pass can't read. Export again from Raivo.",
    ))?;
    let password = password.ok_or(ImportError::new(
        Error::ImportPasswordRequired,
        "This Raivo export is protected by a password.",
    ))?;
    let data = usize::try_from(start)
        .ok()
        .zip(usize::try_from(size).ok())
        .and_then(|(start, size)| bytes.get(start..start.checked_add(size)?))
        .ok_or_else(damaged)?;
    let plain = decrypt(data, strength, password)?;
    match method {
        STORED => Ok(plain),
        DEFLATED => {
            let mut json = Zeroizing::new(Vec::new());
            flate2::read::DeflateDecoder::new(plain.as_slice())
                .take(MAX_JSON_LEN)
                .read_to_end(&mut json)
                .map_err(|_| damaged())?;
            Ok(json)
        }
        _ => Err(damaged()),
    }
}

/// The AES strength (1 to 3) and the real compression method, from the WinZip AES extra field
/// of the local header at `header`.
fn aes_settings(bytes: &[u8], header: u64) -> Option<(u8, u16)> {
    let header = bytes.get(usize::try_from(header).ok()?..)?;
    let u16_at = |at: usize| Some(u16::from_le_bytes(header.get(at..at + 2)?.try_into().ok()?));
    if !header.starts_with(b"PK\x03\x04") || u16_at(8)? != WINZIP_AES {
        return None;
    }
    let (name_len, extra_len) = (usize::from(u16_at(26)?), usize::from(u16_at(28)?));
    let mut extra = header.get(30 + name_len..30 + name_len + extra_len)?;
    while extra.len() >= 4 {
        let id = u16::from_le_bytes([extra[0], extra[1]]);
        let len = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
        let field = extra.get(4..4 + len)?;
        // Vendor version (2), "AE", strength (1), compression method (2).
        if id == AES_EXTRA_FIELD && len == 7 && &field[2..4] == b"AE" {
            return Some((field[4], u16::from_le_bytes([field[5], field[6]])));
        }
        extra = &extra[4 + len..];
    }
    None
}

fn decrypt(data: &[u8], strength: u8, password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let key_len = match strength {
        1 => 16,
        2 => 24,
        3 => 32,
        _ => return Err(damaged()),
    };
    let salt_len = key_len / 2;
    if data.len() < salt_len + 2 + MAC_LEN {
        return Err(damaged());
    }
    let (salt, rest) = data.split_at(salt_len);
    let (check, rest) = rest.split_at(2);
    let (ciphertext, mac) = rest.split_at(rest.len() - MAC_LEN);
    let mut keys = Zeroizing::new(vec![0u8; 2 * key_len + 2]);
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, ITERATIONS, &mut keys);
    let (aes_key, rest) = keys.split_at(key_len);
    let (mac_key, expected_check) = rest.split_at(key_len);
    let wrong = ImportError::new(
        Error::WrongImportPassword,
        "Wrong password for this Raivo export.",
    );
    if check != expected_check {
        return Err(wrong);
    }
    let mut hmac = Hmac::<Sha1>::new_from_slice(mac_key).expect("any key length");
    hmac.update(ciphertext);
    // The two check bytes match one wrong password in 65,536: the MAC tells it apart from damage.
    hmac.verify_truncated_left(mac).map_err(|_| wrong)?;
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    let mut counter = [0u8; 16];
    counter[0] = 1;
    match key_len {
        16 => ctr::Ctr128LE::<aes::Aes128>::new(aes_key.into(), &counter.into())
            .apply_keystream(&mut plain),
        24 => ctr::Ctr128LE::<aes::Aes192>::new(aes_key.into(), &counter.into())
            .apply_keystream(&mut plain),
        _ => ctr::Ctr128LE::<aes::Aes256>::new(aes_key.into(), &counter.into())
            .apply_keystream(&mut plain),
    }
    Ok(plain)
}

fn not_raivo() -> ImportError {
    ImportError::new(Error::InvalidImportFile, "This is not a Raivo OTP export.")
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This Raivo OTP export is damaged.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_with_text_values() {
        let json = br#"[{"issuer":"Shop","account":"me","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA256","digits":"8","kind":"TOTP","timer":"60","pinned":"true","counter":"0","iconType":"","iconValue":""},{"issuer":"Nothing"}]"#;
        let result = parse(json, &ImportOptions::default()).unwrap();
        assert_eq!(result.items.len(), 1);
        let item = &result.items[0];
        assert_eq!(item.overview.favorite, Some(true));
        let crate::item::ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        let totp = login.totp.as_deref().unwrap();
        assert!(
            totp.contains("algorithm=SHA256&digits=8&period=60"),
            "{totp}"
        );
        assert_eq!(result.warnings, ["Entry 2 skipped: not a Raivo code."]);
    }

    #[test]
    fn short_or_strange_entry_data() {
        assert_eq!(
            decrypt(&[0; 20], 3, "pw").unwrap_err().code,
            Error::InvalidImportFile
        );
        assert_eq!(
            decrypt(&[0; 64], 4, "pw").unwrap_err().code,
            Error::InvalidImportFile
        );
        assert_eq!(
            decrypt(&[0; 64], 3, "pw").unwrap_err().code,
            Error::WrongImportPassword
        );
    }
}
