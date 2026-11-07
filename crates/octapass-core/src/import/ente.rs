//! Ente Auth exports: the plaintext file (`ente-auth-codes-plaintext-….txt`) and the encrypted
//! one (`ente-auth-codes-encrypted-….json`), as Ente Auth's `export_widget.dart` writes them and
//! its CLI's `ente auth decrypt` reads them (<https://ente.com/help/auth/migration/export>).
//!
//! The plaintext is one `otpauth://` link per line. Ente adds a `codeDisplay` parameter holding
//! JSON: `note` becomes the login's notes, `tags` its tags, `pinned` a favourite and `lastUsedAt`
//! (microseconds) its last-used date. Codes in Ente's trash (`trashed`) are skipped. Icons, tap
//! counts and positions aren't kept. Codes have no id in the export, so importing it again
//! recognises codes by their secret.
//!
//! ```text
//! {"version": 1, "kdfParams": {"memLimit", "opsLimit", "salt"}, "encryptedData", "encryptionNonce"}
//! key       = Argon2id(password, salt, t = opsLimit, m = memLimit / 1024 KiB, p = 1, 32 bytes)
//! plaintext = libsodium secretstream XChaCha20-Poly1305, header = encryptionNonce, one message
//! ```
//!
//! Every value is base64. `memLimit` is in bytes, as libsodium counts it; Ente starts at
//! libsodium's "sensitive" limits (1 GiB, 4 passes) and halves the memory while doubling the passes
//! on devices that can't.
//!
//! `encryptedData` is exactly one secretstream message: ending with the FINAL tag, or MESSAGE as
//! older Ente versions wrote it (accepted only because it is the whole, authenticated stream).
//! That is what Ente's CLI accepts too: `decryptChaCha20poly1305V2` in
//! `cli/internal/crypto/crypto_native.go` ("Ente Auth data may end with TagMessage instead of
//! TagFinal"). A PUSH or REKEY tag, a second message, and extra or missing bytes are refused.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20::ChaCha20;
use chacha20::cipher::consts::U10;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use serde_json::Value;
use zeroize::Zeroizing;

use super::authenticator::{Codes, Entry};
use super::build::{ItemMeta, clean, unix_time};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;

/// libsodium's "sensitive" memory limit, which Ente starts from.
const MAX_MEMORY: u64 = 1 << 30;
/// Ente trades memory for passes, so memory × passes stays at most what it starts with.
const MAX_WORK: u64 = MAX_MEMORY * 4;
/// libsodium's `crypto_pwhash_MEMLIMIT_MIN`.
const MIN_MEMORY: u64 = 8192;
/// secretstream's tags: a single-message stream ends with FINAL, but older Ente versions wrote
/// MESSAGE.
const TAG_MESSAGE: u8 = 0;
const TAG_FINAL: u8 = 3;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes).map_err(|_| invalid())?;
    if !text.trim_start().starts_with('{') {
        return links(&text, options).ok_or_else(invalid);
    }
    let export: Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    if export.get("encryptedData").is_none() {
        return Err(invalid());
    }
    if export.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(ImportError::new(
            Error::UnsupportedImport,
            "This Ente Auth export version isn't supported yet.",
        ));
    }
    let password = options.password.as_deref().ok_or(ImportError::new(
        Error::ImportPasswordRequired,
        "This Ente Auth export is protected by a password.",
    ))?;
    let plain = decrypt(&export, password)?;
    let plain = std::str::from_utf8(&plain).map_err(|_| damaged())?;
    links(plain, options).ok_or_else(damaged)
}

/// The key from the password and the file's settings, then the one secretstream message.
fn decrypt(export: &Value, password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let kdf = export.get("kdfParams").ok_or_else(damaged)?;
    let number = |key: &str| kdf.get(key).and_then(Value::as_u64).ok_or_else(damaged);
    let (memory, passes) = (number("memLimit")?, number("opsLimit")?);
    let accepted = (MIN_MEMORY..=MAX_MEMORY).contains(&memory)
        && passes >= 1
        && memory.saturating_mul(passes) <= MAX_WORK;
    let params = accepted
        .then(|| Params::new((memory / 1024) as u32, passes as u32, 1, Some(32)).ok())
        .flatten()
        .ok_or(ImportError::new(
            Error::UnsupportedImport,
            "This Ente Auth export uses key derivation settings Octa Pass doesn't accept.",
        ))?;
    let base64 = |value: Option<&Value>| {
        STANDARD
            .decode(value.and_then(Value::as_str).ok_or_else(damaged)?.trim())
            .map_err(|_| damaged())
    };
    let salt = base64(kdf.get("salt"))?;
    let header: [u8; 24] = base64(export.get("encryptionNonce"))?
        .try_into()
        .map_err(|_| damaged())?;
    let sealed = base64(export.get("encryptedData"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|_| damaged())?;
    match open_secretstream(&key, &header, &sealed) {
        Some((plain, TAG_FINAL | TAG_MESSAGE)) => Ok(plain),
        // PUSH or REKEY: the stream goes on, so this isn't Ente's single-message export.
        Some(_) => Err(damaged()),
        None => Err(ImportError::new(
            Error::WrongImportPassword,
            "Wrong password for this Ente Auth export.",
        )),
    }
}

/// libsodium's `crypto_secretstream_xchacha20poly1305_pull` for the first message of a stream:
/// the plaintext and its tag, or `None` when the MAC doesn't match (a wrong key, or damage).
///
/// ```text
/// k     = HChaCha20(key, header[0..16]);  nonce = counter 1 (LE, 4 bytes) ‖ header[16..24]
/// block = ChaCha20(k, nonce) from block 1 over [tag, 0 × 63];  sealed = block[0] ‖ c ‖ mac
/// mac   = Poly1305(ChaCha20 block 0)(block ‖ c ‖ |c| mod 16 zero bytes ‖ 0 (8 bytes LE) ‖ 64 + |c| (8 bytes LE))
/// m     = ChaCha20(k, nonce) from block 2 over c
/// ```
fn open_secretstream(
    key: &[u8; 32],
    header: &[u8; 24],
    sealed: &[u8],
) -> Option<(Zeroizing<Vec<u8>>, u8)> {
    let (&first, rest) = sealed.split_first()?;
    let (ciphertext, mac) = rest.split_at_checked(rest.len().checked_sub(16)?)?;
    let k = Zeroizing::new(chacha20::hchacha::<U10>(key.into(), header[..16].into()));
    let mut nonce = [0u8; 12];
    nonce[0] = 1;
    nonce[4..].copy_from_slice(&header[16..]);
    let mut stream = ChaCha20::new(&k, &nonce.into());
    let mut poly_key = Zeroizing::new([0u8; 64]);
    stream.apply_keystream(poly_key.as_mut());
    let mut block = [0u8; 64];
    block[0] = first;
    stream.apply_keystream(&mut block);
    let tag = block[0];
    block[0] = first;
    let mut authenticated = Vec::with_capacity(64 + ciphertext.len() + 32);
    authenticated.extend_from_slice(&block);
    authenticated.extend_from_slice(ciphertext);
    // libsodium pads with `(0x10 - 64 + mlen) & 0xf` zero bytes, which is `mlen % 16`, not up
    // to the next multiple of 16; Ente's CLI does the same.
    authenticated.resize(authenticated.len() + ciphertext.len() % 16, 0);
    authenticated.extend_from_slice(&0u64.to_le_bytes());
    authenticated.extend_from_slice(&(64 + ciphertext.len() as u64).to_le_bytes());
    let expected = Poly1305::new(poly_key[..32].into()).compute_unpadded(&authenticated);
    let differ = expected
        .iter()
        .zip(mac)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if differ != 0 {
        return None;
    }
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    stream.apply_keystream(&mut plain);
    Some((plain, tag))
}

/// The codes in the plaintext. `None` when no line is an `otpauth://` link.
fn links(text: &str, options: &ImportOptions) -> Option<ImportResult> {
    let mut codes = Codes::new(&options.existing_logins);
    let (mut found, mut trashed) = (false, 0);
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Ente stores each code as a JSON string; take one written that way too.
        let line = match serde_json::from_str::<String>(line) {
            Ok(unquoted) if line.starts_with('"') => Zeroizing::new(unquoted),
            _ => Zeroizing::new(line.to_owned()),
        };
        let Some(entry) = entry(&line) else {
            codes.skip(format!("Line {number} skipped: not an otpauth:// link."));
            continue;
        };
        found = true;
        match entry {
            Some(entry) => codes.add(number, entry),
            None => {
                trashed += 1;
                codes.skip_quietly();
            }
        }
    }
    if trashed > 0 {
        codes.warn(format!(
            "{trashed} {} in Ente's trash {} skipped.",
            if trashed == 1 { "code" } else { "codes" },
            if trashed == 1 { "was" } else { "were" }
        ));
    }
    found.then(|| codes.finish())
}

/// A line as an entry, `Some(None)` for a code in Ente's trash, or `None` when it isn't a link.
fn entry(line: &str) -> Option<Option<Entry>> {
    if !line.get(..10)?.eq_ignore_ascii_case("otpauth://") {
        return None;
    }
    // As Ente's own reader: a `#` in the account name isn't a URL fragment.
    let url = url::Url::parse(&line.replace('#', "%23")).ok()?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.into_owned())
    };
    let display: Value = param("codeDisplay")
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or(Value::Null);
    if display.get("trashed").and_then(Value::as_bool) == Some(true) {
        return Some(None);
    }
    let path = percent_decode(url.path().trim_start_matches('/'));
    // Ente's issuers once ran into the next parameter ("Issuerperiod=30").
    let issuer = param("issuer").map(|issuer| match issuer.find("period=") {
        Some(at) => issuer[..at].to_owned(),
        None => issuer,
    });
    let account = match (&issuer, path.split_once(':')) {
        (Some(issuer), Some((head, tail))) if head == issuer => tail.to_owned(),
        (Some(_), None) | (None, None) => path.clone(),
        (_, Some((_, tail))) => tail.to_owned(),
    };
    let issuer = issuer.or_else(|| path.split_once(':').map(|(head, _)| head.to_owned()));
    let number = |name: &str| param(name).and_then(|n| n.trim().parse().ok());
    Some(Some(Entry {
        kind: url.host_str().unwrap_or_default().to_owned(),
        secret: Zeroizing::new(param("secret").unwrap_or_default()),
        algorithm: param("algorithm").map(|a| {
            a.trim()
                .trim_start_matches("Algorithm.")
                .trim_start_matches("algorithm.")
                .to_owned()
        }),
        digits: number("digits"),
        period: number("period"),
        counter: number("counter"),
        pin: None,
        title: None,
        issuer,
        account: Some(account),
        notes: clean(display.get("note").and_then(Value::as_str)),
        tags: display
            .get("tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|tag| clean(tag.as_str()))
            .collect(),
        favorite: display.get("pinned").and_then(Value::as_bool) == Some(true),
        meta: ItemMeta {
            last_used_at: display
                .get("lastUsedAt")
                .and_then(Value::as_i64)
                .and_then(|micros| unix_time(micros / 1000)),
            ..ItemMeta::default()
        },
    }))
}

fn percent_decode(text: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", text.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn invalid() -> ImportError {
    ImportError::new(Error::InvalidImportFile, "This is not an Ente Auth export.")
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted Ente Auth export is damaged.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemDetails;

    /// libsodium's `crypto_secretstream_xchacha20poly1305_push` for one message, written from
    /// the same description as the reader; [`libsodium_vector`] and the fixtures come from
    /// libsodium itself.
    fn seal(key: &[u8; 32], header: &[u8; 24], message: &[u8], tag: u8) -> Vec<u8> {
        let k = chacha20::hchacha::<U10>(key.into(), header[..16].into());
        let mut nonce = [0u8; 12];
        nonce[0] = 1;
        nonce[4..].copy_from_slice(&header[16..]);
        let mut stream = ChaCha20::new(&k, &nonce.into());
        let mut poly_key = [0u8; 64];
        stream.apply_keystream(&mut poly_key);
        let mut block = [0u8; 64];
        block[0] = tag;
        stream.apply_keystream(&mut block);
        let mut c = message.to_vec();
        stream.apply_keystream(&mut c);
        let mut authenticated = block.to_vec();
        authenticated.extend(&c);
        authenticated.resize(authenticated.len() + c.len() % 16, 0);
        authenticated.extend(0u64.to_le_bytes());
        authenticated.extend((64 + c.len() as u64).to_le_bytes());
        let mac = Poly1305::new(poly_key[..32].into()).compute_unpadded(&authenticated);
        let mut out = vec![block[0]];
        out.extend(c);
        out.extend(mac);
        out
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `crypto_secretstream_xchacha20poly1305_push(state, b"hello", tag=TAG_FINAL)` after
    /// `init_push` with a key of 32 × 7, from the libsodium bundled with PyNaCl 1.6.2.
    #[test]
    fn libsodium_vector() {
        let header: [u8; 24] = hex("c771cf5e14a98fcd184764b6140588f02cd0da9676725205")
            .try_into()
            .unwrap();
        let sealed = hex("2dee9e8f30c20f00a3721df3d4717b947b01c06302c3");
        let (plain, tag) = open_secretstream(&[7u8; 32], &header, &sealed).unwrap();
        assert_eq!((plain.as_slice(), tag), (&b"hello"[..], TAG_FINAL));
        assert_eq!(seal(&[7u8; 32], &header, b"hello", TAG_FINAL), sealed);
    }

    #[test]
    fn secretstream_tags_and_tampering() {
        let (key, header) = ([7u8; 32], [9u8; 24]);
        for tag in [TAG_MESSAGE, TAG_FINAL] {
            let sealed = seal(&key, &header, b"hello", tag);
            let (plain, found) = open_secretstream(&key, &header, &sealed).unwrap();
            assert_eq!((plain.as_slice(), found), (&b"hello"[..], tag));
        }
        let sealed = seal(&key, &header, b"hello", TAG_FINAL);
        for at in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[at] ^= 1;
            assert!(open_secretstream(&key, &header, &changed).is_none(), "{at}");
        }
        assert!(open_secretstream(&[8u8; 32], &header, &sealed).is_none());
        assert!(open_secretstream(&key, &header, &sealed[..16]).is_none());
        assert!(open_secretstream(&key, &header, &[]).is_none());
    }

    #[test]
    fn kdf_settings_are_capped() {
        let file = |memory: u64, passes: u64| {
            serde_json::json!({
                "version": 1,
                "kdfParams": { "memLimit": memory, "opsLimit": passes, "salt": "AAAAAAAAAAAAAAAAAAAAAA==" },
                "encryptedData": "AA==", "encryptionNonce": "AA=="
            })
        };
        for (memory, passes) in [(2 << 30, 1), (1 << 30, 5), (1024, 1), (1 << 20, 0)] {
            assert_eq!(
                decrypt(&file(memory, passes), "pw").unwrap_err().code,
                Error::UnsupportedImport,
                "{memory} {passes}"
            );
        }
        // Accepted settings reach the nonce, which this file doesn't have.
        assert_eq!(
            decrypt(&file(1 << 20, 1), "pw").unwrap_err().code,
            Error::InvalidImportFile
        );
    }

    #[test]
    fn code_display_and_labels() {
        let text = "otpauth://totp/Shop:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Shop&codeDisplay=%7B%22pinned%22%3Atrue%2C%22trashed%22%3Afalse%2C%22lastUsedAt%22%3A1718000000000000%2C%22tags%22%3A%5B%22Work%22%5D%2C%22note%22%3A%22hi%22%7D\n\
                    otpauth://totp/Old?secret=JBSWY3DPEHPK3PXP&codeDisplay=%7B%22trashed%22%3Atrue%7D\n\
                    \"otpauth://totp/Bank:a#b?secret=JBSWY3DPEHPK3PXP&issuer=Bankperiod=30\"\n\
                    hello\n";
        let result = parse(text.as_bytes(), &ImportOptions::default()).unwrap();
        assert_eq!(result.items.len(), 2);
        let shop = &result.items[0].overview;
        assert_eq!(shop.title, "Shop");
        assert_eq!(shop.subtitle.as_deref(), Some("me@example.com"));
        assert_eq!(shop.favorite, Some(true));
        assert_eq!(shop.tags.as_deref().unwrap(), ["Work"]);
        assert_eq!(shop.last_used_at.as_deref(), Some("2024-06-10T06:13:20Z"));
        let ItemDetails::Login(login) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(login.notes.as_deref(), Some("hi"));
        let bank = &result.items[1].overview;
        assert_eq!(bank.title, "Bank");
        assert_eq!(bank.subtitle.as_deref(), Some("a#b"));
        assert_eq!(result.skipped, 2);
        assert_eq!(
            result.warnings,
            [
                "Line 4 skipped: not an otpauth:// link.",
                "1 code in Ente's trash was skipped."
            ]
        );
        assert_eq!(
            parse(b"just text", &ImportOptions::default())
                .unwrap_err()
                .code,
            Error::InvalidImportFile
        );
    }
}
