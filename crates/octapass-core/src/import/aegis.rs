//! Aegis Authenticator vault exports (`aegis-export-….json`, vault format version 1), plain or
//! encrypted with a password.
//!
//! ```text
//! key        = scrypt(password, slot.salt, slot.n, slot.r, slot.p, 32)       (password slots, type 1)
//! master key = AES-256-GCM(key, slot.key_params.nonce)  over slot.key ‖ slot.key_params.tag
//! db         = AES-256-GCM(master key, header.params.nonce)  over base64(db) ‖ header.params.tag
//! ```
//!
//! Groups become tags: the `groups` UUIDs of content version 3, or the single `group` name of
//! version 2. Each entry's `uuid` is kept, so importing the backup again updates its codes; the
//! vault has no dates. Icons aren't kept. Slots that old Aegis versions made with a password over 64 bytes,
//! and that were never unlocked since (`"repaired": false`), can't be opened.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use zeroize::Zeroizing;

use super::authenticator::{Codes, Entry, number, open_gcm, text};
use super::build::ItemMeta;
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;

/// scrypt limits. Aegis always uses N = 2^15, r = 8, p = 1 (32 MiB); these allow 8 times the
/// memory and 16 times the work, so a crafted file can't freeze the device.
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;
const MAX_SCRYPT_WORK: u64 = 1 << 22;
/// Exports have one password slot; a crafted file can't make the import try many.
const MAX_PASSWORD_SLOTS: usize = 4;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let contents = decode_text(bytes).map_err(|_| not_aegis())?;
    let file: Value = serde_json::from_str(&contents).map_err(|_| not_aegis())?;
    if !file.get("version").is_some_and(Value::is_u64) {
        return Err(not_aegis());
    }
    match file.get("db") {
        Some(db @ Value::Object(_)) => entries(db, options).ok_or_else(not_aegis),
        Some(Value::String(db)) => {
            let plain = decrypt(&file, db, options.password.as_ref().map(|p| p.as_str()))?;
            let db: Value = serde_json::from_slice(&plain).map_err(|_| damaged())?;
            entries(&db, options).ok_or_else(damaged)
        }
        _ => Err(not_aegis()),
    }
}

fn entries(db: &Value, options: &ImportOptions) -> Option<ImportResult> {
    let list = db.get("entries")?.as_array()?;
    let groups: HashMap<&str, String> = db
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| Some((group.get("uuid")?.as_str()?, text(group, "name")?)))
        .collect();
    let mut codes = Codes::new(&options.existing_logins);
    for (index, entry) in list.iter().enumerate() {
        let number_in_file = index + 1;
        let Some(info) = entry.get("info").filter(|info| info.is_object()) else {
            codes.skip(format!(
                "Entry {number_in_file} skipped: not an Aegis entry."
            ));
            continue;
        };
        let tags = match entry.get("groups").and_then(Value::as_array) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| groups.get(id.as_str()?).cloned())
                .collect(),
            None => text(entry, "group").into_iter().collect(),
        };
        codes.add(
            number_in_file,
            Entry {
                kind: text(entry, "type").unwrap_or_default(),
                secret: Zeroizing::new(text(info, "secret").unwrap_or_default()),
                algorithm: text(info, "algo"),
                digits: number(info, "digits"),
                period: number(info, "period"),
                counter: number(info, "counter"),
                pin: text(info, "pin").map(Zeroizing::new),
                title: None,
                issuer: text(entry, "issuer"),
                account: text(entry, "name"),
                notes: entry
                    .get("note")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                tags,
                favorite: entry.get("favorite").and_then(Value::as_bool) == Some(true),
                meta: ItemMeta {
                    source_id: text(entry, "uuid"),
                    ..ItemMeta::default()
                },
            },
        );
    }
    Some(codes.finish())
}

/// The vault contents (JSON bytes), opened with the first password slot the password fits.
fn decrypt(
    file: &Value,
    db: &str,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let header = file.get("header").ok_or_else(not_aegis)?;
    let slots: Vec<&Value> = header
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(damaged)?
        .iter()
        .filter(|slot| slot.get("type").and_then(Value::as_u64) == Some(1))
        .take(MAX_PASSWORD_SLOTS)
        .collect();
    if slots.is_empty() {
        return Err(ImportError::new(
            Error::UnsupportedImport,
            "This Aegis export can't be opened with a password. Export it again with a password, or without encryption.",
        ));
    }
    let password = password.ok_or(ImportError::new(
        Error::ImportPasswordRequired,
        "This Aegis export is protected by a password.",
    ))?;
    let params = header.get("params").ok_or_else(damaged)?;
    let nonce = hex(params, "nonce").ok_or_else(damaged)?;
    let mut sealed = STANDARD.decode(db.trim()).map_err(|_| damaged())?;
    sealed.extend(hex(params, "tag").ok_or_else(damaged)?);

    for slot in slots {
        let key = slot_key(slot, password)?;
        let Some(master_key) = open_slot(slot, &key) else {
            continue;
        };
        let master_key: Zeroizing<[u8; 32]> =
            Zeroizing::new(master_key.as_slice().try_into().map_err(|_| damaged())?);
        // The password fits, so a failure here means the file was changed.
        return open_gcm(&master_key, &nonce, &sealed).ok_or_else(damaged);
    }
    Err(ImportError::new(
        Error::WrongImportPassword,
        "Wrong password for this Aegis export.",
    ))
}

fn slot_key(slot: &Value, password: &str) -> Result<Zeroizing<[u8; 32]>, ImportError> {
    let n = number(slot, "n").ok_or_else(damaged)?;
    let r = number(slot, "r").ok_or_else(damaged)?;
    let p = number(slot, "p").ok_or_else(damaged)?;
    let salt = hex(slot, "salt").ok_or_else(damaged)?;
    let accepted = n.is_power_of_two()
        && n >= 2
        && (1..=64).contains(&r)
        && (1..=16).contains(&p)
        && n.saturating_mul(r).saturating_mul(128) <= MAX_SCRYPT_MEMORY
        && n.saturating_mul(r).saturating_mul(p) <= MAX_SCRYPT_WORK;
    let params = accepted
        .then(|| scrypt::Params::new(n.trailing_zeros() as u8, r as u32, p as u32, 32).ok())
        .flatten()
        .ok_or(ImportError::new(
            Error::UnsupportedImport,
            "This Aegis export uses key derivation settings Octa Pass doesn't accept.",
        ))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password.as_bytes(), &salt, &params, key.as_mut()).map_err(|_| damaged())?;
    Ok(key)
}

/// The master key from a slot, or `None` when the key doesn't open it.
fn open_slot(slot: &Value, key: &[u8; 32]) -> Option<Zeroizing<Vec<u8>>> {
    let params = slot.get("key_params")?;
    let mut sealed = hex(slot, "key")?;
    sealed.extend(hex(params, "tag")?);
    open_gcm(key, &hex(params, "nonce")?, &sealed)
}

fn hex(value: &Value, key: &str) -> Option<Vec<u8>> {
    let text = value.get(key)?.as_str()?.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn not_aegis() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This is not an Aegis vault export.",
    )
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted Aegis export is damaged.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex_strings() {
        let value = json!({ "a": "00ff10", "b": "0f0", "c": "zz", "d": "é1" });
        assert_eq!(hex(&value, "a"), Some(vec![0, 255, 16]));
        assert_eq!(hex(&value, "b"), None);
        assert_eq!(hex(&value, "c"), None);
        assert_eq!(hex(&value, "d"), None);
    }

    #[test]
    fn scrypt_settings_are_capped() {
        let slot = |n: u64, r: u64, p: u64| json!({ "n": n, "r": r, "p": p, "salt": "00" });
        for (n, r, p) in [
            (1 << 20, 8, 1),
            (1 << 15, 8, 32),
            (1 << 18, 8, 4),
            (3000, 8, 1),
            (0, 8, 1),
        ] {
            assert_eq!(
                slot_key(&slot(n, r, p), "pw").unwrap_err().code,
                Error::UnsupportedImport,
                "{n} {r} {p}"
            );
        }
        assert!(slot_key(&slot(1 << 4, 8, 1), "pw").is_ok());
    }

    #[test]
    fn groups_old_and_new() {
        let db = json!({
            "version": 3,
            "entries": [
                { "type": "totp", "name": "a", "issuer": "One", "groups": ["g1", "missing"],
                  "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30 } },
                { "type": "totp", "name": "b", "issuer": "Two", "group": "Old",
                  "info": { "secret": "JBSWY3DPEHPK3PXP" } },
                { "type": "totp", "name": "c" }
            ],
            "groups": [{ "uuid": "g1", "name": "Work" }]
        });
        let result = entries(&db, &ImportOptions::default()).unwrap();
        let tags: Vec<_> = result
            .items
            .iter()
            .map(|item| item.overview.tags.clone().unwrap())
            .collect();
        assert_eq!(tags, [vec!["Work".to_string()], vec!["Old".to_string()]]);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.warnings, ["Entry 3 skipped: not an Aegis entry."]);
    }
}
