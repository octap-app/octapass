//! Bitwarden (and Vaultwarden) JSON exports, unencrypted or password protected.
//!
//! Fields as `CipherExport` in Bitwarden's `libs/common/src/models/export/` writes them: `id`
//! (kept so importing the file again updates the items), `creationDate` and `revisionDate`
//! (RFC 3339), `folderId` and `collectionIds`, `favorite`, `fields`, `passwordHistory`, `notes`,
//! and the type's own object. A login's `passwordRevisionDate`, where an export has it, is when
//! the password changed. `reprompt` (ask for the master password again) has no equivalent.
//!
//! Folders and collections become tags. Per-URL match settings carry over as the overview's
//! `urlMatch`. Passkeys keep all their Bitwarden fields (including the key) so a later version can
//! use them; they can't sign in yet.

use serde_json::{Map, Value};

use super::bitwarden_crypto::{self, ProtectedExport};
use super::build::{
    Collector, ItemMeta, LoginFields, address, card, card_details, clean, custom_field, expiry,
    identity, identity_details, note, notes_with, rfc3339, timestamp, with_meta,
};
use super::{ImportError, ImportResult};
use crate::error::Error;
use crate::item::{CardDetails, CustomField, Passkey, PasswordHistoryEntry};
use crate::matching::MatchMode;

const LOGIN: u64 = 1;
const SECURE_NOTE: u64 = 2;
const CARD: u64 = 3;
const IDENTITY: u64 = 4;
const SSH_KEY: u64 = 5;

pub(super) fn parse(text: &str, password: Option<&str>) -> Result<ImportResult, ImportError> {
    let not_bitwarden = || {
        ImportError::new(
            Error::InvalidImportFile,
            "This is not a Bitwarden JSON export.",
        )
    };
    let data: Value = serde_json::from_str(text).map_err(|_| not_bitwarden())?;
    if data.get("encrypted").and_then(Value::as_bool) == Some(true) {
        if data.get("passwordProtected").and_then(Value::as_bool) != Some(true) {
            return Err(ImportError::new(
                Error::UnsupportedImport,
                "This Bitwarden export is locked to your Bitwarden account. Export again as \".json\", or as \".json (Encrypted)\" with \"Password protected\".",
            ));
        }
        let password = password.ok_or(ImportError::new(
            Error::ImportPasswordRequired,
            "This Bitwarden export is protected by a password.",
        ))?;
        let export: ProtectedExport = serde_json::from_value(data).map_err(|_| not_bitwarden())?;
        let inner = bitwarden_crypto::decrypt(&export, password)?;
        let data: Value = serde_json::from_str(&inner).map_err(|_| not_bitwarden())?;
        if data.get("encrypted").and_then(Value::as_bool) == Some(true) {
            return Err(not_bitwarden());
        }
        return parse_items(&data).ok_or_else(not_bitwarden);
    }
    parse_items(&data).ok_or_else(not_bitwarden)
}

fn parse_items(data: &Value) -> Option<ImportResult> {
    let items = data.get("items")?.as_array()?;
    let names = |key: &str| -> Map<String, Value> {
        data.get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| Some((text(entry, "id")?, Value::String(text(entry, "name")?))))
            .collect()
    };
    let folders = names("folders");
    let collections = names("collections");

    let mut out = Collector::default();
    let mut passkeys = 0;
    let mut other_types = 0;
    for (index, item) in items.iter().enumerate() {
        let Some(kind) = item.get("type").and_then(Value::as_u64) else {
            out.skip(Some(format!("Item {} skipped: not an item.", index + 1)));
            continue;
        };
        let mut tags: Vec<String> = text(item, "folderId")
            .and_then(|id| folders.get(&id)?.as_str().map(str::to_string))
            .into_iter()
            .collect();
        tags.extend(
            item.get("collectionIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|id| collections.get(id.as_str()?)?.as_str().map(str::to_string)),
        );
        let title = text(item, "name");
        let favorite = item.get("favorite").and_then(Value::as_bool) == Some(true);
        let fields = custom_fields(item);
        let notes = text(item, "notes");
        let meta = ItemMeta {
            created_at: timestamp(text(item, "creationDate").as_deref()),
            updated_at: timestamp(text(item, "revisionDate").as_deref()),
            last_used_at: None,
            source_id: text(item, "id"),
        };

        match kind {
            LOGIN => {
                let login = item.get("login").unwrap_or(&Value::Null);
                let item_passkeys = login_passkeys(login);
                passkeys += usize::from(!item_passkeys.is_empty());
                let (urls, url_match) = uris(login);
                let mut overview_extra = Map::new();
                if !url_match.is_empty() {
                    overview_extra.insert("urlMatch".into(), Value::Object(url_match));
                }
                let fields = LoginFields {
                    title,
                    urls,
                    username: text(login, "username"),
                    password: login
                        .get("password")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    totp: text(login, "totp"),
                    notes,
                    tags,
                    favorite,
                    custom_fields: fields,
                    password_history: password_history(item),
                    passkeys: item_passkeys,
                    overview_extra,
                    meta,
                    password_changed_at: timestamp(text(login, "passwordRevisionDate").as_deref()),
                    ..LoginFields::default()
                };
                out.add_login(fields, || {
                    format!(
                        "Item {} skipped: no URL, username, password or notes.",
                        index + 1
                    )
                });
            }
            SECURE_NOTE => out.add(with_meta(
                note(
                    title,
                    tags,
                    favorite,
                    notes_with(&field_lines(&fields), notes),
                ),
                meta,
            )),
            CARD => {
                let c = item.get("card").unwrap_or(&Value::Null);
                let month = text(c, "expMonth").and_then(|m| m.parse().ok());
                let year = text(c, "expYear").and_then(|y| y.parse().ok());
                let details = CardDetails {
                    cardholder: text(c, "cardholderName"),
                    number: text(c, "number"),
                    expiry: month.zip(year).and_then(|(m, y)| expiry(m, y)),
                    cvv: text(c, "code"),
                    brand: text(c, "brand"),
                    notes: notes_with(&field_lines(&fields), notes),
                    ..card_details()
                };
                out.add(with_meta(card(title, tags, favorite, details), meta));
            }
            IDENTITY => {
                let i = item.get("identity").unwrap_or(&Value::Null);
                let join = |keys: &[&str], separator: &str| {
                    clean(Some(
                        &keys
                            .iter()
                            .filter_map(|k| text(i, k))
                            .collect::<Vec<_>>()
                            .join(separator),
                    ))
                };
                let mut details = identity_details();
                details.first_name = join(&["firstName", "middleName"], " ");
                details.last_name = text(i, "lastName");
                details.email = text(i, "email");
                details.phone = text(i, "phone");
                details.address = address(
                    text(i, "address1"),
                    join(&["address2", "address3"], ", "),
                    text(i, "city"),
                    text(i, "state"),
                    text(i, "postalCode"),
                    text(i, "country"),
                );
                let mut lines: Vec<(String, String)> = [
                    ("Title", "title"),
                    ("Company", "company"),
                    ("Username", "username"),
                    ("SSN", "ssn"),
                    ("Passport number", "passportNumber"),
                    ("Licence number", "licenseNumber"),
                ]
                .iter()
                .filter_map(|(label, key)| Some((label.to_string(), text(i, key)?)))
                .collect();
                lines.extend(field_lines(&fields));
                details.notes = notes_with(&lines, notes);
                out.add(with_meta(identity(title, tags, favorite, details), meta));
            }
            SSH_KEY => {
                let key = item.get("sshKey").unwrap_or(&Value::Null);
                let mut lines: Vec<(String, String)> = [
                    ("Public key", "publicKey"),
                    ("Fingerprint", "keyFingerprint"),
                    ("Private key", "privateKey"),
                ]
                .iter()
                .filter_map(|(label, k)| Some((label.to_string(), text(key, k)?)))
                .collect();
                lines.extend(field_lines(&fields));
                out.add(with_meta(
                    note(title, tags, favorite, notes_with(&lines, notes)),
                    meta,
                ));
            }
            _ => {
                other_types += 1;
                let mut lines = field_lines(&fields);
                for (_, value) in item.as_object().into_iter().flatten() {
                    if let Some(object) = value.as_object() {
                        lines.extend(
                            object
                                .iter()
                                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))),
                        );
                    }
                }
                out.add(with_meta(
                    note(title, tags, favorite, notes_with(&lines, notes)),
                    meta,
                ));
            }
        }
    }
    if passkeys > 0 {
        out.warn(format!(
            "{passkeys} {} passkeys: they were kept, but can't be used to sign in yet.",
            if passkeys == 1 {
                "login has"
            } else {
                "logins have"
            }
        ));
    }
    if other_types > 0 {
        out.warn(format!(
            "{other_types} {} of a type Octa Pass doesn't have yet {} imported as secure notes.",
            if other_types == 1 { "item" } else { "items" },
            if other_types == 1 { "was" } else { "were" }
        ));
    }
    Some(out.finish())
}

/// A trimmed, non-empty string field (numbers are written as text).
fn text(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) => clean(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn custom_fields(item: &Value) -> Vec<CustomField> {
    const TEXT: u64 = 0;
    const HIDDEN: u64 = 1;
    const BOOLEAN: u64 = 2;
    item.get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| {
            let kind = field.get("type")?.as_u64()?;
            // Linked fields (type 3) point at another field and have no value of their own.
            if ![TEXT, HIDDEN, BOOLEAN].contains(&kind) {
                return None;
            }
            let label = text(field, "name").unwrap_or_default();
            let value = field
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (!label.is_empty() || !value.is_empty())
                .then(|| custom_field(&label, value, kind == HIDDEN))
        })
        .collect()
}

fn field_lines(fields: &[CustomField]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|f| {
            (
                if f.label.is_empty() {
                    "Field".into()
                } else {
                    f.label.clone()
                },
                f.value.clone(),
            )
        })
        .collect()
}

/// The URLs, and the match mode of each one that has its own.
fn uris(login: &Value) -> (Vec<String>, Map<String, Value>) {
    let mut urls = Vec::new();
    let mut modes = Map::new();
    for uri in login
        .get("uris")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(url) = text(uri, "uri") else {
            continue;
        };
        // 0 domain, 1 host, 2 starts with, 3 exact, 4 regex, 5 never. Exact has no Octa Pass
        // equivalent; "starts with" on the full URL is the closest. Bitwarden's "Base domain"
        // covers every subdomain, so it stays `baseDomain`; no match (Bitwarden's default) uses
        // Octa Pass's default (plan 05, History 2026-11-05).
        let mode = match uri.get("match").and_then(Value::as_u64) {
            Some(0) => Some(MatchMode::BaseDomain),
            Some(1) => Some(MatchMode::Host),
            Some(2 | 3) => Some(MatchMode::StartsWith),
            Some(4) => Some(MatchMode::Regex),
            Some(5) => Some(MatchMode::Never),
            _ => None,
        };
        if let Some(mode) = mode {
            modes.insert(
                url.clone(),
                serde_json::to_value(mode).expect("modes serialize"),
            );
        }
        urls.push(url);
    }
    (urls, modes)
}

fn password_history(item: &Value) -> Vec<PasswordHistoryEntry> {
    item.get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some(PasswordHistoryEntry {
                password: entry.get("password")?.as_str()?.to_string(),
                changed_at: text(entry, "lastUsedDate").unwrap_or_else(|| rfc3339(0)),
                extra: Map::new(),
            })
        })
        .collect()
}

fn login_passkeys(login: &Value) -> Vec<Passkey> {
    login
        .get("fido2Credentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|credential| {
            let mut extra = credential.as_object()?.clone();
            let rp_id = text(credential, "rpId")?;
            for key in ["rpId", "userName", "creationDate"] {
                extra.remove(key);
            }
            Some(Passkey {
                rp_id,
                user_name: text(credential, "userName").unwrap_or_default(),
                created_at: text(credential, "creationDate").unwrap_or_else(|| rfc3339(0)),
                extra,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::item::{ItemDetails, ItemType};

    fn import(value: Value) -> ImportResult {
        parse(&value.to_string(), None).unwrap()
    }

    #[test]
    fn logins_with_everything() {
        let result = import(json!({
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [{
                "type": 1, "name": "GitHub", "folderId": "f1", "favorite": true, "notes": "n",
                "fields": [
                    { "name": "PIN", "value": "1234", "type": 1 },
                    { "name": "Remember", "value": "true", "type": 2 },
                    { "name": "Linked", "value": null, "type": 3, "linkedId": 100 }
                ],
                "passwordHistory": [{ "lastUsedDate": "2025-01-01T00:00:00.000Z", "password": "old" }],
                "login": {
                    "uris": [{ "match": null, "uri": "https://github.com" }, { "match": 1, "uri": "https://gist.github.com" }],
                    "username": "octo", "password": "pw", "totp": "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP",
                    "fido2Credentials": [{ "credentialId": "abc", "keyValue": "pkcs8", "rpId": "github.com", "userName": "octo", "creationDate": "2025-02-01T00:00:00.000Z", "counter": "0" }]
                }
            }]
        }));
        let item = &result.items[0];
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Work"]);
        assert_eq!(
            item.overview.extra["urlMatch"],
            json!({ "https://gist.github.com": "host" })
        );
        let ItemDetails::Login(details) = &item.details else {
            panic!()
        };
        let fields = details.custom_fields.as_ref().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields[0].hidden && !fields[1].hidden);
        assert_eq!(
            details.password_history.as_ref().unwrap()[0].password,
            "old"
        );
        let passkey = &details.passkeys.as_ref().unwrap()[0];
        assert_eq!(passkey.rp_id, "github.com");
        assert_eq!(passkey.extra["keyValue"], "pkcs8");
        assert_eq!(
            result.warnings,
            ["1 login has passkeys: they were kept, but can't be used to sign in yet."]
        );
    }

    #[test]
    fn notes_cards_identities_and_ssh_keys() {
        let result = import(json!({
            "collections": [{ "id": "c1", "name": "Shared" }],
            "items": [
                { "type": 2, "name": "Note", "notes": "body", "secureNote": { "type": 0 }, "fields": [{ "name": "Extra", "value": "x", "type": 0 }], "collectionIds": ["c1"] },
                { "type": 3, "name": "Visa", "card": { "cardholderName": "Jane", "brand": "Visa", "number": "4111 1111 1111 1111", "expMonth": "3", "expYear": "2030", "code": "123" } },
                { "type": 4, "name": "Me", "identity": { "firstName": "Jane", "middleName": "Q", "lastName": "Doe", "address1": "1 St", "address2": "Apt 2", "city": "Amman", "email": "j@example.com", "ssn": "123" } },
                { "type": 5, "name": "Server key", "sshKey": { "privateKey": "-----BEGIN-----\nabc\n-----END-----", "publicKey": "ssh-ed25519 AAA", "keyFingerprint": "SHA256:x" } },
                { "type": 9, "name": "Future", "future": { "thing": "kept" } }
            ]
        }));
        let types: Vec<&ItemType> = result.items.iter().map(|i| &i.overview.item_type).collect();
        assert_eq!(
            types,
            [
                &ItemType::SecureNote,
                &ItemType::Card,
                &ItemType::Identity,
                &ItemType::SecureNote,
                &ItemType::SecureNote
            ]
        );
        assert_eq!(
            result.items[0].overview.tags.as_deref().unwrap(),
            ["Shared"]
        );
        let ItemDetails::SecureNote(n) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(n.notes, "Extra: x\nbody");
        let ItemDetails::Card(c) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(c.expiry.as_deref(), Some("03/30"));
        let ItemDetails::Identity(i) = &result.items[2].details else {
            panic!()
        };
        assert_eq!(i.first_name.as_deref(), Some("Jane Q"));
        assert_eq!(i.notes.as_deref(), Some("SSN: 123"));
        let ItemDetails::SecureNote(ssh) = &result.items[3].details else {
            panic!()
        };
        assert!(ssh.notes.contains("Private key:\n-----BEGIN-----\nabc"));
        let ItemDetails::SecureNote(future) = &result.items[4].details else {
            panic!()
        };
        assert_eq!(future.notes, "thing: kept");
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn rejects_other_files_and_account_locked_exports() {
        assert_eq!(
            parse("[]", None).unwrap_err().code,
            Error::InvalidImportFile
        );
        assert_eq!(
            parse("not json", None).unwrap_err().code,
            Error::InvalidImportFile
        );
        let locked =
            json!({ "encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.x|y|z", "items": [] });
        assert_eq!(
            parse(&locked.to_string(), None).unwrap_err().code,
            Error::UnsupportedImport
        );
        let protected = json!({ "encrypted": true, "passwordProtected": true, "salt": "x", "kdfType": 0, "kdfIterations": 600000, "encKeyValidation_DO_NOT_EDIT": "2.x|y|z", "data": "2.x|y|z" });
        assert_eq!(
            parse(&protected.to_string(), None).unwrap_err().code,
            Error::ImportPasswordRequired
        );
    }
}
