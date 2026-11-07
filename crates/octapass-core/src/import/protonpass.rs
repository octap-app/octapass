//! Proton Pass exports: the ZIP (`Proton Pass/data.json`, plus `files/` when attachments were
//! included), the same `data.json` on its own, the CSV, and the PGP-encrypted export.
//!
//! Logins, notes, cards and identities map to their Octa Pass types. Aliases become logins with
//! the alias address as the username (the alias itself stays with Proton). Wi-Fi networks become
//! logins and SSH keys secure notes; custom items become custom items. Every field is kept. Folders
//! become tags (`Parent/Child`), and so do vault names when the export has several vaults. Trashed
//! items are skipped.
//!
//! The encrypted export is the ZIP with `Proton Pass/data.pgp` instead of `data.json`: an
//! armored OpenPGP message encrypted with the export passphrase (`encryptPassExport` in
//! `packages/pass/lib/crypto/utils/export.ts`: OpenPGP.js, iterated and salted S2K with count
//! byte 255). A `.pgp` file holding the whole ZIP or `data.json` is read too. rPGP decrypts it
//! (SKESK v4 or v6, SEIPD v1 with its MDC or v2 with AEAD); the plaintext is only used once it
//! has been read to the end, which is when the MDC or the last AEAD chunk is checked.
//!
//! Each JSON item's `itemId` is kept so importing the file again updates it; `createTime`,
//! `modifyTime` and, where the export has it, `lastUseTime` (Unix seconds) become its dates
//! (`packages/pass/lib/export` in Proton's WebClients repository). The CSV has the dates but no id.

use std::collections::{BTreeSet, HashMap};
use std::io::{Cursor, Read};

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::build::{
    Collector, ItemMeta, LoginFields, TypedItem, address, card, card_details, civil_date, clean,
    clean_password, custom_field, expiry, identity, identity_details, iso_date, looks_secret, note,
    notes_with, rfc3339, unix_time, with_meta,
};
use super::csv_table::CsvTable;
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;
use crate::item::{CardDetails, CustomField, Passkey};
use crate::matching::MatchMode;

/// `data.json` is a few MB even for large vaults; this stops a ZIP bomb.
const MAX_DATA_LEN: u64 = 256 << 20;
const TRASHED: u64 = 2;

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let password = options.password.as_ref().map(|p| p.as_str());
    if bytes.starts_with(b"PK\x03\x04") {
        return parse_json(&read_zip(bytes, password)?);
    }
    if is_pgp(bytes) {
        let plain = decrypt(bytes, password)?;
        if plain.starts_with(b"PK\x03\x04") {
            return parse_json(&read_zip(&plain, password)?);
        }
        return parse_json(&decode_text(&plain).map_err(|_| invalid())?);
    }
    let text = decode_text(bytes)?;
    if text.trim_start().starts_with('{') {
        return parse_json(&text);
    }
    parse_csv(&text)
}

/// An armored OpenPGP message, or a binary one that starts with a password-encrypted session
/// key (tag 3, new or old packet format).
fn is_pgp(bytes: &[u8]) -> bool {
    bytes
        .trim_ascii_start()
        .starts_with(b"-----BEGIN PGP MESSAGE-----")
        || matches!(bytes.first(), Some(0xc3 | 0x8c..=0x8f))
}

/// The plaintext of a passphrase-encrypted OpenPGP message, at most [`MAX_DATA_LEN`] bytes.
#[cfg(feature = "pgp")]
fn decrypt(bytes: &[u8], password: Option<&str>) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    use pgp::composed::Message;
    let password = password.ok_or_else(password_required)?;
    let message = if bytes.trim_ascii_start().starts_with(b"-----BEGIN") {
        Message::from_armor(bytes.trim_ascii_start()).map(|(message, _)| message)
    } else {
        Message::from_bytes(bytes)
    }
    .map_err(|_| damaged())?;
    if !message.is_encrypted() {
        return Err(invalid());
    }
    let mut message = message
        .decrypt_with_password(&password.into())
        .map_err(|_| wrong_password())?;
    while message.is_compressed() {
        message = message.decompress().map_err(|_| damaged())?;
    }
    let mut plain = Zeroizing::new(Vec::new());
    // Reading to the end checks the MDC (or the last AEAD tag): until then nothing is trusted.
    (&mut message)
        .take(MAX_DATA_LEN + 1)
        .read_to_end(&mut plain)
        .map_err(|_| damaged())?;
    if plain.len() as u64 > MAX_DATA_LEN {
        return Err(damaged());
    }
    Ok(plain)
}

/// Without OpenPGP (the web vault's size-optimised build), which loads the full build for these.
#[cfg(not(feature = "pgp"))]
fn decrypt(_bytes: &[u8], password: Option<&str>) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    password.ok_or_else(password_required)?;
    Err(ImportError::new(
        Error::PgpUnavailable,
        "Open this file in the Octa Pass app, the browser extension or the CLI.",
    ))
}

fn password_required() -> ImportError {
    ImportError::new(
        Error::ImportPasswordRequired,
        "This Proton Pass export is encrypted with a passphrase.",
    )
}

#[cfg(feature = "pgp")]
fn wrong_password() -> ImportError {
    ImportError::new(
        Error::WrongImportPassword,
        "Wrong passphrase for this Proton Pass export.",
    )
}

#[cfg_attr(not(feature = "pgp"), allow(dead_code))]
fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This encrypted Proton Pass export is damaged.",
    )
}

fn invalid() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This is not a Proton Pass export (ZIP, JSON or CSV).",
    )
}

fn encrypted() -> ImportError {
    ImportError::new(
        Error::UnsupportedImport,
        "This Proton Pass export is locked to your Proton account. Export again from Proton Pass as a ZIP, with or without a passphrase, or as CSV.",
    )
}

/// `data.json` from the ZIP, or `data.pgp` (the encrypted export) decrypted.
fn read_zip(bytes: &[u8], password: Option<&str>) -> Result<Zeroizing<String>, ImportError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid())?;
    let find = |archive: &zip::ZipArchive<Cursor<&[u8]>>, file: &str| {
        archive
            .file_names()
            .filter_map(Result::ok)
            .find(|name| name == file || name.ends_with(&format!("/{file}")))
            .map(|name| name.into_owned())
    };
    let read = |archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| {
        let file = archive.by_name(name).map_err(|_| invalid())?;
        let mut data = Zeroizing::new(Vec::new());
        file.take(MAX_DATA_LEN)
            .read_to_end(&mut data)
            .map_err(|_| invalid())?;
        Ok::<_, ImportError>(data)
    };
    if let Some(name) = find(&archive, "data.json") {
        return decode_text(&read(&mut archive, &name)?);
    }
    let name = find(&archive, "data.pgp").ok_or_else(invalid)?;
    let plain = decrypt(&read(&mut archive, &name)?, password)?;
    decode_text(&plain).map_err(|_| damaged())
}

#[derive(Default)]
struct Stats {
    trashed: usize,
    aliases: usize,
    passkeys: usize,
    attachments: usize,
    other_types: usize,
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

impl Stats {
    fn report(&self, out: &mut Collector) {
        if self.trashed > 0 {
            out.warn(format!(
                "{} {} in the trash {} skipped.",
                self.trashed,
                plural(self.trashed, "item", "items"),
                plural(self.trashed, "was", "were")
            ));
        }
        if self.aliases > 0 {
            out.warn(format!(
                "{} {} with the alias address as the username. Aliases themselves stay in your Proton account.",
                self.aliases,
                plural(
                    self.aliases,
                    "alias was imported as a login",
                    "aliases were imported as logins"
                )
            ));
        }
        if self.passkeys > 0 {
            out.warn(format!(
                "{} {} passkeys: they were kept, but can't be used to sign in yet.",
                self.passkeys,
                plural(self.passkeys, "login has", "logins have")
            ));
        }
        if self.attachments > 0 {
            out.warn(format!(
                "Attachments can't be imported yet: {} {} imported without {}.",
                self.attachments,
                plural(self.attachments, "item was", "items were"),
                plural(self.attachments, "its files", "their files")
            ));
        }
        if self.other_types > 0 {
            out.warn(format!(
                "{} {} of a type Octa Pass doesn't have yet (Wi-Fi, SSH key) {} imported as logins or secure notes.",
                self.other_types,
                plural(self.other_types, "item", "items"),
                plural(self.other_types, "was", "were")
            ));
        }
    }
}

/// What every item type has.
struct Common {
    title: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    meta: ItemMeta,
    /// Names the item in a skip warning: `Item 3` or `Row 4`.
    place: String,
}

/// An extra field or a field of a custom section, with its value read as text.
struct Extra {
    label: String,
    value: String,
    hidden: bool,
    totp: bool,
}

fn parse_json(json_text: &str) -> Result<ImportResult, ImportError> {
    let data: Value = serde_json::from_str(json_text).map_err(|_| invalid())?;
    if data.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(encrypted());
    }
    let vaults = data
        .get("vaults")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let tag_vaults = vaults.len() > 1;
    let mut out = Collector::default();
    let mut stats = Stats::default();
    let mut number = 0;
    for vault in vaults.values() {
        let vault_name = text(vault, "name").filter(|_| tag_vaults);
        let folders = folder_paths(vault);
        for item in vault
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            number += 1;
            let mut tags: Vec<String> = vault_name.iter().cloned().collect();
            tags.extend(text(item, "folderId").and_then(|id| folders.get(&id).cloned()));
            add_json_item(item, number, tags, &mut out, &mut stats);
        }
    }
    stats.report(&mut out);
    Ok(out.finish())
}

/// Folder ids → `Parent/Child` paths. Folders whose parent is missing (or that form a loop)
/// stop at the last folder found.
fn folder_paths(vault: &Value) -> HashMap<String, String> {
    let folders: HashMap<String, (Option<String>, String)> = vault
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| {
            Some((
                text(f, "folderId")?,
                (text(f, "parentFolderId"), text(f, "name")?),
            ))
        })
        .collect();
    folders
        .keys()
        .map(|id| {
            let mut names = Vec::new();
            let mut current = Some(id);
            while let Some((parent, name)) = current.and_then(|id| folders.get(id)) {
                if names.len() > folders.len() {
                    break;
                }
                names.push(name.as_str());
                current = parent.as_ref();
            }
            names.reverse();
            (id.clone(), names.join("/"))
        })
        .collect()
}

fn add_json_item(
    item: &Value,
    number: usize,
    tags: Vec<String>,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let data = item.get("data").unwrap_or(&Value::Null);
    let Some(kind) = data.get("type").and_then(Value::as_str) else {
        return out.skip(Some(format!("Item {number} skipped: it has no type.")));
    };
    if item.get("state").and_then(Value::as_u64) == Some(TRASHED) {
        stats.trashed += 1;
        return out.skip(None);
    }
    if item
        .get("files")
        .and_then(Value::as_array)
        .is_some_and(|files| !files.is_empty())
    {
        stats.attachments += 1;
    }
    let metadata = data.get("metadata").unwrap_or(&Value::Null);
    let common = Common {
        title: text(metadata, "name"),
        notes: text(metadata, "note"),
        tags,
        favorite: item.get("pinned").and_then(Value::as_bool) == Some(true),
        meta: ItemMeta {
            created_at: seconds(item.get("createTime")),
            updated_at: seconds(item.get("modifyTime")),
            last_used_at: seconds(item.get("lastUseTime")),
            source_id: text(item, "itemId"),
        },
        place: format!("Item {number}"),
    };
    let mut extras = extra_fields(data.get("extraFields"));
    // Android apps the login is allowed to fill in.
    extras.extend(
        data.pointer("/platformSpecific/android/allowedApps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|app| {
                Some(Extra {
                    label: "Android app".into(),
                    value: text(app, "packageName")?,
                    hidden: false,
                    totp: false,
                })
            }),
    );
    let content = data.get("content").unwrap_or(&Value::Null);
    let alias_email = text(item, "aliasEmail");
    add_item(kind, content, extras, alias_email, common, out, stats);
}

fn add_item(
    kind: &str,
    content: &Value,
    extras: Vec<Extra>,
    alias_email: Option<String>,
    common: Common,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let place = common.place.clone();
    let skipped = move || format!("{place} skipped: it has no fields.");
    match kind {
        "login" => {
            let fields = login_fields(content, extras, common);
            stats.passkeys += usize::from(!fields.passkeys.is_empty());
            out.add_login(fields, skipped);
        }
        "alias" => {
            stats.aliases += 1;
            let fields = LoginFields {
                title: common.title,
                username: alias_email,
                notes: common.notes,
                tags: common.tags,
                favorite: common.favorite,
                custom_fields: custom_fields(extras),
                meta: common.meta,
                ..LoginFields::default()
            };
            out.add_login(fields, skipped);
        }
        "note" => out.add(with_meta(
            note(
                common.title,
                common.tags,
                common.favorite,
                notes_with(&lines(&extras), common.notes),
            ),
            common.meta,
        )),
        "creditCard" => add_card(content, &extras, common, out),
        "identity" => add_identity(content, extras, common, out),
        "wifi" => {
            stats.other_types += 1;
            let mut custom = Vec::new();
            if let Some(ssid) = text(content, "ssid") {
                custom.push(custom_field("SSID", &ssid, false));
            }
            if let Some(security) = content
                .get("security")
                .and_then(Value::as_u64)
                .and_then(wifi_security)
            {
                custom.push(custom_field("Security", security, false));
            }
            custom.extend(custom_fields(extras));
            custom.extend(custom_fields(section_fields(content)));
            let fields = LoginFields {
                title: common.title,
                password: clean_password(content.get("password").and_then(Value::as_str)),
                notes: common.notes,
                tags: common.tags,
                favorite: common.favorite,
                custom_fields: custom,
                meta: common.meta,
                ..LoginFields::default()
            };
            out.add_login(fields, skipped);
        }
        "sshKey" => {
            stats.other_types += 1;
            let mut lines: Vec<(String, String)> = [
                ("Public key", "publicKey"),
                ("Fingerprint", "fingerprint"),
                ("Private key", "privateKey"),
            ]
            .iter()
            .filter_map(|(label, key)| Some((label.to_string(), text(content, key)?)))
            .collect();
            lines.extend(self::lines(&section_fields(content)));
            lines.extend(self::lines(&extras));
            out.add(with_meta(
                note(
                    common.title,
                    common.tags,
                    common.favorite,
                    notes_with(&lines, common.notes),
                ),
                common.meta,
            ));
        }
        "custom" => {
            let mut item = TypedItem::custom_item(None);
            for extra in section_fields(content).into_iter().chain(extras) {
                let kind = match (extra.totp, extra.hidden) {
                    (true, _) => "totp",
                    (_, true) => "hidden",
                    _ => "text",
                };
                item.field(&extra.label, &extra.value, kind);
            }
            out.add(with_meta(
                item.build(common.title, common.tags, common.favorite, common.notes),
                common.meta,
            ));
        }
        _ => {
            // Types from newer Proton Pass versions: every text value as a line.
            stats.other_types += 1;
            let mut lines: Vec<(String, String)> = content
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(key, value)| Some((key.clone(), scalar(value)?)))
                .collect();
            lines.extend(self::lines(&section_fields(content)));
            lines.extend(self::lines(&extras));
            out.add(with_meta(
                note(
                    common.title,
                    common.tags,
                    common.favorite,
                    notes_with(&lines, common.notes),
                ),
                common.meta,
            ));
        }
    }
}

fn login_fields(content: &Value, extras: Vec<Extra>, common: Common) -> LoginFields {
    // Before Proton Pass 1.18 the email was in `username`; since then a login can have both.
    let username = text(content, "itemUsername").or_else(|| text(content, "username"));
    let email = text(content, "itemEmail");
    let (username, email) = match username {
        Some(username) => (Some(username), email),
        None => (email, None),
    };
    let mut custom: Vec<CustomField> = email
        .map(|email| custom_field("Email", &email, false))
        .into_iter()
        .collect();
    let mut totp = text(content, "totpUri");
    let mut rest = Vec::new();
    for extra in extras {
        if extra.totp && totp.is_none() {
            totp = Some(extra.value);
        } else {
            rest.push(extra);
        }
    }
    custom.extend(custom_fields(rest));
    let (urls, url_match) = login_urls(content);
    let mut overview_extra = Map::new();
    if !url_match.is_empty() {
        overview_extra.insert("urlMatch".into(), Value::Object(url_match));
    }
    LoginFields {
        title: common.title,
        urls,
        username,
        password: clean_password(content.get("password").and_then(Value::as_str)),
        totp,
        notes: common.notes,
        tags: common.tags,
        favorite: common.favorite,
        custom_fields: custom,
        passkeys: passkeys(content),
        overview_extra,
        meta: common.meta,
        ..LoginFields::default()
    }
}

/// The URLs and their match modes: `autofillUrls` (with modes) when present, else `urls`.
fn login_urls(content: &Value) -> (Vec<String>, Map<String, Value>) {
    let mut urls = Vec::new();
    let mut modes = Map::new();
    let autofill = content
        .get("autofillUrls")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty());
    if let Some(autofill) = autofill {
        for entry in autofill {
            let Some(url) = text(entry, "url") else {
                continue;
            };
            // 0 default, 1 exact, 2 never, 3 starts with, 4 pattern, 5 regex, 6 exact path.
            // Exact matches have no Octa Pass equivalent; "starts with" is the closest. Patterns
            // keep the default.
            let mode = match entry.get("mode").and_then(Value::as_u64) {
                Some(1 | 3 | 6) => Some(MatchMode::StartsWith),
                Some(2) => Some(MatchMode::Never),
                Some(5) => Some(MatchMode::Regex),
                _ => None,
            };
            if let Some(mode) = mode {
                modes.insert(
                    url.clone(),
                    serde_json::to_value(mode).expect("modes serialize"),
                );
            }
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    } else {
        for url in content
            .get("urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|u| clean(u.as_str()))
        {
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    (urls, modes)
}

/// Passkeys keep every Proton field (including the key) so a later version can use them.
fn passkeys(content: &Value) -> Vec<Passkey> {
    content
        .get("passkeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|passkey| {
            let mut extra = passkey.as_object()?.clone();
            let rp_id = text(passkey, "rpId").or_else(|| text(passkey, "domain"))?;
            let user_name = text(passkey, "userName")
                .or_else(|| text(passkey, "userDisplayName"))
                .unwrap_or_default();
            let created_at = rfc3339(
                passkey
                    .get("createTime")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
            );
            for key in ["rpId", "userName", "createTime"] {
                extra.remove(key);
            }
            Some(Passkey {
                rp_id,
                user_name,
                created_at,
                extra,
            })
        })
        .collect()
}

fn add_card(content: &Value, extras: &[Extra], common: Common, out: &mut Collector) {
    let raw_expiry = text(content, "expirationDate");
    let expiry = raw_expiry.as_deref().and_then(card_expiry);
    let mut lines = Vec::new();
    if expiry.is_none()
        && let Some(raw) = raw_expiry
    {
        lines.push(("Expiry date".to_string(), raw));
    }
    lines.extend(self::lines(extras));
    let details = CardDetails {
        cardholder: text(content, "cardholderName"),
        number: text(content, "number"),
        cvv: text(content, "verificationNumber"),
        pin: text(content, "pin"),
        brand: content
            .get("cardType")
            .and_then(Value::as_u64)
            .and_then(card_brand)
            .map(str::to_string),
        expiry,
        notes: notes_with(&lines, common.notes),
        ..card_details()
    };
    out.add(with_meta(
        card(common.title, common.tags, common.favorite, details),
        common.meta,
    ));
}

/// Identity fields Octa Pass has no place for, as note lines.
const IDENTITY_LINES: [(&str, &str); 20] = [
    ("gender", "Gender"),
    ("organization", "Organization"),
    ("floor", "Floor"),
    ("county", "County"),
    ("socialSecurityNumber", "Social security number"),
    ("passportNumber", "Passport number"),
    ("licenseNumber", "Licence number"),
    ("website", "Website"),
    ("xHandle", "X handle"),
    ("secondPhoneNumber", "Second phone number"),
    ("linkedin", "LinkedIn"),
    ("reddit", "Reddit"),
    ("facebook", "Facebook"),
    ("yahoo", "Yahoo"),
    ("instagram", "Instagram"),
    ("company", "Company"),
    ("jobTitle", "Job title"),
    ("personalWebsite", "Personal website"),
    ("workPhoneNumber", "Work phone number"),
    ("workEmail", "Work email"),
];

const IDENTITY_MAPPED: [&str; 12] = [
    "fullName",
    "firstName",
    "middleName",
    "lastName",
    "email",
    "phoneNumber",
    "birthdate",
    "streetAddress",
    "zipOrPostalCode",
    "city",
    "stateOrProvince",
    "countryOrRegion",
];

const IDENTITY_EXTRAS: [&str; 4] = [
    "extraPersonalDetails",
    "extraAddressDetails",
    "extraContactDetails",
    "extraWorkDetails",
];

fn add_identity(content: &Value, extras: Vec<Extra>, common: Common, out: &mut Collector) {
    let mut details = identity_details();
    let mut lines = Vec::new();
    let first = [text(content, "firstName"), text(content, "middleName")];
    details.first_name = clean(Some(
        &first.into_iter().flatten().collect::<Vec<_>>().join(" "),
    ));
    details.last_name = text(content, "lastName");
    if let Some(full) = text(content, "fullName") {
        if details.first_name.is_none() && details.last_name.is_none() {
            let (first, last) = match full.rsplit_once(' ') {
                Some((first, last)) => (clean(Some(first)), clean(Some(last))),
                None => (Some(full), None),
            };
            details.first_name = first;
            details.last_name = last;
        } else {
            let composed = [details.first_name.clone(), details.last_name.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            if composed != full {
                lines.push(("Full name".to_string(), full));
            }
        }
    }
    details.email = text(content, "email");
    details.phone = text(content, "phoneNumber");
    if let Some(birthdate) = text(content, "birthdate") {
        match iso(&birthdate) {
            Some(date) => details.birth_date = Some(date),
            None => lines.push(("Birth date".to_string(), birthdate)),
        }
    }
    details.address = address(
        text(content, "streetAddress"),
        None,
        text(content, "city"),
        text(content, "stateOrProvince"),
        text(content, "zipOrPostalCode"),
        text(content, "countryOrRegion"),
    );
    lines.extend(
        IDENTITY_LINES
            .iter()
            .filter_map(|(key, label)| Some((label.to_string(), text(content, key)?))),
    );
    // Fields from newer Proton Pass versions.
    lines.extend(
        content
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| {
                let key = key.as_str();
                !IDENTITY_MAPPED.contains(&key)
                    && !IDENTITY_EXTRAS.contains(&key)
                    && key != "extraSections"
                    && !IDENTITY_LINES.iter().any(|(k, _)| *k == key)
            })
            .filter_map(|(key, value)| Some((key.clone(), scalar(value)?))),
    );
    for key in IDENTITY_EXTRAS {
        lines.extend(self::lines(&extra_fields(content.get(key))));
    }
    lines.extend(self::lines(&section_fields_of(
        content.get("extraSections"),
    )));
    lines.extend(self::lines(&extras));
    details.notes = notes_with(&lines, common.notes);
    out.add(with_meta(
        identity(common.title, common.tags, common.favorite, details),
        common.meta,
    ));
}

fn extra_fields(fields: Option<&Value>) -> Vec<Extra> {
    fields
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| {
            let kind = field.get("type").and_then(Value::as_str).unwrap_or("text");
            let data = field.get("data").unwrap_or(&Value::Null);
            let value = match kind {
                "totp" => text(data, "totpUri")?,
                "timestamp" => data.get("timestamp").and_then(timestamp)?,
                _ => text(data, "content")?,
            };
            Some(Extra {
                label: text(field, "fieldName").unwrap_or_else(|| "Field".into()),
                value,
                hidden: kind == "hidden" || kind == "totp",
                totp: kind == "totp",
            })
        })
        .collect()
}

/// The fields of a custom item's (or Wi-Fi's, SSH key's) `sections`.
fn section_fields(content: &Value) -> Vec<Extra> {
    section_fields_of(content.get("sections"))
}

fn section_fields_of(sections: Option<&Value>) -> Vec<Extra> {
    sections
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|section| extra_fields(section.get("sectionFields")))
        .collect()
}

/// Unix seconds, as Proton Pass writes item times.
fn seconds(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Number(n) => unix_time(n.as_i64()?),
        Value::String(s) => super::build::timestamp(Some(s)),
        _ => None,
    }
}

/// A timestamp field: RFC 3339 text, Unix seconds, or `{ "seconds": … }`, as a date.
fn timestamp(value: &Value) -> Option<String> {
    let seconds = match value {
        Value::String(text) => return clean(Some(text)),
        Value::Number(n) => n.as_i64()?,
        Value::Object(object) => match object.get("seconds")? {
            Value::Number(n) => n.as_i64()?,
            Value::String(s) => s.parse().ok()?,
            _ => return None,
        },
        _ => return None,
    };
    let (year, month, day) = civil_date(seconds);
    iso_date(year, month, day)
}

fn custom_fields(extras: Vec<Extra>) -> Vec<CustomField> {
    extras
        .into_iter()
        .map(|extra| custom_field(&extra.label, &extra.value, extra.hidden))
        .collect()
}

fn lines(extras: &[Extra]) -> Vec<(String, String)> {
    extras
        .iter()
        .map(|extra| (extra.label.clone(), extra.value.clone()))
        .collect()
}

/// `2024-02` (or the older `022024`, or `02/24`) → `02/24`.
fn card_expiry(date: &str) -> Option<String> {
    let date = date.trim();
    let (month, year) = if let Some((year, month)) = date.split_once('-') {
        (month, year)
    } else if let Some((month, year)) = date.split_once('/') {
        (month, year)
    } else if date.len() == 6 && date.is_ascii() {
        date.split_at(2)
    } else {
        return None;
    };
    expiry(month.trim().parse().ok()?, year.trim().parse().ok()?)
}

fn card_brand(kind: u64) -> Option<&'static str> {
    match kind {
        2 => Some("Visa"),
        3 => Some("Mastercard"),
        4 => Some("American Express"),
        _ => None,
    }
}

fn wifi_security(kind: u64) -> Option<&'static str> {
    match kind {
        1 => Some("WPA"),
        2 => Some("WPA2"),
        3 => Some("WPA3"),
        4 => Some("WEP"),
        _ => None,
    }
}

/// `YYYY-MM-DD` when the text is a real date in that form.
fn iso(text: &str) -> Option<String> {
    let mut parts = text.trim().splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.parse().ok()?;
    iso_date(year, month, day)
}

/// A trimmed, non-empty string field (numbers are written as text).
fn text(value: &Value, key: &str) -> Option<String> {
    scalar(value.get(key)?)
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => clean(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The CSV export: `type,name,url,email,username,password,note,totp,createTime,modifyTime,vault`
/// (older versions have no `email` or `vault`; newer ones add `autofillUrls`). Cards and
/// identities keep their fields as JSON in `note`.
fn parse_csv(csv: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(csv, b',').map_err(|_| invalid())?;
    if !["name", "url", "username", "password", "note", "totp"]
        .iter()
        .all(|column| table.has(&[column]))
    {
        return Err(ImportError::new(
            Error::InvalidImportFile,
            "This is not a Proton Pass export: it needs the columns name, url, username, password, note and totp.",
        ));
    }
    // Before the email column, `username` held the email.
    let has_email = table.has(&["email"]);
    let kind = table.take(&["type"]);
    let name = table.take(&["name"]);
    let url = table.take(&["url"]);
    let autofill = table.take(&["autofillUrls"]);
    let email = table.take(&["email"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let note_column = table.take(&["note"]);
    let totp = table.take(&["totp"]);
    let vault = table.take(&["vault"]);
    let created = table.take(&["createTime"]);
    let modified = table.take(&["modifyTime"]);

    let vaults: BTreeSet<String> = table
        .rows
        .iter()
        .filter_map(|row| clean(row.get(vault)))
        .collect();
    let tag_vaults = vaults.len() > 1;
    let mut out = Collector::default();
    let mut stats = Stats::default();
    for row in &table.rows {
        let extras: Vec<Extra> = table
            .extras(row)
            .into_iter()
            .map(|(label, value)| Extra {
                hidden: looks_secret(&label),
                label,
                value,
                totp: false,
            })
            .collect();
        let mut common = Common {
            title: clean(row.get(name)),
            notes: clean(row.get(note_column)),
            tags: clean(row.get(vault))
                .filter(|_| tag_vaults)
                .into_iter()
                .collect(),
            favorite: false,
            meta: ItemMeta {
                created_at: super::build::timestamp(row.get(created)),
                updated_at: super::build::timestamp(row.get(modified)),
                ..ItemMeta::default()
            },
            place: format!("Row {}", row.line),
        };
        let kind = clean(row.get(kind)).unwrap_or_else(|| "login".into());
        let cell = |column| row.get(column).unwrap_or_default();
        match kind.as_str() {
            "creditCard" | "identity" => {
                let parsed = common
                    .notes
                    .as_deref()
                    .and_then(|n| serde_json::from_str::<Value>(n).ok())
                    .filter(Value::is_object);
                match parsed {
                    Some(content) => {
                        common.notes = text(&content, "note");
                        add_item(&kind, &content, extras, None, common, &mut out, &mut stats);
                    }
                    None => add_item(
                        "note",
                        &Value::Null,
                        extras,
                        None,
                        common,
                        &mut out,
                        &mut stats,
                    ),
                }
            }
            "login" | "alias" => {
                let (item_email, item_username) = if has_email {
                    (cell(email), cell(username))
                } else {
                    (cell(username), "")
                };
                let autofill_urls = serde_json::from_str::<Value>(cell(autofill))
                    .ok()
                    .filter(Value::is_array)
                    .unwrap_or(Value::Array(vec![]));
                let urls: Vec<&str> = cell(url).split(", ").collect();
                let content = json!({
                    "itemEmail": item_email,
                    "itemUsername": item_username,
                    "password": cell(password),
                    "urls": urls,
                    "autofillUrls": autofill_urls,
                    "totpUri": cell(totp),
                });
                let alias_email = clean(Some(item_email));
                add_item(
                    &kind,
                    &content,
                    extras,
                    alias_email,
                    common,
                    &mut out,
                    &mut stats,
                );
            }
            _ => {
                let content = match clean_password(Some(cell(password))) {
                    Some(password) => json!({ "password": password }),
                    None => json!({}),
                };
                add_item(&kind, &content, extras, None, common, &mut out, &mut stats);
            }
        }
    }
    stats.report(&mut out);
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemDetails, ItemType};

    fn import(value: Value) -> ImportResult {
        parse(value.to_string().as_bytes(), &ImportOptions::default()).unwrap()
    }

    fn export(items: Value) -> Value {
        json!({ "version": "1.30.0", "encrypted": false, "vaults": {
            "v1": { "name": "Personal", "items": items }
        }})
    }

    #[test]
    fn logins_with_email_username_and_url_modes() {
        let result = import(export(json!([{
            "state": 1, "pinned": true,
            "data": {
                "type": "login",
                "metadata": { "name": "GitHub", "note": "n" },
                "extraFields": [
                    { "fieldName": "PIN", "type": "hidden", "data": { "content": "1234" } },
                    { "fieldName": "2FA", "type": "totp", "data": { "totpUri": "JBSWY3DPEHPK3PXP" } }
                ],
                "content": {
                    "itemEmail": "a@example.com", "itemUsername": "octo", "password": " pw ",
                    "urls": ["https://github.com/"],
                    "autofillUrls": [
                        { "url": "https://github.com/", "mode": 0 },
                        { "url": "https://gist.github.com/x", "mode": 1 },
                        { "url": "https://never.example", "mode": 2 }
                    ],
                    "totpUri": "", "passkeys": []
                }
            }
        }])));
        let item = &result.items[0];
        assert_eq!(item.overview.favorite, Some(true));
        assert_eq!(item.overview.urls.as_ref().unwrap().len(), 3);
        assert_eq!(
            item.overview.extra["urlMatch"],
            json!({ "https://gist.github.com/x": "startsWith", "https://never.example": "never" })
        );
        let ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert_eq!(login.username.as_deref(), Some("octo"));
        assert_eq!(login.password.as_deref(), Some(" pw "));
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let fields = login.custom_fields.as_ref().unwrap();
        assert_eq!(
            (fields[0].label.as_str(), fields[0].value.as_str()),
            ("Email", "a@example.com")
        );
        assert!(fields[1].hidden);
    }

    #[test]
    fn old_logins_kept_the_email_in_username() {
        let result = import(export(json!([{
            "data": { "type": "login", "metadata": { "name": "Old" },
                "content": { "username": "me@example.com", "password": "pw", "urls": ["https://a.example"] } }
        }])));
        let ItemDetails::Login(login) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(login.username.as_deref(), Some("me@example.com"));
        assert_eq!(login.custom_fields, None);
    }

    #[test]
    fn trashed_aliases_and_other_types() {
        let result = import(export(json!([
            { "state": 2, "data": { "type": "login", "metadata": { "name": "Gone" }, "content": {} } },
            { "state": 1, "aliasEmail": "shop.x1@passmail.net",
              "data": { "type": "alias", "metadata": { "name": "Shop", "note": "" }, "content": {} } },
            { "state": 1, "data": { "type": "wifi", "metadata": { "name": "Home" },
              "content": { "ssid": "home-net", "password": "wifipw", "security": 2 } } },
            { "state": 1, "data": { "type": "sshKey", "metadata": { "name": "Server" },
              "content": { "privateKey": "-----BEGIN KEY-----\nabc\n-----END KEY-----", "publicKey": "ssh-ed25519 AAA" } } },
            { "state": 1, "data": { "type": "custom", "metadata": { "name": "Locker" },
              "content": { "sections": [{ "sectionName": "S", "sectionFields": [
                  { "fieldName": "Code", "type": "hidden", "data": { "content": "4321" } },
                  { "fieldName": "Since", "type": "timestamp", "data": { "timestamp": { "seconds": 0 } } }
              ] }] } } }
        ])));
        assert_eq!(result.skipped, 1);
        let ItemDetails::Login(alias) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(alias.username.as_deref(), Some("shop.x1@passmail.net"));
        let ItemDetails::Login(wifi) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(wifi.password.as_deref(), Some("wifipw"));
        assert_eq!(wifi.custom_fields.as_ref().unwrap()[1].value, "WPA2");
        let ItemDetails::SecureNote(ssh) = &result.items[2].details else {
            panic!()
        };
        assert!(
            ssh.notes
                .starts_with("Public key: ssh-ed25519 AAA\nPrivate key:\n-----BEGIN")
        );
        let ItemDetails::Custom(custom) = &result.items[3].details else {
            panic!()
        };
        let fields: Vec<_> = custom
            .fields
            .iter()
            .map(|f| (f.label.as_str(), f.value.as_str(), f.kind.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("Code", "4321", "hidden"), ("Since", "1970-01-01", "text")]
        );
        assert_eq!(result.warnings.len(), 3, "{:?}", result.warnings);
    }

    #[test]
    fn cards_and_identities() {
        let result = import(export(json!([
            { "data": { "type": "creditCard", "metadata": { "name": "Visa", "note": "card note" },
              "content": { "cardholderName": "Jane", "cardType": 2, "number": "4111111111111111",
                "verificationNumber": "123", "expirationDate": "2030-03", "pin": "9876" } } },
            { "data": { "type": "identity", "metadata": { "name": "Me" },
              "content": { "fullName": "Omar K Haddad", "email": "o@example.com", "birthdate": "1995-04-19",
                "streetAddress": "1 Main St", "city": "Amman", "passportNumber": "X1",
                "newField": "kept", "extraPersonalDetails": [
                  { "fieldName": "Nickname", "type": "text", "data": { "content": "OK" } }] } } }
        ])));
        let ItemDetails::Card(card) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(card.expiry.as_deref(), Some("03/30"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.pin.as_deref(), Some("9876"));
        let ItemDetails::Identity(id) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(id.first_name.as_deref(), Some("Omar K"));
        assert_eq!(id.last_name.as_deref(), Some("Haddad"));
        assert_eq!(id.birth_date.as_deref(), Some("1995-04-19"));
        assert_eq!(
            id.notes.as_deref(),
            Some("Passport number: X1\nnewField: kept\nNickname: OK")
        );
        assert_eq!(result.items[1].overview.item_type, ItemType::Identity);
    }

    #[test]
    fn folders_become_paths() {
        let vault = json!({ "folders": [
            { "folderId": "b", "parentFolderId": "a", "name": "Child" },
            { "folderId": "a", "parentFolderId": null, "name": "Parent" },
            { "folderId": "x", "parentFolderId": "y", "name": "Loop" },
            { "folderId": "y", "parentFolderId": "x", "name": "Pool" }
        ]});
        let paths = folder_paths(&vault);
        assert_eq!(paths["b"], "Parent/Child");
        assert_eq!(paths["a"], "Parent");
        assert!(paths["x"].len() < 100, "loops end");
    }

    #[test]
    fn encrypted_exports() {
        let pgp = b"-----BEGIN PGP MESSAGE-----\n\nwy4ECQMI\n-----END PGP MESSAGE-----\n";
        let error = parse(pgp, &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::ImportPasswordRequired);
        let flagged = parse(
            br#"{"encrypted":true,"vaults":{}}"#,
            &ImportOptions::default(),
        );
        assert_eq!(flagged.unwrap_err().code, Error::UnsupportedImport);
    }

    #[test]
    fn expiry_formats() {
        assert_eq!(card_expiry("2024-02").as_deref(), Some("02/24"));
        assert_eq!(card_expiry("022024").as_deref(), Some("02/24"));
        assert_eq!(card_expiry("12/31").as_deref(), Some("12/31"));
        assert_eq!(card_expiry("2024-13"), None);
        assert_eq!(card_expiry("ééé"), None);
    }

    #[test]
    fn csv_rows() {
        let csv = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
            login,Site,\"https://a.example/, https://b.example/\",me@example.com,me,pw,hi,,1,2,Personal\n\
            creditCard,Card,,,,,\"{\"\"cardholderName\"\":\"\"J\"\",\"\"number\"\":\"\"4242424242424242\"\",\"\"expirationDate\"\":\"\"2027-01\"\",\"\"note\"\":\"\"cn\"\"}\",,1,2,Work\n\
            alias,Alias,,a.b@passmail.net,,,,,1,2,Work\n";
        let result = parse(csv.as_bytes(), &ImportOptions::default()).unwrap();
        assert_eq!(result.items.len(), 3);
        assert_eq!(
            result.items[0].overview.urls.as_deref().unwrap(),
            ["https://a.example/", "https://b.example/"]
        );
        assert_eq!(
            result.items[0].overview.tags.as_deref().unwrap(),
            ["Personal"]
        );
        let ItemDetails::Card(card) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(card.notes.as_deref(), Some("cn"));
        assert_eq!(card.expiry.as_deref(), Some("01/27"));
    }
}
