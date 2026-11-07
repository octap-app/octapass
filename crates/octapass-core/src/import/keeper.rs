//! Keeper: the CSV export and the JSON export (Web Vault or Keeper Commander).
//!
//! The CSV has no header row: folder, title, login, password, website, notes, shared folder, then
//! custom field name/value pairs. `TFC:Keeper` (and other one-time code fields) become the TOTP.
//! Commander adds `$record_uid` and `$type` pairs, and typed fields such as `$paymentCard`.
//!
//! The JSON has `records` with `title`, `login`, `password`, `login_url`, `notes`, a
//! `custom_fields` object keyed `$type:label:index` (or a plain label) and `folders`. The record
//! `$type` picks the item type: `bankCard` → card; `contact` and `address` → identity;
//! `bankAccount` → bank account; `passport`, `driverLicense`, `ssnCard` and `birthCertificate` → ID
//! document; `softwareLicense` → software licence; `databaseCredentials` and `serverCredentials` →
//! database; `encryptedNotes` → secure note. Other Keeper types become logins when they hold a
//! username, password, website or one-time code, and secure notes otherwise; record types the user
//! made become custom items when they hold no login. Folders and shared folders become tags. Files
//! aren't in either export.
//!
//! A record's uid is kept so importing the file again updates it: `$record_uid` in Commander's
//! CSV, `uid` in Commander's JSON. The Web Vault's JSON numbers its records 1, 2, 3 … instead,
//! which says nothing about the record next time, so those numbers aren't kept. Commander's JSON
//! also has `last_modified` (Unix seconds), the record's last-changed date; neither export has a
//! created date. Sources: Keeper Commander's `importer/csv` and `importer/json` exporters, and
//! docs.keeper.io's import and export guides.

use serde_json::Value;

use super::build::{
    Collector, ItemMeta, LoginFields, TypedItem, address, card, card_details, civil_date, clean,
    clean_password, custom_field, expiry, identity, identity_details, iso_date, looks_secret, note,
    notes_with, security_question, unix_time,
};
use super::csv_table::invalid;
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::item::{CustomField, ItemType};
use crate::item_fields::is_port;

/// The CSV columns before the custom field pairs.
const FOLDER: usize = 0;
const TITLE: usize = 1;
const LOGIN: usize = 2;
const PASSWORD: usize = 3;
const URL: usize = 4;
const NOTES: usize = 5;
const SHARED_FOLDER: usize = 6;
const FIRST_FIELD: usize = 7;

/// Keeper's own column names, in case someone added a header row.
const HEADER: [&str; 6] = [
    "folder",
    "title",
    "login",
    "password",
    "website address",
    "notes",
];

/// Record types that become identities.
const IDENTITY_TYPES: [&str; 2] = ["contact", "address"];
/// Record types with an Octa Pass type of their own.
const TYPED_TYPES: [&str; 8] = [
    "bankAccount",
    "softwareLicense",
    "databaseCredentials",
    "serverCredentials",
    "passport",
    "driverLicense",
    "ssnCard",
    "birthCertificate",
];
/// Keeper's own record types with no Octa Pass type. Any other is one the user made.
const BUILT_IN_TYPES: [&str; 7] = [
    "encryptedNotes",
    "file",
    "healthInsurance",
    "membership",
    "photo",
    "sshKeys",
    "wifiCredentials",
];

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let start = text.trim_start();
    if start.starts_with('{') {
        let json = serde_json::from_str(start)
            .map_err(|_| invalid("This is not a Keeper export: the JSON is damaged."))?;
        return parse_json(&json);
    }
    // A CSV whose first folder starts with `[` is still a CSV.
    if start.starts_with('[')
        && let Ok(json) = serde_json::from_str::<Value>(start)
    {
        return parse_json(&json);
    }
    parse_csv(&text)
}

/// A Keeper record, from either format.
#[derive(Default)]
struct Record {
    title: Option<String>,
    login: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    /// The record type (`$type`). `None` for the legacy "general" records, which are logins.
    kind: Option<String>,
    tags: Vec<String>,
    fields: Vec<Field>,
    has_files: bool,
    meta: ItemMeta,
}

/// A custom field: its Keeper field type (empty for plain custom fields), label and value.
struct Field {
    kind: String,
    label: String,
    value: Value,
}

impl Field {
    fn from_key(key: &str, value: Value) -> Self {
        let (kind, label) = field_key(key);
        Self { kind, label, value }
    }

    fn is_totp(&self) -> bool {
        matches!(self.kind.as_str(), "oneTimeCode" | "otp")
            || ["one-time code", "one time code", "totp", "2fa"]
                .contains(&self.label.to_lowercase().as_str())
            || self.value.as_str().is_some_and(|v| {
                v.trim()
                    .get(..10)
                    .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
            })
    }
}

/// `$text:Security Question:1` → (`text`, `Security Question`); `$paymentCard::1` →
/// (`paymentCard`, ``); a plain `Account ID` → (``, `Account ID`).
fn field_key(key: &str) -> (String, String) {
    if key.trim() == "TFC:Keeper" {
        return ("oneTimeCode".into(), String::new());
    }
    let Some(rest) = key.trim().strip_prefix('$') else {
        return (String::new(), key.trim().to_string());
    };
    let (kind, mut label) = rest.split_once(':').unwrap_or((rest, ""));
    // `:1`, `:2` … number repeated fields of the same type.
    if let Some((before, index)) = label.rsplit_once(':')
        && index.len() == 1
        && index.bytes().all(|b| b.is_ascii_digit())
    {
        label = before;
    }
    (kind.trim().to_string(), label.trim().to_string())
}

fn parse_json(json: &Value) -> Result<ImportResult, ImportError> {
    let not_keeper = || invalid("This is not a Keeper JSON export: it has no records.");
    let records = match json {
        Value::Array(records) => records,
        Value::Object(object) => object
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(not_keeper)?,
        _ => return Err(not_keeper()),
    };
    let mut out = Collector::default();
    let mut stats = Stats::default();
    for (index, record) in records.iter().enumerate() {
        let Some(object) = record.as_object() else {
            out.skip(Some(format!(
                "Record {} skipped: it isn't a record.",
                index + 1
            )));
            continue;
        };
        let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
        let tags = object
            .get("folders")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|folder| {
                folder_tag(
                    folder.get("shared_folder").and_then(Value::as_str),
                    folder.get("folder").and_then(Value::as_str),
                )
            })
            .collect();
        let fields = object
            .get("custom_fields")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(key, value)| Field::from_key(key, value.clone()))
            .collect();
        let file_refs = object
            .get("references")
            .and_then(Value::as_object)
            .is_some_and(|refs| refs.keys().any(|k| k.starts_with("$fileRef")));
        let record = Record {
            title: text("title"),
            login: text("login"),
            password: text("password"),
            url: text("login_url"),
            notes: text("notes"),
            kind: clean(object.get("$type").and_then(Value::as_str)),
            tags,
            fields,
            has_files: file_refs || object.contains_key("attachments"),
            meta: ItemMeta {
                updated_at: object
                    .get("last_modified")
                    .and_then(Value::as_i64)
                    .and_then(unix_time),
                // Only Commander's uids name a record; the Web Vault's are numbers.
                source_id: object
                    .get("uid")
                    .and_then(Value::as_str)
                    .and_then(|uid| clean(Some(uid))),
                ..ItemMeta::default()
            },
        };
        add_record(record, &mut out, &mut stats, || {
            format!("Record {} skipped: it has no fields.", index + 1)
        });
    }
    stats.report(&mut out);
    Ok(out.finish())
}

fn parse_csv(text: &str) -> Result<ImportResult, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut out = Collector::default();
    let mut stats = Stats::default();
    let (mut rows, mut short_rows) = (0, 0);
    for (index, record) in reader.records().enumerate() {
        let record = record.map_err(|_| invalid("The file isn't valid CSV."))?;
        let cells: Vec<&str> = record.iter().collect();
        if cells.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let line = record.position().map_or(0, |p| p.line());
        if index == 0 && is_header(&cells) {
            if cells.len() >= 6
                && HEADER
                    .iter()
                    .zip(&cells)
                    .all(|(name, cell)| cell.trim().eq_ignore_ascii_case(name))
            {
                continue;
            }
            return Err(invalid(
                "This is not a Keeper export: Keeper's CSV has no header row.",
            ));
        }
        if cells.len() < 6 {
            short_rows += 1;
            out.skip(Some(format!(
                "Row {line} skipped: it has fewer columns than a Keeper export."
            )));
            continue;
        }
        rows += 1;
        let get = |i: usize| cells.get(i).map(|cell| cell.to_string());
        let mut record = Record {
            title: get(TITLE),
            login: get(LOGIN),
            password: get(PASSWORD),
            url: get(URL),
            notes: get(NOTES).map(|n| n.trim_end().to_string()),
            ..Record::default()
        };
        let shared = cells.get(SHARED_FOLDER).map(|s| shared_folder_name(s));
        record
            .tags
            .extend(folder_tag(shared, cells.get(FOLDER).copied()));
        for pair in cells.get(FIRST_FIELD..).unwrap_or_default().chunks(2) {
            let key = pair[0].trim();
            let value = pair.get(1).copied().unwrap_or_default();
            match key {
                "$record_uid" => record.meta.source_id = clean(Some(value)),
                "$type" => record.kind = clean(Some(value)),
                _ if value.trim().is_empty() => {}
                "" => record
                    .fields
                    .push(Field::from_key("Field", Value::String(value.into()))),
                _ => record
                    .fields
                    .push(Field::from_key(key, Value::String(value.into()))),
            }
        }
        add_record(record, &mut out, &mut stats, || {
            format!("Row {line} skipped: no URL, username, password or notes.")
        });
    }
    if rows == 0 {
        return Err(invalid(if short_rows > 0 {
            "This is not a Keeper export: no row has Keeper's columns."
        } else {
            "The file is empty."
        }));
    }
    stats.report(&mut out);
    Ok(out.finish())
}

/// A first row of column names from another app (`url,username,password…`).
fn is_header(cells: &[&str]) -> bool {
    const NAMES: [&str; 14] = [
        "folder",
        "title",
        "name",
        "login",
        "username",
        "user name",
        "password",
        "website address",
        "url",
        "website",
        "notes",
        "note",
        "extra",
        "shared folder",
    ];
    let lower: Vec<String> = cells.iter().map(|c| c.trim().to_lowercase()).collect();
    lower.iter().any(|c| c == "password")
        && lower.iter().filter(|c| NAMES.contains(&c.as_str())).count() >= 3
}

/// `Shared#edit#reshare` → `Shared`: Commander appends the folder permissions.
fn shared_folder_name(cell: &str) -> &str {
    let mut name = cell.trim();
    while let Some(rest) = name
        .strip_suffix("#edit")
        .or_else(|| name.strip_suffix("#reshare"))
    {
        name = rest;
    }
    name
}

/// One tag per folder: `Shared\Sub` when a folder is inside a shared folder.
fn folder_tag(shared: Option<&str>, folder: Option<&str>) -> Option<String> {
    let parts: Vec<String> = [shared, folder]
        .into_iter()
        .filter_map(|part| clean(part))
        .collect();
    (!parts.is_empty()).then(|| parts.join("\\"))
}

#[derive(Default)]
struct Stats {
    files: usize,
}

impl Stats {
    fn report(&self, out: &mut Collector) {
        if self.files > 0 {
            out.warn(format!(
                "Keeper's exports don't include files: {} {} imported without {}.",
                self.files,
                if self.files == 1 {
                    "item was"
                } else {
                    "items were"
                },
                if self.files == 1 {
                    "its files"
                } else {
                    "their files"
                },
            ));
        }
    }
}

fn add_record(
    mut record: Record,
    out: &mut Collector,
    stats: &mut Stats,
    skipped: impl FnOnce() -> String,
) {
    let kind = record.kind.clone().unwrap_or_default();
    if record.has_files || matches!(kind.as_str(), "file" | "photo") {
        stats.files += 1;
    }
    let title = record.title.take();
    let tags = std::mem::take(&mut record.tags);
    let meta = std::mem::take(&mut record.meta);
    let before = out.count();
    match kind.as_str() {
        "bankCard" => add_card(record, title, tags, out, skipped),
        k if IDENTITY_TYPES.contains(&k) => add_identity(record, title, tags, out, skipped),
        k if TYPED_TYPES.contains(&k) => add_typed(record, &kind, title, tags, out, skipped),
        "encryptedNotes" => add_note(record, None, title, tags, out, skipped),
        "" | "login" | "general" => {
            let fields = login_fields(record, None, title, tags);
            out.add_login(fields, skipped);
        }
        _ => {
            let has_credentials = clean(record.login.as_deref()).is_some()
                || clean_password(record.password.as_deref()).is_some()
                || clean(record.url.as_deref()).is_some()
                || record.fields.iter().any(Field::is_totp);
            if has_credentials {
                let fields = login_fields(record, Some(&kind), title, tags);
                out.add_login(fields, skipped);
            } else if BUILT_IN_TYPES.contains(&kind.as_str()) {
                add_note(record, Some(&kind), title, tags, out, skipped);
            } else {
                add_custom(record, &kind, title, tags, out, skipped);
            }
        }
    }
    out.meta_since(before, &meta);
}

/// A login, with the record type (for types other than logins) as the first custom field.
fn login_fields(
    record: Record,
    kind: Option<&str>,
    title: Option<String>,
    tags: Vec<String>,
) -> LoginFields {
    let mut urls: Vec<String> = record.url.into_iter().collect();
    let mut totp = None;
    let mut custom_fields: Vec<CustomField> = kind
        .map(|kind| custom_field("Type", type_name(kind), false))
        .into_iter()
        .collect();
    let mut notes = Vec::new();
    let mut security_questions = Vec::new();
    for field in record.fields {
        if totp.is_none() && field.is_totp() {
            totp = field.value.as_str().map(str::to_string);
            continue;
        }
        let is_url = field.kind == "url";
        let is_note = field.kind == "note";
        let is_question = field.kind == "securityQuestion";
        for (label, value, hidden) in flatten(&field) {
            if is_url && !urls.contains(&value) {
                urls.push(value);
            } else if is_note {
                notes.push(value);
            } else if is_question && label != NO_QUESTION {
                security_questions.push(security_question(&label, &value));
            } else {
                custom_fields.push(custom_field(&label, &value, hidden));
            }
        }
    }
    notes.extend(record.notes);
    LoginFields {
        title,
        urls,
        username: record.login,
        password: clean_password(record.password.as_deref()),
        totp,
        notes: Some(notes.join("\n")),
        tags,
        custom_fields,
        security_questions,
        ..LoginFields::default()
    }
}

fn add_card(
    record: Record,
    title: Option<String>,
    tags: Vec<String>,
    out: &mut Collector,
    skipped: impl FnOnce() -> String,
) {
    let mut details = card_details();
    let mut lines = Vec::new();
    let mut notes = Vec::new();
    for field in &record.fields {
        match (field.kind.as_str(), field.label.as_str()) {
            ("paymentCard", _) if details.number.is_none() => {
                let (number, expiry_date, cvv) = payment_card(&field.value);
                details.number = number;
                details.cvv = cvv;
                if let Some(date) = expiry_date {
                    match card_expiry(&date) {
                        Some(expiry) => details.expiry = Some(expiry),
                        None => lines.push(("Expiry".into(), date)),
                    }
                }
            }
            ("text", "cardholderName") if details.cardholder.is_none() => {
                details.cardholder = field.value.as_str().and_then(|v| clean(Some(v)));
            }
            ("pinCode", _) if details.pin.is_none() => {
                details.pin = field.value.as_str().and_then(|v| clean(Some(v)));
            }
            ("note", _) => notes.extend(flatten(field).into_iter().map(|(_, v, _)| v)),
            _ => lines.extend(flatten(field).into_iter().map(|(l, v, _)| (l, v))),
        }
    }
    lines.extend(credential_lines(&record));
    notes.extend(record.notes);
    details.notes = notes_with(&lines, clean(Some(&notes.join("\n"))));
    if title.is_none() && details == card_details() {
        return out.skip(Some(skipped()));
    }
    out.add(card(title, tags, false, details));
}

fn add_identity(
    record: Record,
    title: Option<String>,
    tags: Vec<String>,
    out: &mut Collector,
    skipped: impl FnOnce() -> String,
) {
    let mut details = identity_details();
    let mut lines = Vec::new();
    let mut notes = Vec::new();
    for field in &record.fields {
        let claimed = match (field.kind.as_str(), &field.value) {
            ("name", Value::Object(name)) if details.first_name.is_none() => {
                let get = |k: &str| clean(name.get(k).and_then(Value::as_str));
                details.first_name = join_words([get("first"), get("middle")]);
                details.last_name = get("last");
                true
            }
            ("name", Value::String(name)) if details.first_name.is_none() => {
                (details.first_name, details.last_name) = split_name(name);
                true
            }
            // The first email or phone has its place; more of them (a list) become lines.
            ("email" | "phone", _)
                if (field.kind == "email" && details.email.is_none())
                    || (field.kind == "phone" && details.phone.is_none()) =>
            {
                let mut entries = flatten(field).into_iter();
                let first = entries.next().map(|(_, value, _)| value);
                if field.kind == "email" {
                    details.email = first;
                } else {
                    details.phone = first;
                }
                lines.extend(entries.map(|(label, value, _)| (label, value)));
                true
            }
            ("address", Value::Object(a)) if details.address.is_none() => {
                let get = |k: &str| clean(a.get(k).and_then(Value::as_str));
                details.address = address(
                    get("street1"),
                    get("street2"),
                    get("city"),
                    get("state"),
                    get("zip"),
                    get("country"),
                );
                true
            }
            ("birthDate", value) if details.birth_date.is_none() => {
                details.birth_date = date(value);
                details.birth_date.is_some()
            }
            _ => false,
        };
        if claimed {
            continue;
        }
        if field.kind == "note" {
            notes.extend(flatten(field).into_iter().map(|(_, v, _)| v));
        } else {
            lines.extend(flatten(field).into_iter().map(|(l, v, _)| (l, v)));
        }
    }
    lines.extend(credential_lines(&record));
    notes.extend(record.notes);
    details.notes = notes_with(&lines, clean(Some(&notes.join("\n"))));
    if title.is_none() && details == identity_details() {
        return out.skip(Some(skipped()));
    }
    out.add(identity(title, tags, false, details));
}

/// The first value of a field, as text.
fn first_value(field: &Field) -> Option<String> {
    flatten(field).into_iter().next().map(|(_, value, _)| value)
}

/// `field` when it goes to one of the item's places. Everything else stays a custom field.
fn claim(item: &mut TypedItem, kind: &str, field: &Field) -> bool {
    let holder = match kind {
        "bankAccount" => Some("accountHolder"),
        "softwareLicense" => Some("licensedTo"),
        "passport" | "driverLicense" | "ssnCard" | "birthCertificate" => Some("fullName"),
        _ => None,
    };
    let is_document = holder == Some("fullName");
    let day = || date(&field.value).or_else(|| first_value(field));
    match (field.kind.as_str(), field.label.as_str(), &field.value) {
        ("name", _, _) if holder.is_some_and(|key| !item.has(key)) => {
            item.set(holder.unwrap_or_default(), first_value(field));
        }
        ("bankAccount", _, Value::Object(account)) if kind == "bankAccount" => {
            let get = |k: &str| clean(account.get(k).and_then(Value::as_str));
            item.set(
                "accountType",
                get("otherType").or_else(|| get("accountType")),
            );
            item.set("routingNumber", get("routingNumber"));
            item.set("accountNumber", get("accountNumber"));
            for (key, inner) in account {
                if !["otherType", "accountType", "routingNumber", "accountNumber"]
                    .contains(&key.as_str())
                    && let Some(value) = inner.as_str()
                {
                    item.custom(&format!("Bank account ({key})"), value, false);
                }
            }
        }
        ("host", _, Value::Object(host)) if matches!(item.kind(), ItemType::Database) => {
            let get = |k: &str| clean(host.get(k).and_then(Value::as_str));
            item.set("host", get("hostName"));
            item.set("port", get("port"));
        }
        ("host", _, Value::String(host)) if matches!(item.kind(), ItemType::Database) => {
            match host.trim().rsplit_once(':') {
                Some((name, port)) if is_port(port) => {
                    item.set("host", clean(Some(name)));
                    item.set("port", clean(Some(port)));
                }
                _ => item.set("host", clean(Some(host))),
            }
        }
        ("text", "type", _) if matches!(item.kind(), ItemType::Database) => {
            item.set("databaseType", first_value(field));
        }
        ("licenseNumber", _, _) if kind == "softwareLicense" => {
            item.set("licenseKey", first_value(field));
        }
        ("accountNumber" | "licenseNumber", _, _) if is_document => {
            item.set("number", first_value(field));
        }
        ("birthDate", _, _) if is_document => item.set("birthDate", day()),
        ("date", "dateIssued", _) if is_document => item.set("issueDate", day()),
        ("expirationDate", _, _) if is_document || kind == "softwareLicense" => {
            item.set("expiryDate", day());
        }
        _ => return false,
    }
    true
}

/// A bank account, licence, database, server or ID document. Its username, password and one-time
/// code go to their places when the item has them, and stay as fields when it doesn't.
fn add_typed(
    record: Record,
    kind: &str,
    title: Option<String>,
    tags: Vec<String>,
    out: &mut Collector,
    skipped: impl FnOnce() -> String,
) {
    let mut item = match kind {
        "bankAccount" => TypedItem::bank_account(),
        "softwareLicense" => TypedItem::software_license(),
        "databaseCredentials" => TypedItem::database(None),
        "serverCredentials" => TypedItem::database(Some("server".into())),
        "passport" => TypedItem::id_document("passport"),
        "driverLicense" => TypedItem::id_document("driverLicense"),
        "ssnCard" => TypedItem::id_document("nationalId"),
        _ => TypedItem::id_document("other"),
    };
    if kind == "birthCertificate" {
        item.custom("Type", type_name(kind), false);
    }
    let mut notes = Vec::new();
    for field in &record.fields {
        if field.kind == "note" {
            notes.extend(flatten(field).into_iter().map(|(_, v, _)| v));
        } else if field.kind == "url" {
            flatten(field)
                .into_iter()
                .for_each(|(_, url, _)| item.url(Some(url)));
        } else if !claim(&mut item, kind, field) {
            for (label, value, hidden) in flatten(field) {
                item.custom(&label, &value, hidden);
            }
        }
    }
    item.url(record.url);
    if matches!(item.kind(), ItemType::Database) {
        item.set("username", record.login);
        item.set("password", record.password);
    } else {
        item.custom(
            "Username",
            record.login.as_deref().unwrap_or_default(),
            false,
        );
        item.custom(
            "Password",
            record.password.as_deref().unwrap_or_default(),
            true,
        );
    }
    notes.extend(record.notes);
    let notes = clean(Some(&notes.join("\n")));
    if title.is_none() && notes.is_none() && item.is_empty() {
        return out.skip(Some(skipped()));
    }
    out.add(item.build(title, tags, false, notes));
}

/// A record of a type the user made: a custom item, named after the type.
fn add_custom(
    record: Record,
    kind: &str,
    title: Option<String>,
    tags: Vec<String>,
    out: &mut Collector,
    skipped: impl FnOnce() -> String,
) {
    let mut item = TypedItem::custom_item(Some(kind.to_owned()));
    let mut notes = Vec::new();
    for field in &record.fields {
        if field.kind == "note" {
            notes.extend(flatten(field).into_iter().map(|(_, v, _)| v));
            continue;
        }
        let field_kind = match field.kind.as_str() {
            "url" => "url",
            "email" => "email",
            "phone" => "phone",
            "multiline" => "multiline",
            kind if is_date(kind) => "date",
            _ => "text",
        };
        for (label, value, hidden) in flatten(field) {
            let date_like = field_kind == "date" && value.len() != 10;
            let field_kind = if hidden {
                "hidden"
            } else if date_like {
                "text"
            } else {
                field_kind
            };
            item.field(&label, &value, field_kind);
        }
    }
    notes.extend(record.notes);
    let notes = clean(Some(&notes.join("\n")));
    if title.is_none() && notes.is_none() && item.is_empty() {
        return out.skip(Some(skipped()));
    }
    out.add(item.build(title, tags, false, notes));
}

/// A secure note: `$note` fields, then the record's notes, with every other field as a line.
fn add_note(
    record: Record,
    kind: Option<&str>,
    title: Option<String>,
    tags: Vec<String>,
    out: &mut Collector,
    skipped: impl FnOnce() -> String,
) {
    let mut lines = Vec::new();
    let mut notes = Vec::new();
    for field in &record.fields {
        if field.kind == "note" {
            notes.extend(flatten(field).into_iter().map(|(_, v, _)| v));
        } else {
            lines.extend(flatten(field).into_iter().map(|(l, v, _)| (l, v)));
        }
    }
    lines.extend(credential_lines(&record));
    notes.extend(record.notes);
    let body = notes_with(&lines, clean(Some(&notes.join("\n"))));
    if body.is_none() && title.is_none() {
        out.skip(Some(skipped()));
        return;
    }
    let type_line: Vec<(String, String)> = kind
        .map(|kind| ("Type".to_string(), type_name(kind).to_string()))
        .into_iter()
        .collect();
    out.add(note(title, tags, false, notes_with(&type_line, body)));
}

/// The top-level login, password and website of a record that isn't a login.
fn credential_lines(record: &Record) -> Vec<(String, String)> {
    [
        ("Username", &record.login),
        ("Password", &record.password),
        ("Website", &record.url),
    ]
    .into_iter()
    .filter_map(|(label, value)| Some((label.to_string(), value.clone()?)))
    .collect()
}

/// The label of an answer with no question: it stays a hidden field.
const NO_QUESTION: &str = "Security answer";

/// A field as `(label, value, hidden)` entries: one per value, and one per part of a
/// structured value that has several (cards, bank accounts, key pairs).
fn flatten(field: &Field) -> Vec<(String, String, bool)> {
    let secret_type = matches!(
        field.kind.as_str(),
        "password" | "secret" | "pinCode" | "oneTimeCode" | "otp" | "securityQuestion"
    );
    flatten_value(
        &field.kind,
        &field_label(&field.kind, &field.label),
        &field.value,
    )
    .into_iter()
    .map(|(label, value)| {
        let hidden = secret_type || looks_secret(&label);
        (label, value, hidden)
    })
    .collect()
}

fn flatten_value(kind: &str, label: &str, value: &Value) -> Vec<(String, String)> {
    let one = |text: Option<String>| -> Vec<(String, String)> {
        text.filter(|t| !t.trim().is_empty())
            .map(|t| (label.to_string(), t))
            .into_iter()
            .collect()
    };
    match value {
        Value::Null => vec![],
        Value::Array(values) => values
            .iter()
            .flat_map(|v| flatten_value(kind, label, v))
            .collect(),
        Value::String(text) if is_date(kind) && text.bytes().all(|b| b.is_ascii_digit()) => {
            one(date(value).or_else(|| Some(text.clone())))
        }
        Value::String(text) => one(Some(text.clone())),
        Value::Number(_) if is_date(kind) => one(date(value)),
        Value::Number(n) => one(Some(n.to_string())),
        Value::Bool(b) => one(Some(if *b { "Yes" } else { "No" }.into())),
        Value::Object(object) => {
            let get = |k: &str| clean(object.get(k).and_then(Value::as_str));
            match kind {
                "name" => one(join_words([get("first"), get("middle"), get("last")])),
                "phone" => {
                    let number = join_words([get("region"), get("number")]);
                    let number = match (number, get("ext")) {
                        (Some(number), Some(ext)) => Some(format!("{number} ext. {ext}")),
                        (number, _) => number,
                    };
                    let label = match get("type") {
                        Some(kind) => format!("{label} ({kind})"),
                        None => label.to_string(),
                    };
                    number.map(|n| (label, n)).into_iter().collect::<Vec<_>>()
                }
                "address" => one(clean(Some(
                    &[
                        get("street1"),
                        get("street2"),
                        get("city"),
                        join_words([get("state"), get("zip")]),
                        get("country"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", "),
                ))),
                "host" => one(match (get("hostName"), get("port")) {
                    (Some(host), Some(port)) => Some(format!("{host}:{port}")),
                    (host, port) => host.or(port),
                }),
                "securityQuestion" => get("answer")
                    .map(|answer| {
                        (
                            get("question").unwrap_or_else(|| NO_QUESTION.into()),
                            answer,
                        )
                    })
                    .into_iter()
                    .collect(),
                _ => {
                    let parts: &[(&str, &str)] = match kind {
                        "paymentCard" => &[
                            ("cardNumber", "Card number"),
                            ("cardExpirationDate", "Expiry"),
                            ("cardSecurityCode", "Security code"),
                        ],
                        "bankAccount" => &[
                            ("accountType", "Account type"),
                            ("otherType", "Account type"),
                            ("routingNumber", "Routing number"),
                            ("accountNumber", "Account number"),
                        ],
                        "keyPair" => &[("publicKey", "Public key"), ("privateKey", "Private key")],
                        _ => &[],
                    };
                    let mut out: Vec<(String, String)> = parts
                        .iter()
                        .filter_map(|(key, name)| Some((name.to_string(), get(key)?)))
                        .collect();
                    // Anything else (including keys Keeper adds later) keeps its own name.
                    for (key, inner) in object {
                        if parts.iter().any(|(k, _)| k == key) {
                            continue;
                        }
                        let text = match inner {
                            Value::String(s) => Some(s.clone()),
                            Value::Null => None,
                            other => Some(other.to_string()),
                        };
                        if let Some(text) = text.filter(|t| !t.trim().is_empty()) {
                            out.push((format!("{label} ({key})"), text));
                        }
                    }
                    out
                }
            }
        }
    }
}

fn is_date(kind: &str) -> bool {
    matches!(kind, "date" | "birthDate" | "expirationDate")
}

/// Keeper dates are Unix times in milliseconds.
fn date(value: &Value) -> Option<String> {
    let millis = match value {
        Value::Number(n) => n.as_i64()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    // Beyond ±10,000 years is no date.
    if millis.unsigned_abs() > 253_402_300_799_000 {
        return None;
    }
    let (year, month, day) = civil_date(millis.div_euclid(1000));
    iso_date(year, month, day)
}

/// A field's label: its own, or a name for its type.
fn field_label(kind: &str, label: &str) -> String {
    let named = match label {
        "" => None,
        "cardholderName" => Some("Cardholder name"),
        "company" => Some("Company"),
        "dlNumber" => Some("License number"),
        "passportNumber" => Some("Passport number"),
        "identityNumber" => Some("Identity number"),
        "dateIssued" => Some("Date issued"),
        "dateActive" => Some("Date active"),
        _ => return label.to_string(),
    };
    named
        .unwrap_or(match kind {
            "login" => "Username",
            "password" => "Password",
            "url" => "Website",
            "email" => "Email",
            "phone" => "Phone",
            "name" => "Name",
            "address" => "Address",
            "note" => "Note",
            "text" | "multiline" => "Text",
            "secret" => "Hidden field",
            "pinCode" => "PIN",
            "accountNumber" => "Account number",
            "licenseNumber" => "License number",
            "date" => "Date",
            "birthDate" => "Date of birth",
            "expirationDate" => "Expiration date",
            "oneTimeCode" | "otp" => "One-time code",
            "host" => "Host",
            "keyPair" => "Key pair",
            "paymentCard" => "Card",
            "bankAccount" => "Bank account",
            "securityQuestion" => "Security question",
            "" => "Field",
            other => other,
        })
        .to_string()
}

/// A readable name for a record type.
fn type_name(kind: &str) -> &str {
    match kind {
        "bankAccount" => "Bank account",
        "birthCertificate" => "Birth certificate",
        "databaseCredentials" => "Database",
        "driverLicense" => "Driver's license",
        "encryptedNotes" => "Secure note",
        "file" => "File",
        "healthInsurance" => "Health insurance",
        "membership" => "Membership",
        "passport" => "Passport",
        "photo" => "Photo",
        "serverCredentials" => "Server",
        "softwareLicense" => "Software license",
        "ssnCard" => "Identity card",
        "sshKeys" => "SSH key",
        "wifiCredentials" => "Wi-Fi",
        other => other,
    }
}

/// `(number, expiry, security code)` of a `$paymentCard`: an object in JSON, or
/// `4111… 03/2030 123` (Commander) or `4111… | 03/2030 | 123` in CSV.
fn payment_card(value: &Value) -> (Option<String>, Option<String>, Option<String>) {
    match value {
        Value::Object(card) => {
            let get = |k: &str| clean(card.get(k).and_then(Value::as_str));
            (
                get("cardNumber"),
                get("cardExpirationDate"),
                get("cardSecurityCode"),
            )
        }
        Value::String(text) => {
            let parts: Vec<&str> = text
                .split(['|', ' '])
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .collect();
            let Some(expiry_at) = parts.iter().position(|p| p.contains('/')) else {
                return (clean(Some(&parts.concat())), None, None);
            };
            (
                clean(Some(&parts[..expiry_at].concat())),
                Some(parts[expiry_at].to_string()),
                clean(Some(&parts[expiry_at + 1..].concat())),
            )
        }
        _ => (None, None, None),
    }
}

/// `MM/YYYY` → `MM/YY`.
fn card_expiry(text: &str) -> Option<String> {
    let (month, year) = text.trim().split_once('/')?;
    expiry(month.trim().parse().ok()?, year.trim().parse().ok()?)
}

/// `Bilbo Baggins` → (`Bilbo`, `Baggins`); Commander's `Baggins, Bilbo` too.
fn split_name(name: &str) -> (Option<String>, Option<String>) {
    if let Some((last, first)) = name.split_once(',') {
        return (clean(Some(first)), clean(Some(last)));
    }
    match name.trim().rsplit_once(char::is_whitespace) {
        Some((first, last)) => (clean(Some(first)), clean(Some(last))),
        None => (clean(Some(name)), None),
    }
}

fn join_words<const N: usize>(words: [Option<String>; N]) -> Option<String> {
    clean(Some(
        &words.into_iter().flatten().collect::<Vec<_>>().join(" "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemDetails, ItemType};
    use serde_json::json;

    fn json_import(value: Value) -> ImportResult {
        parse(value.to_string().as_bytes(), &ImportOptions::default()).unwrap()
    }

    #[test]
    fn field_keys() {
        assert_eq!(
            field_key("$paymentCard::1"),
            ("paymentCard".into(), "".into())
        );
        assert_eq!(
            field_key("$text:Security Question & Answer:1"),
            ("text".into(), "Security Question & Answer".into())
        );
        assert_eq!(field_key("$email"), ("email".into(), "".into()));
        assert_eq!(field_key("Account ID"), ("".into(), "Account ID".into()));
        assert_eq!(field_key("TFC:Keeper"), ("oneTimeCode".into(), "".into()));
        assert_eq!(
            field_key("$text:Gate 12"),
            ("text".into(), "Gate 12".into())
        );
    }

    #[test]
    fn structured_values() {
        let phone = json!({"region": "JO", "number": "791234567", "ext": "12", "type": "Mobile"});
        assert_eq!(
            flatten_value("phone", "Phone", &phone),
            [(
                "Phone (Mobile)".to_string(),
                "JO 791234567 ext. 12".to_string()
            )]
        );
        let host = json!({"hostName": "db.example.com", "port": "5432"});
        assert_eq!(
            flatten_value("host", "Host", &host)[0].1,
            "db.example.com:5432"
        );
        let unknown = json!({"color": "blue", "nested": {"a": 1}});
        assert_eq!(
            flatten_value("widget", "Widget", &unknown),
            [
                ("Widget (color)".to_string(), "blue".to_string()),
                ("Widget (nested)".to_string(), "{\"a\":1}".to_string())
            ]
        );
        assert_eq!(
            date(&json!(648597600000_i64)).as_deref(),
            Some("1990-07-21")
        );
        assert_eq!(date(&json!(i64::MAX)), None);
    }

    #[test]
    fn payment_cards_in_both_formats() {
        assert_eq!(
            payment_card(&json!("4111 1111 1111 1111 | 03/2030 | 123")),
            (
                Some("4111111111111111".into()),
                Some("03/2030".into()),
                Some("123".into())
            )
        );
        assert_eq!(
            payment_card(&json!("4111111111111111 03/2030 123"))
                .2
                .as_deref(),
            Some("123")
        );
        assert_eq!(payment_card(&json!("4111")).0.as_deref(), Some("4111"));
        assert_eq!(card_expiry("03/2030").as_deref(), Some("03/30"));
        assert_eq!(card_expiry("13/2030"), None);
    }

    #[test]
    fn names_and_folders() {
        assert_eq!(
            split_name("Baggins, Bilbo"),
            (Some("Bilbo".into()), Some("Baggins".into()))
        );
        assert_eq!(
            split_name("Mary Ann Smith"),
            (Some("Mary Ann".into()), Some("Smith".into()))
        );
        assert_eq!(shared_folder_name("Team#edit#reshare"), "Team");
        assert_eq!(
            folder_tag(Some("Team"), Some("Sub")).as_deref(),
            Some("Team\\Sub")
        );
        assert_eq!(folder_tag(Some(" "), None), None);
    }

    #[test]
    fn other_types_with_credentials_are_logins() {
        let result = json_import(json!({"records": [
            {"title": "DB", "$type": "databaseCredentials", "login": "root", "password": "pw",
             "custom_fields": {"$host::1": {"hostName": "db.local", "port": "5432"}}},
            {"title": "Bank", "$type": "bankAccount",
             "custom_fields": {"$bankAccount::1": {"accountType": "Checking", "accountNumber": "123"}}},
            {"title": "Club", "$type": "membership", "login": "me"},
        ]}));
        let ItemDetails::Database(db) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(db.host.as_deref(), Some("db.local"));
        assert_eq!(db.port.as_deref(), Some("5432"));
        assert_eq!(db.username.as_deref(), Some("root"));
        assert_eq!(db.password.as_deref(), Some("pw"));
        let ItemDetails::BankAccount(bank) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(bank.account_type.as_deref(), Some("checking"));
        assert_eq!(bank.account_number.as_deref(), Some("123"));
        assert_eq!(result.items[2].overview.item_type, ItemType::Login);
    }

    #[test]
    fn id_documents_licences_and_custom_record_types() {
        let result = json_import(json!({"records": [
            {"title": "DL", "$type": "driverLicense", "custom_fields": {
                "$accountNumber:dlNumber:1": "D1", "$name::1": {"first": "Omar", "last": "Khalil"},
                "$birthDate::1": 648597600000_i64, "$expirationDate::1": 2005603200000_i64,
                "$addressRef::1": "ref"}},
            {"title": "ID", "$type": "ssnCard", "custom_fields": {"$accountNumber:identityNumber:1": "S1"}},
            {"title": "Born", "$type": "birthCertificate", "custom_fields": {"$accountNumber:certificateNumber:1": "B1"}},
            {"title": "Editor", "$type": "softwareLicense", "notes": "n", "custom_fields": {
                "$licenseNumber::1": "AAAA", "$expirationDate::1": 2005603200000_i64, "$date:dateActive:1": 1692057600000_i64}},
            {"title": "Locker", "$type": "gymLocker", "custom_fields": {
                "$text:Row:1": "5", "$pinCode::1": "4321", "$url::1": "https://gym.example"}},
            {"title": "Member", "$type": "membership", "custom_fields": {"$accountNumber::1": "M1"}},
            {"title": "Team", "$type": "teamSite", "login": "me", "password": "pw"},
        ]}));
        let ItemDetails::IdDocument(license) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(license.document_type.as_deref(), Some("driverLicense"));
        assert_eq!(license.number.as_deref(), Some("D1"));
        assert_eq!(license.full_name.as_deref(), Some("Omar Khalil"));
        assert_eq!(license.birth_date.as_deref(), Some("1990-07-21"));
        assert_eq!(license.expiry_date.as_deref(), Some("2033-07-22"));
        assert_eq!(license.custom_fields.as_ref().unwrap()[0].value, "ref");
        let ItemDetails::IdDocument(card) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(card.document_type.as_deref(), Some("nationalId"));
        let ItemDetails::IdDocument(birth) = &result.items[2].details else {
            panic!()
        };
        assert_eq!(birth.document_type.as_deref(), Some("other"));
        assert_eq!(birth.number.as_deref(), Some("B1"));
        let ItemDetails::SoftwareLicense(software) = &result.items[3].details else {
            panic!()
        };
        assert_eq!(software.license_key.as_deref(), Some("AAAA"));
        assert_eq!(software.expiry_date.as_deref(), Some("2033-07-22"));
        assert_eq!(
            software.custom_fields.as_ref().unwrap()[0].label,
            "Date active"
        );
        let ItemDetails::Custom(locker) = &result.items[4].details else {
            panic!()
        };
        assert_eq!(locker.template_name.as_deref(), Some("gymLocker"));
        let fields: Vec<_> = locker
            .fields
            .iter()
            .map(|f| (f.label.as_str(), f.value.as_str(), f.kind.as_str()))
            .collect();
        assert!(fields.contains(&("Row", "5", "text")), "{fields:?}");
        assert!(fields.contains(&("PIN", "4321", "hidden")), "{fields:?}");
        assert!(
            fields.contains(&("Website", "https://gym.example", "url")),
            "{fields:?}"
        );
        assert_eq!(result.items[5].overview.item_type, ItemType::SecureNote);
        assert_eq!(result.items[6].overview.item_type, ItemType::Login);
    }

    #[test]
    fn empty_records_are_skipped() {
        let result = json_import(json!({"records": [
            {"$type": "bankCard"}, {"$type": "contact"}, {"$type": "wifiCredentials"}, "not a record"
        ]}));
        assert!(result.items.is_empty());
        assert_eq!(result.skipped, 4);
        assert_eq!(result.warnings[3], "Record 4 skipped: it isn't a record.");
    }

    #[test]
    fn csv_header_rows() {
        let keeper = "Folder,Title,Login,Password,Website Address,Notes\n,A,u,p,,\n";
        let result = parse(keeper.as_bytes(), &ImportOptions::default()).unwrap();
        assert_eq!(result.items.len(), 1);
        let other =
            "url,username,password,totp,extra,name,grouping,fav\nhttps://a.com,u,p,,,A,,0\n";
        assert!(parse(other.as_bytes(), &ImportOptions::default()).is_err());
    }
}
