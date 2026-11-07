//! Dashlane exports: the CSV export (a ZIP of `credentials.csv`, `securenotes.csv`,
//! `payments.csv`, `ids.csv` and `personalInfo.csv`, or one of those files on its own) and the
//! older JSON export (`AUTHENTIFIANT`, `SECURENOTE`, `PAYMENTMEANS_CREDITCARD`, `IDENTITY` …).
//!
//! Credentials become logins (with their category as a tag), payment cards become cards, bank
//! accounts become bank accounts, IDs become ID documents and personal info becomes identities.
//! Other kinds become secure notes with every field kept. The encrypted `.dash` archive can't be
//! read.
//!
//! `credentials.csv` is `username,username2,username3,title,password,note,url,category,otpUrl`
//! (`otpSecret` before 2024); the CSVs have no ids or dates. Entries of the JSON export keep
//! their `id` (so importing the file again updates them), `creationDatetime` and
//! `userModificationDatetime` as their dates, and `lastUse` as when they were last used (Unix
//! seconds; field names as in Bitwarden's `dashlane-json-importer` test data).

use std::io::{Cursor, Read};

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::build::{
    Collector, ItemMeta, LoginFields, TypedItem, address, card, card_details, clean,
    clean_password, custom_field, expiry, extra_fields, identity, identity_details, iso_date,
    looks_secret, note, notes_with, skipped_row, timestamp,
};
use super::csv_table::CsvTable;
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;
use crate::item::{CardDetails, IdentityDetails};
use crate::item_fields::{is_iban, is_swift};

/// Each CSV is a few MB even for large vaults; this stops a ZIP bomb.
const MAX_FILE_LEN: u64 = 256 << 20;

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    if bytes.starts_with(b"PK\x03\x04") {
        return parse_zip(bytes);
    }
    let text = decode_text(bytes)?;
    if text.trim_start().starts_with('{') {
        return parse_json(&text);
    }
    let kind = Kind::from_header(&text).ok_or_else(invalid)?;
    let mut out = Collector::default();
    kind.parse(&text, &mut out)?;
    Ok(out.finish())
}

fn invalid() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This is not a Dashlane export (the ZIP of CSV files, one of its CSV files, or JSON).",
    )
}

/// The CSV files of the export, in the order they are imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Credentials,
    SecureNotes,
    Payments,
    Ids,
    PersonalInfo,
}

impl Kind {
    fn from_file_name(name: &str) -> Option<Self> {
        let base = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
        Some(match base.as_str() {
            "credentials.csv" => Self::Credentials,
            "securenotes.csv" => Self::SecureNotes,
            "payments.csv" => Self::Payments,
            "ids.csv" => Self::Ids,
            "personalinfo.csv" => Self::PersonalInfo,
            _ => return None,
        })
    }

    /// A lone CSV file, recognised by its first columns.
    fn from_header(text: &str) -> Option<Self> {
        let header = text.lines().next()?.to_ascii_lowercase();
        let columns: Vec<&str> = header
            .split(',')
            .map(|c| c.trim().trim_matches('"'))
            .collect();
        Some(match columns.as_slice() {
            ["username", ..] => Self::Credentials,
            ["title", "note", ..] => Self::SecureNotes,
            ["type", "account_name", ..] => Self::Payments,
            ["type", "number", ..] => Self::Ids,
            ["type", "title", ..] => Self::PersonalInfo,
            _ => return None,
        })
    }

    fn parse(self, text: &str, out: &mut Collector) -> Result<(), ImportError> {
        // Dashlane writes files with no rows, sometimes without even a header.
        if text.trim().is_empty() {
            return Ok(());
        }
        let table = CsvTable::parse(text, b',')?;
        match self {
            Self::Credentials => credentials(table, out),
            Self::SecureNotes => secure_notes(table, out),
            Self::Payments => payments(table, out),
            Self::Ids => ids(table, out),
            Self::PersonalInfo => personal_info(&table, out),
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Credentials => "credentials.csv",
            Self::SecureNotes => "securenotes.csv",
            Self::Payments => "payments.csv",
            Self::Ids => "ids.csv",
            Self::PersonalInfo => "personalInfo.csv",
        }
    }

    /// Columns a file must have to be read.
    fn required(self) -> &'static [&'static str] {
        match self {
            Self::Credentials => &["username", "title", "password", "url"],
            Self::SecureNotes => &["title", "note"],
            Self::Payments => &["type", "account_name", "cc_number"],
            Self::Ids => &["type", "number", "name"],
            Self::PersonalInfo => &["type", "first_name", "last_name"],
        }
    }
}

fn parse_zip(bytes: &[u8]) -> Result<ImportResult, ImportError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid())?;
    let mut out = Collector::default();
    let mut files: Vec<(Kind, Zeroizing<String>)> = Vec::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|_| invalid())?;
        if file.is_dir() {
            continue;
        }
        let Ok(name) = file.name().map(|name| name.into_owned()) else {
            continue;
        };
        let Some(kind) = Kind::from_file_name(&name) else {
            out.warn(format!(
                "\"{name}\" was skipped: Octa Pass doesn't know this Dashlane file."
            ));
            continue;
        };
        let mut data = Zeroizing::new(Vec::new());
        file.take(MAX_FILE_LEN)
            .read_to_end(&mut data)
            .map_err(|_| invalid())?;
        files.push((kind, decode_text(&data)?));
    }
    if files.is_empty() {
        return Err(ImportError::new(
            Error::InvalidImportFile,
            "This is not a Dashlane export: the ZIP has none of credentials.csv, securenotes.csv, payments.csv, ids.csv or personalInfo.csv.",
        ));
    }
    files.sort_by_key(|(kind, _)| *kind);
    for (kind, text) in &files {
        if let Err(error) = kind.parse(text, &mut out) {
            out.warn(format!(
                "{} was skipped: {}",
                kind.file_name(),
                error.detail
            ));
        }
    }
    Ok(out.finish())
}

fn check_columns(table: &CsvTable, kind: Kind) -> Result<(), ImportError> {
    if kind.required().iter().all(|c| table.has(&[c])) {
        Ok(())
    } else {
        Err(ImportError::new(
            Error::InvalidImportFile,
            "its columns aren't the ones Dashlane writes.",
        ))
    }
}

fn credentials(mut table: CsvTable, out: &mut Collector) -> Result<(), ImportError> {
    check_columns(&table, Kind::Credentials)?;
    let username = table.take(&["username"]);
    let username2 = table.take(&["username2"]);
    let username3 = table.take(&["username3"]);
    let title = table.take(&["title"]);
    let password = table.take(&["password"]);
    let note_column = table.take(&["note"]);
    let url = table.take(&["url"]);
    let category = table.take(&["category"]);
    // `otpUrl` replaced `otpSecret` in 2024.
    let otp_url = table.take(&["otpUrl"]);
    let otp_secret = table.take(&["otpSecret"]);
    for row in &table.rows {
        let mut custom = Vec::new();
        for (label, column) in [("Username 2", username2), ("Username 3", username3)] {
            if let Some(value) = clean(row.get(column)) {
                custom.push(custom_field(label, &value, false));
            }
        }
        custom.extend(extra_fields(table.extras(row)));
        let fields = LoginFields {
            title: clean(row.get(title)),
            urls: clean(row.get(url)).into_iter().collect(),
            username: clean(row.get(username)),
            password: clean_password(row.get(password)),
            totp: clean(row.get(otp_url)).or_else(|| clean(row.get(otp_secret))),
            notes: clean(row.get(note_column)),
            tags: clean(row.get(category)).into_iter().collect(),
            custom_fields: custom,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(())
}

fn secure_notes(mut table: CsvTable, out: &mut Collector) -> Result<(), ImportError> {
    check_columns(&table, Kind::SecureNotes)?;
    let title = table.take(&["title"]);
    let note_column = table.take(&["note"]);
    let category = table.take(&["category"]);
    for row in &table.rows {
        out.add(note(
            clean(row.get(title)),
            clean(row.get(category)).into_iter().collect(),
            false,
            notes_with(&table.extras(row), clean(row.get(note_column))),
        ));
    }
    Ok(())
}

fn payments(mut table: CsvTable, out: &mut Collector) -> Result<(), ImportError> {
    check_columns(&table, Kind::Payments)?;
    let kind = table.take(&["type"]);
    let account_name = table.take(&["account_name"]);
    let holder = table.take(&["account_holder"]);
    let number = table.take(&["cc_number"]);
    let code = table.take(&["code"]);
    let month = table.take(&["expiration_month"]);
    let year = table.take(&["expiration_year"]);
    let note_column = table.take(&["note"]);
    let name = table.take(&["name"]);
    let routing = table.take(&["routing_number"]);
    let account_number = table.take(&["account_number"]);
    let issuing_bank = table.take(&["issuing_bank"]);
    let country = table.take(&["country"]);
    for row in &table.rows {
        let mut lines: Vec<(String, String)> = [
            ("Routing number", routing),
            ("Account number", account_number),
            ("Issuing bank", issuing_bank),
            ("Country", country),
        ]
        .into_iter()
        .filter_map(|(label, column)| Some((label.to_string(), clean(row.get(column))?)))
        .collect();
        lines.extend(table.extras(row));
        let notes = clean(row.get(note_column));
        match clean(row.get(kind)).as_deref() {
            Some("bank") => {
                let named = clean(row.get(name));
                let mut bank = TypedItem::bank_account();
                bank.set("bankName", clean(row.get(issuing_bank)));
                bank.set("accountHolder", clean(row.get(holder)));
                set_bank_numbers(
                    &mut bank,
                    clean(row.get(account_number)),
                    clean(row.get(routing)),
                );
                for (label, column) in [
                    (
                        "Account name",
                        if named.is_some() { account_name } else { None },
                    ),
                    ("Country", country),
                    ("Card number", number),
                    ("Security code", code),
                    ("Expiry month", month),
                    ("Expiry year", year),
                ] {
                    if let Some(value) = clean(row.get(column)) {
                        bank.custom(label, &value, looks_secret(label));
                    }
                }
                for (label, value) in table.extras(row) {
                    bank.custom(&label, &value, looks_secret(&label));
                }
                // The account name is the title when the item has no name of its own.
                let title = named
                    .or_else(|| clean(row.get(account_name)))
                    .or_else(|| Some("Bank account".into()));
                out.add(bank.build(title, vec![], false, notes));
            }
            // `credit_card` in older exports.
            Some("payment_card" | "credit_card") => {
                let expiry = row
                    .get(month)
                    .and_then(|m| m.trim().parse().ok())
                    .zip(row.get(year).and_then(|y| y.trim().parse().ok()))
                    .and_then(|(m, y)| expiry(m, y));
                let details = CardDetails {
                    cardholder: clean(row.get(holder)).or_else(|| clean(row.get(account_name))),
                    number: clean(row.get(number)),
                    cvv: clean(row.get(code)),
                    expiry,
                    notes: notes_with(&lines, notes),
                    ..card_details()
                };
                let title = clean(row.get(name)).or_else(|| clean(row.get(account_name)));
                out.add(card(title, vec![], false, details));
            }
            _ => {
                // The account name is the title when the item has no name of its own.
                let named = clean(row.get(name));
                let title = named
                    .clone()
                    .or_else(|| clean(row.get(account_name)))
                    .or_else(|| Some("Payment".into()));
                let mut all = Vec::new();
                for (label, column) in [
                    (
                        "Account name",
                        if named.is_some() { account_name } else { None },
                    ),
                    ("Account holder", holder),
                    ("Card number", number),
                    ("Security code", code),
                    ("Expiry month", month),
                    ("Expiry year", year),
                ] {
                    if let Some(value) = clean(row.get(column)) {
                        all.push((label.to_string(), value));
                    }
                }
                all.extend(lines);
                out.add(note(title, vec![], false, notes_with(&all, notes)));
            }
        }
    }
    Ok(())
}

fn ids(mut table: CsvTable, out: &mut Collector) -> Result<(), ImportError> {
    check_columns(&table, Kind::Ids)?;
    let kind = table.take(&["type"]);
    let number = table.take(&["number"]);
    let name = table.take(&["name"]);
    let issued = table.take(&["issue_date"]);
    let expires = table.take(&["expiration_date"]);
    let place = table.take(&["place_of_issue"]);
    let state = table.take(&["state"]);
    for row in &table.rows {
        let kind = clean(row.get(kind)).unwrap_or_default();
        let (label, document_type) = id_kind(&kind);
        let holder = clean(row.get(name));
        let title = match &holder {
            Some(holder) => format!("{label} ({holder})"),
            None => label.to_string(),
        };
        let mut document = TypedItem::id_document(document_type);
        if document_type == "other" {
            document.custom("Type", label, false);
        }
        document.set("number", clean(row.get(number)));
        document.set("fullName", holder);
        document.set("issueDate", clean(row.get(issued)));
        document.set("expiryDate", clean(row.get(expires)));
        document.set("issuer", clean(row.get(place)));
        if let Some(state) = clean(row.get(state)) {
            document.custom("State", &state, false);
        }
        for (label, value) in table.extras(row) {
            document.custom(&label, &value, looks_secret(&label));
        }
        out.add(document.build(Some(title), vec![], false, None));
    }
    Ok(())
}

/// What an entry of `ids.csv` or the JSON export is: its name, and its `documentType`.
fn id_kind(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "card" | "IDCARD" => ("ID card", "nationalId"),
        "passport" | "PASSPORT" => ("Passport", "passport"),
        "license" | "DRIVERLICENCE" => ("Driving licence", "driverLicense"),
        "social_security" | "SOCIALSECURITYSTATEMENT" => ("Social security number", "other"),
        "tax_number" | "FISCALSTATEMENT" => ("Tax number", "other"),
        _ => ("ID", "other"),
    }
}

/// Dashlane has an account number and a routing number; outside the US they hold the IBAN and BIC.
fn set_bank_numbers(bank: &mut TypedItem, account: Option<String>, routing: Option<String>) {
    match account {
        Some(account) if is_iban(&account) => bank.set("iban", Some(account)),
        account => bank.set("accountNumber", account),
    }
    match routing {
        Some(routing) if is_swift(&routing) => bank.set("swift", Some(routing)),
        routing => bank.set("routingNumber", routing),
    }
}

/// `personalInfo.csv` has one row per name, email, phone number, address or website. With one
/// name, all rows make one identity (as Dashlane shows them); otherwise each row is its own.
fn personal_info(table: &CsvTable, out: &mut Collector) -> Result<(), ImportError> {
    check_columns(table, Kind::PersonalInfo)?;
    let rows: Vec<Map<String, Value>> = table
        .rows
        .iter()
        .map(|row| {
            table
                .headers
                .iter()
                .zip(row.cells())
                .filter_map(|(header, cell)| {
                    Some((
                        header.to_ascii_lowercase(),
                        Value::String(clean(Some(cell))?),
                    ))
                })
                .collect()
        })
        .collect();
    let names = rows
        .iter()
        .filter(|row| row.get("type").and_then(Value::as_str) == Some("name"))
        .count();
    if names == 1 {
        let mut details = identity_details();
        let mut lines = Vec::new();
        let mut title = None;
        for row in rows {
            if row.get("type").and_then(Value::as_str) == Some("name") {
                title = text(&row, "item_name");
            }
            fill_identity(row, &mut details, &mut lines);
        }
        let title = title.or_else(|| full_name(&details));
        details.notes = notes_with(&lines, None);
        out.add(identity(title, vec![], false, details));
    } else {
        for row in rows {
            let mut details = identity_details();
            let mut lines = Vec::new();
            let title = text(&row, "item_name");
            fill_identity(row, &mut details, &mut lines);
            let title = title.or_else(|| full_name(&details));
            details.notes = notes_with(&lines, None);
            out.add(identity(title, vec![], false, details));
        }
    }
    Ok(())
}

/// Adds one personal info row: the first email, phone and address fill the identity's own
/// fields, everything else becomes a note line.
fn fill_identity(
    mut row: Map<String, Value>,
    details: &mut IdentityDetails,
    lines: &mut Vec<(String, String)>,
) {
    let mut take = |key: &str| row.remove(key).and_then(|v| clean(v.as_str()));
    let kind = take("type").unwrap_or_default();
    take("item_name");
    match kind.as_str() {
        "name" => {
            let first = [take("first_name"), take("middle_name")];
            details.first_name = clean(Some(
                &first.into_iter().flatten().collect::<Vec<_>>().join(" "),
            ));
            details.last_name = take("last_name");
            if let Some(date) = take("date_of_birth") {
                match iso(&date) {
                    Some(date) => details.birth_date = Some(date),
                    None => lines.push(("Date of birth".into(), date)),
                }
            }
        }
        "email" if details.email.is_none() => details.email = take("email"),
        "number" if details.phone.is_none() => details.phone = take("phone_number"),
        "address" if details.address.is_none() => {
            let building = [take("address_building"), take("address_apartment")];
            details.address = address(
                take("address"),
                clean(Some(
                    &building
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(", "),
                )),
                take("city"),
                take("state"),
                take("zip"),
                take("country"),
            );
        }
        _ => {}
    }
    for (key, value) in row {
        if let Some(value) = clean(value.as_str()) {
            lines.push((label(&key), value));
        }
    }
}

fn full_name(details: &IdentityDetails) -> Option<String> {
    clean(Some(
        &[details.first_name.as_deref(), details.last_name.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
    ))
}

/// `address_door_code` → `Address door code`.
fn label(key: &str) -> String {
    let words = key.replace('_', " ");
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => words,
    }
}

/// `Jane Q Public` → (`Jane Q`, `Public`).
fn split_name(name: &str) -> (Option<String>, Option<String>) {
    match name.trim().rsplit_once(' ') {
        Some((first, last)) => (clean(Some(first)), clean(Some(last))),
        None => (clean(Some(name)), None),
    }
}

/// Dashlane writes dates as `YYYY-M-D`; this pads them to `YYYY-MM-DD`.
fn iso(text: &str) -> Option<String> {
    let mut parts = text.trim().splitn(3, '-');
    let year = parts.next()?.trim().parse().ok()?;
    let month = parts.next()?.trim().parse().ok()?;
    let day = parts.next()?.trim().parse().ok()?;
    iso_date(year, month, day)
}

/// Metadata keys of the JSON export that aren't the user's data (the dates and id are read
/// into [`ItemMeta`]).
const JSON_METADATA: [&str; 9] = [
    "id",
    "anonId",
    "spaceId",
    "localeFormat",
    "creationDatetime",
    "userModificationDatetime",
    "lastUse",
    "lastBackupTime",
    "creationDate",
];

/// Sections of the JSON export; a file needs one of them to be read as Dashlane's.
const JSON_SECTIONS: [&str; 14] = [
    "AUTHENTIFIANT",
    "SECURENOTE",
    "PAYMENTMEANS_CREDITCARD",
    "PAYMENTMEAN_PAYPAL",
    "BANKSTATEMENT",
    "IDENTITY",
    "ADDRESS",
    "EMAIL",
    "PHONE",
    "IDCARD",
    "PASSPORT",
    "DRIVERLICENCE",
    "SOCIALSECURITYSTATEMENT",
    "FISCALSTATEMENT",
];

/// The older JSON export: an object of sections, each a list of objects of text values.
fn parse_json(json_text: &str) -> Result<ImportResult, ImportError> {
    let data: Value = serde_json::from_str(json_text).map_err(|_| invalid())?;
    let sections = data.as_object().ok_or_else(invalid)?;
    if !JSON_SECTIONS.iter().any(|key| sections.contains_key(*key)) {
        return Err(invalid());
    }
    let mut out = Collector::default();
    let mut others = 0;
    for (section, entries) in sections {
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(entry) = entry.as_object() else {
                out.skip(Some(format!(
                    "{section} entry {} skipped: not an item.",
                    index + 1
                )));
                continue;
            };
            let mut fields: Map<String, Value> = entry
                .iter()
                .filter(|(key, _)| !JSON_METADATA.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let place = format!("{section} entry {}", index + 1);
            let date = |key: &str| timestamp(entry.get(key).and_then(scalar).as_deref());
            let meta = ItemMeta {
                created_at: date("creationDatetime").or_else(|| date("creationDate")),
                updated_at: date("userModificationDatetime"),
                last_used_at: date("lastUse"),
                source_id: text(entry, "id"),
            };
            let before = out.count();
            match section.as_str() {
                "AUTHENTIFIANT" => json_login(fields, &place, &mut out),
                "PAYMENTMEAN_PAYPAL" => {
                    let mut take = |key: &str| take_text(&mut fields, key);
                    let login = LoginFields {
                        title: take("name").or_else(|| Some("PayPal".into())),
                        urls: vec!["https://www.paypal.com".into()],
                        username: take("login"),
                        password: take_password(&mut fields, "password"),
                        custom_fields: extra_fields(lines_of(fields)),
                        ..LoginFields::default()
                    };
                    out.add_login(login, || format!("{place} skipped: it has no fields."));
                }
                "SECURENOTE" => {
                    let title = take_text(&mut fields, "title");
                    let content = take_text(&mut fields, "content")
                        .or_else(|| take_text(&mut fields, "note"));
                    let category = take_text(&mut fields, "category");
                    out.add(note(
                        title,
                        category.into_iter().collect(),
                        false,
                        notes_with(&lines_of(fields), content),
                    ));
                }
                "PAYMENTMEANS_CREDITCARD" => json_card(fields, &mut out),
                "BANKSTATEMENT" => json_bank(fields, &mut out),
                "IDCARD"
                | "PASSPORT"
                | "DRIVERLICENCE"
                | "SOCIALSECURITYSTATEMENT"
                | "FISCALSTATEMENT" => json_id(section, fields, &mut out),
                "IDENTITY" | "ADDRESS" | "EMAIL" | "PHONE" => {
                    json_identity(section, fields, &mut out)
                }
                _ => {
                    others += 1;
                    let title = ["title", "name", "Fullname", "fullName", "BankAccountName"]
                        .iter()
                        .find_map(|key| take_text(&mut fields, key))
                        .unwrap_or_else(|| label(&section.to_lowercase()));
                    let mut lines = vec![("Type".to_string(), section.clone())];
                    lines.extend(lines_of(fields));
                    out.add(note(Some(title), vec![], false, notes_with(&lines, None)));
                }
            }
            out.meta_since(before, &meta);
        }
    }
    if others > 0 {
        out.warn(format!(
            "{others} {} of a type Octa Pass doesn't have yet {} imported as secure notes.",
            if others == 1 { "item" } else { "items" },
            if others == 1 { "was" } else { "were" }
        ));
    }
    Ok(out.finish())
}

fn json_login(mut fields: Map<String, Value>, place: &str, out: &mut Collector) {
    let mut take = |key: &str| take_text(&mut fields, key);
    let title = take("title");
    let login = take("login");
    let secondary = take("secondaryLogin");
    let email = take("email");
    let url = take("domain").or_else(|| take("url"));
    let notes = take("note");
    let totp = take("otpUrl").or_else(|| take("otpSecret"));
    let category = take("category");
    let password = take_password(&mut fields, "password");
    // The first of login, secondary login and email is the username; the others are kept.
    let mut names = [("Secondary login", secondary), ("Email", email)]
        .into_iter()
        .filter_map(|(label, value)| Some((label, value?)));
    let username = login.or_else(|| names.next().map(|(_, value)| value));
    let mut custom: Vec<_> = names
        .map(|(label, value)| custom_field(label, &value, false))
        .collect();
    custom.extend(extra_fields(lines_of(fields)));
    let place = place.to_string();
    out.add_login(
        LoginFields {
            title,
            urls: url.into_iter().collect(),
            username,
            password,
            totp,
            notes,
            tags: category.into_iter().collect(),
            custom_fields: custom,
            ..LoginFields::default()
        },
        || format!("{place} skipped: it has no fields."),
    );
}

fn json_card(mut fields: Map<String, Value>, out: &mut Collector) {
    let mut take = |key: &str| take_text(&mut fields, key);
    let name = take("name");
    let bank = take("bank");
    let month = take("expireMonth").and_then(|m| m.parse().ok());
    let year = take("expireYear").and_then(|y| y.parse().ok());
    let details = CardDetails {
        cardholder: take("owner").or_else(|| take("ownerName")),
        number: take("cardNumber"),
        cvv: take("securityCode"),
        brand: take("type").or_else(|| take("cardType")),
        expiry: month.zip(year).and_then(|(m, y)| expiry(m, y)),
        ..card_details()
    };
    let mut lines = Vec::new();
    // `bank` is written as `ISSUER|CODE` by some versions.
    let title = name.or_else(|| bank.as_deref().and_then(|b| clean(b.split('|').next())));
    if let Some(bank) = bank {
        lines.push(("Bank".to_string(), bank));
    }
    let note_text = take_text(&mut fields, "cCNote").or_else(|| take_text(&mut fields, "note"));
    lines.extend(lines_of(fields));
    out.add(card(
        title,
        vec![],
        false,
        CardDetails {
            notes: notes_with(&lines, note_text),
            ..details
        },
    ));
}

fn json_bank(mut fields: Map<String, Value>, out: &mut Collector) {
    let mut bank = TypedItem::bank_account();
    let title = take_text(&mut fields, "BankAccountName");
    bank.set("accountHolder", take_text(&mut fields, "BankAccountOwner"));
    bank.set("bankName", take_text(&mut fields, "BankAccountBank"));
    bank.set("iban", take_text(&mut fields, "BankAccountIBAN"));
    bank.set("swift", take_text(&mut fields, "BankAccountBIC"));
    for (label, value) in lines_of(fields) {
        bank.custom(&label, &value, looks_secret(&label));
    }
    let title = title.or_else(|| Some("Bank account".into()));
    out.add(bank.build(title, vec![], false, None));
}

/// The ID sections of the JSON export. Dashlane's own names for these keys aren't documented, so
/// these are best guesses; whatever isn't recognised stays as a custom field.
fn json_id(section: &str, mut fields: Map<String, Value>, out: &mut Collector) {
    let mut take = |keys: &[&str]| keys.iter().find_map(|key| take_text(&mut fields, key));
    let (label, document_type) = id_kind(section);
    let mut document = TypedItem::id_document(document_type);
    if document_type == "other" {
        document.custom("Type", label, false);
    }
    let holder = take(&["fullname", "fullName", "socialSecurityFullname"]);
    let title = take(&["title", "name"]).or_else(|| {
        Some(match &holder {
            Some(holder) => format!("{label} ({holder})"),
            None => label.to_string(),
        })
    });
    document.set(
        "number",
        take(&["number", "socialSecurityNumber", "fiscalNumber"]),
    );
    document.set("fullName", holder);
    document.set("birthDate", take(&["dateOfBirth", "birthDate"]));
    document.set("issueDate", take(&["deliveryDate", "issueDate"]));
    document.set("expiryDate", take(&["expireDate", "expiryDate"]));
    document.set("issuer", take(&["deliveryPlace", "placeOfIssue"]));
    for (label, value) in lines_of(fields) {
        document.custom(&label, &value, looks_secret(&label));
    }
    out.add(document.build(title, vec![], false, None));
}

fn json_identity(section: &str, mut fields: Map<String, Value>, out: &mut Collector) {
    let mut take = |key: &str| take_text(&mut fields, key);
    let mut details = identity_details();
    let title = match section {
        "IDENTITY" => {
            let first = [take("firstName"), take("middleName")];
            details.first_name = clean(Some(
                &first.into_iter().flatten().collect::<Vec<_>>().join(" "),
            ));
            details.last_name = take("lastName");
            let full = take("fullName");
            if details.first_name.is_none()
                && details.last_name.is_none()
                && let Some(full) = &full
            {
                (details.first_name, details.last_name) = split_name(full);
            }
            details.birth_date = fields
                .get("birthDate")
                .and_then(Value::as_str)
                .and_then(iso);
            if details.birth_date.is_some() {
                fields.remove("birthDate");
            }
            full.or_else(|| full_name(&details))
        }
        "ADDRESS" => {
            details.address = address(
                take("addressFull").or_else(|| take("streetName")),
                None,
                take("city"),
                take("state"),
                take("zipcode").or_else(|| take("zipCode")),
                take("country"),
            );
            take("addressName")
        }
        "EMAIL" => {
            details.email = take("email");
            take("emailName").or_else(|| details.email.clone())
        }
        _ => {
            details.phone = take("number");
            take("phoneName").or_else(|| details.phone.clone())
        }
    };
    let mut lines = Vec::new();
    if let Some(pseudo) = take_text(&mut fields, "pseudo") {
        lines.push(("Username".to_string(), pseudo));
    }
    lines.extend(lines_of(fields));
    details.notes = notes_with(&lines, None);
    out.add(identity(title, vec![], false, details));
}

fn take_text(fields: &mut Map<String, Value>, key: &str) -> Option<String> {
    scalar(&fields.remove(key)?)
}

fn take_password(fields: &mut Map<String, Value>, key: &str) -> Option<String> {
    clean_password(fields.remove(key)?.as_str())
}

/// The remaining text values as `(key, value)`, for custom fields or note lines.
fn lines_of(fields: Map<String, Value>) -> Vec<(String, String)> {
    fields
        .into_iter()
        .filter_map(|(key, value)| Some((key, scalar(&value)?)))
        .collect()
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => clean(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn text(row: &Map<String, Value>, key: &str) -> Option<String> {
    clean(row.get(key)?.as_str())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::item::{ItemDetails, ItemType};

    fn import(text: &str) -> ImportResult {
        parse(text.as_bytes(), &ImportOptions::default()).unwrap()
    }

    #[test]
    fn credentials_with_otp_and_extra_usernames() {
        let result = import(
            "username,username2,username3,title,password,note,url,category,otpUrl\n\
             jane,jane2,,GitHub,pw,\"multi\nline\",https://github.com,Work,otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&lock=false\n\
             ,,,,,,,,\n",
        );
        assert_eq!(result.items.len(), 1);
        let item = &result.items[0];
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Work"]);
        let ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert!(login.totp.as_deref().unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(login.custom_fields.as_ref().unwrap()[0].value, "jane2");
        assert_eq!(login.notes.as_deref(), Some("multi\nline"));
    }

    #[test]
    fn payment_cards_and_banks() {
        let result = import(
            "type,account_name,account_holder,cc_number,code,expiration_month,expiration_year,routing_number,account_number,country,issuing_bank,note,name\n\
             payment_card,JANE DOE,,4111111111111111,123,3,2030,,,US,Big Bank,n,My Visa\n\
             bank,Checking,Jane Doe,,,,,021000021,123456,US,Big Bank,,\n",
        );
        let ItemDetails::Card(card) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(result.items[0].overview.title, "My Visa");
        assert_eq!(card.cardholder.as_deref(), Some("JANE DOE"));
        assert_eq!(card.expiry.as_deref(), Some("03/30"));
        assert_eq!(
            card.notes.as_deref(),
            Some("Issuing bank: Big Bank\nCountry: US\nn")
        );
        let ItemDetails::BankAccount(bank) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(result.items[1].overview.title, "Checking");
        assert_eq!(
            result.items[1].overview.subtitle.as_deref(),
            Some("Big Bank")
        );
        assert_eq!(bank.account_number.as_deref(), Some("123456"));
        assert_eq!(bank.routing_number.as_deref(), Some("021000021"));
        assert_eq!(bank.account_holder.as_deref(), Some("Jane Doe"));
        assert_eq!(bank.custom_fields.as_ref().unwrap()[0].value, "US");
    }

    #[test]
    fn european_banks_put_their_iban_and_bic_in_the_number_columns() {
        let result = import(
            "type,account_name,account_holder,cc_number,code,expiration_month,expiration_year,routing_number,account_number,country,issuing_bank,note,name\n\
             bank,Girokonto,Jane,,,,,COBADEFFXXX,DE89370400440532013000,DE,Bank,,\n",
        );
        let ItemDetails::BankAccount(bank) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(bank.iban.as_deref(), Some("DE89370400440532013000"));
        assert_eq!(bank.swift.as_deref(), Some("COBADEFFXXX"));
        assert_eq!(bank.account_number, None);
    }

    #[test]
    fn ids_and_dates() {
        let result = import(
            "type,number,name,issue_date,expiration_date,place_of_issue,state\n\
             passport,P123,Omar K Haddad,2020-1-5,2030-1-4,Amman,\n\
             license,D1,Jane,soon,,,CA\n\
             tax_number,T1,,,,,\n",
        );
        let item = &result.items[0];
        assert_eq!(item.overview.title, "Passport (Omar K Haddad)");
        let ItemDetails::IdDocument(id) = &item.details else {
            panic!()
        };
        assert_eq!(id.document_type.as_deref(), Some("passport"));
        assert_eq!(id.number.as_deref(), Some("P123"));
        assert_eq!(id.full_name.as_deref(), Some("Omar K Haddad"));
        assert_eq!(id.issue_date.as_deref(), Some("2020-01-05"));
        assert_eq!(id.expiry_date.as_deref(), Some("2030-01-04"));
        assert_eq!(id.issuer.as_deref(), Some("Amman"));
        let ItemDetails::IdDocument(license) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(license.document_type.as_deref(), Some("driverLicense"));
        let kept: Vec<_> = license.custom_fields.iter().flatten().collect();
        assert_eq!(
            kept.iter()
                .map(|f| (f.label.as_str(), f.value.as_str()))
                .collect::<Vec<_>>(),
            [("Issue date", "soon"), ("State", "CA")]
        );
        let ItemDetails::IdDocument(tax) = &result.items[2].details else {
            panic!()
        };
        assert_eq!(tax.document_type.as_deref(), Some("other"));
        assert_eq!(tax.custom_fields.as_ref().unwrap()[0].value, "Tax number");
        assert_eq!(iso("2020-13-1"), None);
    }

    #[test]
    fn json_ids_keep_unknown_keys() {
        let result = import(
            &json!({
                "PASSPORT": [{ "fullname": "Jane", "number": "P1", "deliveryDate": "2020-02-01",
                    "expireDate": "2030-02-01", "deliveryPlace": "Paris", "sex": "F", "id": "{P}" }],
                "SOCIALSECURITYSTATEMENT": [{ "socialSecurityFullname": "Jane", "socialSecurityNumber": "1 23" }]
            })
            .to_string(),
        );
        let ItemDetails::IdDocument(passport) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(result.items[0].overview.title, "Passport (Jane)");
        assert_eq!(
            result.items[0].overview.imported_from.as_ref().unwrap().id,
            "{P}"
        );
        assert_eq!(passport.expiry_date.as_deref(), Some("2030-02-01"));
        assert_eq!(passport.issuer.as_deref(), Some("Paris"));
        assert_eq!(passport.custom_fields.as_ref().unwrap()[0].label, "sex");
        let ItemDetails::IdDocument(social) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(social.number.as_deref(), Some("1 23"));
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[test]
    fn personal_info_with_one_name_is_one_identity() {
        let header = "type,title,first_name,middle_name,last_name,login,date_of_birth,place_of_birth,email,email_type,item_name,phone_number,address,country,state,city,zip,address_recipient,address_building,address_apartment,address_floor,address_door_code,job_title,url\n";
        let result = import(&format!(
            "{header}name,Mr,Jane,Q,Doe,jdoe,1990-2-3,Paris,,,Me,,,,,,,,,,,,Engineer,\n\
             email,,,,,,,,jane@example.com,personal,Email 1,,,,,,,,,,,,,\n\
             email,,,,,,,,work@example.com,business,Email 2,,,,,,,,,,,,,\n\
             address,,,,,,,,,,Home,,1 Main St,FR,,Paris,75001,,B,4,,1234,,\n"
        ));
        assert_eq!(result.items.len(), 1);
        let ItemDetails::Identity(id) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(result.items[0].overview.title, "Me");
        assert_eq!(id.first_name.as_deref(), Some("Jane Q"));
        assert_eq!(id.birth_date.as_deref(), Some("1990-02-03"));
        assert_eq!(id.email.as_deref(), Some("jane@example.com"));
        assert_eq!(id.address.as_ref().unwrap().line2.as_deref(), Some("B, 4"));
        let notes = id.notes.as_deref().unwrap();
        assert!(notes.contains("Email: work@example.com"), "{notes}");
        assert!(notes.contains("Address door code: 1234"), "{notes}");
        assert!(notes.contains("Job title: Engineer"), "{notes}");
    }

    #[test]
    fn json_sections() {
        let result = import(
            &json!({
                "AUTHENTIFIANT": [{ "title": "Site", "login": "u", "email": "e@example.com",
                    "password": "pw", "domain": "example.com", "note": "n", "id": "{X}", "autoLogin": "true",
                    "creationDatetime": 1600000000, "userModificationDatetime": "1650000000", "lastUse": 1700000000 }],
                "SECURENOTE": [{ "title": "Diary", "content": "dear diary", "category": "Personal" }],
                "PAYMENTMEANS_CREDITCARD": [{ "bank": "BANK|XX", "cardNumber": "4111111111111111",
                    "owner": "Jane", "securityCode": "321", "expireMonth": "4", "expireYear": "2031" }],
                "IDENTITY": [{ "fullName": "Jane Doe", "pseudo": "jd", "birthDate": "1990-01-02" }],
                "BANKSTATEMENT": [{ "BankAccountName": "Main", "BankAccountIBAN": "FR76" }],
                "BROKEN": ["not an object"]
            })
            .to_string(),
        );
        // Sections come in key order.
        let types: Vec<&ItemType> = result.items.iter().map(|i| &i.overview.item_type).collect();
        assert_eq!(
            types,
            [
                &ItemType::Login,
                &ItemType::BankAccount,
                &ItemType::Identity,
                &ItemType::Card,
                &ItemType::SecureNote
            ]
        );
        let ItemDetails::BankAccount(bank) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(bank.iban.as_deref(), Some("FR76"));
        assert_eq!(result.items[1].overview.title, "Main");
        let ItemDetails::Login(login) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(login.username.as_deref(), Some("u"));
        let overview = &result.items[0].overview;
        assert_eq!(overview.created_at.as_deref(), Some("2020-09-13T12:26:40Z"));
        assert_eq!(overview.updated_at.as_deref(), Some("2022-04-15T05:20:00Z"));
        assert_eq!(
            overview.last_used_at.as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(overview.imported_from.as_ref().unwrap().id, "{X}");
        let labels: Vec<&str> = login
            .custom_fields
            .as_ref()
            .unwrap()
            .iter()
            .map(|f| f.label.as_str())
            .collect();
        assert_eq!(labels, ["Email", "autoLogin"]);
        let ItemDetails::Card(card) = &result.items[3].details else {
            panic!()
        };
        assert_eq!(card.expiry.as_deref(), Some("04/31"));
        assert_eq!(result.items[3].overview.title, "BANK");
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn unknown_files_are_errors() {
        let error = parse(b"a,b\n1,2\n", &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile);
        assert!(parse(b"[1]", &ImportOptions::default()).is_err());
        assert!(parse(br#"{"a":1}"#, &ImportOptions::default()).is_err());
    }
}
