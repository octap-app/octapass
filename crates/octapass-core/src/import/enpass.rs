//! Enpass JSON export: `{ "folders": [...], "items": [...] }`, each item with a `category`
//! (`login`, `creditcard`, `identity`, `note`, `password`, `finance` …) and typed `fields`.
//!
//! Logins, cards, identities and notes map to their Octa Pass types, and the templates for bank
//! accounts, passports, driver's licences, ID cards, software licences, databases, servers and
//! crypto wallets (`template_type`, such as `finance.bankaccount`) to theirs: fields are read by
//! field type and English label, and whatever isn't recognised stays as a custom field. Other
//! categories (travel, vehicles …) become logins when they have a username or password and secure
//! notes otherwise, with every field kept. Folders (tags in Enpass) become tags; archived items
//! get the tag "archived"; trashed items are skipped. Attachments aren't imported.
//!
//! Each item's `uuid` is kept so importing the file again updates it, and `createdAt`,
//! `updated_at` and `last_used` (Unix seconds) become its dates; the password field's
//! `value_updated_at` is when the password changed. Field names as in Enpass's JSON export and
//! Bitwarden's `enpass-json-importer` types.

use std::collections::HashMap;

use serde_json::{Map, Value};

use super::build::{
    Collector, ItemMeta, LoginFields, TypedItem, address, card, card_details, clean,
    clean_password, custom_field, expiry, identity, identity_details, iso_date, note, notes_with,
    rfc3339, unix_time,
};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::error::Error;
use crate::item::{CardDetails, CustomField, PasswordHistoryEntry};

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let invalid = || {
        ImportError::new(
            Error::InvalidImportFile,
            "This is not an Enpass JSON export.",
        )
    };
    let text = decode_text(bytes)?;
    let data: Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    // Other apps' JSON (Bitwarden's) has `items` too, without Enpass's categories.
    let enpass_items = items
        .iter()
        .any(|item| item.get("category").is_some() || item.get("template_type").is_some());
    if !items.is_empty() && !enpass_items {
        return Err(invalid());
    }
    let folders = folder_paths(&data);
    let mut out = Collector::default();
    let mut stats = Stats::default();
    for (index, item) in items.iter().enumerate() {
        add_item(item, index + 1, &folders, &mut out, &mut stats);
    }
    stats.report(&mut out);
    Ok(out.finish())
}

#[derive(Default)]
struct Stats {
    trashed: usize,
    archived: usize,
    attachments: usize,
    other_categories: usize,
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
        if self.archived > 0 {
            out.warn(format!(
                "{} archived {} imported with the tag \"archived\".",
                self.archived,
                plural(self.archived, "item was", "items were")
            ));
        }
        if self.attachments > 0 {
            out.warn(format!(
                "Attachments can't be imported from Enpass: {} {} imported without {}. Add the files again in Octa Pass.",
                self.attachments,
                plural(self.attachments, "item was", "items were"),
                plural(self.attachments, "its files", "their files")
            ));
        }
        if self.other_categories > 0 {
            out.warn(format!(
                "{} {} of a type Octa Pass doesn't have yet (travel, vehicles …) {} imported as logins or secure notes.",
                self.other_categories,
                plural(self.other_categories, "item", "items"),
                plural(self.other_categories, "was", "were")
            ));
        }
    }
}

/// Folder uuids → `Parent/Child` paths.
fn folder_paths(data: &Value) -> HashMap<String, String> {
    let folders: HashMap<String, (Option<String>, String)> = data
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| {
            Some((
                text(f, "uuid")?,
                (text(f, "parent_uuid"), text(f, "title")?),
            ))
        })
        .collect();
    folders
        .keys()
        .map(|id| {
            let mut names = Vec::new();
            let mut current = Some(id);
            // The length check ends parent loops.
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

/// A field with a value. Section headings and deleted fields are left out.
struct Field<'a> {
    kind: &'a str,
    label: String,
    value: String,
    sensitive: bool,
    uid: Option<u64>,
    raw: &'a Value,
}

fn fields(item: &Value) -> Vec<Field<'_>> {
    item.get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| {
            let kind = field.get("type").and_then(Value::as_str).unwrap_or("text");
            if kind == "section" || field.get("deleted").and_then(Value::as_u64).unwrap_or(0) != 0 {
                return None;
            }
            let value = match field.get("value")? {
                Value::String(s) if !s.trim().is_empty() => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return None,
            };
            Some(Field {
                kind,
                label: text(field, "label").unwrap_or_else(|| kind.to_string()),
                value,
                sensitive: field.get("sensitive").and_then(Value::as_u64).unwrap_or(0) != 0,
                uid: field.get("uid").and_then(Value::as_u64),
                raw: field,
            })
        })
        .collect()
}

fn add_item(
    item: &Value,
    number: usize,
    folders: &HashMap<String, String>,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let flag = |key: &str| item.get(key).and_then(Value::as_u64).unwrap_or(0) != 0;
    if !item.is_object() {
        return out.skip(Some(format!("Item {number} skipped: not an item.")));
    }
    if flag("trashed") {
        stats.trashed += 1;
        return out.skip(None);
    }
    let mut tags: Vec<String> = item
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|id| folders.get(id.as_str()?).cloned())
        .collect();
    if flag("archived") {
        stats.archived += 1;
        tags.push("archived".into());
    }
    if item
        .get("attachments")
        .and_then(Value::as_array)
        .is_some_and(|files| !files.is_empty())
    {
        stats.attachments += 1;
    }
    let title = text(item, "title");
    let favorite = flag("favorite");
    let notes = text(item, "note");
    let fields = fields(item);
    // `category` is the template's prefix: `finance` for `finance.bankaccount`.
    let category = text(item, "category")
        .or_else(|| {
            text(item, "template_type").map(|t| t.split('.').next().unwrap_or_default().to_string())
        })
        .unwrap_or_default();
    let has_credentials = fields
        .iter()
        .any(|f| f.kind == "password" || f.kind == "username");
    let time = |key: &str| item.get(key).and_then(Value::as_i64).and_then(unix_time);
    let meta = ItemMeta {
        created_at: time("createdAt"),
        updated_at: time("updated_at"),
        last_used_at: time("last_used"),
        source_id: text(item, "uuid"),
    };
    let before = out.count();
    let template = text(item, "template_type").unwrap_or_default();

    match category.as_str() {
        _ if typed_template(&template).is_some() => {
            let kind = typed_template(&template).expect("checked");
            add_typed(kind, title, tags, favorite, notes, fields, out);
        }
        "creditcard" => add_card(title, tags, favorite, notes, fields, out),
        "identity" => add_identity(title, tags, favorite, notes, fields, out),
        "note" => out.add(note(
            title,
            tags,
            favorite,
            notes_with(&lines(&fields), notes),
        )),
        "login" | "password" => add_login(title, tags, favorite, notes, fields, number, out),
        _ => {
            stats.other_categories += 1;
            if has_credentials {
                add_login(title, tags, favorite, notes, fields, number, out);
            } else {
                out.add(note(
                    title,
                    tags,
                    favorite,
                    notes_with(&lines(&fields), notes),
                ));
            }
        }
    }
    out.meta_since(before, &meta);
}

/// The Enpass templates with an Octa Pass type of their own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Template {
    Bank,
    Passport,
    DriverLicense,
    IdCard,
    Software,
    Database,
    Server,
    Wallet,
}

/// Enpass's template names aren't documented beyond a few examples, so they're matched loosely.
fn typed_template(template: &str) -> Option<Template> {
    let name = template.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|word| name.contains(word));
    Some(if has(&["bankaccount", "bank_account"]) {
        Template::Bank
    } else if has(&["passport"]) {
        Template::Passport
    } else if has(&["driving", "driver"]) {
        Template::DriverLicense
    } else if has(&["idcard", "nationalid", "identitycard", "socialsecurity"]) {
        Template::IdCard
    } else if has(&["softwarelicen", "software"]) {
        Template::Software
    } else if has(&["database"]) {
        Template::Database
    } else if has(&["server", "webhosting"]) {
        Template::Server
    } else if has(&["crypto", "wallet"]) {
        Template::Wallet
    } else {
        return None;
    })
}

/// Which field a label means, by words in it; the first match wins.
const BANK_LABELS: &[(&str, &str)] = &[
    ("iban", "iban"),
    ("swift", "swift"),
    ("bic", "swift"),
    ("routing", "routingNumber"),
    ("sort code", "routingNumber"),
    ("account number", "accountNumber"),
    ("account type", "accountType"),
    ("type of account", "accountType"),
    ("holder", "accountHolder"),
    ("owner", "accountHolder"),
    ("branch", "branch"),
    ("bank name", "bankName"),
    ("pin", "pin"),
];
const DOCUMENT_LABELS: &[(&str, &str)] = &[
    ("expir", "expiryDate"),
    ("valid until", "expiryDate"),
    ("issue date", "issueDate"),
    ("date of issue", "issueDate"),
    ("issued on", "issueDate"),
    ("issued by", "issuer"),
    ("issuing authority", "issuer"),
    ("authority", "issuer"),
    ("country", "country"),
    ("birth", "birthDate"),
    ("number", "number"),
    ("name", "fullName"),
];
const SOFTWARE_LABELS: &[(&str, &str)] = &[
    ("licensed to", "licensedTo"),
    ("registered", "licensedTo"),
    ("key", "licenseKey"),
    ("version", "version"),
    ("publisher", "publisher"),
    ("email", "email"),
    ("order", "orderNumber"),
    ("purchase", "purchaseDate"),
    ("expir", "expiryDate"),
    ("product", "product"),
];
const DATABASE_LABELS: &[(&str, &str)] = &[
    ("type", "databaseType"),
    ("host", "host"),
    ("server", "host"),
    ("port", "port"),
    ("connection", "connectionString"),
    ("database", "database"),
    ("username", "username"),
    ("user", "username"),
    ("password", "password"),
];
const WALLET_LABELS: &[(&str, &str)] = &[
    ("seed", "seedPhrase"),
    ("recovery", "seedPhrase"),
    ("mnemonic", "seedPhrase"),
    ("passphrase", "passphrase"),
    ("wallet name", "walletName"),
];

fn add_typed(
    template: Template,
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
    fields: Vec<Field>,
    out: &mut Collector,
) {
    let (mut item, labels) = match template {
        Template::Bank => (TypedItem::bank_account(), BANK_LABELS),
        Template::Passport => (TypedItem::id_document("passport"), DOCUMENT_LABELS),
        Template::DriverLicense => (TypedItem::id_document("driverLicense"), DOCUMENT_LABELS),
        Template::IdCard => (TypedItem::id_document("nationalId"), DOCUMENT_LABELS),
        Template::Software => (TypedItem::software_license(), SOFTWARE_LABELS),
        Template::Database => (TypedItem::database(None), DATABASE_LABELS),
        Template::Server => (TypedItem::database(Some("server".into())), DATABASE_LABELS),
        Template::Wallet => (TypedItem::crypto_wallet(), WALLET_LABELS),
    };
    let database = matches!(template, Template::Database | Template::Server);
    for field in &fields {
        let label = field.label.to_lowercase();
        let key = labels
            .iter()
            .find(|(word, _)| label.contains(word))
            .map(|(_, key)| *key);
        match (field.kind, key) {
            ("url", _) => item.url(Some(field.value.clone())),
            ("ccBankname", _) if template == Template::Bank => {
                item.set("bankName", Some(field.value.clone()));
            }
            ("email", _) if template == Template::Software => {
                item.set("email", Some(field.value.clone()));
            }
            ("username", _) if database && !item.has("username") => {
                item.set("username", Some(field.value.clone()));
            }
            ("password", _) if database && !item.has("password") => {
                item.set("password", Some(field.value.clone()));
                item.password_history(history(field.raw));
            }
            // A key taken by an earlier field keeps this one as a field of its own.
            (kind, Some(key)) if !item.has(key) && kind != "password" && kind != "username" => {
                item.set(key, Some(field.value.clone()));
            }
            (_, None) if template == Template::Wallet && label.contains("address") => {
                item.address("", &field.value, None);
            }
            (kind, _) => {
                let hidden = field.sensitive || is_secret(kind);
                item.custom(&field.label, &field.value, hidden);
            }
        }
    }
    out.add(item.build(title, tags, favorite, notes));
}

fn add_login(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
    fields: Vec<Field>,
    number: usize,
    out: &mut Collector,
) {
    let mut password = None;
    let mut password_changed_at = None;
    let mut password_history = Vec::new();
    let mut totp = None;
    let mut urls = Vec::new();
    let mut custom: Vec<CustomField> = Vec::new();
    // An email only becomes the username when there is no username field.
    let username_index = fields
        .iter()
        .position(|f| f.kind == "username")
        .or_else(|| fields.iter().position(|f| f.kind == "email"));
    let username = username_index.map(|index| fields[index].value.clone());
    for (index, field) in fields.iter().enumerate() {
        if Some(index) == username_index {
            continue;
        }
        match field.kind {
            "password" if password.is_none() => {
                password = clean_password(Some(&field.value));
                password_changed_at = ["value_updated_at", "updated_at"]
                    .iter()
                    .find_map(|key| field.raw.get(*key)?.as_i64())
                    .and_then(unix_time);
                password_history = history(field.raw);
            }
            "totp" if totp.is_none() => totp = clean(Some(&field.value)),
            "url" => urls.extend(clean(Some(&field.value))),
            ".Android#" => custom.push(custom_field("Android app", &field.value, false)),
            _ => custom.push(custom_field(
                &field.label,
                &field.value,
                field.sensitive || is_secret(field.kind),
            )),
        }
    }
    let fields = LoginFields {
        title,
        urls,
        username,
        password,
        totp,
        notes,
        tags,
        favorite,
        custom_fields: custom,
        password_history,
        password_changed_at,
        ..LoginFields::default()
    };
    out.add_login(fields, || {
        format!("Item {number} skipped: no URL, username, password or notes.")
    });
}

/// Field types that hold secrets even when not marked sensitive.
fn is_secret(kind: &str) -> bool {
    matches!(
        kind,
        "password" | "pin" | "totp" | "ccCvc" | "ccPin" | "ccTxnpassword"
    )
}

/// Earlier values of the password field, oldest first as Enpass lists them.
fn history(field: &Value) -> Vec<PasswordHistoryEntry> {
    field
        .get("history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("encrypted").and_then(Value::as_bool) != Some(true))
        .filter_map(|entry| {
            Some(PasswordHistoryEntry {
                password: clean_password(entry.get("value")?.as_str())?,
                changed_at: rfc3339(entry.get("updated_at").and_then(Value::as_i64).unwrap_or(0)),
                extra: Map::new(),
            })
        })
        .collect()
}

fn add_card(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
    fields: Vec<Field>,
    out: &mut Collector,
) {
    let mut details = card_details();
    let mut rest = Vec::new();
    for field in fields {
        let value = Some(field.value.clone());
        match field.kind {
            "ccName" if details.cardholder.is_none() => {
                details.cardholder = clean(value.as_deref())
            }
            "ccNumber" if details.number.is_none() => details.number = clean(value.as_deref()),
            "ccCvc" if details.cvv.is_none() => details.cvv = clean(value.as_deref()),
            "ccPin" if details.pin.is_none() => details.pin = clean(value.as_deref()),
            "ccType" if details.brand.is_none() => details.brand = clean(value.as_deref()),
            "ccExpiry" if details.expiry.is_none() && card_expiry(&field.value).is_some() => {
                details.expiry = card_expiry(&field.value);
            }
            _ => rest.push(field),
        }
    }
    let notes = notes_with(&lines(&rest), notes);
    out.add(card(
        title,
        tags,
        favorite,
        CardDetails { notes, ..details },
    ));
}

/// `03/27` or `03/2027` → `03/27`.
fn card_expiry(value: &str) -> Option<String> {
    let (month, year) = value.trim().split_once('/')?;
    expiry(month.trim().parse().ok()?, year.trim().parse().ok()?)
}

/// Identity fields by their Enpass uid, which doesn't change with the app's language.
const FIRST_NAME: u64 = 130;
const MIDDLE_NAME: u64 = 131;
const LAST_NAME: u64 = 132;
const BIRTH_DATE: u64 = 134;
const STREET: u64 = 143;
const CITY: u64 = 144;
const STATE: u64 = 145;
const COUNTRY: u64 = 146;
const ZIP: u64 = 147;
const PHONE: u64 = 149;
const EMAIL: u64 = 165;

fn add_identity(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
    mut fields: Vec<Field>,
    out: &mut Collector,
) {
    let mut take = |uid: u64, kind: Option<&str>| {
        let index = fields
            .iter()
            .position(|f| f.uid == Some(uid))
            .or_else(|| kind.and_then(|kind| fields.iter().position(|f| f.kind == kind)))?;
        clean(Some(&fields.remove(index).value))
    };
    let mut details = identity_details();
    let first = [take(FIRST_NAME, None), take(MIDDLE_NAME, None)];
    details.first_name = clean(Some(
        &first.into_iter().flatten().collect::<Vec<_>>().join(" "),
    ));
    details.last_name = take(LAST_NAME, None);
    details.email = take(EMAIL, Some("email"));
    details.phone = take(PHONE, Some("phone"));
    details.address = address(
        take(STREET, None),
        None,
        take(CITY, None),
        take(STATE, None),
        take(ZIP, None),
        take(COUNTRY, None),
    );
    let mut lines = Vec::new();
    if let Some(date) = take(BIRTH_DATE, None) {
        match iso(&date) {
            Some(iso) => details.birth_date = Some(iso),
            None => lines.push(("Birth date".to_string(), date)),
        }
    }
    lines.extend(self::lines(&fields));
    details.notes = notes_with(&lines, notes);
    out.add(identity(title, tags, favorite, details));
}

fn iso(text: &str) -> Option<String> {
    let mut parts = text.trim().splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.parse().ok()?;
    iso_date(year, month, day)
}

fn lines(fields: &[Field]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|f| (f.label.clone(), f.value.clone()))
        .collect()
}

fn text(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) => clean(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::item::{ItemDetails, ItemType};

    fn import(value: Value) -> ImportResult {
        parse(value.to_string().as_bytes(), &ImportOptions::default()).unwrap()
    }

    fn field(kind: &str, label: &str, value: &str, sensitive: u8) -> Value {
        json!({ "type": kind, "label": label, "value": value, "sensitive": sensitive, "deleted": 0 })
    }

    #[test]
    fn logins_with_tags_history_and_extras() {
        let mut password = field("password", "Password", "new", 1);
        password["history"] = json!([
            { "encrypted": false, "updated_at": 0, "value": "old" },
            { "encrypted": true, "updated_at": 1, "value": "AAAA" }
        ]);
        let result = import(json!({
            "folders": [
                { "uuid": "p", "parent_uuid": "", "title": "Social" },
                { "uuid": "c", "parent_uuid": "p", "title": "Friends" }
            ],
            "items": [{
                "category": "login", "title": "Twitter", "favorite": 1, "note": "n",
                "folders": ["c"], "trashed": 0, "archived": 0,
                "fields": [
                    field("email", "E-mail", "me@example.com", 0),
                    field("username", "Username", "me", 0),
                    password,
                    field("url", "Website", "https://twitter.com", 0),
                    field("section", "ADDITIONAL", "", 0),
                    field("totp", "One-time code", "JBSW Y3DP EHPK 3PXP", 0),
                    field("text", "Security answer", "blue", 1),
                    json!({ "type": "text", "label": "Gone", "value": "x", "deleted": 1 })
                ]
            }]
        }));
        let item = &result.items[0];
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Social/Friends"]);
        assert_eq!(item.overview.favorite, Some(true));
        let ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert_eq!(login.username.as_deref(), Some("me"));
        assert_eq!(login.totp.as_deref(), Some("JBSW Y3DP EHPK 3PXP"));
        assert_eq!(login.password_history.as_ref().unwrap().len(), 1);
        let fields = login.custom_fields.as_ref().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].value, "me@example.com");
        assert!(fields[1].hidden);
    }

    #[test]
    fn cards_identities_and_other_categories() {
        let result = import(json!({ "items": [
            { "category": "creditcard", "title": "Amex", "fields": [
                field("ccName", "Cardholder", "Jane", 0),
                field("ccNumber", "Number", "378282246310005", 0),
                field("ccExpiry", "Expiry date", "03/2027", 0),
                field("ccCvc", "CVC", "1234", 1),
                field("username", "Username", "bank-user", 0),
                field("numeric", "Credit limit", "1000", 0)
            ]},
            { "category": "identity", "title": "Me", "fields": [
                { "uid": 130, "type": "text", "label": "الاسم", "value": "عمر", "deleted": 0 },
                { "uid": 132, "type": "text", "label": "Last name", "value": "Haddad", "deleted": 0 },
                { "uid": 134, "type": "date", "label": "Birthday", "value": "01/02/1990", "deleted": 0 },
                { "uid": 999, "type": "email", "label": "E-mail", "value": "o@example.com", "deleted": 0 },
                { "uid": 133, "type": "text", "label": "Gender", "value": "M", "deleted": 0 }
            ]},
            { "category": "finance", "title": "Bank", "fields": [
                field("username", "Username", "u", 0), field("password", "Login password", "p", 1),
                field("ccTxnpassword", "Transaction password", "t", 0)
            ]},
            { "category": "misc", "title": "Car", "fields": [field("text", "VIN", "123", 0)] },
            { "category": "login", "title": "Old", "trashed": 1, "fields": [] }
        ]}));
        assert_eq!(result.skipped, 1);
        let ItemDetails::Card(card) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(card.expiry.as_deref(), Some("03/27"));
        assert_eq!(
            card.notes.as_deref(),
            Some("Username: bank-user\nCredit limit: 1000")
        );
        let ItemDetails::Identity(id) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(id.first_name.as_deref(), Some("عمر"));
        assert_eq!(id.email.as_deref(), Some("o@example.com"));
        assert_eq!(
            id.notes.as_deref(),
            Some("Birth date: 01/02/1990\nGender: M")
        );
        assert_eq!(result.items[2].overview.item_type, ItemType::Login);
        let ItemDetails::Login(bank) = &result.items[2].details else {
            panic!()
        };
        assert!(bank.custom_fields.as_ref().unwrap()[0].hidden);
        assert_eq!(result.items[3].overview.item_type, ItemType::SecureNote);
    }

    #[test]
    fn typed_templates() {
        let result = import(json!({ "items": [
            { "template_type": "finance.bankaccount", "title": "Bank", "note": "n", "fields": [
                field("ccBankname", "Bank name", "Example", 0),
                field("text", "IBAN", "DE89370400440532013000", 0),
                field("pin", "PIN", "1234", 1),
                field("username", "Username", "u", 0),
                field("password", "Login password", "p", 1),
                field("url", "Website", "https://bank.example", 0),
                field("text", "Phone banking", "77", 0)
            ]},
            { "template_type": "travel.passport", "title": "Passport", "fields": [
                field("text", "Passport number", "X1", 1),
                field("text", "Full name", "Jane", 0),
                field("date", "Expiry date", "2030-01-04", 0),
                field("date", "Date of birth", "01/02/1990", 0),
                field("text", "Issuing country", "JO", 0),
                field("text", "Eye colour", "brown", 0)
            ]},
            { "template_type": "license.software", "title": "Editor", "fields": [
                field("text", "License key", "AAAA", 1), field("email", "E-mail", "a@example.com", 0)
            ]},
            { "template_type": "computer.database", "title": "DB", "fields": [
                field("text", "Type", "PostgreSQL", 0), field("text", "Server", "db.local", 0),
                field("text", "Port", "5432", 0), field("username", "Username", "root", 0),
                field("password", "Password", "pw", 1)
            ]},
            { "template_type": "computer.crypto", "title": "Wallet", "fields": [
                field("text", "Recovery phrase", "legal winner", 1),
                field("text", "Wallet address", "bc1qxyz", 0)
            ]}
        ]}));
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let ItemDetails::BankAccount(bank) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(bank.bank_name.as_deref(), Some("Example"));
        assert_eq!(bank.iban.as_deref(), Some("DE89370400440532013000"));
        assert_eq!(bank.pin.as_deref(), Some("1234"));
        assert_eq!(bank.notes.as_deref(), Some("n"));
        assert_eq!(
            result.items[0].overview.urls.as_deref().unwrap(),
            ["https://bank.example"]
        );
        let kept: Vec<_> = bank
            .custom_fields
            .iter()
            .flatten()
            .map(|f| (f.label.as_str(), f.hidden))
            .collect();
        assert_eq!(
            kept,
            [
                ("Username", false),
                ("Login password", true),
                ("Phone banking", false)
            ]
        );
        let ItemDetails::IdDocument(passport) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(passport.document_type.as_deref(), Some("passport"));
        assert_eq!(passport.number.as_deref(), Some("X1"));
        assert_eq!(passport.expiry_date.as_deref(), Some("2030-01-04"));
        assert_eq!(passport.country.as_deref(), Some("JO"));
        assert_eq!(passport.birth_date, None, "not a date Octa Pass can read");
        let labels: Vec<_> = passport
            .custom_fields
            .iter()
            .flatten()
            .map(|f| f.label.as_str())
            .collect();
        assert_eq!(labels, ["Birth date", "Eye colour"]);
        let ItemDetails::SoftwareLicense(license) = &result.items[2].details else {
            panic!()
        };
        assert_eq!(license.license_key.as_deref(), Some("AAAA"));
        assert_eq!(license.email.as_deref(), Some("a@example.com"));
        let ItemDetails::Database(database) = &result.items[3].details else {
            panic!()
        };
        assert_eq!(database.database_type.as_deref(), Some("postgresql"));
        assert_eq!(database.host.as_deref(), Some("db.local"));
        assert_eq!(database.username.as_deref(), Some("root"));
        assert_eq!(database.password.as_deref(), Some("pw"));
        let ItemDetails::CryptoWallet(wallet) = &result.items[4].details else {
            panic!()
        };
        assert_eq!(wallet.seed_phrase.as_deref(), Some("legal winner"));
        assert_eq!(wallet.addresses.as_ref().unwrap()[0].address, "bc1qxyz");
    }

    #[test]
    fn folder_loops_end() {
        let paths = folder_paths(&json!({ "folders": [
            { "uuid": "a", "parent_uuid": "b", "title": "A" },
            { "uuid": "b", "parent_uuid": "a", "title": "B" }
        ]}));
        assert!(paths["a"].len() < 20);
    }

    #[test]
    fn not_enpass() {
        for bad in [&b"[]"[..], b"{\"items\":{}}", b"title,url\n"] {
            let error = parse(bad, &ImportOptions::default()).unwrap_err();
            assert_eq!(error.code, Error::InvalidImportFile);
        }
    }
}
