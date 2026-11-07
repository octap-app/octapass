//! 1Password's 1PUX export: a ZIP with `export.data`, JSON of accounts → vaults → items.
//!
//! Logins, passwords, cards, identities and secure notes map to their Octa Pass types, and so do
//! bank accounts, databases, servers, API credentials, software licences, crypto wallets, passports,
//! driver licenses and social security numbers (category numbers as in Bitwarden's 1PUX importer);
//! fields without a place stay as custom fields. Other categories (memberships, routers …) become
//! logins when they hold a username or password and secure notes otherwise, with every field kept.
//! Item tags carry over; when the export has several vaults, the vault name is added as a tag.
//! Attachments aren't imported yet.
//!
//! Each item's `uuid` is kept so importing the file again updates it, and `createdAt` and
//! `updatedAt` (Unix seconds) become its dates (support.1password.com/1pux-format). Password
//! history entries are dated when that password was replaced.

use std::io::{Cursor, Read};

use serde_json::{Map, Value};

use super::build::{
    Collector, ItemMeta, LoginFields, TypedItem, address, card, card_details, civil_date, clean,
    custom_field, expiry, identity, identity_details, iso_date, note, notes_with, rfc3339,
    unix_time, with_meta,
};
use super::{ImportError, ImportResult};
use crate::error::Error;
use crate::item::{CardDetails, CustomField, PasswordHistoryEntry};

/// `export.data` is a few MB even for large vaults; this stops a ZIP bomb.
const MAX_DATA_LEN: u64 = 256 << 20;

const LOGIN: &str = "001";
const CARD: &str = "002";
const NOTE: &str = "003";
const IDENTITY: &str = "004";
const PASSWORD: &str = "005";
const DOCUMENT: &str = "006";
const SOFTWARE_LICENSE: &str = "100";
const BANK_ACCOUNT: &str = "101";
const DATABASE: &str = "102";
const DRIVER_LICENSE: &str = "103";
const PASSPORT: &str = "106";
const SOCIAL_SECURITY: &str = "108";
const SERVER: &str = "110";
const API_CREDENTIAL: &str = "112";
const CRYPTO_WALLET: &str = "115";

pub(super) fn parse(bytes: &[u8]) -> Result<ImportResult, ImportError> {
    let invalid = || {
        ImportError::new(
            Error::InvalidImportFile,
            "This is not a 1Password .1pux export.",
        )
    };
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid())?;
    let file = archive.by_name("export.data").map_err(|_| invalid())?;
    let mut data = Vec::new();
    file.take(MAX_DATA_LEN)
        .read_to_end(&mut data)
        .map_err(|_| invalid())?;
    let data: Value =
        serde_json::from_slice(&zeroize::Zeroizing::new(data)).map_err(|_| invalid())?;
    let accounts = data
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;

    let vaults: Vec<&Value> = accounts
        .iter()
        .flat_map(|account| {
            account
                .get("vaults")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect();
    let tag_vaults = vaults.len() > 1;
    let mut out = Collector::default();
    let mut stats = Stats::default();
    for vault in vaults {
        let vault_name = vault
            .pointer("/attrs/name")
            .and_then(Value::as_str)
            .and_then(|n| clean(Some(n)));
        for item in vault
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut tags = Vec::new();
            if tag_vaults {
                tags.extend(vault_name.clone());
            }
            add_item(item, tags, &mut out, &mut stats);
        }
    }
    stats.report(&mut out);
    Ok(out.finish())
}

#[derive(Default)]
struct Stats {
    archived: usize,
    attachments: usize,
    other_categories: usize,
}

impl Stats {
    fn report(&self, out: &mut Collector) {
        let plural = |n: usize, one: &str, many: &str| {
            if n == 1 {
                one.to_string()
            } else {
                many.to_string()
            }
        };
        if self.archived > 0 {
            out.warn(format!(
                "{} archived {} imported with the tag \"archived\".",
                self.archived,
                plural(self.archived, "item was", "items were")
            ));
        }
        if self.attachments > 0 {
            out.warn(format!(
                "Attachments can't be imported yet: {} {} imported without {}.",
                self.attachments,
                plural(self.attachments, "item was", "items were"),
                plural(self.attachments, "its file", "their files")
            ));
        }
        if self.other_categories > 0 {
            out.warn(format!(
                "{} {} of a type Octa Pass doesn't have yet (membership, router …) {} imported as logins or secure notes.",
                self.other_categories,
                plural(self.other_categories, "item", "items"),
                plural(self.other_categories, "was", "were")
            ));
        }
    }
}

/// One field of a section, with its value read as text.
struct Field {
    id: String,
    label: String,
    value: String,
    concealed: bool,
    totp: bool,
}

fn add_item(item: &Value, mut tags: Vec<String>, out: &mut Collector, stats: &mut Stats) {
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let details = item.get("details").unwrap_or(&Value::Null);
    let category = item
        .get("categoryUuid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match item.get("state").and_then(Value::as_str) {
        Some("archived") => {
            stats.archived += 1;
            tags.push("archived".into());
        }
        Some("deleted") => return out.skip(None),
        _ => {}
    }
    tags.extend(
        overview
            .get("tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|t| clean(t.as_str())),
    );
    if details.get("documentAttributes").is_some() || category == DOCUMENT {
        stats.attachments += 1;
    }
    let title = overview
        .get("title")
        .and_then(Value::as_str)
        .and_then(|t| clean(Some(t)));
    let favorite = item.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0;
    let notes = details
        .get("notesPlain")
        .and_then(Value::as_str)
        .and_then(|n| clean(Some(n)));
    let mut fields = section_fields(details);
    let meta = ItemMeta {
        created_at: item
            .get("createdAt")
            .and_then(Value::as_i64)
            .and_then(unix_time),
        updated_at: item
            .get("updatedAt")
            .and_then(Value::as_i64)
            .and_then(unix_time),
        last_used_at: None,
        source_id: item.get("uuid").and_then(Value::as_str).map(str::to_string),
    };

    match category {
        CARD => {
            let mut take = |id: &str| take_field(&mut fields, id);
            let card_details = CardDetails {
                cardholder: take("cardholder"),
                brand: take("type"),
                number: take("ccnum"),
                cvv: take("cvv"),
                pin: take("pin"),
                expiry: take("expiry").and_then(|e| month_year(&e)),
                ..card_details()
            };
            let notes = notes_with(&lines(&fields), notes);
            out.add(with_meta(
                card(
                    title,
                    tags,
                    favorite,
                    CardDetails {
                        notes,
                        ..card_details
                    },
                ),
                meta,
            ));
        }
        IDENTITY => {
            let mut take = |id: &str| take_field(&mut fields, id);
            let mut details = identity_details();
            details.first_name = clean(Some(
                &[take("firstname"), take("initial")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
            ));
            details.last_name = take("lastname");
            details.email = take("email");
            details.phone = take("defphone")
                .or_else(|| take("cellphone"))
                .or_else(|| take("homephone"));
            details.birth_date = take("birthdate");
            if let Some(index) = fields.iter().position(|f| f.id == "address") {
                details.address = item_address(address_value(item));
                if details.address.is_some() {
                    fields.remove(index);
                }
            }
            details.notes = notes_with(&lines(&fields), notes);
            out.add(with_meta(identity(title, tags, favorite, details), meta));
        }
        SOFTWARE_LICENSE | BANK_ACCOUNT | DATABASE | DRIVER_LICENSE | PASSPORT
        | SOCIAL_SECURITY | SERVER | API_CREDENTIAL | CRYPTO_WALLET => {
            let typed = add_typed(category, item, fields, title, tags, favorite, notes);
            out.add(with_meta(typed, meta));
        }
        NOTE | DOCUMENT => {
            out.add(with_meta(
                note(title, tags, favorite, notes_with(&lines(&fields), notes)),
                meta,
            ));
        }
        _ => {
            if ![LOGIN, PASSWORD].contains(&category) {
                stats.other_categories += 1;
            }
            let common = LoginFields {
                title,
                tags,
                favorite,
                notes,
                meta,
                ..LoginFields::default()
            };
            add_login(item, common, fields, out);
        }
    }
}

/// An item of a category with an Octa Pass type of its own. Field ids as 1Password's templates name
/// them; anything else stays a custom field.
fn add_typed(
    category: &str,
    item: &Value,
    mut fields: Vec<Field>,
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
) -> crate::item::Item {
    let details = item.get("details").unwrap_or(&Value::Null);
    let (mut typed, places): (TypedItem, &[(&str, &str)]) = match category {
        SOFTWARE_LICENSE => (
            TypedItem::software_license(),
            &[
                ("licenseKey", "reg_code"),
                ("version", "product_version"),
                ("licensedTo", "reg_name"),
                ("email", "reg_email"),
                ("publisher", "publisher_name"),
                ("orderNumber", "order_number"),
                ("purchaseDate", "order_date"),
            ],
        ),
        BANK_ACCOUNT => (
            TypedItem::bank_account(),
            &[
                ("bankName", "bankName"),
                ("accountHolder", "owner"),
                ("accountType", "accountType"),
                ("routingNumber", "routingNo"),
                ("accountNumber", "accountNo"),
                ("swift", "swift"),
                ("iban", "iban"),
                ("pin", "telephonePin"),
            ],
        ),
        DATABASE | SERVER => {
            let kind = if category == SERVER {
                Some("server".to_owned())
            } else {
                take_field(&mut fields, "database_type")
            };
            let places: &[(&str, &str)] = &[
                ("host", "hostname"),
                ("host", "url"),
                ("port", "port"),
                ("database", "database"),
                ("username", "username"),
                ("password", "password"),
            ];
            (TypedItem::database(kind), places)
        }
        DRIVER_LICENSE | PASSPORT | SOCIAL_SECURITY => {
            let document_type = match category {
                PASSPORT => "passport",
                DRIVER_LICENSE => "driverLicense",
                _ => "other",
            };
            let places: &[(&str, &str)] = &[
                ("number", "number"),
                ("fullName", "fullname"),
                ("fullName", "name"),
                ("birthDate", "birthdate"),
                ("issuer", "issuing_authority"),
                ("country", "issuing_country"),
                ("country", "country"),
                ("issueDate", "issue_date"),
                ("expiryDate", "expiry_date"),
            ];
            (TypedItem::id_document(document_type), places)
        }
        API_CREDENTIAL => (
            TypedItem::api_credential(),
            &[
                ("key", "credential"),
                ("username", "username"),
                ("credentialType", "type"),
                ("host", "hostname"),
                ("expiryDate", "expires"),
            ],
        ),
        _ => (
            TypedItem::crypto_wallet(),
            &[("seedPhrase", "recoveryPhrase")],
        ),
    };
    if category == SOCIAL_SECURITY {
        typed.custom("Type", "Social security number", false);
    }
    for (key, id) in places {
        if !typed.has(key)
            && let Some(index) = fields.iter().position(|f| f.id == *id)
        {
            typed.set(key, Some(fields.remove(index).value));
        }
    }
    while let Some(index) = fields.iter().position(|f| f.id == "walletAddress") {
        typed.address("", &fields.remove(index).value, None);
    }
    for field in &fields {
        typed.custom(&field.label, &field.value, field.concealed || field.totp);
    }
    for login in details
        .get("loginFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let value = login
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let label = login.get("name").and_then(Value::as_str).unwrap_or("Field");
        let hidden = login.get("fieldType").and_then(Value::as_str) == Some("P");
        typed.custom(label, value, hidden);
    }
    if let Some(password) = details.get("password").and_then(Value::as_str) {
        typed.custom("Password", password, true);
    }
    for url in item_urls(item.get("overview").unwrap_or(&Value::Null)) {
        typed.url(Some(url));
    }
    if matches!(category, DATABASE | SERVER) {
        typed.password_history(password_history(details));
    }
    typed.build(title, tags, favorite, notes)
}

/// Logins, passwords and other categories with credentials. `common` has the title, tags,
/// favourite and notes.
fn add_login(item: &Value, common: LoginFields, mut fields: Vec<Field>, out: &mut Collector) {
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let details = item.get("details").unwrap_or(&Value::Null);
    let mut username = None;
    let mut password = details
        .get("password")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut custom_fields: Vec<CustomField> = Vec::new();
    for field in details
        .get("loginFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let value = field
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match field.get("designation").and_then(Value::as_str) {
            Some("username") if username.is_none() => username = Some(value.to_string()),
            Some("password") if password.is_none() => password = Some(value.to_string()),
            _ if !value.is_empty() => {
                let label = field.get("name").and_then(Value::as_str).unwrap_or("Field");
                let hidden = field.get("fieldType").and_then(Value::as_str) == Some("P");
                custom_fields.push(custom_field(label, value, hidden));
            }
            _ => {}
        }
    }
    // Other categories keep their credentials in sections: `username`, `password`, `credential` …
    if username.is_none() {
        username = take_field(&mut fields, "username");
    }
    if password.is_none() {
        password = fields
            .iter()
            .position(|f| f.concealed && !f.totp)
            .map(|i| fields.remove(i).value);
    }
    let totp = fields
        .iter()
        .position(|f| f.totp)
        .map(|i| fields.remove(i).value);
    let url_field = take_field(&mut fields, "url").or_else(|| take_field(&mut fields, "hostname"));
    custom_fields.extend(
        fields
            .iter()
            .map(|f| custom_field(&f.label, &f.value, f.concealed)),
    );

    let mut urls = item_urls(overview);
    urls.extend(url_field);

    let password_history = password_history(details);
    let fields = LoginFields {
        urls,
        username,
        password,
        totp,
        custom_fields,
        password_history,
        ..common
    };
    let uuid = item
        .get("uuid")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    out.add_login(fields, || format!("Item {uuid} skipped: it has no fields."));
}

/// The item's websites: its main URL first.
fn item_urls(overview: &Value) -> Vec<String> {
    let mut urls: Vec<String> = overview
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|u| clean(u.get("url")?.as_str()))
        .collect();
    if let Some(url) = overview
        .get("url")
        .and_then(Value::as_str)
        .and_then(|u| clean(Some(u)))
        && !urls.contains(&url)
    {
        urls.insert(0, url);
    }
    urls
}

fn password_history(details: &Value) -> Vec<PasswordHistoryEntry> {
    details
        .get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some(PasswordHistoryEntry {
                password: entry.get("value")?.as_str()?.to_string(),
                changed_at: rfc3339(entry.get("time").and_then(Value::as_i64).unwrap_or(0)),
                extra: Map::new(),
            })
        })
        .collect()
}

fn section_fields(details: &Value) -> Vec<Field> {
    details
        .get("sections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|section| {
            section
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|field| {
            let value = field.get("value")?.as_object()?;
            let (kind, inner) = value.iter().next()?;
            let text = value_text(kind, inner)?;
            let id = field
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let label = field
                .get("title")
                .and_then(Value::as_str)
                .and_then(|t| clean(Some(t)))
                .unwrap_or_else(|| {
                    if id.is_empty() {
                        "Field".into()
                    } else {
                        id.clone()
                    }
                });
            Some(Field {
                id,
                label,
                value: text,
                concealed: kind == "concealed" || kind == "creditCardNumber",
                totp: kind == "totp",
            })
        })
        .collect()
}

/// A section field's value as text. `None` for empty values and files.
fn value_text(kind: &str, value: &Value) -> Option<String> {
    let text = match (kind, value) {
        ("date", Value::Number(n)) => {
            let (year, month, day) = civil_date(n.as_i64()?);
            iso_date(year, month, day)?
        }
        ("monthYear", Value::Number(n)) => {
            let n = n.as_u64()?;
            format!("{:02}/{}", n % 100, n / 100)
        }
        ("address", Value::Object(address)) => ["street", "city", "state", "zip", "country"]
            .iter()
            .filter_map(|k| clean(address.get(*k)?.as_str()))
            .collect::<Vec<_>>()
            .join(", "),
        ("email", Value::Object(email)) => email.get("email_address")?.as_str()?.to_string(),
        ("sshKey", Value::Object(key)) => key.get("privateKey")?.as_str()?.to_string(),
        ("file" | "reference", _) => return None,
        (_, Value::String(s)) => s.clone(),
        (_, Value::Number(n)) => n.to_string(),
        (_, Value::Bool(b)) => b.to_string(),
        _ => return None,
    };
    (!text.trim().is_empty()).then_some(text)
}

/// The structured value of the identity's `address` field.
fn address_value(item: &Value) -> Option<&Value> {
    item.pointer("/details/sections")?
        .as_array()?
        .iter()
        .flat_map(|s| {
            s.get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .find(|f| f.get("id").and_then(Value::as_str) == Some("address"))?
        .pointer("/value/address")
}

fn item_address(value: Option<&Value>) -> Option<crate::item::Address> {
    let value = value?;
    let get = |k: &str| clean(value.get(k)?.as_str());
    address(
        get("street"),
        None,
        get("city"),
        get("state"),
        get("zip"),
        get("country"),
    )
}

fn take_field(fields: &mut Vec<Field>, id: &str) -> Option<String> {
    let index = fields.iter().position(|f| f.id == id)?;
    clean(Some(&fields.remove(index).value))
}

/// `MM/YYYY` (how [`value_text`] writes a month-year) → `MM/YY`.
fn month_year(text: &str) -> Option<String> {
    let (month, year) = text.split_once('/')?;
    expiry(month.parse().ok()?, year.parse().ok()?)
}

fn lines(fields: &[Field]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|f| (f.label.clone(), f.value.clone()))
        .collect()
}
