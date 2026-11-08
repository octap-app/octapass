//! Octa Pass's own CSV export (`vault,type,title,url,username,password,totp,notes,tags,favorite`,
//! written by the clients' `exportCsv`). The `type` column says what each row was, and the fields
//! with no column of their own are `Label: value` lines at the top of the notes, so Wi-Fi networks,
//! cards, identities and the field-table types come back as what they were rather than as logins
//! or notes. Types the CSV can't hold in full (SSH keys, documents, certificates …) become notes
//! with every line kept; the JSON and encrypted exports are the full ones.
//!
//! The `vault` column is left out: an import goes into the vault the user chose.

use super::ImportResult;
use super::build::{
    Collector, LoginFields, TypedItem, address, card, card_details, clean, clean_password,
    custom_field, identity, identity_details, is_true, looks_secret, note, overview, skipped_row,
    split_tags,
};
use super::csv_table::{CsvTable, Row};
use crate::item::{CustomField, Item, ItemDetails, ItemType, SCHEMA_VERSION, WifiDetails};
use crate::item_fields::fields_of;

const HEADER: [&str; 10] = [
    "vault", "type", "title", "url", "username", "password", "totp", "notes", "tags", "favorite",
];

/// Whether the file is this export: exactly its header, in its order.
pub(super) fn is_own(table: &CsvTable) -> bool {
    table.headers.len() == HEADER.len()
        && table
            .headers
            .iter()
            .zip(HEADER)
            .all(|(header, name)| header.trim().eq_ignore_ascii_case(name))
}

pub(super) fn parse(table: &CsvTable) -> ImportResult {
    let mut out = Collector::default();
    let mut as_notes = 0;
    for row in &table.rows {
        let cell = |index: usize| row.get(Some(index));
        let kind = cell(1).unwrap_or_default().trim();
        let common = Common {
            title: clean(cell(2)),
            tags: split_tags(cell(8)),
            favorite: is_true(cell(9)),
        };
        let item = match kind {
            "wifi" => Some(wifi(row, common)),
            "card" => Some(card_row(row, common)),
            "identity" => Some(identity_row(row, common)),
            "secureNote" => Some(note(
                common.title,
                common.tags,
                common.favorite,
                clean(cell(7)),
            )),
            "bankAccount" | "softwareLicense" | "idDocument" | "database" | "cryptoWallet" => {
                Some(typed(kind, row, common))
            }
            _ => {
                let password_type = kind == "password";
                let is_login = matches!(kind, "login" | "password" | "");
                if !is_login {
                    as_notes += 1;
                }
                // A login's custom fields are the lines at the top of its notes.
                let (custom_fields, notes) = if is_login {
                    custom_lines(clean(cell(7)))
                } else {
                    (Vec::new(), cell(7).map(str::to_owned))
                };
                LoginFields {
                    title: common.title,
                    urls: cell(3)
                        .unwrap_or_default()
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect(),
                    username: cell(4).map(str::to_owned),
                    password: cell(5).map(str::to_owned),
                    totp: cell(6).map(str::to_owned),
                    notes,
                    tags: common.tags,
                    favorite: common.favorite,
                    custom_fields,
                    ..LoginFields::default()
                }
                .build(&mut out)
                .map(|mut item| {
                    if password_type && matches!(item.details, ItemDetails::Login(_)) {
                        item.overview.item_type = ItemType::Password;
                    }
                    item
                })
            }
        };
        match item {
            Some(item) => out.add(item),
            None => out.skip(Some(skipped_row(row.line))),
        }
    }
    if as_notes > 0 {
        let (items, were) = if as_notes == 1 {
            ("item", "was")
        } else {
            ("items", "were")
        };
        out.warn(format!(
            "{as_notes} {items} of a type a CSV can't hold in full {were} imported as notes, with every field kept. The JSON or encrypted export keeps every type as it is."
        ));
    }
    out.finish()
}

struct Common {
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
}

/// The `Label: value` lines at the top of the notes whose label is one of `labels`, and the rest
/// of the notes. Reading stops at the first other line, so the item's own notes stay as written.
fn fields(
    notes: Option<&str>,
    labels: &[&'static str],
) -> (Vec<(&'static str, String)>, Option<String>) {
    let notes = notes.unwrap_or_default();
    let mut found: Vec<(&'static str, String)> = Vec::new();
    let mut rest = notes;
    for line in notes.split_inclusive('\n') {
        let field = line.split_once(": ").and_then(|(label, value)| {
            labels
                .iter()
                .find(|known| **known == label)
                .map(|known| (*known, value.trim_end_matches(['\r', '\n']).to_owned()))
        });
        let Some(field) = field else {
            break;
        };
        found.push(field);
        rest = &rest[line.len()..];
    }
    (found, clean(Some(rest)))
}

/// The `Label: value` lines at the top of `notes` as custom fields (the export writes an item's
/// custom fields there, ahead of its notes), and the rest of the notes. A field whose label sounds
/// secret is hidden.
fn custom_lines(notes: Option<String>) -> (Vec<CustomField>, Option<String>) {
    let Some(notes) = notes else {
        return (Vec::new(), None);
    };
    let mut fields = Vec::new();
    let mut rest = notes.as_str();
    for line in notes.split_inclusive('\n') {
        let Some((label, value)) = line.split_once(": ") else {
            break;
        };
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 64 {
            break;
        }
        let value = value.trim_end_matches(['\r', '\n']);
        fields.push(custom_field(label, value, looks_secret(label)));
        rest = &rest[line.len()..];
    }
    (fields, clean(Some(rest)))
}

fn value(fields: &[(&str, String)], label: &str) -> Option<String> {
    fields
        .iter()
        .find(|(name, _)| *name == label)
        .and_then(|(_, value)| clean(Some(value)))
}

fn yes(fields: &[(&str, String)], label: &str) -> Option<bool> {
    value(fields, label)
        .is_some_and(|value| value.eq_ignore_ascii_case("yes"))
        .then_some(true)
}

const WIFI: &[&str] = &[
    "SSID",
    "Security",
    "Hidden",
    "EAP method",
    "Phase 2",
    "Identity",
    "Server domain",
    "Sign-in page",
    "Managed",
    "Personal Hotspot",
];

fn wifi(row: &Row, common: Common) -> Item {
    let (found, notes) = fields(row.get(Some(7)), WIFI);
    let (custom_fields, notes) = custom_lines(notes);
    let password = clean_password(row.get(Some(5)));
    let ssid = value(&found, "SSID")
        .or_else(|| common.title.clone())
        .unwrap_or_default();
    let security = value(&found, "Security")
        .unwrap_or_else(|| if password.is_some() { "wpa2" } else { "open" }.to_owned());
    let details = WifiDetails {
        schema_version: SCHEMA_VERSION,
        ssid: ssid.clone(),
        security,
        password,
        hidden: yes(&found, "Hidden"),
        eap_method: value(&found, "EAP method"),
        phase2: value(&found, "Phase 2"),
        username: clean(row.get(Some(4))),
        identity: value(&found, "Identity"),
        server_domain: value(&found, "Server domain"),
        ca_certificate: None,
        captive_portal: yes(&found, "Sign-in page"),
        managed: yes(&found, "Managed"),
        hotspot: yes(&found, "Personal Hotspot"),
        notes,
        custom_fields: (!custom_fields.is_empty()).then_some(custom_fields),
        password_history: None,
        extra: Default::default(),
    };
    let subtitle = clean(Some(&ssid));
    Item {
        overview: overview(
            ItemType::Wifi,
            common.title,
            vec![],
            subtitle,
            common.tags,
            common.favorite,
        ),
        details: ItemDetails::Wifi(details),
    }
}

fn card_row(row: &Row, common: Common) -> Item {
    const CARD: &[&str] = &["Cardholder", "Number", "Expiry", "CVV", "PIN", "Brand"];
    let (found, notes) = fields(row.get(Some(7)), CARD);
    let details = crate::item::CardDetails {
        cardholder: value(&found, "Cardholder"),
        number: value(&found, "Number"),
        expiry: value(&found, "Expiry"),
        cvv: value(&found, "CVV"),
        pin: value(&found, "PIN"),
        brand: value(&found, "Brand"),
        notes,
        ..card_details()
    };
    card(common.title, common.tags, common.favorite, details)
}

fn identity_row(row: &Row, common: Common) -> Item {
    const IDENTITY: &[&str] = &["Name", "Email", "Phone", "Address", "Birth date"];
    let (found, notes) = fields(row.get(Some(7)), IDENTITY);
    let name = value(&found, "Name");
    let (first_name, last_name) = match name.as_deref().map(|name| name.split_once(' ')) {
        Some(Some((first, last))) => (clean(Some(first)), clean(Some(last))),
        Some(None) => (name.clone(), None),
        None => (None, None),
    };
    let details = crate::item::IdentityDetails {
        first_name,
        last_name,
        email: value(&found, "Email"),
        phone: value(&found, "Phone"),
        address: value(&found, "Address").and_then(|text| address_of(&text)),
        birth_date: value(&found, "Birth date"),
        notes,
        ..identity_details()
    };
    identity(common.title, common.tags, common.favorite, details)
}

/// The export writes `line1, line2, postal-code city region, country`, leaving out empty parts.
/// The first part is the first line and, with three parts or more, the last is the country; the
/// part before the country (postal code, city and region) is kept whole as the city.
fn address_of(text: &str) -> Option<crate::item::Address> {
    let parts: Vec<String> = text.split(", ").filter_map(|p| clean(Some(p))).collect();
    let part = |index: usize| parts.get(index).cloned();
    match parts.len() {
        0 => None,
        1 => address(part(0), None, None, None, None, None),
        2 => address(part(0), None, part(1), None, None, None),
        3 => address(part(0), None, part(1), None, None, part(2)),
        n => address(
            part(0),
            Some(parts[1..n - 2].join(", ")),
            part(n - 2),
            None,
            None,
            part(n - 1),
        ),
    }
}

/// The field-table types write each field as `key: value`.
fn typed(kind: &str, row: &Row, common: Common) -> Item {
    let keys: Vec<&str> = fields_of(kind).iter().map(|spec| spec.key).collect();
    let (found, notes) = fields(row.get(Some(7)), &keys);
    let mut item = TypedItem::new(ItemType::from(kind.to_owned()));
    for (key, value) in found {
        item.set(key, Some(value));
    }
    item.build(common.title, common.tags, common.favorite, notes)
}
