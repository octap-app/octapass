//! NordPass CSV: `name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,
//! pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,
//! state,type,custom_fields`.
//!
//! `type` is `password` (logins), `note`, `credit_card`, `identity`, `document` or `folder`.
//! Folder rows aren't items: the `folder` of the items in them becomes a tag. `additional_urls`
//! is a JSON list of URLs and `custom_fields` a JSON list of `{label, type, value}` (`text`,
//! `hidden` or `date`). Documents come without their files, as secure notes. Older exports
//! without the last two columns work too.

use serde_json::Value;

use super::build::{
    Collector, LoginFields, address, card, card_details, civil_date, clean, custom_field, expiry,
    extra_fields, identity, identity_details, iso_date, looks_secret, note, notes_with,
    skipped_row,
};
use super::csv_table::{CsvTable, Row, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::item::CustomField;

/// Every column with the label it gets when an item type has no place for it.
const COLUMNS: [(&str, &str); 22] = [
    ("name", "Name"),
    ("url", "Website"),
    ("additional_urls", "Additional websites"),
    ("username", "Username"),
    ("password", "Password"),
    ("note", "Note"),
    ("cardholdername", "Cardholder name"),
    ("cardnumber", "Card number"),
    ("cvc", "Security code"),
    ("pin", "PIN"),
    ("expirydate", "Expiry date"),
    ("zipcode", "ZIP code"),
    ("folder", "Folder"),
    ("full_name", "Full name"),
    ("phone_number", "Phone"),
    ("email", "Email"),
    ("address1", "Address line 1"),
    ("address2", "Address line 2"),
    ("city", "City"),
    ("country", "Country"),
    ("state", "State"),
    ("custom_fields", "Custom fields"),
];

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(&text, b',')?;
    if !table.has(&["name"]) || !table.has(&["type"]) || !table.has(&["password"]) {
        return Err(invalid(
            "This is not a NordPass export: it needs the columns name, password and type.",
        ));
    }
    let type_column = table.take(&["type"]);
    let columns: Vec<Option<usize>> = COLUMNS
        .iter()
        .map(|(name, _)| table.take(&[name]))
        .collect();

    let mut out = Collector::default();
    let mut stats = Stats::default();
    for row in &table.rows {
        let kind = row
            .get(type_column)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if kind == "folder" {
            continue;
        }
        let mut item = Fields {
            row,
            columns: &columns,
            claimed: vec![false; COLUMNS.len()],
        };
        let title = item.take("name");
        let tags: Vec<String> = item.take("folder").into_iter().collect();
        let custom = item.custom_fields();
        let extras = extra_fields(table.extras(row));
        match kind.as_str() {
            "password" => add_login(item, title, tags, custom, extras, &mut out),
            "credit_card" => add_card(item, title, tags, custom, extras, &mut out),
            "identity" => add_identity(item, title, tags, custom, extras, &mut out),
            "note" | "document" => {
                if kind == "document" {
                    stats.documents += 1;
                }
                add_note(item, title, tags, custom, extras, &mut out);
            }
            _ => {
                if !kind.is_empty() {
                    stats.other_types += 1;
                }
                // Unknown or missing types: whatever the row looks like.
                if item.has("cardnumber") {
                    add_card(item, title, tags, custom, extras, &mut out);
                } else if item.has("username") || item.has("password") || item.has("url") {
                    add_login(item, title, tags, custom, extras, &mut out);
                } else {
                    add_note(item, title, tags, custom, extras, &mut out);
                }
            }
        }
    }
    stats.report(&mut out);
    Ok(out.finish())
}

/// The cells of one row; each item type claims the columns it has a place for.
struct Fields<'a> {
    row: &'a Row,
    columns: &'a [Option<usize>],
    claimed: Vec<bool>,
}

impl Fields<'_> {
    fn index(name: &str) -> usize {
        COLUMNS
            .iter()
            .position(|(n, _)| *n == name)
            .expect("a known column")
    }

    fn raw(&self, name: &str) -> Option<&str> {
        self.row.get(self.columns[Self::index(name)])
    }

    fn has(&self, name: &str) -> bool {
        clean(self.raw(name)).is_some()
    }

    fn take(&mut self, name: &str) -> Option<String> {
        self.claimed[Self::index(name)] = true;
        clean(self.raw(name))
    }

    /// Passwords, PINs and codes keep their spaces.
    fn take_secret(&mut self, name: &str) -> Option<String> {
        self.claimed[Self::index(name)] = true;
        self.raw(name).filter(|v| !v.is_empty()).map(str::to_string)
    }

    /// `custom_fields`: hidden ones stay hidden; dates (Unix seconds) become `YYYY-MM-DD`.
    fn custom_fields(&mut self) -> Vec<CustomField> {
        let Some(text) = self.take("custom_fields") else {
            return vec![];
        };
        let Ok(Value::Array(fields)) = serde_json::from_str::<Value>(&text) else {
            return vec![custom_field("Custom fields", &text, false)];
        };
        fields
            .iter()
            .filter_map(|field| {
                let value = match field.get("value")? {
                    Value::String(s) => s.clone(),
                    Value::Null => return None,
                    other => other.to_string(),
                };
                let label = clean(field.get("label").and_then(Value::as_str))
                    .unwrap_or_else(|| "Field".into());
                let value = match field.get("type").and_then(Value::as_str) {
                    Some("date") => unix_date(&value).unwrap_or(value),
                    _ => value,
                };
                let hidden = field.get("type").and_then(Value::as_str) == Some("hidden")
                    || looks_secret(&label);
                (!value.trim().is_empty()).then(|| custom_field(&label, &value, hidden))
            })
            .collect()
    }

    /// The columns no one claimed, as `(label, value)`.
    fn rest(&self) -> Vec<(String, String)> {
        COLUMNS
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.claimed[*i])
            .filter_map(|(_, (name, label))| Some((label.to_string(), clean(self.raw(name))?)))
            .collect()
    }
}

#[derive(Default)]
struct Stats {
    documents: usize,
    other_types: usize,
}

impl Stats {
    fn report(&self, out: &mut Collector) {
        match self.documents {
            0 => {}
            1 => out.warn(
                "NordPass exports don't include files: 1 document was imported as a secure note without its file.",
            ),
            n => out.warn(format!(
                "NordPass exports don't include files: {n} documents were imported as secure notes without their files."
            )),
        }
        match self.other_types {
            0 => {}
            1 => {
                out.warn("1 item of an unknown type was imported as a login, card or secure note.")
            }
            n => out.warn(format!(
                "{n} items of unknown types were imported as logins, cards or secure notes."
            )),
        }
    }
}

fn add_login(
    mut item: Fields,
    title: Option<String>,
    tags: Vec<String>,
    mut custom: Vec<CustomField>,
    extras: Vec<CustomField>,
    out: &mut Collector,
) {
    let mut urls: Vec<String> = item.take("url").into_iter().collect();
    if let Some(more) = item.take("additional_urls") {
        match serde_json::from_str::<Vec<Value>>(&more) {
            Ok(list) => urls.extend(list.iter().filter_map(|u| clean(u.as_str()))),
            Err(_) => custom.push(custom_field("Additional websites", &more, false)),
        }
    }
    let username = item.take("username");
    let password = item.take_secret("password");
    let notes = item.take("note");
    custom.extend(
        item.rest()
            .into_iter()
            .map(|(label, value)| custom_field(&label, &value, looks_secret(&label))),
    );
    custom.extend(extras);
    let fields = LoginFields {
        title,
        urls,
        username,
        password,
        notes,
        tags,
        custom_fields: custom,
        ..LoginFields::default()
    };
    out.add_login(fields, || skipped_row(item.row.line));
}

fn add_card(
    mut item: Fields,
    title: Option<String>,
    tags: Vec<String>,
    custom: Vec<CustomField>,
    extras: Vec<CustomField>,
    out: &mut Collector,
) {
    let mut details = card_details();
    details.cardholder = item.take("cardholdername");
    details.number = item.take("cardnumber");
    details.cvv = item.take_secret("cvc");
    details.pin = item.take_secret("pin");
    let mut lines = Vec::new();
    if let Some(date) = item.take("expirydate") {
        match card_expiry(&date) {
            Some(expiry) => details.expiry = Some(expiry),
            None => lines.push(("Expiry date".to_string(), date)),
        }
    }
    let notes = item.take("note");
    lines.extend(item.rest());
    lines.extend(field_lines(custom, extras));
    let empty = details.cardholder.is_none()
        && details.number.is_none()
        && details.cvv.is_none()
        && details.pin.is_none()
        && details.expiry.is_none();
    details.notes = notes_with(&lines, notes);
    if empty && details.notes.is_none() {
        return out.skip(Some(no_fields(item.row.line)));
    }
    out.add(card(title, tags, false, details));
}

fn add_identity(
    mut item: Fields,
    title: Option<String>,
    tags: Vec<String>,
    custom: Vec<CustomField>,
    extras: Vec<CustomField>,
    out: &mut Collector,
) {
    let mut details = identity_details();
    (details.first_name, details.last_name) = split_name(item.take("full_name"));
    details.email = item.take("email");
    details.phone = item.take("phone_number");
    details.address = address(
        item.take("address1"),
        item.take("address2"),
        item.take("city"),
        item.take("state"),
        item.take("zipcode"),
        item.take("country"),
    );
    let notes = item.take("note");
    let mut lines = item.rest();
    lines.extend(field_lines(custom, extras));
    let empty = details.first_name.is_none()
        && details.email.is_none()
        && details.phone.is_none()
        && details.address.is_none();
    details.notes = notes_with(&lines, notes);
    if empty && details.notes.is_none() {
        return out.skip(Some(no_fields(item.row.line)));
    }
    out.add(identity(title, tags, false, details));
}

fn add_note(
    mut item: Fields,
    title: Option<String>,
    tags: Vec<String>,
    custom: Vec<CustomField>,
    extras: Vec<CustomField>,
    out: &mut Collector,
) {
    let notes = item.take("note");
    let mut lines = item.rest();
    lines.extend(field_lines(custom, extras));
    let notes = notes_with(&lines, notes);
    if notes.is_none() && title.is_none() {
        return out.skip(Some(no_fields(item.row.line)));
    }
    out.add(note(title, tags, false, notes));
}

fn field_lines(custom: Vec<CustomField>, extras: Vec<CustomField>) -> Vec<(String, String)> {
    custom
        .into_iter()
        .chain(extras)
        .map(|field| (field.label, field.value))
        .collect()
}

fn no_fields(line: u64) -> String {
    format!("Row {line} skipped: it has no fields.")
}

/// NordPass writes `MM/YY`; `MM/YYYY` works too.
fn card_expiry(text: &str) -> Option<String> {
    let (month, year) = text.trim().split_once('/')?;
    expiry(month.trim().parse().ok()?, year.trim().parse().ok()?)
}

/// A custom date field: Unix seconds → `YYYY-MM-DD`. Other text stays as it is.
fn unix_date(text: &str) -> Option<String> {
    let seconds: i64 = text.trim().parse().ok()?;
    // Beyond ±10,000 years is no date.
    if seconds.unsigned_abs() > 253_402_300_799 {
        return None;
    }
    let (year, month, day) = civil_date(seconds);
    iso_date(year, month, day)
}

/// `Layla Haddad` → (`Layla`, `Haddad`): the last word is the last name.
fn split_name(name: Option<String>) -> (Option<String>, Option<String>) {
    let Some(name) = name else {
        return (None, None);
    };
    match name.rsplit_once(char::is_whitespace) {
        Some((first, last)) => (clean(Some(first)), clean(Some(last))),
        None => (Some(name), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemDetails, ItemType};

    const HEADER: &str = "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n";

    fn import(rows: &str) -> ImportResult {
        parse(
            format!("{HEADER}{rows}").as_bytes(),
            &ImportOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn logins_with_urls_and_custom_fields() {
        let result = import(
            "Mail,https://mail.example.com,\"[\"\"https://a.example.com\"\",\"\"https://b.example.com\"\"]\",me, pw ,hi,,,,,,,Work,,,,,,,,,password,\"[{\"\"type\"\":\"\"hidden\"\",\"\"label\"\":\"\"Recovery\"\",\"\"value\"\":\"\"abc\"\"},{\"\"type\"\":\"\"date\"\",\"\"label\"\":\"\"Since\"\",\"\"value\"\":\"\"1772150400\"\"},{\"\"type\"\":\"\"text\"\",\"\"label\"\":\"\"Empty\"\",\"\"value\"\":\"\"\"\"}]\"\n\
             Work,,,,,,,,,,,,,,,,,,,,,folder,\n",
        );
        assert_eq!(result.items.len(), 1);
        let item = &result.items[0];
        assert_eq!(item.overview.urls.as_ref().unwrap().len(), 3);
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Work"]);
        let ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert_eq!(login.password.as_deref(), Some(" pw "));
        let fields = login.custom_fields.as_ref().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields[0].hidden);
        assert_eq!(fields[1].value, "2026-02-27");
    }

    #[test]
    fn broken_json_columns_are_kept() {
        let result = import("A,https://a.com,not json,u,p,,,,,,,,,,,,,,,,,password,{oops\n");
        let ItemDetails::Login(login) = &result.items[0].details else {
            panic!()
        };
        let fields = login.custom_fields.as_ref().unwrap();
        assert_eq!(fields[0].value, "{oops");
        assert_eq!(fields[1].value, "not json");
    }

    #[test]
    fn cards_identities_and_unknown_types() {
        let result = import(
            "Visa,,,,,,Jane Doe,4111111111111111,123,9876,07/29,11118,,,,,,,,,,credit_card,\n\
             Me,,,,,,,,,,,11118,,Layla Bint Omar,+962700000000,l@example.com,1 Main St,,Amman,Jordan,,identity,\n\
             Odd,,,,,secret text,,,,,,,,,,,,,,,,bank_account,\n",
        );
        let ItemDetails::Card(card) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(card.expiry.as_deref(), Some("07/29"));
        assert_eq!(card.pin.as_deref(), Some("9876"));
        assert_eq!(card.notes.as_deref(), Some("ZIP code: 11118"));
        let ItemDetails::Identity(id) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(id.first_name.as_deref(), Some("Layla Bint"));
        assert_eq!(id.last_name.as_deref(), Some("Omar"));
        assert_eq!(
            id.address.as_ref().unwrap().postal_code.as_deref(),
            Some("11118")
        );
        assert_eq!(result.items[2].overview.item_type, ItemType::SecureNote);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn dates() {
        assert_eq!(unix_date("0").as_deref(), Some("1970-01-01"));
        assert_eq!(unix_date("14 December 1990"), None);
        assert_eq!(unix_date("99999999999999999"), None);
        assert_eq!(card_expiry("7/2031").as_deref(), Some("07/31"));
    }
}
