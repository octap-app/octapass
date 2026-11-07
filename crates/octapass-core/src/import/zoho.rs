//! Zoho Vault CSV, both of Zoho's export choices: **General CSV** (`Password Name,Password URL,
//! Username,Password…`) and **Zoho Vault CSV** (`Secret Name,Secret URL,SecretData,CustomData…`,
//! older files say `ChamberName` for the folder).
//!
//! `SecretData` and `CustomData` hold one `Field:value` per line. Username and password lines
//! fill the login; `SecretType` says which of Zoho's templates the entry used and isn't kept;
//! other lines become custom fields, and a line without a colon continues the value above it.
//! Zoho doesn't publish the layout: it's read as Bitwarden's importer reads it.

use super::build::{
    Collector, LoginFields, clean, clean_password, custom_field, extra_fields, is_true,
    looks_secret, notes_with, skipped_row, split_tags,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::item::CustomField;

const USERNAME_FIELDS: [&str; 8] = [
    "username",
    "user name",
    "user",
    "login",
    "login name",
    "user id",
    "email",
    "e-mail",
];
const PASSWORD_FIELDS: [&str; 4] = ["password", "pass", "passwd", "pwd"];

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(&text, b',')?;
    let has_name = table.has(&["password name", "secret name"]);
    let has_data = table.has(&["password url", "secret url", "secretdata", "username"]);
    if !has_name || !has_data {
        return Err(invalid(
            "This is not a Zoho Vault export: it needs the columns Password Name or Secret Name, and Password URL or Secret URL.",
        ));
    }
    let password_name = table.take(&["password name"]);
    let secret_name = table.take(&["secret name"]);
    let password_url = table.take(&["password url"]);
    let secret_url = table.take(&["secret url"]);
    let username = table.take(&["username", "user name"]);
    let password = table.take(&["password"]);
    let description = table.take(&["description"]);
    let notes = table.take(&["notes"]);
    let tags = table.take(&["tags"]);
    let favorite = table.take(&["favorite"]);
    let folder = table.take(&["folder name", "chambername"]);
    let totp = table.take(&["totp"]);
    let login_totp = table.take(&["login_totp"]);
    let secret_data = table.take(&["secretdata"]);
    let custom_data = table.take(&["customdata"]);
    table.ignore(&["classification", "secrettype", "password id", "secret id"]);

    let mut out = Collector::default();
    for row in &table.rows {
        let mut fields = LoginFields {
            title: clean(row.get(password_name)).or_else(|| clean(row.get(secret_name))),
            urls: clean(row.get(password_url))
                .or_else(|| clean(row.get(secret_url)))
                .into_iter()
                .collect(),
            username: clean(row.get(username)),
            password: clean_password(row.get(password)),
            totp: clean(row.get(totp)).or_else(|| clean(row.get(login_totp))),
            favorite: is_true(row.get(favorite)),
            notes: notes_with(
                &[(
                    "Description".to_string(),
                    row.get(description).unwrap_or_default().to_string(),
                )],
                clean(row.get(notes)),
            ),
            tags: split_tags(row.get(tags)),
            ..LoginFields::default()
        };
        fields.tags.extend(clean(row.get(folder)));
        for block in [row.get(secret_data), row.get(custom_data)] {
            read_data(block.unwrap_or_default(), &mut fields);
        }
        fields.custom_fields.extend(extra_fields(table.extras(row)));
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

fn read_data(block: &str, fields: &mut LoginFields) {
    let mut custom: Vec<CustomField> = Vec::new();
    for line in block.lines() {
        let Some((name, value)) = line.split_once(':') else {
            if let Some(last) = custom.last_mut()
                && !line.trim().is_empty()
            {
                last.value.push('\n');
                last.value.push_str(line);
            }
            continue;
        };
        let name = name.trim();
        if name.is_empty() || value.trim().is_empty() || name == "SecretType" {
            continue;
        }
        let lower = name.to_lowercase();
        if fields.username.is_none() && USERNAME_FIELDS.contains(&lower.as_str()) {
            fields.username = clean(Some(value));
        } else if fields.password.is_none() && PASSWORD_FIELDS.contains(&lower.as_str()) {
            fields.password = Some(value.to_string());
        } else {
            custom.push(custom_field(name, value.trim(), looks_secret(name)));
        }
    }
    fields.custom_fields.extend(custom);
}
