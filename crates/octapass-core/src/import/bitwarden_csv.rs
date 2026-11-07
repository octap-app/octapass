//! Bitwarden (and Vaultwarden) CSV exports, as `buildCsvExport` and `buildCommonCipher` in
//! Bitwarden's `libs/tools/export-vault-core` write them:
//!
//! ```text
//! folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp
//! ```
//!
//! Organisation exports have `collections` (names, separated by commas) instead of `folder` and
//! `favorite`; older exports have no `archivedDate`. Only logins and secure notes are exported
//! (`type` `login` or `note`). A login's URIs share one cell, separated by commas. `fields` holds
//! the custom fields as `Name: value` lines; a line without `: ` continues the value above it (a
//! value with several lines). A field without a value is written as `null`. The CSV has no ids
//! or dates, so importing it again relies on duplicate matching; `reprompt` has no equivalent.

use super::build::{
    Collector, LoginFields, clean, custom_field, looks_secret, note, notes_with, skipped_row,
    split_tags,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};
use crate::item::CustomField;

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["login_uri"]) || !table.has(&["name"]) || !table.has(&["type"]) {
        return Err(invalid(
            "This is not a Bitwarden CSV export: it needs the columns type, name and login_uri.",
        ));
    }
    let folder = table.take(&["folder"]);
    let collections = table.take(&["collections"]);
    let favorite = table.take(&["favorite"]);
    let kind = table.take(&["type"]);
    let name = table.take(&["name"]);
    let notes = table.take(&["notes"]);
    let fields = table.take(&["fields"]);
    let archived = table.take(&["archiveddate", "archived_date"]);
    let uri = table.take(&["login_uri"]);
    let username = table.take(&["login_username"]);
    let password = table.take(&["login_password"]);
    let totp = table.take(&["login_totp"]);
    table.ignore(&["reprompt"]);

    let mut out = Collector::default();
    let mut archived_count = 0;
    for row in &table.rows {
        let mut tags: Vec<String> = clean(row.get(folder)).into_iter().collect();
        tags.extend(split_tags(row.get(collections)));
        if clean(row.get(archived)).is_some() {
            archived_count += 1;
            tags.push("archived".into());
        }
        let mut custom_fields = row.get(fields).map(custom_fields).unwrap_or_default();
        custom_fields.extend(super::build::extra_fields(table.extras(row)));
        let title = row.get(name).map(str::to_string);
        let favorite = row
            .get(favorite)
            .is_some_and(|f| !matches!(f.trim(), "" | "0"));
        if row
            .get(kind)
            .is_some_and(|k| k.trim().eq_ignore_ascii_case("note"))
        {
            let lines: Vec<(String, String)> = custom_fields
                .into_iter()
                .map(|field| (field.label, field.value))
                .collect();
            let notes = notes_with(&lines, row.get(notes).map(str::to_string));
            out.add(note(title, tags, favorite, notes));
            continue;
        }
        let fields = LoginFields {
            title,
            urls: row
                .get(uri)
                .unwrap_or_default()
                .split(',')
                .filter_map(|url| clean(Some(url)))
                .collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(totp).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            tags,
            favorite,
            custom_fields,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    if archived_count > 0 {
        out.warn(format!(
            "{archived_count} archived {} imported with the tag \"archived\".",
            if archived_count == 1 {
                "item was"
            } else {
                "items were"
            }
        ));
    }
    Ok(out.finish())
}

/// The `Name: value` lines of the `fields` cell. Hidden fields aren't marked in the CSV, so
/// fields are hidden when their name suggests a secret.
fn custom_fields(cell: &str) -> Vec<CustomField> {
    let mut fields: Vec<CustomField> = Vec::new();
    for line in cell.lines() {
        match (line.split_once(": "), fields.last_mut()) {
            (None, Some(last)) => {
                last.value.push('\n');
                last.value.push_str(line);
            }
            (None, None) if line.trim().is_empty() => {}
            (None, None) => fields.push(custom_field("Field", line, false)),
            (Some((label, value)), _) => {
                let value = if value == "null" { "" } else { value };
                let label = if label.trim().is_empty() {
                    "Field"
                } else {
                    label
                };
                fields.push(custom_field(label, value, looks_secret(label)));
            }
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_lines() {
        let fields = custom_fields("PIN: 1234\nAddress: 1 Main St\nFlat 2\nLinked: null\n: x");
        let fields: Vec<(&str, &str, bool)> = fields
            .iter()
            .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
            .collect();
        assert_eq!(
            fields,
            [
                ("PIN", "1234", true),
                ("Address", "1 Main St\nFlat 2", false),
                ("Linked", "", false),
                ("Field", "x", false),
            ]
        );
    }

    #[test]
    fn needs_bitwarden_columns() {
        assert!(parse("name,url,username,password\na,b,c,d\n").is_err());
    }
}
