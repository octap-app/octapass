//! Avira Password Manager CSV: `name,website,username,secondary_username,password`.
//!
//! When there's no `username`, `secondary_username` is the sign-in name; otherwise it's kept as a
//! custom field. Avira doesn't publish the layout: it's read as Bitwarden's importer reads it.

use super::build::{
    Collector, LoginFields, clean, clean_password, custom_field, extra_fields, skipped_row,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(&text, b',')?;
    if !table.has(&["name"]) || !table.has(&["website"]) || !table.has(&["password"]) {
        return Err(invalid(
            "This is not an Avira export: it needs the columns name, website and password.",
        ));
    }
    let name = table.take(&["name"]);
    let website = table.take(&["website"]);
    let username = table.take(&["username"]);
    let secondary = table.take(&["secondary_username"]);
    let password = table.take(&["password"]);
    let notes = table.take(&["notes", "note"]);

    let mut out = Collector::default();
    for row in &table.rows {
        let mut custom_fields = extra_fields(table.extras(row));
        let primary = clean(row.get(username));
        let second = clean(row.get(secondary));
        let username = match (primary, second) {
            (Some(primary), Some(second)) => {
                custom_fields.insert(0, custom_field("Secondary username", &second, false));
                Some(primary)
            }
            (primary, second) => primary.or(second),
        };
        let fields = LoginFields {
            title: clean(row.get(name)),
            urls: clean(row.get(website)).into_iter().collect(),
            username,
            password: clean_password(row.get(password)),
            notes: row.get(notes).map(str::to_string),
            custom_fields,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}
