//! Safari and the Apple Passwords app: `Title,URL,Username,Password,Notes,OTPAuth`.

use super::build::{Collector, LoginFields, extra_fields, skipped_row};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["url"]) || !table.has(&["username"]) || !table.has(&["password"]) {
        return Err(invalid(
            "This is not a Safari or Passwords export: it needs the columns Title, URL, Username and Password.",
        ));
    }
    let title = table.take(&["title"]);
    let url = table.take(&["url"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let notes = table.take(&["notes"]);
    let otp = table.take(&["otpauth"]);
    let mut out = Collector::default();
    for row in &table.rows {
        let fields = LoginFields {
            title: row.get(title).map(str::to_string),
            urls: row.get(url).map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(otp).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            custom_fields: extra_fields(table.extras(row)),
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemDetails;

    #[test]
    fn parses_passwords_app_exports() {
        let result = parse(
            "Title,URL,Username,Password,Notes,OTPAuth\n\
             Example (alice),https://example.com/,alice,pw,note,otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\n",
        )
        .unwrap();
        let item = &result.items[0];
        assert_eq!(item.overview.title, "Example (alice)");
        let ItemDetails::Login(details) = &item.details else {
            panic!()
        };
        assert!(
            details
                .totp
                .as_deref()
                .unwrap()
                .starts_with("otpauth://totp/")
        );
        assert_eq!(details.notes.as_deref(), Some("note"));
    }
}
