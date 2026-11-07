//! Norton Password Manager CSV.
//!
//! Current exports open with two lines about the file (`Format,Version,Product,Product Version,
//! Exported Date`, then their values), then `Item Type,User Name,Password,Site Name,Login URL,
//! Notes,Secure,Favorite`. Older ones have no preamble and say `Username,Password,Title,URL,Notes`.
//! Norton publishes no layout: these come from users' reports, so columns are matched by name and
//! anything unknown is kept as a custom field. Notes rows have no login fields and become secure
//! notes on their own.

use super::build::{
    Collector, LoginFields, clean, clean_password, extra_fields, is_true, skipped_row,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(without_preamble(&text), b',')?;
    if !table.has(&["password"]) || !table.has(&["login url", "url"]) {
        return Err(invalid(
            "This is not a Norton Password Manager export: it needs the columns Password and Login URL.",
        ));
    }
    let title = table.take(&["site name", "title", "account name", "name"]);
    let url = table.take(&["login url", "url"]);
    let username = table.take(&["user name", "username", "login"]);
    let password = table.take(&["password"]);
    let notes = table.take(&["notes", "note", "extra"]);
    let favorite = table.take(&["favorite", "favourite", "fav"]);
    // `Secure` asks Norton for the vault password before filling; Octa Pass has its own gates.
    // The type is implied by which fields a row has.
    table.ignore(&["item type", "secure"]);

    let mut out = Collector::default();
    for row in &table.rows {
        let fields = LoginFields {
            title: clean(row.get(title)),
            urls: clean(row.get(url)).into_iter().collect(),
            username: clean(row.get(username)),
            password: clean_password(row.get(password)),
            notes: row.get(notes).map(str::to_string),
            favorite: is_true(row.get(favorite)),
            custom_fields: extra_fields(table.extras(row)),
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

/// The text from the column names on: the two lines about the file are dropped.
fn without_preamble(text: &str) -> &str {
    let plain = text
        .trim_start()
        .trim_start_matches('"')
        .to_ascii_lowercase();
    if !plain.starts_with("format") || !plain.lines().next().is_some_and(|l| l.contains("version"))
    {
        return text;
    }
    text.trim_start().splitn(3, '\n').nth(2).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::without_preamble;

    #[test]
    fn only_norton_s_own_preamble_is_dropped() {
        let header = "Item Type,User Name,Password,Site Name,Login URL,Notes,Secure,Favorite\n";
        let file = format!(
            "Format,Version,Product,Product Version,Exported Date\nCSV,1,N,8,2025\n{header}"
        );
        assert_eq!(without_preamble(&file), header);
        assert_eq!(without_preamble(header), header);
        assert_eq!(
            without_preamble("Format,Password,URL\n"),
            "Format,Password,URL\n"
        );
        assert_eq!(without_preamble("Format,Version\n"), "");
    }
}
