//! Chrome, Edge, Brave, Opera, Vivaldi and Arc: `name,url,username,password[,note]`.

use super::build::{Collector, LoginFields, extra_fields, skipped_row};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["url"]) || !table.has(&["username"]) || !table.has(&["password"]) {
        return Err(invalid(
            "This is not a browser password export: it needs the columns url, username and password.",
        ));
    }
    let name = table.take(&["name"]);
    let url = table.take(&["url"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let note = table.take(&["note", "notes"]);
    let mut out = Collector::default();
    for row in &table.rows {
        let fields = LoginFields {
            title: row.get(name).map(str::to_string),
            urls: row.get(url).map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            notes: row.get(note).map(str::to_string),
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
    fn parses_chrome_exports() {
        let result = parse(
            "name,url,username,password,note\n\
             github.com,https://github.com/login,octo,\"p,w\"\"1\",\"two\nlines\"\n\
             ,https://www.example.com/,,secret,\n\
             ,,,,\n\
             nothing,,,,\n",
        )
        .unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.skipped, 1);
        assert_eq!(
            result.warnings,
            ["Row 6 skipped: no URL, username, password or notes."]
        );
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(details.password.as_deref(), Some("p,w\"1"));
        assert_eq!(details.notes.as_deref(), Some("two\nlines"));
        assert_eq!(result.items[1].overview.title, "example.com");
    }

    #[test]
    fn unknown_columns_become_custom_fields() {
        let result =
            parse("origin,name,url,username,password,Backup PIN\nx,a,https://a.com,u,p,1234\n")
                .unwrap();
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        let fields = details.custom_fields.as_ref().unwrap();
        assert_eq!(
            (fields[0].label.as_str(), fields[0].hidden),
            ("origin", false)
        );
        assert_eq!(
            (
                fields[1].label.as_str(),
                fields[1].value.as_str(),
                fields[1].hidden
            ),
            ("Backup PIN", "1234", true)
        );
    }

    #[test]
    fn rejects_other_files() {
        assert!(parse("title,website\nx,y\n").is_err());
    }
}
