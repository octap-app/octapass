//! RoboForm CSV: `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`.
//!
//! Logins, bookmarks (a URL only) and safenotes (a note only) share the layout; rows with only a
//! note become secure notes. The folder path (`/Work/Banking`) becomes one tag. `RfFieldsV2` runs
//! to the end of the row, one cell per form field, each itself a CSV record
//! `name,id,?,type,value`: `TOTP KEY$` is the one-time code, fields repeating the login or
//! password are dropped, and the rest become custom fields (`pwd` ones hidden). RoboForm puts a
//! `'` before values starting with `@` or `'`; it is removed again.

use super::build::{
    Collector, LoginFields, clean, clean_password, custom_field, extra_fields, looks_secret,
    skipped_row,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::item::CustomField;

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(&text, b',')?;
    let roboform_columns = ["pwd", "matchurl", "rffieldsv2", "rf_fields"];
    if !table.has(&["name"]) || !table.has(&["url"]) || !table.has(&roboform_columns) {
        return Err(invalid(
            "This is not a RoboForm export: it needs the columns Name, Url, MatchUrl and Pwd.",
        ));
    }
    let name = table.take(&["name"]);
    let url = table.take(&["url"]);
    let match_url = table.take(&["matchurl"]);
    let login = table.take(&["login"]);
    let pwd = table.take(&["pwd", "password"]);
    let note = table.take(&["note"]);
    let folder = table.take(&["folder"]);
    let fields_v2 = table.take(&["rffieldsv2"]);
    let fields_v1 = table.take(&["rf_fields"]);
    let form_fields = fields_v2.or(fields_v1);
    // Form fields run past the last header; those cells aren't unknown columns.
    let width = table.headers.len();
    let overflow: Vec<String> = match form_fields {
        Some(_) => (width
            ..table
                .rows
                .iter()
                .map(|r| r.cells().len())
                .max()
                .unwrap_or(0))
            .map(|i| format!("Column {}", i + 1))
            .collect(),
        None => vec![],
    };

    let mut out = Collector::default();
    for row in &table.rows {
        let mut username = row.get(login).map(unescape);
        let mut password = row.get(pwd).map(unescape);
        let mut totp = None;
        let mut custom_fields: Vec<CustomField> = Vec::new();
        let cells = form_fields
            .and_then(|start| row.cells().get(start..))
            .unwrap_or_default();
        for cell in cells.iter().filter(|c| !c.trim().is_empty()) {
            let field = if fields_v2.is_some() {
                FormField::parse_v2(cell)
            } else {
                FormField::parse_v1(cell)
            };
            match field.name.as_str() {
                "TOTP KEY$" if totp.is_none() => totp = Some(field.value),
                "User ID$" if clean(username.as_deref()).is_none() => {
                    username = Some(field.value);
                }
                "Password$" if clean_password(password.as_deref()).is_none() => {
                    password = Some(field.value);
                }
                "User ID$" if username.as_deref() == Some(&field.value) => {}
                "Password$" if password.as_deref() == Some(&field.value) => {}
                _ => {
                    let label = field.label();
                    let hidden = field.kind == "pwd" || looks_secret(&label);
                    custom_fields.push(custom_field(&label, &field.value, hidden));
                }
            }
        }
        custom_fields.extend(extra_fields(
            table
                .extras(row)
                .into_iter()
                .filter(|(label, _)| !overflow.contains(label))
                .collect(),
        ));

        let mut urls: Vec<String> = Vec::new();
        for url in [row.get(url), row.get(match_url)].into_iter().flatten() {
            if let Some(url) = clean(Some(url))
                && !urls.contains(&url)
            {
                urls.push(url);
            }
        }
        let fields = LoginFields {
            title: clean(row.get(name)),
            urls,
            username,
            password,
            totp,
            notes: row.get(note).map(str::to_string),
            tags: folder_tag(row.get(folder)).into_iter().collect(),
            custom_fields,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

/// A form field from `RfFieldsV2` (or the older `Rf_fields`).
struct FormField {
    name: String,
    /// The field's id in the form, for unnamed fields.
    id: String,
    /// `txt`, `pwd`, `chk`, `rad`, `sel`, `are` …
    kind: String,
    value: String,
}

impl FormField {
    /// `User ID$,,,txt,jane@example.com`. The value may itself be quoted.
    fn parse_v2(cell: &str) -> Self {
        let parts: Vec<String> = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_reader(cell.as_bytes())
            .records()
            .next()
            .and_then(Result::ok)
            .map(|record| record.iter().map(str::to_string).collect())
            .unwrap_or_default();
        if parts.len() < 5 {
            return Self::unparsed(cell);
        }
        Self {
            name: parts[0].trim().to_string(),
            id: parts[1].trim().to_string(),
            kind: parts[3].trim().to_string(),
            // A value with unquoted commas spans the remaining parts.
            value: unescape(&parts[4..].join(",")),
        }
    }

    /// `name:type:value` (older `Rf_fields` exports, read as Bitwarden reads them; `rck` fields
    /// have the value second).
    fn parse_v1(cell: &str) -> Self {
        let parts: Vec<&str> = cell.split(':').collect();
        if parts.len() < 3 {
            return Self::unparsed(cell);
        }
        let value = if parts.len() == 4 && parts[2] == "rck" {
            parts[1]
        } else {
            parts[2]
        };
        Self {
            name: parts[0].trim().to_string(),
            id: String::new(),
            kind: String::new(),
            value: unescape(value),
        }
    }

    /// A cell in no known shape: kept whole.
    fn unparsed(cell: &str) -> Self {
        Self {
            name: String::new(),
            id: String::new(),
            kind: String::new(),
            value: cell.to_string(),
        }
    }

    /// RoboForm marks its own field names with `$` (`User ID$`).
    fn label(&self) -> String {
        let name = (self.name != "-no-name-").then(|| self.name.trim_end_matches('$'));
        clean(name)
            .or_else(|| clean(Some(&self.id)))
            .unwrap_or_else(|| "Field".into())
    }
}

/// `'@x` → `@x` and `''x` → `'x`: RoboForm's guard against spreadsheet formulas.
fn unescape(value: &str) -> String {
    match value.strip_prefix('\'') {
        Some(rest) if rest.starts_with(['@', '\'']) => rest.to_string(),
        _ => value.to_string(),
    }
}

/// `/Work/Banking` → `Work/Banking`.
fn folder_tag(folder: Option<&str>) -> Option<String> {
    clean(folder.map(|f| f.trim().trim_start_matches(['/', '\\'])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemDetails, ItemType};

    const HEADER: &str = "Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\n";

    fn import(rows: &str) -> ImportResult {
        parse(
            format!("{HEADER}{rows}").as_bytes(),
            &ImportOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn form_fields() {
        let field = FormField::parse_v2("Password$,,,pwd,\"'@'pass\"\"\"");
        assert_eq!(field.value, "@'pass\"");
        assert_eq!(field.kind, "pwd");
        assert_eq!(FormField::parse_v2("PIN,,,txt,1,2,3").value, "1,2,3");
        let unnamed = FormField::parse_v2("-no-name-,field7,,txt,x");
        assert_eq!(unnamed.label(), "field7");
        assert_eq!(FormField::parse_v2("garbage").value, "garbage");
        assert_eq!(FormField::parse_v1("Pin:txt:1234").value, "1234");
        assert_eq!(FormField::parse_v1("Remember:on:rck:x").value, "on");
    }

    #[test]
    fn escapes_and_folders() {
        assert_eq!(unescape("'@me"), "@me");
        assert_eq!(unescape("''pw"), "'pw");
        assert_eq!(unescape("'plain"), "'plain");
        assert_eq!(
            folder_tag(Some("/Work/Banking")).as_deref(),
            Some("Work/Banking")
        );
        assert_eq!(folder_tag(Some("/")), None);
    }

    #[test]
    fn logins_with_fields_totp_and_duplicates() {
        let result = import(
            "Site,https://a.example.com/login,https://a.example.com/,'@me,''pw,,/Work,\"User ID$,,,txt,'@me\",\"Password$,,,pwd,''pw\",\"TOTP KEY$,,,txt,JBSWY3DPEHPK3PXP\",\"Account,acct,,txt,42\",\"Old Password$,,,pwd,older\"\n",
        );
        let item = &result.items[0];
        assert_eq!(item.overview.urls.as_ref().unwrap().len(), 2);
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Work"]);
        let ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert_eq!(login.username.as_deref(), Some("@me"));
        assert_eq!(login.password.as_deref(), Some("'pw"));
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let fields = login.custom_fields.as_ref().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(
            (fields[0].label.as_str(), fields[0].hidden),
            ("Account", false)
        );
        assert_eq!(
            (fields[1].label.as_str(), fields[1].hidden),
            ("Old Password", true)
        );
    }

    #[test]
    fn notes_bookmarks_and_empty_rows() {
        let result = import(
            "Diary,,,,,\"line one\nline two\",/Personal\n\
             Bookmark,https://news.example.com,,,,,\n\
             Nothing,,,,,,\n",
        );
        assert_eq!(result.items[0].overview.item_type, ItemType::SecureNote);
        assert_eq!(result.items[1].overview.item_type, ItemType::Login);
        assert_eq!(result.skipped, 1);
    }
}
