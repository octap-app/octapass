//! McAfee True Key CSV (`Truekey_export`), also read for McAfee Password Manager's file.
//!
//! One row per entry. `kind` is `login`, `cc` (a card) or something else for a note or document.
//! Logins use `name,url,login,password,memo`; other kinds `title,note,document_content`, cards
//! also `cardholder,number,expiryDate`. Files with no `kind` are read as logins; users report
//! that newer versions export logins only. McAfee publishes no layout: it's read as Bitwarden's
//! importer reads it, and McAfee Password Manager's own columns are a best guess.

use super::build::{
    Collector, LoginFields, card, card_details, clean, clean_password, expiry, extra_fields,
    is_true, note, notes_with, skipped_row,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let mut table = CsvTable::parse(&text, b',')?;
    let true_key = table.has(&["kind", "tk_export_version"]);
    let plain = table.has(&["password"]) && table.has(&["url"]);
    if !true_key && !plain {
        return Err(invalid(
            "This is not a McAfee True Key export: it needs the columns kind, or password and url.",
        ));
    }
    let kind = table.take(&["kind"]);
    let favorite = table.take(&["favorite"]);
    let name = table.take(&["name"]);
    let title = table.take(&["title"]);
    let url = table.take(&["url", "website"]);
    let login = table.take(&["login", "username", "user name"]);
    let password = table.take(&["password"]);
    let memo = table.take(&["memo", "notes"]);
    let note_text = table.take(&["note"]);
    let document = table.take(&["document_content"]);
    let cardholder = table.take(&["cardholder"]);
    let number = table.take(&["number"]);
    let expiry_date = table.take(&["expirydate"]);
    table.ignore(&[
        "autologin",
        "hexcolor",
        "protectedwithpassword",
        "subdomainonly",
        "type",
        "tk_export_version",
    ]);

    let mut out = Collector::default();
    for row in &table.rows {
        let favorite = is_true(row.get(favorite));
        let extras = table.extras(row);
        let kind = clean(row.get(kind)).unwrap_or_else(|| "login".into());
        if kind.eq_ignore_ascii_case("login") {
            let fields = LoginFields {
                title: clean(row.get(name)).or_else(|| clean(row.get(title))),
                urls: clean(row.get(url)).into_iter().collect(),
                username: clean(row.get(login)),
                password: clean_password(row.get(password)),
                notes: row.get(memo).or(row.get(note_text)).map(str::to_string),
                favorite,
                custom_fields: extra_fields(extras),
                ..LoginFields::default()
            };
            out.add_login(fields, || skipped_row(row.line));
            continue;
        }
        let item_title = clean(row.get(title)).or_else(|| clean(row.get(name)));
        let mut notes = clean(row.get(note_text)).or_else(|| clean(row.get(memo)));
        if let Some(content) = clean(row.get(document)) {
            notes = Some(match notes {
                Some(notes) if notes != content => format!("{notes}\n{content}"),
                _ => content,
            });
        }
        if kind.eq_ignore_ascii_case("cc") {
            let written = clean(row.get(expiry_date));
            let parsed = written.as_deref().and_then(card_expiry);
            let mut lines = extras;
            if parsed.is_none()
                && let Some(written) = written
            {
                lines.insert(0, ("Expiry date".into(), written));
            }
            out.add(card(
                item_title,
                vec![],
                favorite,
                crate::item::CardDetails {
                    cardholder: clean(row.get(cardholder)),
                    number: clean(row.get(number)),
                    expiry: parsed,
                    notes: notes_with(&lines, notes),
                    ..card_details()
                },
            ));
        } else if item_title.is_none() && notes.is_none() && extras.is_empty() {
            out.skip(Some(skipped_row(row.line)));
        } else {
            out.add(note(
                item_title,
                vec![],
                favorite,
                notes_with(&extras, notes),
            ));
        }
    }
    Ok(out.finish())
}

/// `MM/YY` from `2031-07-01T00:00:00Z`, `2031-07`, `07/2031` or `07/31`.
fn card_expiry(text: &str) -> Option<String> {
    let (first, rest) = text.trim().split_once(['-', '/'])?;
    let digits = |part: &str| -> Option<u32> {
        (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    let second: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if first.len() == 4 {
        expiry(digits(&second)?, digits(first)?)
    } else {
        expiry(digits(first)?, digits(&second)?)
    }
}

#[cfg(test)]
mod tests {
    use super::card_expiry;

    #[test]
    fn expiry_dates() {
        for text in [
            "2031-07-01T00:00:00Z",
            "2031-07",
            "07/2031",
            "07/31",
            "7/31",
        ] {
            assert_eq!(card_expiry(text).as_deref(), Some("07/31"), "{text}");
        }
        for text in ["", "soon", "13/2031", "2031-13-01", "a/b", "07-"] {
            assert_eq!(card_expiry(text), None, "{text}");
        }
    }
}
