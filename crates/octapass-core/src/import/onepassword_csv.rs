//! 1Password CSV: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes` (1Password 8;
//! 1Password 7 lets people pick columns, so other names are recognised too).

use super::build::{Collector, LoginFields, extra_fields, is_true, skipped_row, split_tags};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["title"]) || !table.has(&["password"]) {
        return Err(invalid(
            "This is not a 1Password CSV export: it needs at least the columns Title and Password.",
        ));
    }
    let title = table.take(&["title"]);
    let url = table.take(&["url", "website", "login_url", "urls"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let otp = table.take(&["otpauth", "one-time_password", "totp"]);
    let favorite = table.take(&["favorite"]);
    let archived = table.take(&["archived"]);
    let tags = table.take(&["tags"]);
    let notes = table.take(&["notes", "notesplain"]);
    let mut out = Collector::default();
    let mut archived_count = 0;
    for row in &table.rows {
        let mut tags = split_tags(row.get(tags));
        if is_true(row.get(archived)) {
            archived_count += 1;
            tags.push("archived".into());
        }
        let fields = LoginFields {
            title: row.get(title).map(str::to_string),
            urls: row.get(url).map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(otp).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            tags,
            favorite: is_true(row.get(favorite)),
            custom_fields: extra_fields(table.extras(row)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_1password_8_csv() {
        let result = parse(
            "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
             GitHub,https://github.com,octo,pw,,true,false,\"work,dev\",\n\
             Old,https://old.example,me,pw2,,false,true,,gone\n",
        )
        .unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].overview.favorite, Some(true));
        assert_eq!(
            result.items[0].overview.tags.as_deref().unwrap(),
            ["work", "dev"]
        );
        assert_eq!(
            result.items[1].overview.tags.as_deref().unwrap(),
            ["archived"]
        );
        assert_eq!(
            result.warnings,
            ["1 archived item was imported with the tag \"archived\"."]
        );
    }
}
