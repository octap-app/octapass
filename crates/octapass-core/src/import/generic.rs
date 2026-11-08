//! Any CSV with a header row. Columns are recognised by common names (LastPass, Bitwarden CSV,
//! KeePass, Dashlane, browsers), or given by a [`ColumnMapping`] the user picked after
//! [`preview_csv`]. Columns that aren't mapped become custom fields.
//!
//! Without a mapping, a file whose header is another app's export (Firefox, Chrome, Safari,
//! LastPass, 1Password, Bitwarden, Proton Pass, NordPass, RoboForm, KeePassXC, Dashlane, Zoho Vault, Avira, Norton, McAfee True Key, Kaspersky) is read
//! by that app's importer, so its ids, dates and special columns are understood.

use serde::{Deserialize, Serialize};

use super::build::{
    Collector, ItemMeta, LoginFields, extra_fields, is_true, skipped_row, split_tags, timestamp,
};
use super::csv_table::{CsvTable, invalid, sniff_delimiter};
use super::{ImportError, ImportOptions, ImportResult, ImportSource, decode_text};

/// Which column (by its header, exactly as in the file) holds each field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ColumnMapping {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Several tags, separated by `,` or `;`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// One folder name, kept as one tag even if it contains commas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorite: Option<String>,
    /// When the item was created, last changed, last used, and when its password changed: Unix
    /// seconds or milliseconds, or ISO 8601 dates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_changed: Option<String>,
    /// The item's id in the app, so importing the file again updates the items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Columns to leave out. Every other unmapped column is kept as a custom field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
}

/// What the mapping screen shows: the headers, a few rows and the mapping we'd guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvPreview {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub row_count: usize,
    pub suggested: ColumnMapping,
    /// `","`, `";"` or `"\t"`.
    pub delimiter: String,
}

const PREVIEW_ROWS: usize = 3;

// Header names used by common exporters, most specific first.
const TITLE: &[&str] = &["title", "name", "account", "entry"];
const URL: &[&str] = &[
    "url",
    "website",
    "uri",
    "login_uri",
    "web_site",
    "address",
    "site",
];
const USERNAME: &[&str] = &[
    "username",
    "login_username",
    "user",
    "user_name",
    "login",
    "email",
    "e-mail",
];
const PASSWORD: &[&str] = &["password", "login_password", "pass", "passwd"];
const TOTP: &[&str] = &[
    "totp",
    "login_totp",
    "otp",
    "otpauth",
    "2fa",
    "one-time_password",
];
const NOTES: &[&str] = &["notes", "note", "extra", "comments", "comment"];
const TAGS: &[&str] = &["tags", "tag", "labels"];
const FOLDER: &[&str] = &["folder", "grouping", "group", "category"];
const FAVORITE: &[&str] = &["favorite", "favourite", "fav"];
const CREATED: &[&str] = &[
    "created",
    "created_at",
    "creation_date",
    "creationdate",
    "date_created",
    "created_date",
    "time_created",
    "timecreated",
    "createtime",
];
const MODIFIED: &[&str] = &[
    "modified",
    "last_modified",
    "lastmodified",
    "modified_at",
    "date_modified",
    "updated",
    "updated_at",
    "last_updated",
    "revision_date",
    "revisiondate",
    "modifytime",
];
const LAST_USED: &[&str] = &[
    "last_used",
    "lastused",
    "last_used_at",
    "last_use",
    "last_accessed",
    "time_last_used",
    "timelastused",
];
const PASSWORD_CHANGED: &[&str] = &[
    "password_changed",
    "password_changed_at",
    "password_last_changed",
    "password_modified",
    "password_revision_date",
    "passwordrevisiondate",
    "time_password_changed",
    "timepasswordchanged",
];
const ID: &[&str] = &["id", "uuid", "guid", "uid", "item_id", "record_id"];

// LastPass exports secure notes as rows whose URL is this placeholder.
const LASTPASS_NOTE_URL: &str = "http://sn";

pub fn preview_csv(bytes: &[u8]) -> Result<CsvPreview, ImportError> {
    let text = decode_text(bytes)?;
    let delimiter = sniff_delimiter(&text);
    let mut table = CsvTable::parse(&text, delimiter)?;
    let suggested = suggest(&mut table);
    Ok(CsvPreview {
        rows: table
            .rows
            .iter()
            .take(PREVIEW_ROWS)
            .map(|row| row.cells().to_vec())
            .collect(),
        row_count: table.rows.len(),
        headers: table.headers,
        suggested,
        delimiter: char::from(delimiter).to_string(),
    })
}

fn suggest(table: &mut CsvTable) -> ColumnMapping {
    let mut pick = |names: &[&str]| table.take(names).map(|i| table.headers[i].clone());
    ColumnMapping {
        title: pick(TITLE),
        url: pick(URL),
        username: pick(USERNAME),
        password: pick(PASSWORD),
        totp: pick(TOTP),
        notes: pick(NOTES),
        tags: pick(TAGS),
        folder: pick(FOLDER),
        favorite: pick(FAVORITE),
        created: pick(CREATED),
        modified: pick(MODIFIED),
        last_used: pick(LAST_USED),
        password_changed: pick(PASSWORD_CHANGED),
        id: pick(ID),
        ignore: Vec::new(),
    }
}

/// The app whose CSV export has exactly these columns, when it has its own importer.
fn known_format(table: &CsvTable) -> Option<(ImportSource, &'static str)> {
    let all = |names: &[&str]| names.iter().all(|name| table.has(&[name]));
    let only = |names: &[&str]| all(names) && table.headers.len() == names.len();
    if all(&[
        "url",
        "username",
        "password",
        "httpRealm",
        "formActionOrigin",
        "guid",
    ]) {
        Some((ImportSource::Firefox, "Firefox"))
    } else if all(&["url", "username", "password", "extra", "name", "grouping"]) {
        Some((ImportSource::LastPassCsv, "LastPass"))
    } else if all(&[
        "title", "url", "username", "password", "otpauth", "favorite", "archived",
    ]) {
        Some((ImportSource::OnePasswordCsv, "1Password"))
    } else if all(&[
        "type",
        "name",
        "fields",
        "reprompt",
        "login_uri",
        "login_password",
    ]) {
        Some((ImportSource::BitwardenCsv, "Bitwarden"))
    } else if all(&["title", "url", "username", "password", "otpauth"]) {
        Some((ImportSource::Safari, "Safari or Apple Passwords"))
    } else if only(&["name", "url", "username", "password"])
        || only(&["name", "url", "username", "password", "note"])
    {
        Some((ImportSource::Chrome, "Chrome"))
    } else if all(&[
        "name",
        "url",
        "username",
        "password",
        "note",
        "totp",
        "createTime",
        "modifyTime",
    ]) {
        Some((ImportSource::ProtonPass, "Proton Pass"))
    } else if all(&[
        "name",
        "url",
        "username",
        "password",
        "type",
        "cardholdername",
        "folder",
    ]) {
        Some((ImportSource::NordPass, "NordPass"))
    } else if all(&["name", "url", "matchurl", "pwd"]) {
        Some((ImportSource::RoboForm, "RoboForm"))
    } else if table.has(&["password name", "secret name"]) {
        Some((ImportSource::ZohoVault, "Zoho Vault"))
    } else if all(&["name", "website", "secondary_username", "password"]) {
        Some((ImportSource::Avira, "Avira"))
    } else if all(&[
        "item type",
        "user name",
        "password",
        "site name",
        "login url",
    ]) {
        Some((ImportSource::Norton, "Norton Password Manager"))
    } else if all(&["kind", "login", "password", "url", "memo"]) {
        Some((ImportSource::McAfee, "McAfee True Key"))
    } else if all(&["login name", "password", "web site"])
        || all(&["website name", "website url", "password"])
    {
        Some((ImportSource::Kaspersky, "Kaspersky Password Manager"))
    } else if all(&[
        "group",
        "title",
        "username",
        "password",
        "url",
        "notes",
        "last modified",
        "created",
    ]) {
        Some((ImportSource::KeePass, "KeePassXC"))
    } else if all(&[
        "username",
        "username2",
        "title",
        "password",
        "note",
        "url",
        "category",
    ]) {
        Some((ImportSource::Dashlane, "Dashlane"))
    } else {
        None
    }
}

pub(super) fn parse(
    text: &str,
    mapping: Option<&ColumnMapping>,
) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, sniff_delimiter(text))?;
    if mapping.is_none() && super::own_csv::is_own(&table) {
        return Ok(super::own_csv::parse(&table));
    }
    if mapping.is_none()
        && let Some((source, app)) = known_format(&table)
        && let Ok(mut result) = super::parse(source, text.as_bytes(), &ImportOptions::default())
    {
        super::stamp_source(&mut result, source.name());
        result
            .warnings
            .insert(0, format!("This is a {app} export, so it was read as one."));
        return Ok(result);
    }
    let mapping = match mapping {
        Some(mapping) => mapping.clone(),
        None => {
            let suggested = suggest(&mut table);
            if suggested.password.is_none() && suggested.url.is_none() {
                return Err(invalid(
                    "No password or URL column found. Name the columns in the first row, for example title, url, username, password, or choose them.",
                ));
            }
            suggested
        }
    };
    let mut column = |header: &Option<String>| -> Result<Option<usize>, ImportError> {
        match header {
            Some(header) => table
                .take_exact(header)
                .map(Some)
                .ok_or(invalid("A chosen column isn't in the file.")),
            None => Ok(None),
        }
    };
    let title = column(&mapping.title)?;
    let url = column(&mapping.url)?;
    let username = column(&mapping.username)?;
    let password = column(&mapping.password)?;
    let totp = column(&mapping.totp)?;
    let notes = column(&mapping.notes)?;
    let tags = column(&mapping.tags)?;
    let folder = column(&mapping.folder)?;
    let favorite = column(&mapping.favorite)?;
    let created = column(&mapping.created)?;
    let modified = column(&mapping.modified)?;
    let last_used = column(&mapping.last_used)?;
    let password_changed = column(&mapping.password_changed)?;
    let id = column(&mapping.id)?;
    for ignored in &mapping.ignore {
        table.take_exact(ignored);
    }

    let mut out = Collector::default();
    for row in &table.rows {
        let url = row.get(url).filter(|u| u.trim() != LASTPASS_NOTE_URL);
        let mut row_tags = split_tags(row.get(tags));
        row_tags.extend(row.get(folder).map(str::to_string));
        let custom_fields = extra_fields(table.extras(row));
        let fields = LoginFields {
            title: row.get(title).map(str::to_string),
            urls: url.map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(totp).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            tags: row_tags,
            favorite: is_true(row.get(favorite)),
            custom_fields,
            meta: ItemMeta {
                created_at: timestamp(row.get(created)),
                updated_at: timestamp(row.get(modified)),
                last_used_at: timestamp(row.get(last_used)),
                source_id: row.get(id).map(str::to_string),
            },
            password_changed_at: timestamp(row.get(password_changed)),
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
    fn recognises_common_headers_and_keeps_the_rest() {
        let result = parse(
            "Account;Web Site;Login;Password;Folder;Security answer\n\
             Bank;https://bank.example;me;pw;Money, savings;blue\n",
            None,
        )
        .unwrap();
        let item = &result.items[0];
        assert_eq!(item.overview.title, "Bank");
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Money, savings"]);
        let ItemDetails::Login(details) = &item.details else {
            panic!()
        };
        assert_eq!(details.username.as_deref(), Some("me"));
        let field = &details.custom_fields.as_ref().unwrap()[0];
        assert_eq!(
            (field.label.as_str(), field.value.as_str()),
            ("Security answer", "blue")
        );
    }

    #[test]
    fn a_mapping_picks_columns_and_ignores_others() {
        let text = "c1,c2,c3,c4\nhttps://a.com,alice,secret,junk\n";
        assert!(parse(text, None).is_err());
        let mapping = ColumnMapping {
            url: Some("c1".into()),
            username: Some("c2".into()),
            password: Some("c3".into()),
            ignore: vec!["c4".into()],
            ..ColumnMapping::default()
        };
        let result = parse(text, Some(&mapping)).unwrap();
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(details.password.as_deref(), Some("secret"));
        assert!(details.custom_fields.is_none());

        let wrong = ColumnMapping {
            password: Some("missing".into()),
            ..ColumnMapping::default()
        };
        assert_eq!(
            parse(text, Some(&wrong)).unwrap_err().detail,
            "A chosen column isn't in the file."
        );
    }

    #[test]
    fn previews_suggest_a_mapping() {
        let preview =
            preview_csv(b"name\turl\tusername\tpassword\nA\thttps://a.com\tu\tp\nB\t\t\t\n")
                .unwrap();
        assert_eq!(preview.delimiter, "\t");
        assert_eq!(preview.headers, ["name", "url", "username", "password"]);
        assert_eq!(preview.row_count, 2);
        assert_eq!(preview.rows[0], ["A", "https://a.com", "u", "p"]);
        assert_eq!(preview.suggested.title.as_deref(), Some("name"));
        assert_eq!(preview.suggested.password.as_deref(), Some("password"));
        assert_eq!(preview.suggested.totp, None);
    }

    #[test]
    fn other_apps_exports_are_read_by_their_importer() {
        let firefox = parse(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
             \"https://a.com\",\"u\",\"p\",,\"https://a.com\",\"{1}\",\"1718000000000\",\"1718000000000\",\"1718000000000\"\n",
            None,
        )
        .unwrap();
        assert_eq!(
            firefox.warnings,
            ["This is a Firefox export, so it was read as one."]
        );
        let ItemDetails::Login(details) = &firefox.items[0].details else {
            panic!()
        };
        assert!(details.custom_fields.is_none());
        let from = firefox.items[0].overview.imported_from.as_ref().unwrap();
        assert_eq!((from.source.as_str(), from.id.as_str()), ("firefox", "{1}"));

        let chrome = parse(
            "name,url,username,password,note
A,https://a.com,u,p,n
",
            None,
        )
        .unwrap();
        assert_eq!(
            chrome.warnings,
            ["This is a Chrome export, so it was read as one."]
        );
        // A mapping always wins.
        let mapping = ColumnMapping {
            url: Some("url".into()),
            ..ColumnMapping::default()
        };
        assert!(
            parse(
                "name,url,username,password,note
A,https://a.com,u,p,n
",
                Some(&mapping)
            )
            .unwrap()
            .warnings
            .is_empty()
        );
    }

    #[test]
    fn dates_and_ids_are_recognised() {
        let result = parse(
            "Title,URL,Password,ID,Created,Last Modified,Last Used,Password Changed\n\
             A,https://a.com,p,42,2020-01-02T03:04:05Z,1718000000,1718000000000,2021-05-06\n",
            None,
        )
        .unwrap();
        let overview = &result.items[0].overview;
        assert_eq!(overview.created_at.as_deref(), Some("2020-01-02T03:04:05Z"));
        assert_eq!(overview.updated_at.as_deref(), Some("2024-06-10T06:13:20Z"));
        assert_eq!(
            overview.last_used_at.as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(overview.imported_from.as_ref().unwrap().id, "42");
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(
            details.password_changed_at.as_deref(),
            Some("2021-05-06T00:00:00Z")
        );
        assert!(details.custom_fields.is_none());
    }

    #[test]
    fn bitwarden_csv_is_read_as_bitwarden() {
        let result = parse(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
             Work,1,login,Mail,hi,\"PIN: 1234\nRecovery: blue\",0,https://mail.example,me,pw,\n",
            None,
        )
        .unwrap();
        assert_eq!(
            result.warnings[0],
            "This is a Bitwarden export, so it was read as one."
        );
        let item = &result.items[0];
        assert_eq!(item.overview.tags.as_deref().unwrap(), ["Work"]);
        assert_eq!(item.overview.favorite, Some(true));
        let ItemDetails::Login(details) = &item.details else {
            panic!()
        };
        let fields = details.custom_fields.as_ref().unwrap();
        assert_eq!(
            fields
                .iter()
                .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
                .collect::<Vec<_>>(),
            [("PIN", "1234", true), ("Recovery", "blue", false)]
        );
    }

    #[test]
    fn lastpass_note_rows_have_no_url() {
        let result = parse(
            "url,name,extra,password\nhttp://sn,Diary,dear diary,\n",
            None,
        )
        .unwrap();
        assert!(result.items[0].overview.urls.is_none());
    }
}
