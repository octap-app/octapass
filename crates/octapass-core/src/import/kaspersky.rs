//! Kaspersky Password Manager: the text export, and the CSV files My Kaspersky reads and writes.
//!
//! The text file is meant for printing, so nothing promises it stays parseable. It has sections
//! (`Websites`, `Applications`, `Other Accounts`, `Notes`) of entries ended by a `---` line
//! (`* * *` in some versions):
//!
//! ```text
//! Websites
//!
//! Website name: Example
//! Website URL: www.example.com
//! Login name: Personal
//! Login: jane@example.com
//! Password: secret
//! Comment: a comment,
//! which may run over several lines
//!
//! ---
//! ```
//!
//! Applications say `Application:`, other accounts `Account name:`, and notes `Name:` and `Text:`.
//! `Comment` and `Text` come last in an entry, so everything up to the next `---` belongs to them,
//! even a line that looks like a field. Other `Label: value` lines become custom fields. Labels
//! are in the app's language; only English is known, and other languages are refused with a
//! sentence saying so rather than read wrongly.
//!
//! The CSVs have a header row, either `Account,Login Name,Password,Web Site,Comments` (where
//! `Login Name` is the sign-in name) or `Website name;Website URL;Login name;Login;Password;
//! Comment` (where it's a label for the account, and `Login` is the sign-in name).

use super::build::{
    Collector, LoginFields, clean, clean_password, custom_field, extra_fields, note, notes_with,
    skipped_row,
};
use super::csv_table::{CsvTable, invalid, sniff_delimiter};
use super::{ImportError, ImportOptions, ImportResult, decode_text};

const SECTIONS: [&str; 4] = ["Websites", "Applications", "Other Accounts", "Notes"];

pub(super) fn parse(bytes: &[u8], _options: &ImportOptions) -> Result<ImportResult, ImportError> {
    let text = decode_text(bytes)?;
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default();
    if SECTIONS.contains(&first.trim()) || field(first).is_some() {
        parse_text(&text)
    } else if first.to_lowercase().contains("password") {
        parse_csv(&text)
    } else {
        Err(not_kaspersky())
    }
}

fn not_kaspersky() -> ImportError {
    invalid(
        "This is not a Kaspersky Password Manager export. Text exports can only be read in English: set Kaspersky's language to English and export again.",
    )
}

fn parse_csv(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, sniff_delimiter(text))?;
    if !table.has(&["password"]) || !table.has(&["website url", "web site", "url"]) {
        return Err(not_kaspersky());
    }
    let title = table.take(&["website name", "account", "application", "name"]);
    let url = table.take(&["website url", "web site", "url"]);
    let login = table.take(&["login"]);
    let login_name = table.take(&["login name"]);
    let password = table.take(&["password"]);
    let comment = table.take(&["comment", "comments"]);

    let mut out = Collector::default();
    for row in &table.rows {
        let mut custom_fields = extra_fields(table.extras(row));
        let label = clean(row.get(login_name));
        let username = match clean(row.get(login)) {
            Some(login) => {
                custom_fields.extend(account_label(label.as_deref(), &login));
                Some(login)
            }
            None => label,
        };
        let fields = LoginFields {
            title: clean(row.get(title)),
            urls: website(row.get(url)).into_iter().collect(),
            username: username.as_deref().map(sign_in_name),
            password: clean_password(row.get(password)),
            notes: row.get(comment).map(str::to_string),
            custom_fields,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

/// `Login name` when it says something `Login` doesn't.
fn account_label(label: Option<&str>, login: &str) -> Option<crate::item::CustomField> {
    label
        .filter(|label| *label != login)
        .map(|label| custom_field("Login name", label, false))
}

/// One entry as the file wrote it.
#[derive(Default)]
struct Entry {
    section: &'static str,
    line: usize,
    title: Option<String>,
    url: Option<String>,
    login_name: Option<String>,
    login: Option<String>,
    password: Option<String>,
    /// `Comment` or `Text`, which run to the end of the entry.
    body: Option<String>,
    is_note: bool,
    others: Vec<(String, String)>,
}

impl Entry {
    fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.url.is_none()
            && self.login_name.is_none()
            && self.login.is_none()
            && self.password.is_none()
            && self.body.is_none()
            && self.others.is_empty()
    }
}

fn parse_text(text: &str) -> Result<ImportResult, ImportError> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut open: Option<Entry> = None;
    let mut section = "Websites";
    let mut recognised = false;
    let mut out = Collector::default();

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if is_separator(trimmed) {
            if let Some(entry) = open.take() {
                entries.push(entry);
            }
            continue;
        }
        if trimmed.is_empty() && open.as_ref().is_none_or(|e| e.body.is_none()) {
            continue;
        }
        if open.is_none()
            && let Some(name) = SECTIONS.iter().find(|name| **name == trimmed)
        {
            section = name;
            recognised = true;
            continue;
        }
        let entry = match &mut open {
            Some(entry) => entry,
            // Text after a `---` that isn't a new entry: the comment itself had a `---` line.
            None if field(line).is_none() && entries.last().is_some_and(|e| e.body.is_some()) => {
                let mut last = entries.pop().unwrap_or_default();
                if let Some(body) = &mut last.body {
                    body.push_str("\n---");
                }
                open.insert(last)
            }
            None => open.insert(Entry {
                section,
                line: index + 1,
                ..Entry::default()
            }),
        };
        // The last field in an entry runs to its end, whatever its lines look like.
        if let Some(body) = &mut entry.body {
            body.push('\n');
            body.push_str(line);
            continue;
        }
        let Some((label, value)) = line.split_once(':').map(|(l, v)| (l.trim(), one_space(v)))
        else {
            out.warn(format!(
                "Line {} wasn't understood and was left out.",
                index + 1
            ));
            continue;
        };
        recognised |= field(line).is_some();
        match label {
            "Website name" | "Application" | "Account name" | "Name" => {
                entry.title = clean(Some(value));
            }
            "Website URL" => entry.url = clean(Some(value)),
            "Login name" => entry.login_name = clean(Some(value)),
            "Login" => entry.login = clean(Some(value)),
            "Password" => entry.password = clean_password(Some(value)),
            "Comment" => entry.body = Some(value.to_string()),
            "Text" => {
                entry.body = Some(value.to_string());
                entry.is_note = true;
            }
            _ => entry.others.push((label.to_string(), value.to_string())),
        }
    }
    entries.extend(open);
    if !recognised {
        return Err(not_kaspersky());
    }

    for entry in entries.into_iter().filter(|e| !e.is_empty()) {
        add_entry(entry, &mut out);
    }
    Ok(out.finish())
}

fn add_entry(entry: Entry, out: &mut Collector) {
    let tags: Vec<String> = match entry.section {
        "Websites" | "Notes" => vec![],
        section => vec![section.to_string()],
    };
    if entry.is_note && entry.login.is_none() && entry.password.is_none() {
        let notes = notes_with(&entry.others, entry.body);
        out.add(note(entry.title, tags, false, notes));
        return;
    }
    let mut custom_fields = extra_fields(entry.others);
    let username = match entry.login {
        Some(login) => {
            custom_fields.extend(account_label(entry.login_name.as_deref(), &login));
            Some(login)
        }
        None => entry.login_name,
    };
    let line = entry.line;
    let fields = LoginFields {
        title: entry.title,
        urls: website(entry.url.as_deref()).into_iter().collect(),
        username: username.as_deref().map(sign_in_name),
        password: entry.password,
        notes: entry.body,
        tags,
        custom_fields,
        ..LoginFields::default()
    };
    out.add_login(fields, || skipped_row(line as u64));
}

/// Kaspersky keeps websites as typed, usually `www.example.com`. Items need a scheme to match.
fn website(url: Option<&str>) -> Option<String> {
    let url = clean(url)?;
    let bare = !url.contains("://") && !url.contains(char::is_whitespace) && url.contains('.');
    Some(if bare { format!("https://{url}") } else { url })
}

/// Sign-in names that came from an address book link.
fn sign_in_name(login: &str) -> String {
    login.strip_prefix("mailto:").unwrap_or(login).to_string()
}

fn is_separator(line: &str) -> bool {
    line == "* * *" || (line.len() >= 3 && line.bytes().all(|b| b == b'-'))
}

/// `Label: value` keeps everything after the space, so a password may start with another.
fn one_space(value: &str) -> &str {
    value.strip_prefix(' ').unwrap_or(value)
}

/// The label when a line starts with one this format uses.
fn field(line: &str) -> Option<&str> {
    const LABELS: [&str; 9] = [
        "Website name",
        "Website URL",
        "Application",
        "Account name",
        "Login name",
        "Login",
        "Password",
        "Comment",
        "Name",
    ];
    let (label, _) = line.split_once(':')?;
    LABELS.iter().find(|known| **known == label.trim()).copied()
}

#[cfg(test)]
mod tests {
    use super::{is_separator, one_space, website};

    #[test]
    fn separators() {
        for line in ["---", "------", "* * *"] {
            assert!(is_separator(line), "{line}");
        }
        for line in ["--", "- - -", "***", ""] {
            assert!(!is_separator(line), "{line}");
        }
    }

    #[test]
    fn websites_get_a_scheme_when_they_have_none() {
        assert_eq!(website(Some("www.a.com")).unwrap(), "https://www.a.com");
        assert_eq!(website(Some("http://a.com")).unwrap(), "http://a.com");
        assert_eq!(website(Some("My router")).unwrap(), "My router");
        assert_eq!(website(Some("  ")), None);
    }

    #[test]
    fn a_password_keeps_its_own_spaces() {
        assert_eq!(one_space("  pw "), " pw ");
    }
}
