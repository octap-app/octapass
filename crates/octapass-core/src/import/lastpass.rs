//! LastPass CSV: `url,username,password,totp,extra,name,grouping,fav`.
//!
//! Secure notes are rows with the URL `http://sn`. Structured ones start their `extra` with
//! `NoteType:` followed by `Key:value` lines, and a final `Notes:` that runs to the end. Credit
//! cards and addresses become cards and identities; bank accounts, databases, servers, software
//! licences, passports, driver's licences and social security numbers their own types; other
//! templates with a username or password become logins, and the rest secure notes with every field
//! kept as a line.

use super::build::{
    Collector, LoginFields, TypedItem, address, card, card_details, clean, clean_password,
    custom_field, expiry, extra_fields, identity, identity_details, is_true, iso_date,
    looks_secret, month_number, note, notes_with, skipped_row,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};
use crate::item::CardDetails;

const NOTE_URL: &str = "http://sn";

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["url"]) || !table.has(&["extra"]) || !table.has(&["name"]) {
        return Err(invalid(
            "This is not a LastPass export: it needs the columns url, extra and name.",
        ));
    }
    let url = table.take(&["url"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let totp = table.take(&["totp"]);
    let extra = table.take(&["extra"]);
    let name = table.take(&["name"]);
    let grouping = table.take(&["grouping"]);
    let fav = table.take(&["fav"]);

    let mut out = Collector::default();
    for row in &table.rows {
        let title = clean(row.get(name));
        // LastPass folders nest with `\`; the folder is one tag.
        let tags: Vec<String> = clean(row.get(grouping)).into_iter().collect();
        let favorite = is_true(row.get(fav));
        let extra_text = row.get(extra).unwrap_or_default();
        let is_note = row.get(url).map(str::trim) == Some(NOTE_URL);

        if is_note && let Some(note) = StructuredNote::parse(extra_text) {
            note.add_to(&mut out, title, tags, favorite);
            continue;
        }
        let fields = LoginFields {
            title,
            urls: if is_note {
                vec![]
            } else {
                row.get(url).map(str::to_string).into_iter().collect()
            },
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(totp).map(str::to_string),
            notes: Some(extra_text.to_string()),
            tags,
            favorite,
            custom_fields: extra_fields(table.extras(row)),
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    Ok(out.finish())
}

struct StructuredNote {
    kind: String,
    fields: Vec<(String, String)>,
    notes: Option<String>,
}

impl StructuredNote {
    fn parse(extra: &str) -> Option<Self> {
        let body = extra.strip_prefix("NoteType:")?;
        let (kind, mut rest) = body.split_once('\n').unwrap_or((body, ""));
        let mut fields = Vec::new();
        let mut notes = None;
        while !rest.is_empty() {
            if let Some(text) = rest.strip_prefix("Notes:") {
                notes = clean(Some(text));
                break;
            }
            let (line, next) = rest.split_once('\n').unwrap_or((rest, ""));
            rest = next;
            if let Some((key, value)) = line.split_once(':') {
                fields.push((
                    key.trim().to_string(),
                    value.trim_end_matches('\r').to_string(),
                ));
            }
        }
        Some(Self {
            kind: kind.trim().to_string(),
            fields,
            notes,
        })
    }

    /// Removes and returns a field's value.
    fn take(&mut self, key: &str) -> Option<String> {
        let index = self.fields.iter().position(|(k, _)| k == key)?;
        let value = self.fields.remove(index).1;
        clean(Some(&value))
    }

    /// The field's value in its place on `item`.
    fn set(&mut self, item: &mut TypedItem, key: &str, field: &str) {
        let value = self.take(field);
        item.set(key, value);
    }

    /// A date as LastPass writes it (`January,15,1990`) in its place on `item`.
    fn set_date(&mut self, item: &mut TypedItem, key: &str, field: &str) {
        let value = self
            .take(field)
            .map(|date| lastpass_date(&date).unwrap_or(date));
        item.set(key, value);
    }

    /// The item with what's left as custom fields, and the note's notes.
    fn finish(
        mut self,
        mut item: TypedItem,
        out: &mut Collector,
        title: Option<String>,
        tags: Vec<String>,
        favorite: bool,
    ) {
        for (label, value) in self.remaining_lines() {
            item.custom(&label, &value, looks_secret(&label));
        }
        out.add(item.build(title, tags, favorite, self.notes));
    }

    /// The fields nobody claimed, as note lines. `Language` is LastPass's own setting.
    fn remaining_lines(&mut self) -> Vec<(String, String)> {
        self.take("Language");
        std::mem::take(&mut self.fields)
    }

    fn add_to(
        mut self,
        out: &mut Collector,
        title: Option<String>,
        tags: Vec<String>,
        favorite: bool,
    ) {
        match self.kind.as_str() {
            "Credit Card" => {
                let details = CardDetails {
                    cardholder: self.take("Name on Card"),
                    brand: self.take("Type"),
                    number: self.take("Number"),
                    cvv: self.take("Security Code"),
                    expiry: self
                        .take("Expiration Date")
                        .and_then(|date| lastpass_expiry(&date)),
                    ..card_details()
                };
                let notes = notes_with(&self.remaining_lines(), self.notes.take());
                out.add(card(
                    title,
                    tags,
                    favorite,
                    CardDetails { notes, ..details },
                ));
            }
            "Address" => {
                let first = [self.take("First Name"), self.take("Middle Name")];
                let line2 = [self.take("Address 2"), self.take("Address 3")];
                let mut details = identity_details();
                details.first_name = clean(Some(
                    &first.into_iter().flatten().collect::<Vec<_>>().join(" "),
                ));
                details.last_name = self.take("Last Name");
                details.email = self.take("Email Address");
                details.phone = self.take("Phone").map(|phone| phone_number(&phone));
                details.birth_date = self.take("Birthday").and_then(|date| lastpass_date(&date));
                details.address = address(
                    self.take("Address 1"),
                    clean(Some(
                        &line2.into_iter().flatten().collect::<Vec<_>>().join(", "),
                    )),
                    self.take("City / Town"),
                    self.take("State"),
                    self.take("Zip / Postal Code"),
                    self.take("Country"),
                );
                let mut lines = self.remaining_lines();
                for (key, value) in &mut lines {
                    if key.contains("Phone") || key == "Fax" {
                        *value = phone_number(value);
                    }
                }
                details.notes = notes_with(&lines, self.notes.take());
                out.add(identity(title, tags, favorite, details));
            }
            "Bank Account" => {
                let mut item = TypedItem::bank_account();
                for (key, field) in [
                    ("bankName", "Bank Name"),
                    ("accountType", "Account Type"),
                    ("routingNumber", "Routing Number"),
                    ("accountNumber", "Account Number"),
                    ("swift", "SWIFT Code"),
                    ("iban", "IBAN Number"),
                    ("pin", "PIN"),
                    ("branch", "Branch Address"),
                ] {
                    self.set(&mut item, key, field);
                }
                self.finish(item, out, title, tags, favorite);
            }
            "Database" | "Server" => {
                let server = self.kind == "Server";
                let kind = if server {
                    Some("server".to_owned())
                } else {
                    self.take("Type")
                };
                let mut item = TypedItem::database(kind);
                for (key, field) in [
                    ("host", "Hostname"),
                    ("port", "Port"),
                    ("database", "Database"),
                    ("username", "Username"),
                    ("password", "Password"),
                ] {
                    self.set(&mut item, key, field);
                }
                self.finish(item, out, title, tags, favorite);
            }
            "Software License" => {
                let mut item = TypedItem::software_license();
                for (key, field) in [
                    ("licenseKey", "License Key"),
                    ("licensedTo", "Licensee"),
                    ("version", "Version"),
                    ("publisher", "Publisher"),
                    ("email", "Support Email"),
                    ("orderNumber", "Order Number"),
                ] {
                    self.set(&mut item, key, field);
                }
                self.set_date(&mut item, "purchaseDate", "Purchase Date");
                item.url(self.take("Website"));
                self.finish(item, out, title, tags, favorite);
            }
            "Passport" | "Driver's License" | "Social Security" => {
                let (document_type, kept_type) = match self.kind.as_str() {
                    "Passport" => ("passport", None),
                    "Driver's License" => ("driverLicense", None),
                    other => ("other", Some(other.to_owned())),
                };
                let mut item = TypedItem::id_document(document_type);
                if let Some(kind) = kept_type {
                    item.custom("Type", &kind, false);
                }
                self.set(&mut item, "number", "Number");
                self.set(&mut item, "fullName", "Name");
                self.set(&mut item, "country", "Country");
                self.set(&mut item, "issuer", "Issuing Authority");
                self.set_date(&mut item, "birthDate", "Date of Birth");
                self.set_date(&mut item, "issueDate", "Issued Date");
                self.set_date(&mut item, "expiryDate", "Expiration Date");
                self.finish(item, out, title, tags, favorite);
            }
            _ => {
                let username = self.take("Username");
                let password = self.take("Password");
                if username.is_none() && password.is_none() {
                    let mut lines = vec![("Type".to_string(), self.kind.clone())];
                    lines.extend(self.remaining_lines());
                    out.add(note(
                        title,
                        tags,
                        favorite,
                        notes_with(&lines, self.notes.take()),
                    ));
                    return;
                }
                let url = self.take("Hostname").or_else(|| self.take("Server"));
                let mut custom_fields = vec![custom_field("Type", &self.kind, false)];
                custom_fields.extend(
                    self.remaining_lines()
                        .into_iter()
                        .filter(|(_, value)| !value.trim().is_empty())
                        .map(|(label, value)| custom_field(&label, &value, looks_secret(&label))),
                );
                let fields = LoginFields {
                    title,
                    urls: url.into_iter().collect(),
                    username,
                    password: clean_password(password.as_deref()),
                    notes: self.notes.take(),
                    tags,
                    favorite,
                    custom_fields,
                    ..LoginFields::default()
                };
                // Never empty: it has a username or password.
                if let Some(item) = fields.build(out) {
                    out.add(item);
                }
            }
        }
    }
}

/// `January,2030` → `01/30`.
fn lastpass_expiry(date: &str) -> Option<String> {
    let (month, year) = date.split_once(',')?;
    expiry(month_number(month)?, year.trim().parse().ok()?)
}

/// `January,15,1990` → `1990-01-15`.
fn lastpass_date(date: &str) -> Option<String> {
    let mut parts = date.split(',');
    let month = month_number(parts.next()?)?;
    let day = parts.next()?.trim().parse().ok()?;
    let year = parts.next()?.trim().parse().ok()?;
    iso_date(year, month, day)
}

/// LastPass stores phones as `{"num":"5551234","ext":"","cc3l":"USA"}`.
fn phone_number(value: &str) -> String {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .and_then(|json| {
            let num = json.get("num")?.as_str()?.to_string();
            let ext = json
                .get("ext")
                .and_then(|e| e.as_str())
                .filter(|e| !e.is_empty());
            Some(match ext {
                Some(ext) => format!("{num} ext. {ext}"),
                None => num,
            })
        })
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemDetails, ItemType};

    const HEADER: &str = "url,username,password,totp,extra,name,grouping,fav\n";

    fn import(rows: &str) -> ImportResult {
        parse(&format!("{HEADER}{rows}")).unwrap()
    }

    #[test]
    fn logins_and_plain_notes() {
        let result = import(
            "https://github.com,octo,pw,JBSWY3DPEHPK3PXP,my note,GitHub,Work\\Dev,1\n\
             http://sn,,,,\"just\ntext\",Diary,,0\n",
        );
        let login = &result.items[0];
        assert_eq!(login.overview.tags.as_deref().unwrap(), ["Work\\Dev"]);
        assert_eq!(login.overview.favorite, Some(true));
        let ItemDetails::Login(details) = &login.details else {
            panic!()
        };
        assert_eq!(details.notes.as_deref(), Some("my note"));
        assert_eq!(details.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let ItemDetails::SecureNote(note) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(note.notes, "just\ntext");
    }

    #[test]
    fn credit_cards() {
        let result = import(
            "http://sn,,,,\"NoteType:Credit Card\nLanguage:en-US\nName on Card:Jane Doe\nType:Visa\nNumber:4111111111111111\nSecurity Code:123\nStart Date:January,2024\nExpiration Date:March,2030\nNotes:line one\nline two: with colon\",Visa,,0\n",
        );
        let ItemDetails::Card(card) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(card.cardholder.as_deref(), Some("Jane Doe"));
        assert_eq!(card.expiry.as_deref(), Some("03/30"));
        assert_eq!(card.cvv.as_deref(), Some("123"));
        assert_eq!(
            card.notes.as_deref(),
            Some("Start Date: January,2024\nline one\nline two: with colon")
        );
        assert_eq!(
            result.items[0].overview.subtitle.as_deref(),
            Some("•••• 1111")
        );
    }

    #[test]
    fn addresses() {
        let result = import(
            "http://sn,,,,\"NoteType:Address\nLanguage:en-US\nTitle:mr\nFirst Name:Omar\nMiddle Name:K\nLast Name:Haddad\nBirthday:April,19,1995\nAddress 1:1 Main St\nAddress 2:Apt 2\nCity / Town:Amman\nZip / Postal Code:11118\nCountry:JO\nEmail Address:omar@example.com\nPhone:{\"\"num\"\":\"\"5551234\"\",\"\"ext\"\":\"\"\"\",\"\"cc3l\"\":\"\"JOR\"\"}\nMobile Phone:{\"\"num\"\":\"\"7777\"\",\"\"ext\"\":\"\"9\"\",\"\"cc3l\"\":\"\"JOR\"\"}\nNotes:\",Home,,0\n",
        );
        let ItemDetails::Identity(identity) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(identity.first_name.as_deref(), Some("Omar K"));
        assert_eq!(identity.birth_date.as_deref(), Some("1995-04-19"));
        assert_eq!(identity.phone.as_deref(), Some("5551234"));
        assert_eq!(
            identity.address.as_ref().unwrap().line2.as_deref(),
            Some("Apt 2")
        );
        assert_eq!(
            identity.notes.as_deref(),
            Some("Title: mr\nMobile Phone: 7777 ext. 9")
        );
    }

    #[test]
    fn templates_with_credentials_become_logins_and_others_notes() {
        let result = import(
            "http://sn,,,,\"NoteType:Email Account\nLanguage:en-US\nServer:mail.example.com\nUsername:root\nPassword:toor\nNotes:prod\",Mail,,0\n\
             http://sn,,,,\"NoteType:Membership\nLanguage:en-US\nNumber:X123\nNotes:\",Gym,,0\n",
        );
        let mail = &result.items[0];
        assert_eq!(mail.overview.item_type, ItemType::Login);
        assert_eq!(mail.overview.urls.as_deref().unwrap(), ["mail.example.com"]);
        let ItemDetails::Login(login) = &mail.details else {
            panic!()
        };
        assert_eq!(login.password.as_deref(), Some("toor"));
        assert_eq!(login.notes.as_deref(), Some("prod"));
        let ItemDetails::SecureNote(gym) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(gym.notes, "Type: Membership\nNumber: X123");
    }

    #[test]
    fn templates_with_types_of_their_own() {
        let result = import(
            "http://sn,,,,\"NoteType:Server\nLanguage:en-US\nHostname:db.example.com\nUsername:root\nPassword:toor\nNotes:prod\",Server,,0\n\
             http://sn,,,,\"NoteType:Database\nLanguage:en-US\nType:PostgreSQL\nHostname:db\nPort:5432\nDatabase:app\nUsername:u\nPassword:p\nSID:x\nAlias:\nNotes:\",DB,,0\n\
             http://sn,,,,\"NoteType:Bank Account\nLanguage:en-US\nBank Name:Example\nAccount Type:Savings\nRouting Number:021000021\nAccount Number:123\nSWIFT Code:COBADEFF\nIBAN Number:DE89370400440532013000\nPIN:0000\nBranch Address:Main St\nBranch Phone:555\nNotes:\",Bank,,0\n\
             http://sn,,,,\"NoteType:Software License\nLanguage:en-US\nLicense Key:AAAA\nLicensee:Jane\nVersion:4\nPublisher:Acme\nSupport Email:s@example.com\nWebsite:https://acme.example\nPrice:10\nPurchase Date:January,15,2024\nOrder Number:42\nNumber of Licenses:1\nOrder Total:10\nNotes:\",Editor,,0\n\
             http://sn,,,,\"NoteType:Passport\nLanguage:en-US\nType:\nName:Jane\nCountry:Jordan\nNumber:X123\nSex:F\nNationality:Jordanian\nIssuing Authority:Amman\nDate of Birth:April,19,1975\nIssued Date:March,3,2020\nExpiration Date:Smarch,3,2030\nNotes:\",Passport,,0\n\
             http://sn,,,,\"NoteType:Driver's License\nLanguage:en-US\nNumber:D1\nExpiration Date:March,3,2030\nLicense Class:B\nName:Jane\nNotes:\",DL,,0\n\
             http://sn,,,,\"NoteType:Social Security\nLanguage:en-US\nName:Jane\nNumber:123\nNotes:\",SSN,,0\n",
        );
        let ItemDetails::Database(server) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(server.database_type.as_deref(), Some("server"));
        assert_eq!(server.host.as_deref(), Some("db.example.com"));
        assert_eq!(server.password.as_deref(), Some("toor"));
        assert_eq!(server.notes.as_deref(), Some("prod"));
        let ItemDetails::Database(database) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(database.database_type.as_deref(), Some("postgresql"));
        assert_eq!(database.port.as_deref(), Some("5432"));
        assert_eq!(database.custom_fields.as_ref().unwrap()[0].label, "SID");
        let ItemDetails::BankAccount(bank) = &result.items[2].details else {
            panic!()
        };
        assert_eq!(bank.account_type.as_deref(), Some("savings"));
        assert_eq!(bank.iban.as_deref(), Some("DE89370400440532013000"));
        assert_eq!(bank.swift.as_deref(), Some("COBADEFF"));
        assert_eq!(bank.pin.as_deref(), Some("0000"));
        assert_eq!(bank.custom_fields.as_ref().unwrap()[0].value, "555");
        let ItemDetails::SoftwareLicense(license) = &result.items[3].details else {
            panic!()
        };
        assert_eq!(license.license_key.as_deref(), Some("AAAA"));
        assert_eq!(license.purchase_date.as_deref(), Some("2024-01-15"));
        assert_eq!(
            result.items[3].overview.urls.as_deref().unwrap(),
            ["https://acme.example"]
        );
        let ItemDetails::IdDocument(passport) = &result.items[4].details else {
            panic!()
        };
        assert_eq!(passport.number.as_deref(), Some("X123"));
        assert_eq!(passport.birth_date.as_deref(), Some("1975-04-19"));
        assert_eq!(
            passport.expiry_date, None,
            "an unreadable date stays a field"
        );
        let labels: Vec<_> = passport
            .custom_fields
            .iter()
            .flatten()
            .map(|f| f.label.as_str())
            .collect();
        assert_eq!(labels, ["Expiry date", "Sex", "Nationality"]);
        let ItemDetails::IdDocument(license) = &result.items[5].details else {
            panic!()
        };
        assert_eq!(license.document_type.as_deref(), Some("driverLicense"));
        assert_eq!(license.expiry_date.as_deref(), Some("2030-03-03"));
        let ItemDetails::IdDocument(social) = &result.items[6].details else {
            panic!()
        };
        assert_eq!(social.document_type.as_deref(), Some("other"));
        assert_eq!(
            social.custom_fields.as_ref().unwrap()[0].value,
            "Social Security"
        );
    }

    #[test]
    fn dates_and_phones() {
        assert_eq!(lastpass_expiry("December,2029").as_deref(), Some("12/29"));
        assert_eq!(lastpass_expiry(","), None);
        assert_eq!(lastpass_date("February,30,2020"), None);
        assert_eq!(phone_number("not json"), "not json");
    }
}
