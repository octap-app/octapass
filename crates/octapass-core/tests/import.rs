//! Every importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::io::Write;
use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{
    CodeLink, ExistingLogin, ImportOptions, ImportResult, ImportSource, import_file, link_codes,
};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};
use serde_json::json;
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn import(source: ImportSource, name: &str) -> ImportResult {
    import_file(source, &fixture(name), &ImportOptions::default()).unwrap()
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

fn titles(result: &ImportResult) -> Vec<&str> {
    result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect()
}

/// Every imported item must survive the item model's own JSON round trip.
fn assert_valid(result: &ImportResult) {
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
}

#[test]
fn chrome() {
    let result = import(ImportSource::Chrome, "chrome.csv");
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "github.com",
            "بنك الأمل",
            "Bücher",
            "empty-name.example",
            "emoji 🔐",
            "android"
        ]
    );
    assert_eq!(
        login(&result.items[0]).password.as_deref(),
        Some("pa,ss\"word")
    );
    let arabic = login(&result.items[1]);
    assert_eq!(arabic.username.as_deref(), Some("مستخدم"));
    assert_eq!(arabic.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));
    assert_eq!(
        login(&result.items[2]).password.as_deref(),
        Some("  leading and trailing  ")
    );
    assert_eq!(result.items[3].overview.title, "empty-name.example");
    assert_eq!(
        login(&result.items[4]).notes.as_deref(),
        Some("Notes with \"quotes\", commas, and\nthree\nlines")
    );
    assert_eq!(result.skipped, 0, "the blank row isn't an item");
}

#[test]
fn firefox() {
    let result = import(ImportSource::Firefox, "firefox.csv");
    assert_valid(&result);
    assert_eq!(result.items.len(), 4);
    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.items[0].overview.urls.as_deref().unwrap(),
        ["https://www.example.org", "https://login.example.org"]
    );
    assert_eq!(
        login(&result.items[1]).password.as_deref(),
        Some("pässwörd")
    );
    assert_eq!(
        login(&result.items[3]).password.as_deref(),
        Some("سر,مع\"علامات")
    );
}

#[test]
fn safari() {
    let result = import(ImportSource::Safari, "safari.csv");
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        ["example.com (jane)", "متجر", "Wi-Fi notes only"]
    );
    assert!(login(&result.items[0]).totp.is_some());
    assert_eq!(result.items[2].overview.item_type, ItemType::SecureNote);
    assert_eq!(result.skipped, 1);
}

#[test]
fn onepassword_csv() {
    let result = import(ImportSource::OnePasswordCsv, "onepassword.csv");
    assert_valid(&result);
    assert_eq!(result.items.len(), 3);
    assert_eq!(
        login(&result.items[1]).password.as_deref(),
        Some("pass \"quoted\"")
    );
    assert_eq!(
        result.items[2].overview.tags.as_deref().unwrap(),
        ["archived"]
    );
}

#[test]
fn onepassword_1pux() {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("export.attributes", options).unwrap();
    zip.write_all(
        br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#,
    )
    .unwrap();
    zip.start_file("export.data", options).unwrap();
    zip.write_all(&fixture("onepassword-export.data.json"))
        .unwrap();
    let bytes = zip.finish().unwrap().into_inner();

    let result = import_file(
        ImportSource::OnePassword1Pux,
        &bytes,
        &ImportOptions::default(),
    )
    .unwrap();
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "GitHub",
            "Wi-Fi guest",
            "Visa",
            "Me",
            "House",
            "App database",
            "Lease"
        ]
    );
    let github = &result.items[0];
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login", "https://gist.github.com"]
    );
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2023-11-14T22:13:20Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2023-11-14T22:21:40Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "item-login"
    );
    assert_eq!(
        result.items[2].overview.imported_from.as_ref().unwrap().id,
        "item-card"
    );
    assert_eq!(
        github.overview.tags.as_deref().unwrap(),
        ["Private", "work", "dev"]
    );
    assert_eq!(github.overview.favorite, Some(true));
    let details = login(github);
    assert_eq!(details.password.as_deref(), Some("1p-pass \"quoted\""));
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/GitHub")
    );
    let fields = details.custom_fields.as_ref().unwrap();
    assert_eq!(
        fields.iter().map(|f| f.label.as_str()).collect::<Vec<_>>(),
        ["remember", "recovery codes"]
    );
    assert!(fields[1].hidden);
    assert_eq!(
        details.password_history.as_ref().unwrap()[0].changed_at,
        "2023-07-22T04:26:40Z"
    );

    assert_eq!(
        login(&result.items[1]).password.as_deref(),
        Some("standalone-password")
    );
    assert!(
        result.items[1]
            .overview
            .tags
            .as_ref()
            .unwrap()
            .contains(&"archived".to_string())
    );

    let ItemDetails::Card(card) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(
        (
            card.expiry.as_deref(),
            card.cvv.as_deref(),
            card.brand.as_deref()
        ),
        (Some("03/31"), Some("123"), Some("visa"))
    );
    assert_eq!(
        card.notes.as_deref(),
        Some("valid from: 03/2021\nissuing bank: Example Bank\nTravel card")
    );

    let ItemDetails::Identity(me) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(me.first_name.as_deref(), Some("ليلى"));
    assert_eq!(me.birth_date.as_deref(), Some("1995-04-19"));
    assert_eq!(me.email.as_deref(), Some("layla@example.jo"));
    assert_eq!(me.address.as_ref().unwrap().city.as_deref(), Some("Amman"));
    assert_eq!(me.notes.as_deref(), Some("occupation: Engineer"));

    assert_eq!(
        result.items[4].overview.tags.as_deref().unwrap(),
        ["Shared, family"]
    );
    let ItemDetails::Database(db) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(db.database_type.as_deref(), Some("postgresql"));
    assert_eq!(db.host.as_deref(), Some("db.example.internal"));
    assert_eq!(db.port.as_deref(), Some("5432"));
    assert_eq!(
        (db.username.as_deref(), db.password.as_deref()),
        (Some("app_user"), Some("db-secret"))
    );
    assert_eq!(result.items[6].overview.item_type, ItemType::SecureNote);
    assert_eq!(result.warnings.len(), 2, "{:?}", result.warnings);

    let not_zip = import_file(
        ImportSource::OnePassword1Pux,
        b"PK nope",
        &ImportOptions::default(),
    );
    assert_eq!(not_zip.unwrap_err().code, Error::InvalidImportFile);
}

#[test]
fn lastpass() {
    let result = import(ImportSource::LastPassCsv, "lastpass.csv");
    assert_valid(&result);
    let types: Vec<&ItemType> = result.items.iter().map(|i| &i.overview.item_type).collect();
    assert_eq!(
        types,
        [
            &ItemType::Login,
            &ItemType::SecureNote,
            &ItemType::Card,
            &ItemType::Identity,
            &ItemType::Database,
            &ItemType::IdDocument
        ]
    );
    let ItemDetails::Database(database) = &result.items[4].details else {
        panic!()
    };
    assert_eq!(database.database_type.as_deref(), Some("postgresql"));
    assert_eq!(database.host.as_deref(), Some("db.example.internal"));
    assert_eq!(database.password.as_deref(), Some("db-secret"));
    assert_eq!(database.notes.as_deref(), Some("Production database"));
    let ItemDetails::Identity(address) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(address.first_name.as_deref(), Some("ليلى"));
    assert_eq!(address.phone.as_deref(), Some("790000000"));
    let ItemDetails::IdDocument(passport) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(passport.document_type.as_deref(), Some("passport"));
    assert_eq!(passport.full_name.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(passport.country.as_deref(), Some("Jordan"));
    assert_eq!(passport.number.as_deref(), Some("X0000000"));
}

#[test]
fn generic_csv() {
    let result = import(ImportSource::GenericCsv, "generic.csv");
    assert_valid(&result);
    assert_eq!(titles(&result), ["Bank", "مكتبة", "No password"]);
    let bank = login(&result.items[0]);
    assert_eq!(bank.notes.as_deref(), Some("multi\nline"));
    assert_eq!(
        bank.custom_fields.as_ref().unwrap()[0].value,
        "First pet: Rex"
    );
    assert_eq!(result.items[0].overview.tags.as_deref().unwrap(), ["Money"]);
}

#[test]
fn bitwarden() {
    let plain = import(ImportSource::BitwardenJson, "bitwarden.json");
    assert_valid(&plain);
    assert_eq!(titles(&plain), ["GitHub", "ملاحظة سرية", "Visa", "Me"]);
    assert_eq!(plain.skipped, 1);
    let github = &plain.items[0];
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["عمل"]);
    assert_eq!(
        github.overview.extra["urlMatch"],
        json!({ "https://gist.github.com": "host", "^https://([a-z]+\\.)?github\\.com/": "regex" })
    );
    assert_eq!(login(github).password.as_deref(), Some("  spaces kept  "));
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2021-03-04T05:06:07Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2025-06-01T08:30:00Z")
    );
    assert_eq!(
        login(github).password_changed_at.as_deref(),
        Some("2025-01-02T03:04:05Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "1b2c3d4e-0000-4000-8000-000000000001"
    );
    assert_eq!(
        plain.items[2].overview.created_at.as_deref(),
        Some("2024-02-03T00:00:00Z")
    );

    for name in [
        "bitwarden-encrypted-pbkdf2.json",
        "bitwarden-encrypted-argon2.json",
    ] {
        let bytes = fixture(name);
        let with = |password: Option<&str>| {
            let options = ImportOptions {
                password: password.map(|p| Zeroizing::new(p.to_string())),
                ..ImportOptions::default()
            };
            import_file(ImportSource::BitwardenJson, &bytes, &options)
        };
        let decrypted = with(Some("correct horse battery staple")).unwrap();
        assert_eq!(decrypted.items, plain.items, "{name}");
        assert_eq!(with(None).unwrap_err().code, Error::ImportPasswordRequired);
        assert_eq!(
            with(Some("wrong")).unwrap_err().code,
            Error::WrongImportPassword
        );
    }
}

#[test]
fn authenticator_links() {
    let options = ImportOptions {
        existing_logins: vec![ExistingLogin {
            id: "0192f0c0-0000-7000-8000-000000000001".into(),
            title: "Code host".into(),
            urls: vec!["https://github.com".into()],
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    };
    let result = import_file(ImportSource::OtpAuth, &fixture("otpauth.txt"), &options).unwrap();
    assert_valid(&result);
    assert_eq!(result.totp_updates.len(), 1);
    assert_eq!(titles(&result), ["Example Bank", "بنك", "ACME", "bob"]);
    assert!(
        login(&result.items[0])
            .totp
            .as_deref()
            .unwrap()
            .contains("digits=8&period=60")
    );
    assert_eq!(result.skipped, 1);
}

#[test]
fn the_review_links_codes_to_other_logins() {
    const GITHUB: &str = "0192f0c0-0000-7000-8000-000000000001";
    const BANK: &str = "0192f0c0-0000-7000-8000-000000000002";
    let options = ImportOptions {
        existing_logins: vec![ExistingLogin {
            id: GITHUB.into(),
            title: "Code host".into(),
            urls: vec!["https://github.com".into()],
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    };
    let result = import_file(ImportSource::OtpAuth, &fixture("otpauth.txt"), &options).unwrap();
    // GitHub matched; the bank, the Arabic one, ACME and bob's HOTP code became logins.
    let titles: Vec<_> = result.codes.iter().map(|c| c.title.as_str()).collect();
    assert_eq!(titles, ["GitHub", "Example Bank", "بنك", "ACME", "bob"]);
    assert_eq!(result.codes[0].update, Some(0));
    assert_eq!(result.codes[1].item, Some(0));
    assert_eq!(result.codes[1].account.as_deref(), Some("jane@example.com"));
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["codes"][0]["update"], 0);
    assert_eq!(json["codes"][1]["issuer"], "Example Bank");
    // Clients hand the result back after the review.
    let result: ImportResult = serde_json::from_value(json).unwrap();

    let bank_totp = login(&result.items[0]).totp.clone().unwrap();
    let linked = link_codes(
        result,
        &[
            // The bank's code joins the bank login; GitHub's stays as its own login instead.
            CodeLink {
                code: 1,
                login_id: Some(BANK.into()),
            },
            CodeLink {
                code: 0,
                login_id: None,
            },
            // Same login twice: the second keeps its own login.
            CodeLink {
                code: 2,
                login_id: Some(BANK.into()),
            },
            // Out of range: ignored.
            CodeLink {
                code: 9,
                login_id: Some(BANK.into()),
            },
        ],
    );
    assert!(linked.codes.is_empty());
    assert_eq!(titles_of(&linked), ["بنك", "ACME", "bob", "GitHub"]);
    assert_eq!(linked.totp_updates.len(), 1);
    assert_eq!(linked.totp_updates[0].item_id, BANK);
    assert_eq!(linked.totp_updates[0].totp, bank_totp);
    let github = login(&linked.items[3]);
    assert_eq!(github.username.as_deref(), Some("octocat"));
    assert!(
        github
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP")
    );
    assert!(
        linked
            .warnings
            .iter()
            .any(|w| w.contains("\"بنك\": another code"))
    );
}

#[test]
fn linking_a_code_keeps_its_note() {
    let aegis = json!({
        "version": 1,
        "header": { "slots": null, "params": null },
        "db": { "version": 3, "entries": [{
            "type": "totp", "uuid": "1", "name": "jane", "issuer": "ACME", "note": "Backup codes in the drawer",
            "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30 }
        }] }
    });
    let result = import_file(
        ImportSource::Aegis,
        aegis.to_string().as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!((result.items.len(), result.codes.len()), (1, 1));
    let linked = link_codes(
        result,
        &[CodeLink {
            code: 0,
            login_id: Some("login".into()),
        }],
    );
    assert_eq!(linked.totp_updates[0].item_id, "login");
    assert_eq!(titles_of(&linked), ["ACME (note)"]);
    assert_eq!(linked.items[0].overview.item_type, ItemType::SecureNote);

    // No choices: everything stays.
    let result = import_file(
        ImportSource::Aegis,
        aegis.to_string().as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    let same = link_codes(result, &[]);
    assert_eq!((same.items.len(), same.totp_updates.len()), (1, 0));
}

fn titles_of(result: &ImportResult) -> Vec<&str> {
    result
        .items
        .iter()
        .map(|item| item.overview.title.as_str())
        .collect()
}

#[test]
fn ten_thousand_rows() {
    let mut csv = String::from("name,url,username,password,note\n");
    for i in 0..10_000 {
        csv.push_str(&format!(
            "Site {i},https://site{i}.example.com/login,user{i},\"p@ss,{i}\",\"note {i}\nline 2\"\n"
        ));
    }
    let result = import_file(
        ImportSource::Chrome,
        csv.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(result.items.len(), 10_000);
    assert_eq!(
        login(&result.items[9_999]).password.as_deref(),
        Some("p@ss,9999")
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn wrong_formats_are_errors() {
    for (source, name) in [
        (ImportSource::Chrome, "bitwarden.json"),
        (ImportSource::Firefox, "chrome.csv"),
        (ImportSource::LastPassCsv, "chrome.csv"),
        (ImportSource::OnePasswordCsv, "firefox.csv"),
        (ImportSource::BitwardenJson, "chrome.csv"),
        (ImportSource::OnePassword1Pux, "chrome.csv"),
    ] {
        let error = import_file(source, &fixture(name), &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{source:?} {name}");
        assert!(!error.detail.is_empty());
    }
}

proptest::proptest! {
    /// The cargo-fuzz targets in `fuzz/` go deeper; this keeps the basic guarantee in CI: no input
    /// makes an importer panic.
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        for source in [
            ImportSource::Chrome,
            ImportSource::Firefox,
            ImportSource::Safari,
            ImportSource::BitwardenJson,
            ImportSource::OnePassword1Pux,
            ImportSource::OnePasswordCsv,
            ImportSource::LastPassCsv,
            ImportSource::GenericCsv,
            ImportSource::OtpAuth,
        ] {
            let _ = import_file(source, &bytes, &ImportOptions::default());
            let _ = import_file(source, text.as_bytes(), &ImportOptions::default());
            let with_header = format!("name,url,username,password,extra,title,notes\n{text}");
            let _ = import_file(source, with_header.as_bytes(), &ImportOptions::default());
        }
        let _ = octapass_core::import::preview_csv(&bytes);
    }
}
