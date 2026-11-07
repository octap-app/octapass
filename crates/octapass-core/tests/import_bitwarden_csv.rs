//! The Bitwarden CSV importer against `bitwarden.csv` and `bitwarden-org.csv`, laid out as
//! Bitwarden's `individual-vault-export.service.ts` and the organisation export write them.

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportResult, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};

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

#[test]
fn individual_export() {
    let result = import(ImportSource::BitwardenCsv, "bitwarden.csv");
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(titles, ["GitHub", "بنك الأمل", "Old forum", "Wi-Fi at home"]);
    assert_eq!(result.skipped, 1, "the empty login");

    let github = &result.items[0];
    assert_eq!(github.overview.favorite, Some(true));
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Work"]);
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login", "https://gist.github.com"]
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octocat"));
    assert_eq!(details.password.as_deref(), Some("pa,ss\"word"));
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/GitHub:octocat")
    );
    assert_eq!(
        details.notes.as_deref(),
        Some("Two-factor is on.\nSecond line, with \"quotes\".")
    );
    let fields: Vec<(&str, &str, bool)> = details
        .custom_fields
        .as_ref()
        .unwrap()
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect();
    assert_eq!(
        fields,
        [
            ("Recovery email", "octo@example.com", false),
            ("PIN", "4321", true),
            ("Address", "1 Main Street\nFlat 2", false),
        ]
    );

    let bank = &result.items[1];
    assert_eq!(bank.overview.tags.as_deref().unwrap(), ["مالية"]);
    assert_eq!(login(bank).password.as_deref(), Some("كلمة-سر-🔑"));

    let archived = &result.items[2];
    assert_eq!(archived.overview.tags.as_deref().unwrap(), ["archived"]);
    assert!(
        result
            .warnings
            .contains(&"1 archived item was imported with the tag \"archived\".".to_string())
    );

    let note = &result.items[3];
    assert_eq!(note.overview.item_type, ItemType::SecureNote);
    assert_eq!(note.overview.tags.as_deref().unwrap(), ["Personal/Ideas"]);
    let ItemDetails::SecureNote(text) = &note.details else {
        panic!()
    };
    assert_eq!(text.notes, "Network: Casa\nPassword is on the router.");
}

#[test]
fn organisation_export() {
    let result = import(ImportSource::BitwardenCsv, "bitwarden-org.csv");
    assert_eq!(result.items.len(), 2);
    assert_eq!(
        result.items[0].overview.tags.as_deref().unwrap(),
        ["Engineering", "Shared"]
    );
    assert_eq!(result.items[0].overview.favorite, None);
    let token = &login(&result.items[0]).custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (token.label.as_str(), token.value.as_str(), token.hidden),
        ("Token", "abc123", true)
    );
    assert_eq!(result.items[1].overview.item_type, ItemType::SecureNote);
}

#[test]
fn as_any_csv_it_is_read_as_bitwarden() {
    let bitwarden = import(ImportSource::BitwardenCsv, "bitwarden.csv");
    let generic = import(ImportSource::GenericCsv, "bitwarden.csv");
    assert_eq!(
        generic.warnings[0],
        "This is a Bitwarden export, so it was read as one."
    );
    assert_eq!(generic.items.len(), bitwarden.items.len());
}

#[test]
fn other_files() {
    for name in ["chrome.csv", "bitwarden.json", "lastpass.csv"] {
        let error = import_file(
            ImportSource::BitwardenCsv,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(text in "\\PC{0,256}") {
        let csv = format!("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n{text}");
        let _ = import_file(ImportSource::BitwardenCsv, csv.as_bytes(), &ImportOptions::default());
    }
}
