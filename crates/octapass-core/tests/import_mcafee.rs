//! The McAfee True Key importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

#[test]
fn true_key_csv() {
    let result = import_file(
        ImportSource::McAfee,
        &fixture("mcafee.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let summary: Vec<(&str, ItemType)> = result
        .items
        .iter()
        .map(|i| (i.overview.title.as_str(), i.overview.item_type.clone()))
        .collect();
    assert_eq!(
        summary,
        [
            ("GitHub", ItemType::Login),
            ("بنك الأمل", ItemType::Login),
            ("Visa", ItemType::Card),
            ("Mastercard", ItemType::Card),
            ("Diary", ItemType::SecureNote),
            ("Contract", ItemType::SecureNote),
        ]
    );
    let github = &result.items[0];
    assert_eq!(github.overview.favorite, Some(true));
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("jane@example.com"));
    assert_eq!(details.password.as_deref(), Some("true,key \"pw\""));
    assert_eq!(details.notes.as_deref(), Some("Deploy notes\nsecond line"));
    assert_eq!(
        details.custom_fields, None,
        "hexColor and the rest aren't fields"
    );

    let ItemDetails::Card(visa) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(visa.cardholder.as_deref(), Some("Jane Doe"));
    assert_eq!(visa.number.as_deref(), Some("4242424242424242"));
    assert_eq!(visa.expiry.as_deref(), Some("07/31"));
    assert_eq!(
        visa.notes.as_deref(),
        Some("verificationCode: 123\nTravel card")
    );

    let ItemDetails::Card(master) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(master.expiry, None);
    assert_eq!(
        master.notes.as_deref(),
        Some("Expiry date: sometime"),
        "an unread date is kept"
    );

    let ItemDetails::SecureNote(document) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(document.notes, "The whole text");
    assert_eq!(result.skipped, 2, "{:?}", result.warnings);
}

#[test]
fn a_file_without_kinds_is_logins() {
    let result = import_file(
        ImportSource::McAfee,
        &fixture("mcafee-plain.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(login(&result.items[0]).username.as_deref(), Some("jane"));
}

#[test]
fn generic_csv_recognises_true_key() {
    let result = import_file(
        ImportSource::GenericCsv,
        &fixture("mcafee.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(result.items[2].overview.item_type, ItemType::Card);
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for name in ["mcafee-malformed.csv", "bitwarden.json", "kaspersky.txt"] {
        let error = import_file(
            ImportSource::McAfee,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
}
