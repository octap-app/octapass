//! The Norton importer against the synthetic fixtures in `tests/import-fixtures/`.

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
fn csv_with_the_preamble() {
    let result = import_file(
        ImportSource::Norton,
        &fixture("norton.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(titles, ["GitHub", "بنك الأمل", "Diary"]);
    let github = &result.items[0];
    assert_eq!(github.overview.favorite, Some(true));
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("jane@example.com"));
    assert_eq!(details.password.as_deref(), Some("nor,ton \"pw\" "));
    assert_eq!(details.notes.as_deref(), Some("Deploy notes\nsecond line"));
    assert_eq!(
        details.custom_fields, None,
        "Item Type and Secure aren't fields"
    );
    assert_eq!(result.items[1].overview.favorite, None);
    assert_eq!(result.items[2].overview.item_type, ItemType::SecureNote);
    let ItemDetails::SecureNote(diary) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(diary.notes, "Dear diary,\nemoji 🔐");
    assert_eq!(result.skipped, 1);
}

#[test]
fn older_header() {
    let result = import_file(
        ImportSource::Norton,
        &fixture("norton-old.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    let forum = login(&result.items[0]);
    assert_eq!(result.items[0].overview.title, "Forum");
    assert_eq!(forum.username.as_deref(), Some("jane"));
    assert_eq!(forum.custom_fields.as_ref().unwrap()[0].label, "Colour");
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for name in ["norton-malformed.csv", "bitwarden.json", "kaspersky.txt"] {
        let error = import_file(
            ImportSource::Norton,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
}
