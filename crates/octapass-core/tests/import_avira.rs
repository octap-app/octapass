//! The Avira importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, LoginDetails};

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
fn csv() {
    let result = import_file(
        ImportSource::Avira,
        &fixture("avira.csv"),
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
    assert_eq!(titles, ["GitHub", "mail.example.com", "بنك الأمل"]);

    let github = login(&result.items[0]);
    assert_eq!(github.username.as_deref(), Some("jane"));
    assert_eq!(github.password.as_deref(), Some("av,ira \"pw\""));
    let extra = &github.custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (extra.label.as_str(), extra.value.as_str(), extra.hidden),
        ("Secondary username", "jane@example.com", false)
    );

    let mail = login(&result.items[1]);
    assert_eq!(mail.username.as_deref(), Some("jane@mail.example.com"));
    assert_eq!(mail.custom_fields, None);

    assert_eq!(
        login(&result.items[2]).password.as_deref(),
        Some("كلمة-سر-١٢٣")
    );
    assert_eq!(result.skipped, 1, "a row with only a name");
    assert_eq!(result.warnings.len(), 1);
}

#[test]
fn generic_csv_recognises_avira() {
    let result = import_file(
        ImportSource::GenericCsv,
        &fixture("avira.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(
        login(&result.items[1]).username.as_deref(),
        Some("jane@mail.example.com")
    );
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for name in ["avira-malformed.csv", "lastpass.csv", "bitwarden.json"] {
        let error = import_file(
            ImportSource::Avira,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
}
