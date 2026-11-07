//! The Zoho Vault importer against the synthetic fixtures in `tests/import-fixtures/`.

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
fn zoho_vault_csv() {
    let result = import_file(
        ImportSource::ZohoVault,
        &fixture("zoho-vault.csv"),
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
    assert_eq!(
        titles,
        ["GitHub", "بنك الأمل", "Wi-Fi notes", "no-name.example.com"]
    );

    let github = &result.items[0];
    assert_eq!(github.overview.favorite, Some(true));
    assert_eq!(
        github.overview.tags.as_deref().unwrap(),
        ["work", "dev", "Work"]
    );
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login"]
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("jane@example.com"));
    assert_eq!(
        details.password.as_deref(),
        Some("zoho:pass,word"),
        "a colon stays in the value"
    );
    assert_eq!(details.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(
        details.notes.as_deref(),
        Some("Description: Work account\nDeploy notes")
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
            ("Recovery PIN", "4821", true),
            ("API host", "api.github.example", false),
            ("Token", "tok-123\nsecond token line", true),
        ],
        "SecretType is dropped, a line with no colon continues the one above"
    );

    let arabic = login(&result.items[1]);
    assert_eq!(arabic.password.as_deref(), Some("كلمة-سر-١٢٣"));
    assert_eq!(result.items[1].overview.tags.as_deref().unwrap(), ["عائلة"]);

    assert_eq!(result.items[2].overview.item_type, ItemType::SecureNote);
    assert_eq!(result.skipped, 1, "{:?}", result.warnings);
}

#[test]
fn general_csv() {
    let result = import_file(
        ImportSource::ZohoVault,
        &fixture("zoho-vault-general.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    let details = login(&result.items[0]);
    assert_eq!(details.username.as_deref(), Some("jane"));
    assert_eq!(
        details.password.as_deref(),
        Some("p,w "),
        "password spaces stay"
    );
    assert!(details.totp.as_deref().unwrap().starts_with("otpauth://"));
    assert_eq!(
        result.items[0].overview.tags.as_deref().unwrap(),
        ["personal", "Home"]
    );
}

#[test]
fn generic_csv_recognises_zoho() {
    let result = import_file(
        ImportSource::GenericCsv,
        &fixture("zoho-vault.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(
        login(&result.items[0]).password.as_deref(),
        Some("zoho:pass,word")
    );
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for name in ["zoho-vault-malformed.csv", "lastpass.csv", "bitwarden.json"] {
        let error = import_file(
            ImportSource::ZohoVault,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
        assert!(!error.detail.is_empty());
    }
    let empty = import_file(ImportSource::ZohoVault, b"", &ImportOptions::default()).unwrap_err();
    assert_eq!(empty.code, Error::InvalidImportFile);
}
