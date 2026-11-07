//! The RoboForm importer against the synthetic fixtures in `tests/import-fixtures/`.

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
fn csv() {
    let result = import_file(
        ImportSource::RoboForm,
        &fixture("roboform.csv"),
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
    assert_eq!(titles, ["GitHub", "بنك الأمل", "Twitter", "Diary", "News"]);
    let types: Vec<ItemType> = result
        .items
        .iter()
        .map(|i| i.overview.item_type.clone())
        .collect();
    use ItemType::*;
    assert_eq!(types, [Login, Login, Login, SecureNote, Login]);

    let github = &result.items[0];
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login"],
        "Url; MatchUrl is the same website (one site is listed once, plan 07 History 2026-11-05)"
    );
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Work/Dev"]);
    let details = login(github);
    assert_eq!(details.password.as_deref(), Some("rf-pass,with \"quotes\""));
    assert_eq!(details.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(details.notes.as_deref(), Some("Deploy notes\nsecond line"));
    let fields = details.custom_fields.as_ref().unwrap();
    let summary: Vec<(&str, &str, bool)> = fields
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect();
    assert_eq!(
        summary,
        [
            ("Account ID", "12345", false),
            ("Old Password", "older-pass", true)
        ],
        "the form's username and password fields repeat the login"
    );

    let arabic = &result.items[1];
    assert_eq!(arabic.overview.tags.as_deref().unwrap(), ["عائلة"]);
    let arabic = login(arabic);
    assert_eq!(arabic.password.as_deref(), Some("كلمة-سر-١٢٣"));
    assert_eq!(arabic.custom_fields, None);
    assert_eq!(arabic.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));

    let twitter = login(&result.items[2]);
    assert_eq!(twitter.username.as_deref(), Some("@handle"));
    assert_eq!(twitter.password.as_deref(), Some("'quote-first"));
    let remember = &twitter.custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (remember.label.as_str(), remember.value.as_str()),
        ("remember_me", "*")
    );

    let ItemDetails::SecureNote(diary) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(diary.notes, "Dear diary,\nemoji 🔐 and \"quotes\"");

    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        ["Row 10 skipped: no URL, username, password or notes."]
    );
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for (name, bytes) in [
        ("roboform-malformed.csv", fixture("roboform-malformed.csv")),
        ("lastpass.csv", fixture("lastpass.csv")),
        ("bitwarden.json", fixture("bitwarden.json")),
        ("empty", Vec::new()),
    ] {
        let error =
            import_file(ImportSource::RoboForm, &bytes, &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
        assert!(!error.detail.is_empty());
    }
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let options = ImportOptions::default();
        let _ = import_file(ImportSource::RoboForm, &bytes, &options);
        let with_header = format!("Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\n{text}");
        let _ = import_file(ImportSource::RoboForm, with_header.as_bytes(), &options);
        let legacy = format!("Name,Url,MatchUrl,Login,Pwd,Note,Folder,Rf_fields\n{text}");
        let _ = import_file(ImportSource::RoboForm, legacy.as_bytes(), &options);
    }
}
