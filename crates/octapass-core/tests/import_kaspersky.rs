//! The Kaspersky importer against the synthetic fixtures in `tests/import-fixtures/`.

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
fn text_export() {
    let result = import_file(
        ImportSource::Kaspersky,
        &fixture("kaspersky.txt"),
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
            ("Skype", ItemType::Login),
            ("Home router", ItemType::Login),
            ("Diary", ItemType::SecureNote),
            ("Empty note", ItemType::SecureNote),
        ],
        "{:?}",
        result.warnings
    );

    let github = &result.items[0];
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://www.github.com"]
    );
    let details = login(github);
    assert_eq!(
        details.username.as_deref(),
        Some("jane@example.com"),
        "mailto: goes"
    );
    assert_eq!(
        details.password.as_deref(),
        Some(" kas:per sky "),
        "only one space goes"
    );
    assert_eq!(
        details.notes.as_deref(),
        Some(
            "Deploy notes\nPassword: this line is part of the comment\n\nand more after a blank line"
        )
    );
    let label = &details.custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (label.label.as_str(), label.value.as_str()),
        ("Login name", "Work")
    );

    assert_eq!(
        login(&result.items[1]).custom_fields,
        None,
        "the same name isn't repeated"
    );
    assert_eq!(
        result.items[2].overview.tags.as_deref().unwrap(),
        ["Applications"]
    );

    let router = &result.items[3];
    assert_eq!(router.overview.tags.as_deref().unwrap(), ["Other Accounts"]);
    let router = login(router);
    assert_eq!(
        router.username.as_deref(),
        Some("admin"),
        "Login name when there's no Login"
    );
    assert_eq!(
        router.notes.as_deref(),
        Some("a comment\n---\nthat had a dashed line")
    );
    let question = &router.custom_fields.as_ref().unwrap()[0];
    assert_eq!(question.label, "Security question");

    let ItemDetails::SecureNote(diary) = &result.items[4].details else {
        panic!()
    };
    assert_eq!(
        diary.notes,
        "Dear diary,\nPassword: not a field here\n\nemoji 🔐"
    );
    assert_eq!(result.skipped, 1, "the entry with only a name");
}

#[test]
fn csv_exports() {
    let result = import_file(
        ImportSource::Kaspersky,
        &fixture("kaspersky.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    let site = login(&result.items[0]);
    assert_eq!(result.items[0].overview.title, "Site1");
    assert_eq!(
        result.items[0].overview.urls.as_deref().unwrap(),
        ["https://www.site1.org"]
    );
    assert_eq!(
        site.username.as_deref(),
        Some("User1"),
        "Login Name is the sign-in name here"
    );
    assert_eq!(site.password.as_deref(), Some("pw,1"));
    assert_eq!(site.notes.as_deref(), Some("Comment1"));
    assert_eq!(result.items.len(), 2);

    let result = import_file(
        ImportSource::Kaspersky,
        &fixture("kaspersky-semicolon.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    let mail = login(&result.items[0]);
    assert_eq!(
        mail.username.as_deref(),
        Some("jane"),
        "Login is the sign-in name here"
    );
    assert_eq!(mail.custom_fields.as_ref().unwrap()[0].value, "Personal");
}

#[test]
fn line_endings_and_a_byte_order_mark() {
    let text = String::from_utf8(fixture("kaspersky.txt"))
        .unwrap()
        .replace('\n', "\r\n");
    let bytes = [b"\xEF\xBB\xBF".as_slice(), text.as_bytes()].concat();
    let result = import_file(ImportSource::Kaspersky, &bytes, &ImportOptions::default()).unwrap();
    assert_eq!(result.items.len(), 6);
    assert_eq!(
        login(&result.items[0]).password.as_deref(),
        Some(" kas:per sky ")
    );
}

#[test]
fn other_languages_and_wrong_files_are_errors() {
    for name in ["kaspersky-french.txt", "bitwarden.json", "aegis.json"] {
        let error = import_file(
            ImportSource::Kaspersky,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
    let empty = import_file(ImportSource::Kaspersky, b"", &ImportOptions::default()).unwrap_err();
    assert_eq!(empty.code, Error::InvalidImportFile);
}
