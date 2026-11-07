//! Importing the same export again: items come back as unchanged, and a changed password updates
//! its item (old password in the history) instead of adding a copy.

use std::path::PathBuf;

use octapass_core::import::{ExistingItem, ImportOptions, ImportResult, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails};
use serde_json::Value;
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn options(existing: Vec<ExistingItem>, password: Option<&str>) -> ImportOptions {
    ImportOptions {
        existing_items: existing,
        now: Some("2026-10-24T12:00:00Z".into()),
        password: password.map(|p| Zeroizing::new(p.to_owned())),
        ..ImportOptions::default()
    }
}

/// The items as a vault would hold them after the first import.
fn stored(items: &[Item]) -> Vec<ExistingItem> {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let value = serde_json::to_value(item).unwrap();
            ExistingItem {
                id: format!("item-{i}"),
                overview: serde_json::from_value(value["overview"].clone()).unwrap(),
                details: value["details"].clone(),
                vault_id: None,
                updated_at: None,
            }
        })
        .collect()
}

/// Imports `bytes`, then the same bytes again into a vault holding the first result, then
/// the file with one password changed from `old` to `new`.
fn check(source: ImportSource, bytes: &[u8], old: &str, new: &str, password: Option<&str>) {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    check_with(
        source,
        &text,
        |text| text.as_bytes().to_vec(),
        old,
        new,
        password,
    );
}

/// As [`check`], for files made from `text` by `encode` (a ZIP, say).
fn check_with(
    source: ImportSource,
    text: &str,
    encode: impl Fn(&str) -> Vec<u8>,
    old: &str,
    new: &str,
    password: Option<&str>,
) {
    let bytes = encode(text);
    let first = import_file(source, &bytes, &options(Vec::new(), password)).unwrap();
    assert!(!first.items.is_empty(), "{source:?}: nothing imported");
    let vault = stored(&first.items);

    let again = import_file(source, &bytes, &options(stored(&first.items), password)).unwrap();
    assert!(
        again.items.is_empty() && again.updates.is_empty(),
        "{source:?}: the same file again added {:?} and changed {:?}",
        again.items.iter().map(Item::to_json).collect::<Vec<_>>(),
        again
            .updates
            .iter()
            .map(|u| u.item.to_json())
            .collect::<Vec<_>>()
    );
    assert_eq!(again.unchanged, first.items.len(), "{source:?}");

    // Every copy changes: some apps repeat the password in their form fields.
    assert!(text.contains(old), "{source:?}: {old} isn't in the file");
    let changed = encode(&text.replace(old, new));
    let result = import_file(source, &changed, &options(vault, password)).unwrap();
    assert!(
        result.items.is_empty(),
        "{source:?}: a changed password added an item"
    );
    assert_eq!(result.updates.len(), 1, "{source:?}");
    assert_eq!(result.unchanged, first.items.len() - 1, "{source:?}");
    let ItemDetails::Login(login) = &result.updates[0].item.details else {
        panic!("{source:?}: not a login")
    };
    assert_eq!(login.password.as_deref(), Some(new));
    let history: Vec<&str> = login
        .password_history
        .iter()
        .flatten()
        .map(|entry| entry.password.as_str())
        .collect();
    assert!(history.contains(&old), "{source:?}: {history:?}");
}

/// A ZIP holding `files` (name, text), stored uncompressed.
fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, text) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(text.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn text(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

/// Every item that has an id in the file carries it, named after the import source.
fn ids(source: ImportSource, result: &ImportResult) -> Vec<String> {
    result
        .items
        .iter()
        .filter_map(|item| item.overview.imported_from.as_ref())
        .map(|from| {
            assert_eq!(from.source, source.name());
            from.id.clone()
        })
        .collect()
}

#[test]
fn chrome() {
    check(
        ImportSource::Chrome,
        &fixture("chrome.csv"),
        "only-password",
        "changed-password",
        None,
    );
}

#[test]
fn firefox() {
    let bytes = fixture("firefox.csv");
    let result = import_file(ImportSource::Firefox, &bytes, &ImportOptions::default()).unwrap();
    assert_eq!(ids(ImportSource::Firefox, &result).len(), 4);
    let router = &result.items[2];
    let value: Value = serde_json::to_value(router).unwrap();
    assert_eq!(value["details"]["httpRealm"], "Router Admin");
    assert_eq!(value["overview"]["createdAt"], "2023-11-14T22:13:20Z");
    check(ImportSource::Firefox, &bytes, "hunter2", "hunter3", None);
}

#[test]
fn a_firefox_file_as_any_csv_matches_the_firefox_import() {
    let bytes = fixture("firefox.csv");
    let first = import_file(ImportSource::Firefox, &bytes, &ImportOptions::default()).unwrap();
    let again = import_file(
        ImportSource::GenericCsv,
        &bytes,
        &options(stored(&first.items), None),
    )
    .unwrap();
    assert_eq!(
        (again.items.len(), again.updates.len(), again.unchanged),
        (0, 0, 4)
    );
}

#[test]
fn safari() {
    check(
        ImportSource::Safari,
        &fixture("safari.csv"),
        "s3cret!",
        "n3w!",
        None,
    );
}

#[test]
fn bitwarden() {
    check(
        ImportSource::BitwardenJson,
        &fixture("bitwarden.json"),
        "  spaces kept  ",
        "new one",
        None,
    );
}

#[test]
fn bitwarden_csv() {
    // No ids in the CSV: logins match by site and username, notes by title and text.
    check(
        ImportSource::BitwardenCsv,
        &fixture("bitwarden.csv"),
        "old-password",
        "new-password",
        None,
    );
    check(
        ImportSource::BitwardenCsv,
        &fixture("bitwarden-org.csv"),
        "s3cret",
        "s3cret-2",
        None,
    );
}

#[test]
fn onepassword_1pux() {
    let data = text("onepassword-export.data.json");
    check_with(
        ImportSource::OnePassword1Pux,
        &data,
        |data| {
            zip(&[
                ("export.attributes", r#"{"version":3}"#),
                ("export.data", data),
            ])
        },
        "standalone-password",
        "a new password",
        None,
    );
}

#[test]
fn onepassword_csv() {
    check(
        ImportSource::OnePasswordCsv,
        &fixture("onepassword.csv"),
        "gh-pass",
        "gh-new",
        None,
    );
}

#[test]
fn lastpass() {
    check(
        ImportSource::LastPassCsv,
        &fixture("lastpass.csv"),
        "lp-pass",
        "lp-new",
        None,
    );
}

#[test]
fn protonpass() {
    let data = text("protonpass-data.json");
    check(
        ImportSource::ProtonPass,
        data.as_bytes(),
        "correct horse",
        "battery staple",
        None,
    );
    check_with(
        ImportSource::ProtonPass,
        &data,
        |data| zip(&[("Proton Pass/data.json", data)]),
        "correct horse",
        "battery staple",
        None,
    );
    // A password the CSV writes without quotes, so it reads back as written.
    let csv = text("protonpass.csv").replace("\"pa,ss\"\"word 1\"", "plain-pass");
    check(
        ImportSource::ProtonPass,
        csv.as_bytes(),
        "plain-pass",
        "new-pass",
        None,
    );
    // The PGP-encrypted export carries the same ids.
    let first = import_file(
        ImportSource::ProtonPass,
        &fixture("protonpass-encrypted.zip"),
        &options(Vec::new(), Some("correct horse battery staple")),
    )
    .unwrap();
    let again = import_file(
        ImportSource::ProtonPass,
        &fixture("protonpass.zip"),
        &options(stored(&first.items), None),
    )
    .unwrap();
    assert!(again.items.is_empty() && again.updates.is_empty());
}

#[test]
fn dashlane() {
    let json = text("dashlane.json").replace(r#""pa,ss\"word 1""#, r#""plain-pass""#);
    check(
        ImportSource::Dashlane,
        json.as_bytes(),
        "plain-pass",
        "new-pass",
        None,
    );
    let csv = text("dashlane-credentials.csv").replace("\"pa,ss\"\"word 1\"", "plain-pass");
    check(
        ImportSource::Dashlane,
        csv.as_bytes(),
        "plain-pass",
        "new-pass",
        None,
    );
}

#[test]
fn enpass() {
    let json = text("enpass.json").replace(r#""pa,ss\"word 1""#, r#""plain-pass""#);
    check(
        ImportSource::Enpass,
        json.as_bytes(),
        "plain-pass",
        "new-pass",
        None,
    );
}

#[test]
fn keeper() {
    check(
        ImportSource::Keeper,
        &fixture("keeper.json"),
        "kp-json-pass",
        "kp-new",
        None,
    );
    check(
        ImportSource::Keeper,
        &fixture("keeper.csv"),
        "كلمة-سر-١٢٣",
        "كلمة-جديدة",
        None,
    );
}

#[test]
fn keeper_web_vault_numbers_are_not_ids() {
    let json = r#"{"records":[{"uid":1,"title":"A","login":"a","password":"p","login_url":"https://a.example"}]}"#;
    let result = import_file(
        ImportSource::Keeper,
        json.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert!(result.items[0].overview.imported_from.is_none());
}

#[test]
fn nordpass() {
    check(
        ImportSource::NordPass,
        &fixture("nordpass.csv"),
        "كلمة-سر-١٢٣",
        "كلمة-جديدة",
        None,
    );
}

#[test]
fn roboform() {
    check(
        ImportSource::RoboForm,
        &fixture("roboform.csv"),
        "كلمة-سر-١٢٣",
        "كلمة-جديدة",
        None,
    );
}

#[test]
fn keepass() {
    let xml = text("keepass.xml");
    check(
        ImportSource::KeePass,
        xml.as_bytes(),
        "tray-pass",
        "tray-new",
        None,
    );
    // A database brings back the same items, so it matches them too.
    let first = import_file(
        ImportSource::KeePass,
        xml.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    let database = fixture("keepass-kdbx4-argon2d.kdbx");
    let again = import_file(
        ImportSource::KeePass,
        &database,
        &options(stored(&first.items), Some("correct horse battery staple")),
    )
    .unwrap();
    assert_eq!((again.items.len(), again.updates.len()), (0, 0));
    assert_eq!(again.unchanged, first.items.len());
    check(
        ImportSource::KeePass,
        &fixture("keepassxc.csv"),
        "كلمة-سر-٢٠٢٥",
        "كلمة-جديدة",
        None,
    );
}

#[test]
fn cxf() {
    for name in [
        "cxf-spec-example.json",
        "cxf-1password.json",
        "cxf-dashlane.json",
    ] {
        let bytes = fixture(name);
        let first = import_file(ImportSource::Cxf, &bytes, &ImportOptions::default()).unwrap();
        let again = import_file(
            ImportSource::Cxf,
            &bytes,
            &options(stored(&first.items), None),
        )
        .unwrap();
        assert_eq!(
            (again.items.len(), again.updates.len(), again.unchanged),
            (0, 0, first.items.len()),
            "{name}"
        );
    }
}
