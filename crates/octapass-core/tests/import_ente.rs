//! The Ente Auth importer against the fixtures in `tests/import-fixtures/`: the plaintext export,
//! and encrypted exports that libsodium (through PyNaCl) wrote.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use octapass_core::Error;
use octapass_core::import::{
    ExistingLogin, ImportOptions, ImportResult, ImportSource, import_file,
};
use octapass_core::item::{Item, ItemDetails, LoginDetails};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn options(password: Option<&str>) -> ImportOptions {
    ImportOptions {
        password: password.map(|p| Zeroizing::new(p.to_string())),
        existing_logins: vec![ExistingLogin {
            id: "0192f0c0-0000-7000-8000-000000000001".into(),
            title: "Code host".into(),
            urls: vec!["https://github.com".into()],
            username: Some("octo".into()),
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    }
}

fn import(bytes: &[u8], password: Option<&str>) -> Result<ImportResult, Error> {
    import_file(ImportSource::EnteAuth, bytes, &options(password)).map_err(|e| e.code)
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

#[test]
fn plaintext_export() {
    let result = import(&fixture("ente-auth.txt"), None).unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(titles, ["بنك الأمل", "Café ☕", "Steam", "Old Bank"]);
    assert_eq!(result.totp_updates.len(), 1, "GitHub joins the login");

    let bank = &result.items[0];
    assert_eq!(bank.overview.favorite, Some(true));
    assert_eq!(bank.overview.tags.as_deref().unwrap(), ["مالية", "Work"]);
    assert_eq!(bank.overview.subtitle.as_deref(), Some("سارة"));
    assert_eq!(
        bank.overview.last_used_at.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
    assert_eq!(
        login(bank).notes.as_deref(),
        Some("Recovery codes in the safe.\nSecond line.")
    );
    assert!(
        login(bank)
            .totp
            .as_deref()
            .unwrap()
            .contains("algorithm=SHA256&digits=8&period=60")
    );

    let cafe = &result.items[1];
    assert_eq!(
        cafe.overview.subtitle.as_deref(),
        Some("me+test@example.com")
    );
    assert_eq!(cafe.overview.tags.as_deref().unwrap(), ["Food"]);
    assert!(cafe.overview.last_used_at.is_none(), "0 means never");

    let steam = &login(&result.items[2]).custom_fields.as_ref().unwrap()[0];
    assert_eq!(steam.label, "One-time code (Steam)");
    assert!(
        steam
            .value
            .starts_with("otpauth://steam/Steam:gamer?secret=KRSXG5CTMVRXEZLU")
    );
    let hotp = login(&result.items[3]).totp.as_deref().unwrap();
    assert!(hotp.contains("counter=5"), "{hotp}");

    assert_eq!(result.skipped, 1);
    assert!(
        result
            .warnings
            .contains(&"1 code in Ente's trash was skipped.".to_string())
    );
}

#[test]
fn encrypted_exports() {
    let plain = import(&fixture("ente-auth.txt"), None).unwrap();
    // Tag FINAL, as Ente Auth writes it, and tag MESSAGE, as older versions did.
    for name in [
        "ente-auth-encrypted.json",
        "ente-auth-encrypted-message.json",
    ] {
        let bytes = fixture(name);
        let result = import(&bytes, Some(PASSWORD)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(result.items, plain.items, "{name}");
        assert_eq!(
            import(&bytes, None).unwrap_err(),
            Error::ImportPasswordRequired
        );
        assert_eq!(
            import(&bytes, Some("wrong")).unwrap_err(),
            Error::WrongImportPassword
        );
    }
}

/// The export is exactly one authenticated message: a PUSH tag, a second message, messages in
/// another order, extra or missing bytes, and any changed byte are refused, with nothing imported.
#[test]
fn anything_but_one_whole_message_is_refused() {
    for name in [
        "ente-auth-encrypted-push.json",
        "ente-auth-encrypted-two-chunks.json",
        "ente-auth-encrypted-reordered.json",
    ] {
        let error = import(&fixture(name), Some(PASSWORD)).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error),
            "{name}: {error:?}"
        );
    }
    let file: serde_json::Value =
        serde_json::from_slice(&fixture("ente-auth-encrypted.json")).unwrap();
    let data = STANDARD
        .decode(file["encryptedData"].as_str().unwrap())
        .unwrap();
    let with = |data: &[u8]| {
        let mut file = file.clone();
        file["encryptedData"] = STANDARD.encode(data).into();
        serde_json::to_vec(&file).unwrap()
    };
    let mut cases = vec![
        data[..data.len() - 1].to_vec(),
        data[..data.len() / 2].to_vec(),
        [&data[..], b"x"].concat(),
    ];
    for at in [0, 1, data.len() / 2, data.len() - 1] {
        let mut changed = data.clone();
        changed[at] ^= 1;
        cases.push(changed);
    }
    for case in cases {
        let error = import(&with(&case), Some(PASSWORD)).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error),
            "{error:?}"
        );
    }
}

#[test]
fn other_files() {
    for name in ["aegis.json", "chrome.csv", "bitwarden.json"] {
        assert_eq!(
            import(&fixture(name), Some(PASSWORD)).unwrap_err(),
            Error::InvalidImportFile,
            "{name}"
        );
    }
    let mut future: serde_json::Value =
        serde_json::from_slice(&fixture("ente-auth-encrypted.json")).unwrap();
    future["version"] = 2.into();
    let bytes = serde_json::to_vec(&future).unwrap();
    assert_eq!(
        import(&bytes, Some(PASSWORD)).unwrap_err(),
        Error::UnsupportedImport
    );
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(text in "\\PC{0,256}") {
        let _ = import_file(ImportSource::EnteAuth, text.as_bytes(), &options(Some(PASSWORD)));
        let link = format!("otpauth://{text}");
        let _ = import_file(ImportSource::EnteAuth, link.as_bytes(), &options(None));
    }
}
