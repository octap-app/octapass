//! The andOTP importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::path::PathBuf;

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
            urls: vec!["https://github.com/login".into()],
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    }
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

fn assert_valid(result: &ImportResult) {
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
}

fn hidden_code(item: &Item) -> (&str, &str) {
    let details = login(item);
    assert!(details.totp.is_none(), "{}", item.overview.title);
    let field = &details.custom_fields.as_ref().unwrap()[0];
    assert!(field.hidden);
    (field.label.as_str(), field.value.as_str())
}

#[test]
fn plain_backup() {
    let result = import_file(
        ImportSource::AndOtp,
        &fixture("andotp.json"),
        &options(None),
    )
    .unwrap();
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "بنك الأمل",
            "Emoji 🔐 Mail",
            "Counter Corp",
            "Steam",
            "Office VPN"
        ]
    );
    assert_eq!(
        result.totp_updates.len(),
        1,
        "GitHub joins the existing login"
    );
    assert_eq!(
        result.totp_updates[0].item_id,
        "0192f0c0-0000-7000-8000-000000000001"
    );

    let bank = &result.items[0];
    assert_eq!(bank.overview.tags.as_deref().unwrap(), ["شخصي", "Work"]);
    assert_eq!(login(bank).username.as_deref(), Some("مستخدم"));
    assert!(
        login(bank)
            .totp
            .as_deref()
            .unwrap()
            .contains("algorithm=SHA256&digits=8&period=60")
    );
    // No issuer: "Issuer:account" in the label, as older andOTP versions wrote it.
    let mail = login(&result.items[1]);
    assert_eq!(mail.username.as_deref(), Some("jane@example.com"));
    assert!(
        mail.totp
            .as_deref()
            .unwrap()
            .contains("issuer=Emoji%20%F0%9F%94%90%20Mail")
    );
    let hotp = login(&result.items[2]).totp.as_deref().unwrap();
    assert!(hotp.starts_with("otpauth://hotp/"), "{hotp}");
    assert!(hotp.contains("counter=42"), "{hotp}");
    assert_eq!(hidden_code(&result.items[3]).0, "One-time code (Steam)");
    assert_eq!(result.items[3].overview.tags.as_deref().unwrap(), ["Work"]);
    assert_eq!(hidden_code(&result.items[4]).0, "One-time code (mOTP)");

    assert_eq!(result.skipped, 1);
    assert_eq!(result.warnings.len(), 3);
    assert_eq!(result.warnings[2], "Entry 7 skipped: not an andOTP entry.");
}

#[test]
fn encrypted_backups() {
    let plain = import_file(
        ImportSource::AndOtp,
        &fixture("andotp.json"),
        &options(None),
    )
    .unwrap();
    for name in ["andotp.json.aes", "andotp-legacy.json.aes"] {
        let bytes = fixture(name);
        let with = |password| import_file(ImportSource::AndOtp, &bytes, &options(password));
        let decrypted = with(Some(PASSWORD)).unwrap();
        assert_eq!(decrypted.items, plain.items, "{name}");
        assert_eq!(decrypted.totp_updates, plain.totp_updates, "{name}");
        assert_eq!(with(None).unwrap_err().code, Error::ImportPasswordRequired);
        assert_eq!(
            with(Some("wrong")).unwrap_err().code,
            Error::WrongImportPassword
        );
    }
}

#[test]
fn damaged_and_other_files() {
    for bytes in [
        fixture("andotp-damaged.json"),
        fixture("aegis.json"),
        fixture("2fas.2fas"),
        fixture("chrome.csv"),
        b"[".to_vec(),
        vec![0xff; 20],
    ] {
        let error =
            import_file(ImportSource::AndOtp, &bytes, &options(Some(PASSWORD))).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile);
        assert_eq!(error.detail, "This is not an andOTP backup.");
    }
    // A cut-off encrypted backup can't be told from a wrong password: the tag fails either way.
    let cut = &fixture("andotp.json.aes")[..200];
    assert_eq!(
        import_file(ImportSource::AndOtp, cut, &options(Some(PASSWORD)))
            .unwrap_err()
            .code,
        Error::WrongImportPassword
    );
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let _ = import_file(ImportSource::AndOtp, &bytes, &options(None));
        let _ = import_file(ImportSource::AndOtp, text.as_bytes(), &options(None));
        let backup = format!("[{text}]");
        let _ = import_file(ImportSource::AndOtp, backup.as_bytes(), &options(None));
    }
}
