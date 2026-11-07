//! The Raivo OTP importer against the fixtures in `tests/import-fixtures/`: the JSON, and the same
//! JSON in ZIPs that 7-Zip encrypted (WinZip AES-256 stored, as Raivo writes them, and AES-128
//! deflated).

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
            urls: vec!["https://github.com".into()],
            username: Some("octo".into()),
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    }
}

fn import(name: &str, password: Option<&str>) -> Result<ImportResult, Error> {
    import_file(ImportSource::Raivo, &fixture(name), &options(password)).map_err(|e| e.code)
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

#[test]
fn plain_json() {
    let result = import("raivo.json", None).unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(titles, ["بنك الأمل", "Café ☕", "Old Bank"]);
    assert_eq!(result.totp_updates.len(), 1, "GitHub joins the login");
    assert_eq!(
        result.totp_updates[0].totp,
        "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=GitHub"
    );
    let bank = &result.items[0];
    assert_eq!(bank.overview.favorite, Some(true));
    assert_eq!(bank.overview.subtitle.as_deref(), Some("سارة"));
    let totp = login(bank).totp.as_deref().unwrap();
    assert!(
        totp.contains("algorithm=SHA256&digits=8&period=60"),
        "{totp}"
    );
    let cafe = login(&result.items[1]).totp.as_deref().unwrap();
    assert!(cafe.contains("algorithm=SHA512"), "{cafe}");
    let hotp = login(&result.items[2]).totp.as_deref().unwrap();
    assert!(
        hotp.starts_with("otpauth://hotp/Old%20Bank:me?secret=KRSXG5CTMVRXEZLU"),
        "{hotp}"
    );
    assert!(hotp.contains("counter=5"));
    assert_eq!(result.skipped, 1);
    assert!(
        result
            .warnings
            .contains(&"Entry 5 skipped: it has no secret.".to_string())
    );
    assert_eq!(
        result.codes.len(),
        4,
        "GitHub, the bank, the café and the HOTP code are reviewed"
    );
}

#[test]
fn zips_encrypted_by_7zip() {
    let plain = import("raivo.json", None).unwrap();
    for name in ["raivo-aes256.zip", "raivo-aes128.zip"] {
        let result = import(name, Some(PASSWORD)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(result.items, plain.items, "{name}");
        assert_eq!(result.totp_updates, plain.totp_updates, "{name}");
        assert_eq!(
            import(name, None).unwrap_err(),
            Error::ImportPasswordRequired,
            "{name}"
        );
        assert_eq!(
            import(name, Some("wrong")).unwrap_err(),
            Error::WrongImportPassword,
            "{name}"
        );
    }
}

/// Where the JSON's entry data sits in the stored AES-256 ZIP: after the local header, its name
/// and its extra field. Salt (16) ‖ check (2) ‖ ciphertext ‖ MAC (10).
fn entry_data(zip: &[u8]) -> std::ops::Range<usize> {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([zip[at], zip[at + 1]]));
    let u32_at = |at: usize| u32::from_le_bytes(zip[at..at + 4].try_into().unwrap()) as usize;
    let mut at = 0;
    loop {
        assert_eq!(&zip[at..at + 4], b"PK\x03\x04");
        let (size, name_len, extra_len) = (u32_at(at + 18), u16_at(at + 26), u16_at(at + 28));
        let name = &zip[at + 30..at + 30 + name_len];
        let start = at + 30 + name_len + extra_len;
        if name == b"raivo-otp-export.json" {
            return start..start + size;
        }
        at = start + size;
    }
}

/// A changed ciphertext or MAC byte, or a cut-off entry, gives an error and nothing else.
#[test]
fn damaged_zips_fail_without_output() {
    let zip = fixture("raivo-aes256.zip");
    let data = entry_data(&zip);
    let ciphertext = data.start + 18 + (data.len() - 28) / 2;
    let mac = data.end - 3;
    for at in [ciphertext, data.start + 18, mac, data.end - 1] {
        let mut changed = zip.clone();
        changed[at] ^= 0x40;
        let error =
            import_file(ImportSource::Raivo, &changed, &options(Some(PASSWORD))).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
            "{at}: {error:?}"
        );
    }
    // The entry cut short (the archive's sizes no longer match), and the file cut short.
    let mut short = zip[..data.end - 5].to_vec();
    short.extend_from_slice(&zip[data.end..]);
    for bytes in [
        short,
        zip[..data.end - 5].to_vec(),
        zip[..zip.len() / 2].to_vec(),
    ] {
        let error = import_file(ImportSource::Raivo, &bytes, &options(Some(PASSWORD))).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
            "{error:?}"
        );
    }
}

#[test]
fn other_files() {
    for name in ["aegis.json", "dashlane.zip", "chrome.csv", "protonpass.zip"] {
        let error = import(name, Some(PASSWORD)).unwrap_err();
        assert_eq!(error, Error::InvalidImportFile, "{name}");
    }
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
        let _ = import_file(ImportSource::Raivo, &bytes, &options(Some(PASSWORD)));
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(&bytes);
        let _ = import_file(ImportSource::Raivo, &zip, &options(Some(PASSWORD)));
    }
}
