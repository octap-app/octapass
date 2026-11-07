//! The KeePass importer against the synthetic fixtures in `tests/import-fixtures/` (the KDBX
//! files are made by `make-keepass.py` from `keepass.xml`).

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportResult, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";
const ARABIC_PASSWORD: &str = "كلمة المرور 🔑";

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn options(password: Option<&str>, key_file: Option<&str>) -> ImportOptions {
    ImportOptions {
        password: password.map(|p| Zeroizing::new(p.to_string())),
        key_file: key_file.map(|name| Zeroizing::new(fixture(name))),
        ..ImportOptions::default()
    }
}

fn import(bytes: &[u8], options: &ImportOptions) -> ImportResult {
    let result = import_file(ImportSource::KeePass, bytes, options).unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    result
}

fn error(bytes: &[u8], options: &ImportOptions) -> Error {
    import_file(ImportSource::KeePass, bytes, options)
        .unwrap_err()
        .code
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

fn tags(item: &Item) -> Vec<&str> {
    item.overview
        .tags
        .iter()
        .flatten()
        .map(String::as_str)
        .collect()
}

#[test]
fn xml_export() {
    let result = import(&fixture("keepass.xml"), &ImportOptions::default());
    let github = result
        .items
        .iter()
        .find(|item| item.overview.title == "GitHub")
        .unwrap();
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2024-01-01T00:00:00Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2025-10-01T08:00:00Z")
    );
    assert_eq!(
        github.overview.last_used_at.as_deref(),
        Some("2025-10-01T08:00:00Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "BgYGBgYGBgYGBgYGBgYGBg=="
    );
    assert_eq!(
        titles(&result),
        [
            "Wi-Fi at home 🏠",
            "Tray TOTP",
            "Steam",
            "Legacy OTP",
            "GitHub",
            "بنك الأمل"
        ]
    );
    // The empty entry and the one in the Recycle Bin.
    assert_eq!(result.skipped, 2);
    assert_eq!(
        result.warnings,
        [
            "Entry 2 skipped: no URL, username, password or notes.",
            "\"Steam\": the one-time code setup isn't a TOTP secret, so it was kept as a hidden field.",
            "1 entry in the Recycle Bin was left out.",
            "1 entry has attachments, which weren't imported. Save them from KeePass and add them to the items in Octa Pass."
        ]
    );

    let wifi = &result.items[0];
    assert_eq!(wifi.overview.item_type, ItemType::SecureNote);
    let ItemDetails::SecureNote(note) = &wifi.details else {
        panic!()
    };
    assert_eq!(
        note.notes,
        "SSID: Home\nThe router password is on the sticker."
    );

    let tray = login(&result.items[1]);
    assert!(
        tray.totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/Tray%20TOTP:tray?secret=JBSWY3DPEHPK3PXP&")
    );
    assert_eq!(tray.custom_fields, None, "the seed fields became the TOTP");

    let steam = login(&result.items[2]);
    assert_eq!(steam.totp, None);
    let field = &steam.custom_fields.as_ref().unwrap()[0];
    assert_eq!(field.label, "One-time code");
    assert!(field.hidden && field.value.contains("encoder=steam"));
    assert_eq!(tags(&result.items[2]), ["Work"]);

    let legacy = login(&result.items[3]);
    assert_eq!(legacy.password.as_deref(), Some("  spaced password  "));
    assert!(
        legacy
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/Legacy%20OTP:legacy?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30")
    );
    let expires = &legacy.custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (expires.label.as_str(), expires.value.as_str()),
        ("Expires", "2030-01-01T00:00:00Z")
    );
    assert_eq!(tags(&result.items[3]), ["Work", "legacy"]);

    let github = &result.items[4];
    assert_eq!(tags(github), ["Work/Dev", "dev", "code"]);
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login", "https://gist.github.com"]
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octocat"));
    assert_eq!(
        details.password.as_deref(),
        Some("gh-Pa55 \"quoted\" & <angled>")
    );
    assert_eq!(
        details.notes.as_deref(),
        Some("Work account, \"quoted\", with <angle brackets> & ampersands.\nSecond line.")
    );
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP")
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
            ("Account ID", "12345", false),
            ("Recovery codes", "1111-2222\n3333-4444", true)
        ]
    );
    let history: Vec<(&str, &str)> = details
        .password_history
        .as_ref()
        .unwrap()
        .iter()
        .map(|h| (h.password.as_str(), h.changed_at.as_str()))
        .collect();
    assert_eq!(
        history,
        [
            ("second-password", "2025-10-01T08:00:00Z"),
            ("first-password", "2025-03-01T00:00:00Z")
        ]
    );

    let bank = &result.items[5];
    assert_eq!(tags(bank), ["مالية"]);
    let details = login(bank);
    assert_eq!(details.username.as_deref(), Some("مستخدم"));
    assert_eq!(details.password.as_deref(), Some("كلمة-سر-٢٠٢٥"));
    assert_eq!(details.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));
    let totp = details.totp.as_deref().unwrap();
    assert!(
        totp.contains("algorithm=SHA256&digits=8&period=60"),
        "{totp}"
    );
    assert_eq!(details.custom_fields, None);
}

/// Every database holds `keepass.xml`, so it must import exactly like the export.
#[test]
fn databases_match_the_xml_export() {
    let expected =
        serde_json::to_value(import(&fixture("keepass.xml"), &ImportOptions::default())).unwrap();
    for (name, options) in [
        ("keepass-kdbx3.kdbx", options(Some(PASSWORD), None)),
        ("keepass-kdbx4-argon2d.kdbx", options(Some(PASSWORD), None)),
        (
            "keepass-kdbx4-argon2id-keyfile.kdbx",
            options(Some(ARABIC_PASSWORD), Some("keepass-keyfile.keyx")),
        ),
        (
            "keepass-kdbx4-aes-twofish.kdbx",
            options(None, Some("keepass-keyfile.txt")),
        ),
        // An empty password next to a key file means no password.
        (
            "keepass-kdbx4-aes-twofish.kdbx",
            options(Some(""), Some("keepass-keyfile.txt")),
        ),
    ] {
        let result = serde_json::to_value(import(&fixture(name), &options)).unwrap();
        assert_eq!(result, expected, "{name}");
    }
}

#[test]
fn locked_databases() {
    for name in ["keepass-kdbx3.kdbx", "keepass-kdbx4-argon2d.kdbx"] {
        let bytes = fixture(name);
        assert_eq!(
            error(&bytes, &ImportOptions::default()),
            Error::ImportPasswordRequired,
            "{name}"
        );
        assert_eq!(
            error(&bytes, &options(Some(""), None)),
            Error::ImportPasswordRequired,
            "{name}"
        );
        assert_eq!(
            error(&bytes, &options(Some("wrong"), None)),
            Error::WrongImportPassword,
            "{name}"
        );
        assert_eq!(
            error(
                &bytes,
                &options(Some(PASSWORD), Some("keepass-keyfile.txt"))
            ),
            Error::WrongImportPassword,
            "{name}"
        );
    }
    let keyfile = fixture("keepass-kdbx4-argon2id-keyfile.kdbx");
    assert_eq!(
        error(&keyfile, &options(Some(ARABIC_PASSWORD), None)),
        Error::WrongImportPassword,
        "the key file is part of the key"
    );
    assert_eq!(
        error(
            &keyfile,
            &options(Some(PASSWORD), Some("keepass-keyfile.keyx"))
        ),
        Error::WrongImportPassword
    );
}

#[test]
fn damaged_databases() {
    let kdbx3 = fixture("keepass-kdbx3.kdbx");
    let kdbx4 = fixture("keepass-kdbx4-argon2d.kdbx");
    let with_password = options(Some(PASSWORD), None);
    for bytes in [
        &kdbx3[..kdbx3.len() - 5],
        &kdbx4[..kdbx4.len() - 5],
        &kdbx4[..200],
        &kdbx4[..12],
        &kdbx4[..6],
    ] {
        assert_eq!(error(bytes, &with_password), Error::InvalidImportFile);
    }
    // A flipped byte in the payload fails its block's HMAC.
    let mut flipped = kdbx4.clone();
    let last = flipped.len() - 100;
    flipped[last] ^= 1;
    assert_eq!(error(&flipped, &with_password), Error::InvalidImportFile);
    // KeePass 1 databases.
    let mut kdb = kdbx4[..12].to_vec();
    kdb[4] = 0x65;
    assert_eq!(error(&kdb, &with_password), Error::UnsupportedImport);
}

/// Replaces the value after a header or KDF-parameter marker.
fn patch(bytes: &[u8], marker: &[u8], value: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap()
        + marker.len();
    let mut out = bytes.to_vec();
    out[at..at + value.len()].copy_from_slice(value);
    out
}

#[test]
fn hostile_kdf_settings_are_refused_before_running() {
    let with_password = options(Some(PASSWORD), None);
    // Argon2 with 4 GiB of memory (`M`, a u64 of bytes).
    let argon2 = patch(
        &fixture("keepass-kdbx4-argon2d.kdbx"),
        b"\x01\x00\x00\x00M\x08\x00\x00\x00",
        &(4u64 << 30).to_le_bytes(),
    );
    assert_eq!(error(&argon2, &with_password), Error::UnsupportedImport);
    // Argon2 with a billion passes (`I`).
    let passes = patch(
        &fixture("keepass-kdbx4-argon2d.kdbx"),
        b"\x01\x00\x00\x00I\x08\x00\x00\x00",
        &1_000_000_000u64.to_le_bytes(),
    );
    assert_eq!(error(&passes, &with_password), Error::UnsupportedImport);
    // AES-KDF with u64::MAX rounds (KDBX 3.1 header field 6).
    let aes = patch(
        &fixture("keepass-kdbx3.kdbx"),
        b"\x06\x08\x00",
        &u64::MAX.to_le_bytes(),
    );
    assert_eq!(error(&aes, &with_password), Error::UnsupportedImport);
    // Refused even without a password: there's no point asking for one.
    assert_eq!(
        error(&aes, &ImportOptions::default()),
        Error::UnsupportedImport
    );
}

#[test]
fn keepassxc_csv() {
    let result = import(&fixture("keepassxc.csv"), &ImportOptions::default());
    assert_eq!(
        titles(&result),
        ["GitHub", "بنك الأمل", "Mail 📧", "Wi-Fi at home"]
    );
    assert_eq!(result.skipped, 2);
    assert_eq!(
        result.warnings,
        [
            "Row 10 skipped: no URL, username, password or notes.",
            "1 entry in the Recycle Bin was left out."
        ]
    );
    let github = login(&result.items[0]);
    assert_eq!(github.password.as_deref(), Some("pa,ss\"word"));
    assert_eq!(github.notes.as_deref(), Some("Line one\nline two"));
    assert!(
        github
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert_eq!(github.custom_fields, None, "icon and dates aren't fields");
    assert_eq!(tags(&result.items[0]), Vec::<&str>::new());
    assert_eq!(tags(&result.items[1]), ["مالية"]);
    assert_eq!(
        login(&result.items[1]).notes.as_deref(),
        Some("ملاحظة بالعربية\nسطر ثاني")
    );
    assert_eq!(tags(&result.items[2]), ["Work/Email"]);
    assert_eq!(
        login(&result.items[2]).password.as_deref(),
        Some("  spaced  ")
    );
    assert_eq!(result.items[3].overview.item_type, ItemType::SecureNote);
}

#[test]
fn keepass_csv() {
    let result = import(&fixture("keepass.csv"), &ImportOptions::default());
    assert_eq!(titles(&result), ["GitHub", "بنك الأمل", "Note only"]);
    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        ["Row 7 skipped: no URL, username, password or notes."]
    );
    let github = login(&result.items[0]);
    assert_eq!(github.password.as_deref(), Some("pa,ss\"word\\"));
    assert_eq!(github.notes.as_deref(), Some("Line one\nline two"));
    assert_eq!(
        result.items[0].overview.urls.as_deref().unwrap(),
        ["https://github.com/login"]
    );
    let ItemDetails::SecureNote(note) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(note.notes, "Just a note, with \"quotes\".");
}

#[test]
fn other_files() {
    let none = ImportOptions::default();
    for bytes in [
        &b"<html><body>Not KeePass</body></html>"[..],
        b"name,url\nx,https://x.example\n",
        b"",
        b"\xff\x00\x01binary",
    ] {
        assert_eq!(error(bytes, &none), Error::InvalidImportFile);
    }
}
