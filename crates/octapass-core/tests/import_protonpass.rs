//! The Proton Pass importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportResult, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};
use serde_json::json;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn import(name: &str) -> ImportResult {
    import_file(
        ImportSource::ProtonPass,
        &fixture(name),
        &ImportOptions::default(),
    )
    .unwrap()
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

fn find<'a>(result: &'a ImportResult, title: &str) -> &'a Item {
    result
        .items
        .iter()
        .find(|i| i.overview.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn assert_valid(result: &ImportResult) {
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
}

/// The ZIP and the bare `data.json` give the same result.
#[test]
fn zip_and_json() {
    let zip = import("protonpass.zip");
    let json = import("protonpass-data.json");
    assert_eq!(
        serde_json::to_value(&zip).unwrap(),
        serde_json::to_value(&json).unwrap()
    );
    assert_valid(&zip);

    let mut titles: Vec<&str> = zip
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    titles.sort_unstable();
    assert_eq!(
        titles,
        [
            "Deploy key",
            "GitHub",
            "Gym locker",
            "Home Wi-Fi",
            "Ideas 💡",
            "Lease scan",
            "Newsletters",
            "Visa",
            "بنك الأمل",
            "عمر"
        ]
    );
    assert_eq!(zip.skipped, 2, "the trashed item and the empty login");
}

#[test]
fn logins() {
    let result = import("protonpass.zip");
    let github = find(&result, "GitHub");
    assert_eq!(github.overview.favorite, Some(true));
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2025-10-23T00:00:00Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2025-10-23T00:00:00Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "aXRlbS0x"
    );
    assert_eq!(
        github.overview.tags.as_deref().unwrap(),
        ["Personal", "Work/Clients"]
    );
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login", "https://github.example.com/"]
    );
    assert_eq!(
        github.overview.extra["urlMatch"],
        json!({ "https://github.example.com/": "never" })
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octo-cat"));
    assert_eq!(details.password.as_deref(), Some("pa,ss\"word 1"));
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP")
    );
    assert_eq!(
        details.notes.as_deref(),
        Some("Work account.\nSecond line, with \"quotes\".")
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
            ("Email", "octo@example.com", false),
            ("Recovery PIN", "8642", true),
            ("Team", "Platform", false),
            (
                "Backup authenticator",
                "otpauth://totp/Backup:octo?secret=GEZDGNBVGY3TQOJQ&issuer=Backup",
                true
            ),
        ]
    );

    let arabic = login(find(&result, "بنك الأمل"));
    assert_eq!(arabic.username.as_deref(), Some("مستخدم@example.com"));
    assert_eq!(arabic.password.as_deref(), Some("سر,مع\"علامات"));
    assert_eq!(arabic.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));
    let passkey = &arabic.passkeys.as_ref().unwrap()[0];
    assert_eq!(passkey.rp_id, "bank.example.jo");
    assert_eq!(passkey.user_name, "مستخدم");
    assert_eq!(passkey.created_at, "2025-10-23T00:00:00Z");
    assert!(passkey.extra.contains_key("content"), "the key is kept");

    let alias = find(&result, "Newsletters");
    assert_eq!(
        alias.overview.tags.as_deref().unwrap(),
        ["Personal", "Work"]
    );
    assert_eq!(
        login(alias).username.as_deref(),
        Some("news.k7q2@passmail.net")
    );
}

#[test]
fn notes_cards_identities_and_other_types() {
    let result = import("protonpass-data.json");
    let ItemDetails::SecureNote(note) = &find(&result, "Ideas 💡").details else {
        panic!()
    };
    assert_eq!(
        note.notes,
        "Line one\nLine two — with a dash\n\nAfter a blank line"
    );

    let visa = find(&result, "Visa");
    assert_eq!(visa.overview.tags.as_deref().unwrap(), ["Family"]);
    assert_eq!(visa.overview.subtitle.as_deref(), Some("•••• 1111"));
    let ItemDetails::Card(card) = &visa.details else {
        panic!()
    };
    assert_eq!(card.cardholder.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(card.brand.as_deref(), Some("Visa"));
    assert_eq!(card.expiry.as_deref(), Some("08/29"));
    assert_eq!(card.cvv.as_deref(), Some("123"));
    assert_eq!(card.pin.as_deref(), Some("4321"));
    assert_eq!(
        card.notes.as_deref(),
        Some("Issuer phone: +962 6 000 0000\nTravel card")
    );

    let ItemDetails::Identity(omar) = &find(&result, "عمر").details else {
        panic!()
    };
    assert_eq!(omar.first_name.as_deref(), Some("عمر خالد"));
    assert_eq!(omar.last_name.as_deref(), Some("حداد"));
    assert_eq!(omar.birth_date.as_deref(), Some("1990-05-17"));
    assert_eq!(omar.phone.as_deref(), Some("+962 79 000 0000"));
    let address = omar.address.as_ref().unwrap();
    assert_eq!(address.city.as_deref(), Some("عمّان"));
    assert_eq!(address.postal_code.as_deref(), Some("11118"));
    assert_eq!(
        omar.notes.as_deref(),
        Some(
            "Floor: 3\nPassport number: N0000000\nCompany: Example Co\nJob title: Engineer\nNickname: أبو خالد\nBlood type: O+"
        )
    );

    let wifi = login(find(&result, "Home Wi-Fi"));
    assert_eq!(wifi.password.as_deref(), Some("correct horse"));
    let ItemDetails::SecureNote(ssh) = &find(&result, "Deploy key").details else {
        panic!()
    };
    assert!(
        ssh.notes
            .contains("Private key:\n-----BEGIN OPENSSH PRIVATE KEY-----\n")
    );
    let ItemDetails::Custom(locker) = &find(&result, "Gym locker").details else {
        panic!()
    };
    let fields: Vec<_> = locker
        .fields
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.kind.as_str()))
        .collect();
    assert_eq!(
        fields,
        [
            ("Combination", "12-34-56", "hidden"),
            ("Renewal", "2026-12-31", "text")
        ]
    );
    assert_eq!(locker.notes.as_deref(), Some("Blue door"));
}

#[test]
fn warnings() {
    let result = import("protonpass.zip");
    assert_eq!(
        result.warnings,
        [
            "Item 12 skipped: it has no fields.",
            "1 item in the trash was skipped.",
            "1 alias was imported as a login with the alias address as the username. Aliases themselves stay in your Proton account.",
            "1 login has passkeys: they were kept, but can't be used to sign in yet.",
            "Attachments can't be imported yet: 1 item was imported without its files.",
            "2 items of a type Octa Pass doesn't have yet (Wi-Fi, SSH key) were imported as logins or secure notes."
        ]
    );
    for warning in &result.warnings {
        for secret in ["pa,ss", "8642", "correct horse", "4321", "N0000000"] {
            assert!(!warning.contains(secret), "{warning}");
        }
    }
}

#[test]
fn csv() {
    let result = import("protonpass.csv");
    assert_valid(&result);
    assert_eq!(
        result.items[0].overview.created_at.as_deref(),
        Some("2025-10-23T00:00:00Z")
    );
    assert!(
        result.items[0].overview.imported_from.is_none(),
        "the CSV has no ids"
    );
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(
        titles,
        [
            "GitHub",
            "بنك الأمل",
            "Newsletters",
            "Ideas 💡",
            "Visa",
            "عمر"
        ]
    );
    assert_eq!(result.skipped, 1);

    let github = &result.items[0];
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Personal"]);
    assert_eq!(
        github.overview.extra["urlMatch"],
        json!({ "https://gist.github.com/": "startsWith" })
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octo-cat"));
    assert_eq!(details.password.as_deref(), Some("pa,ss\"word 1"));
    assert_eq!(
        details.notes.as_deref(),
        Some("Work account.\nSecond line, with \"quotes\".")
    );
    assert_eq!(
        details.custom_fields.as_ref().unwrap()[0].value,
        "octo@example.com"
    );
    assert_eq!(
        login(&result.items[1]).username.as_deref(),
        Some("مستخدم@example.com")
    );
    assert_eq!(
        login(&result.items[2]).username.as_deref(),
        Some("news.k7q2@passmail.net")
    );
    assert_eq!(result.items[3].overview.item_type, ItemType::SecureNote);
    let ItemDetails::Card(card) = &result.items[4].details else {
        panic!()
    };
    assert_eq!(card.expiry.as_deref(), Some("08/29"));
    assert_eq!(card.notes.as_deref(), Some("Travel card"));
    let ItemDetails::Identity(omar) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(omar.email.as_deref(), Some("omar@example.com"));
    assert_eq!(omar.last_name.as_deref(), Some("حداد"));
}

#[test]
fn encrypted_and_malformed_files() {
    let encrypted = import_file(
        ImportSource::ProtonPass,
        &fixture("protonpass-encrypted.zip"),
        &ImportOptions::default(),
    )
    .unwrap_err();
    assert_eq!(encrypted.code, Error::ImportPasswordRequired);

    for name in ["protonpass-malformed.json", "chrome.csv", "bitwarden.json"] {
        let error = import_file(
            ImportSource::ProtonPass,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
    // A ZIP that isn't a Proton Pass export.
    let other = import_file(
        ImportSource::ProtonPass,
        &fixture("dashlane.zip"),
        &ImportOptions::default(),
    )
    .unwrap_err();
    assert_eq!(other.code, Error::InvalidImportFile);
}

proptest::proptest! {
    /// No input makes the importer panic (`fuzz/` goes deeper).
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let _ = import_file(ImportSource::ProtonPass, &bytes, &ImportOptions::default());
        let _ = import_file(ImportSource::ProtonPass, text.as_bytes(), &ImportOptions::default());
        let csv = format!("type,name,url,email,username,password,note,totp,vault\n{text}");
        let _ = import_file(ImportSource::ProtonPass, csv.as_bytes(), &ImportOptions::default());
        let json = format!("{{\"vaults\":{{\"a\":{{\"items\":[{text}]}}}}}}");
        let _ = import_file(ImportSource::ProtonPass, json.as_bytes(), &ImportOptions::default());
    }
}

const PASSPHRASE: &str = "correct horse battery staple";

fn with_passphrase(passphrase: &str) -> ImportOptions {
    ImportOptions {
        password: Some(passphrase.to_string().into()),
        ..ImportOptions::default()
    }
}

/// The PGP-encrypted export as Proton writes it (OpenPGP.js: SKESK v4, SEIPD v1, S2K count byte
/// 255), the newer OpenPGP.js settings (Argon2, AEAD) around the whole ZIP, and GnuPG's own
/// (compressed, binary) all read like the plain export.
#[test]
fn pgp_encrypted_exports() {
    let plain = import("protonpass.zip");
    for name in [
        "protonpass-encrypted.zip",
        "protonpass-data.pgp",
        "protonpass-aead.pgp",
        "protonpass-gpg.pgp",
    ] {
        let result = import_file(
            ImportSource::ProtonPass,
            &fixture(name),
            &with_passphrase(PASSPHRASE),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(result.items, plain.items, "{name}");
        let wrong = import_file(
            ImportSource::ProtonPass,
            &fixture(name),
            &with_passphrase("wrong"),
        )
        .unwrap_err();
        assert_eq!(wrong.code, Error::WrongImportPassword, "{name}");
    }
}

/// Proton's own encrypted test export (`mocks/pgp-export.zip` in Proton's WebClients repository).
/// Its passphrase isn't published, so this only shows the real file is recognised and opened as
/// far as the passphrase.
#[test]
fn protons_own_encrypted_export() {
    let file = fixture("protonpass-proton-mock.zip");
    let needs = import_file(ImportSource::ProtonPass, &file, &ImportOptions::default());
    assert_eq!(needs.unwrap_err().code, Error::ImportPasswordRequired);
    let wrong = import_file(
        ImportSource::ProtonPass,
        &file,
        &with_passphrase(PASSPHRASE),
    );
    assert_eq!(wrong.unwrap_err().code, Error::WrongImportPassword);
}

/// A changed byte anywhere after the passphrase packet, or a cut-off file, gives an error and no
/// items: the MDC or AEAD tag is checked before any plaintext is used.
#[test]
fn tampered_pgp_exports_fail() {
    let binary = fixture("protonpass-gpg.pgp");
    let options = with_passphrase(PASSPHRASE);
    let mut failures = 0;
    for at in (20..binary.len())
        .step_by(97)
        .chain([binary.len() - 1, binary.len() - 21])
    {
        let mut changed = binary.clone();
        changed[at] ^= 0x01;
        let error = import_file(ImportSource::ProtonPass, &changed, &options).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
            "{at}: {error:?}"
        );
        failures += 1;
    }
    assert!(failures > 20);
    for len in [binary.len() / 2, binary.len() - 1] {
        let error = import_file(ImportSource::ProtonPass, &binary[..len], &options).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
            "{len}: {error:?}"
        );
    }
    // Armored files: a changed letter in the body (after the session key packet).
    for name in ["protonpass-data.pgp", "protonpass-aead.pgp"] {
        let text = String::from_utf8(fixture(name)).unwrap();
        let body = text.find("\n\n").unwrap() + 2;
        for at in [
            body + 200,
            body + text[body..].len() / 2,
            text.find("-----END").unwrap() - 70,
        ] {
            let mut bytes = text.clone().into_bytes();
            bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
            let error = import_file(ImportSource::ProtonPass, &bytes, &options).unwrap_err();
            assert!(
                [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
                "{name} {at}: {error:?}"
            );
        }
        let cut = &text[..text.len() / 2];
        let error = import_file(ImportSource::ProtonPass, cut.as_bytes(), &options).unwrap_err();
        assert!(
            [Error::InvalidImportFile, Error::WrongImportPassword].contains(&error.code),
            "{name}: {error:?}"
        );
    }
}
