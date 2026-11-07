//! The Keeper importer against the synthetic fixtures in `tests/import-fixtures/`.

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::import::{ImportOptions, ImportResult, ImportSource, import_file};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn import(name: &str) -> ImportResult {
    import_file(
        ImportSource::Keeper,
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

fn titles(result: &ImportResult) -> Vec<&str> {
    result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect()
}

fn types(result: &ImportResult) -> Vec<ItemType> {
    result
        .items
        .iter()
        .map(|i| i.overview.item_type.clone())
        .collect()
}

/// Every imported item must survive the item model's own JSON round trip.
fn assert_valid(result: &ImportResult) {
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
}

#[test]
fn csv() {
    let result = import("keeper.csv");
    let card = result
        .items
        .iter()
        .find(|item| item.overview.title == "Travel card")
        .unwrap();
    assert_eq!(
        card.overview.imported_from.as_ref().unwrap().id,
        "AbCdEfGh123"
    );
    assert!(
        result.items[0].overview.imported_from.is_none(),
        "Web Vault rows have no uid"
    );
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "GitHub",
            "بنك الأمل",
            "Hotel loyalty",
            "Wi-Fi at home",
            "Recovery codes",
            "Travel card"
        ]
    );
    use ItemType::*;
    assert_eq!(
        types(&result),
        [Login, Login, Login, SecureNote, Login, Card]
    );

    let github = login(&result.items[0]);
    assert_eq!(github.password.as_deref(), Some("kp-pass,with \"quotes\""));
    assert!(
        github
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert_eq!(
        github.notes.as_deref(),
        Some("Deploy key is in the vault.\nSecond line.")
    );
    let fields = github.custom_fields.as_ref().unwrap();
    assert_eq!(fields.len(), 1, "the TFC:Keeper pair is the TOTP");
    assert_eq!(
        (fields[0].label.as_str(), fields[0].value.as_str()),
        ("Account ID", "12345")
    );
    assert_eq!(
        result.items[0].overview.tags.as_deref().unwrap(),
        ["Work\\Dev"]
    );

    let arabic = login(&result.items[1]);
    assert_eq!(arabic.username.as_deref(), Some("مستخدم"));
    assert_eq!(arabic.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));
    assert_eq!(
        result.items[1].overview.tags.as_deref().unwrap(),
        ["Family"],
        "the shared folder's #edit#reshare flags are dropped"
    );
    let pin = &arabic.custom_fields.as_ref().unwrap()[1];
    assert_eq!((pin.label.as_str(), pin.hidden), ("PIN Code", true));

    assert_eq!(
        result.items[2].overview.tags.as_deref().unwrap(),
        ["Team Shared\\Travel"]
    );

    let ItemDetails::SecureNote(wifi) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(wifi.notes, "Network: Casa Verde\nPassword: correct-horse");

    let ItemDetails::Card(card) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(card.number.as_deref(), Some("4111111111111111"));
    assert_eq!(card.expiry.as_deref(), Some("03/30"));
    assert_eq!(card.cvv.as_deref(), Some("123"));
    assert_eq!(card.cardholder.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(card.pin.as_deref(), Some("9876"));

    assert_eq!(result.skipped, 2, "{:?}", result.warnings);
    assert_eq!(
        result.warnings,
        [
            "Row 11 skipped: no URL, username, password or notes.",
            "Row 12 skipped: it has fewer columns than a Keeper export."
        ]
    );
}

#[test]
fn json() {
    let result = import("keeper.json");
    assert_valid(&result);
    let github = &result.items[0].overview;
    assert_eq!(github.updated_at.as_deref(), Some("2025-10-23T00:00:00Z"));
    assert_eq!(github.created_at, None, "Keeper exports no created date");
    assert_eq!(github.imported_from.as_ref().unwrap().id, "rec-login-0001");
    assert_eq!(
        titles(&result),
        [
            "GitHub",
            "بنك الأمل",
            "Travel card",
            "ليلى حداد",
            "Home Address",
            "Passport",
            "Diary",
            "Web server",
            "SSH key",
            "Scanned contract"
        ]
    );
    use ItemType::*;
    assert_eq!(
        types(&result),
        [
            Login, Login, Card, Identity, Identity, IdDocument, SecureNote, Database, SecureNote,
            SecureNote
        ]
    );

    let github = &result.items[0];
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login", "https://gist.github.com"]
    );
    assert_eq!(
        github.overview.tags.as_deref().unwrap(),
        ["Work\\Dev", "Family\\Shared logins"]
    );
    let details = login(github);
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP")
    );
    let fields = details.custom_fields.as_ref().unwrap();
    let field = |label: &str| fields.iter().find(|f| f.label == label).unwrap();
    assert_eq!(field("Account ID").value, "12345");
    assert!(field("Recovery phrase").hidden);
    let questions = details
        .recovery
        .as_ref()
        .unwrap()
        .security_questions
        .as_ref()
        .unwrap();
    assert_eq!(questions[0].question, "First pet?");
    assert_eq!(questions[0].answer, "Biscuit");

    assert_eq!(
        login(&result.items[1]).totp.as_deref(),
        Some("JBSWY3DPEHPK3PXP"),
        "the older TFC:Keeper key"
    );

    let ItemDetails::Card(card) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(card.expiry.as_deref(), Some("03/30"));
    assert_eq!(card.pin.as_deref(), Some("9876"));
    assert_eq!(
        card.notes.as_deref(),
        Some("Bank site: https://bank.example.com/cards\nCard for trips")
    );

    let ItemDetails::Identity(contact) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(contact.first_name.as_deref(), Some("ليلى م."));
    assert_eq!(contact.last_name.as_deref(), Some("حداد"));
    assert_eq!(contact.phone.as_deref(), Some("JO 791234567 ext. 12"));
    assert_eq!(
        contact.notes.as_deref(),
        Some("Phone (Work): JO 64000000\nCompany: شركة المثال"),
        "the second phone isn't dropped"
    );

    let ItemDetails::Identity(home) = &result.items[4].details else {
        panic!()
    };
    let address = home.address.as_ref().unwrap();
    assert_eq!(address.postal_code.as_deref(), Some("11118"));
    assert_eq!(address.line2.as_deref(), Some("Apt 3"));

    let ItemDetails::IdDocument(passport) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(passport.document_type.as_deref(), Some("passport"));
    assert_eq!(passport.number.as_deref(), Some("X1234567"));
    assert_eq!(passport.full_name.as_deref(), Some("Omar Khalil"));
    assert_eq!(passport.birth_date.as_deref(), Some("1990-07-22"));
    assert_eq!(passport.issue_date.as_deref(), Some("2023-08-15"));
    assert_eq!(passport.expiry_date.as_deref(), Some("2033-07-22"));

    let ItemDetails::SecureNote(diary) = &result.items[6].details else {
        panic!()
    };
    assert_eq!(
        diary.notes,
        "Date: 2025-10-23\nDear diary,\nemoji 🔐 and \"quotes\"\nWritten in Keeper's notes box."
    );

    let ItemDetails::Database(server) = &result.items[7].details else {
        panic!()
    };
    assert_eq!(server.database_type.as_deref(), Some("server"));
    assert_eq!(server.host.as_deref(), Some("web01.example.com"));
    assert_eq!(server.port.as_deref(), Some("22"));
    assert_eq!(server.username.as_deref(), Some("deploy"));
    assert_eq!(server.password.as_deref(), Some("srv-pass"));

    let ItemDetails::SecureNote(ssh) = &result.items[8].details else {
        panic!()
    };
    assert!(
        ssh.notes
            .starts_with("Type: SSH key\nPublic key: ssh-ed25519")
    );
    assert!(
        ssh.notes
            .contains("Private key:\n-----BEGIN OPENSSH PRIVATE KEY-----")
    );

    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        [
            "Record 11 skipped: it has no fields.",
            "Keeper's exports don't include files: 1 item was imported without its files."
        ]
    );
}

#[test]
fn json_records_array_is_accepted() {
    let records = br#"[{"title": "A", "login": "u", "password": "p"}]"#;
    let result = import_file(ImportSource::Keeper, records, &ImportOptions::default()).unwrap();
    assert_eq!(login(&result.items[0]).password.as_deref(), Some("p"));
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for (name, bytes) in [
        ("keeper-malformed.json", fixture("keeper-malformed.json")),
        ("lastpass.csv", fixture("lastpass.csv")),
        ("bitwarden.json", fixture("bitwarden.json")),
        ("empty", Vec::new()),
        ("short rows", b"a,b,c\nd,e\n".to_vec()),
        ("latin-1", b"caf\xe9,x,y,z,w,v".to_vec()),
    ] {
        let error =
            import_file(ImportSource::Keeper, &bytes, &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
        assert!(!error.detail.is_empty());
    }
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let options = ImportOptions::default();
        let _ = import_file(ImportSource::Keeper, &bytes, &options);
        let _ = import_file(ImportSource::Keeper, text.as_bytes(), &options);
        let json = format!(r#"{{"records": [{{"title": "x", "$type": "bankCard", "custom_fields": {{"$paymentCard::1": "{}", "$date::1": "{}"}}}}]}}"#, text.escape_default(), text.escape_default());
        let _ = import_file(ImportSource::Keeper, json.as_bytes(), &options);
    }
}
