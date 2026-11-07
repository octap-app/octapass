//! The Enpass importer against the synthetic fixtures in `tests/import-fixtures/`.

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
        ImportSource::Enpass,
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

fn fields(details: &LoginDetails) -> Vec<(&str, &str, bool)> {
    details
        .custom_fields
        .iter()
        .flatten()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect()
}

#[test]
fn every_category() {
    let result = import("enpass.json");
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    let summary: Vec<(&str, &ItemType)> = result
        .items
        .iter()
        .map(|i| (i.overview.title.as_str(), &i.overview.item_type))
        .collect();
    assert_eq!(
        summary,
        [
            ("GitHub", &ItemType::Login),
            ("بنك الأمل", &ItemType::Login),
            ("Router", &ItemType::Login),
            ("Ideas 💡", &ItemType::SecureNote),
            ("Visa", &ItemType::Card),
            ("عمر", &ItemType::Identity),
            ("Bank account", &ItemType::BankAccount),
            ("Car", &ItemType::SecureNote),
        ]
    );
    assert_eq!(result.skipped, 2, "the trashed item and the empty login");
    assert_eq!(
        result.warnings,
        [
            "Item 10 skipped: no URL, username, password or notes.",
            "1 item in the trash was skipped.",
            "1 archived item was imported with the tag \"archived\".",
            "Attachments can't be imported from Enpass: 1 item was imported without its files. Add the files again in Octa Pass.",
            "1 item of a type Octa Pass doesn't have yet (travel, vehicles …) was imported as logins or secure notes."
        ]
    );
}

#[test]
fn logins() {
    let result = import("enpass.json");
    let github = &result.items[0];
    assert_eq!(github.overview.title, "GitHub");
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2023-07-22T04:26:40Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2025-10-23T00:00:00Z")
    );
    assert_eq!(
        github.overview.last_used_at.as_deref(),
        Some("2025-10-24T00:00:00Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "i0000000-0000-4000-8000-000000000001"
    );
    assert_eq!(
        login(github).password_changed_at.as_deref(),
        Some("2025-10-23T00:00:00Z")
    );
    let github = &result.items[0];
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Social/أصدقاء"]);
    assert_eq!(github.overview.favorite, Some(true));
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com/login"]
    );
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octo-cat"));
    assert_eq!(details.password.as_deref(), Some("pa,ss\"word 1"));
    assert_eq!(details.totp.as_deref(), Some("JBSW Y3DP EHPK 3PXP"));
    assert_eq!(
        details.notes.as_deref(),
        Some("Work account.\nSecond line, with \"quotes\".")
    );
    let history = details.password_history.as_ref().unwrap();
    assert_eq!(history[0].password, "older password");
    assert_eq!(history[0].changed_at, "2023-11-14T22:13:20Z");
    assert_eq!(fields(details), [("E-mail", "octo@example.com", false),]);
    let questions = details
        .recovery
        .as_ref()
        .unwrap()
        .security_questions
        .as_ref()
        .unwrap();
    assert_eq!(questions[0].question, "First pet?");
    assert_eq!(questions[0].answer, "Rex");

    let arabic = login(&result.items[1]);
    assert_eq!(arabic.username.as_deref(), Some("مستخدم@example.com"));
    assert_eq!(arabic.password.as_deref(), Some("سر,مع\"علامات"));
    assert_eq!(arabic.notes.as_deref(), Some("ملاحظة بالعربية\nسطر ثاني"));
    assert_eq!(fields(arabic), [("Android app", "jo.example.bank", false)]);

    let router = &result.items[2];
    assert_eq!(router.overview.tags.as_deref().unwrap(), ["Social"]);
    assert_eq!(
        login(router).password.as_deref(),
        Some("  leading and trailing  ")
    );

    let bank = &result.items[6];
    assert_eq!(bank.overview.tags.as_deref().unwrap(), ["archived"]);
    assert_eq!(
        bank.overview.urls.as_deref().unwrap(),
        ["https://bank.example.com"]
    );
    assert_eq!(bank.overview.subtitle.as_deref(), Some("Example Bank"));
    let ItemDetails::BankAccount(bank) = &bank.details else {
        panic!()
    };
    assert_eq!(bank.bank_name.as_deref(), Some("Example Bank"));
    assert_eq!(bank.account_number.as_deref(), Some("000123456789"));
    assert_eq!(
        bank.iban.as_deref(),
        Some("JO00 EXAM 0000 0000 0000 0000 0000 00")
    );
    assert_eq!(bank.notes.as_deref(), Some("Main account"));
    let kept: Vec<_> = bank
        .custom_fields
        .iter()
        .flatten()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect();
    assert_eq!(
        kept,
        [
            ("Username", "jane.doe", false),
            ("Login password", "bank-login", true),
            ("Transaction password", "txn-4455", true),
        ]
    );
}

#[test]
fn notes_cards_and_identities() {
    let result = import("enpass.json");
    let ItemDetails::SecureNote(note) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(
        note.notes,
        "Line one\nLine two — with a dash\n\nAfter a blank line"
    );

    let visa = &result.items[4];
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
        Some("Issuing bank: Example Bank\nCredit limit: 5000\nTravel card")
    );

    let ItemDetails::Identity(omar) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(omar.first_name.as_deref(), Some("عمر خالد"));
    assert_eq!(omar.last_name.as_deref(), Some("حداد"));
    assert_eq!(omar.email.as_deref(), Some("omar@example.com"));
    assert_eq!(omar.phone.as_deref(), Some("+962 79 000 0000"));
    let address = omar.address.as_ref().unwrap();
    assert_eq!(address.line1.as_deref(), Some("12 شارع الرينبو"));
    assert_eq!(address.country.as_deref(), Some("JO"));
    assert_eq!(address.postal_code.as_deref(), Some("11118"));
    assert_eq!(
        omar.notes.as_deref(),
        Some("Birth date: 17/05/1990\nGender: M\nSignature:\nعمر\nO. K. H.")
    );

    let ItemDetails::SecureNote(car) = &result.items[7].details else {
        panic!()
    };
    assert_eq!(
        car.notes,
        "Registration number: PP-9999\nPurchase date: 1 January 2023"
    );
}

#[test]
fn warnings_have_no_secrets() {
    let result = import("enpass.json");
    for warning in &result.warnings {
        for secret in ["pa,ss", "Rex", "bank-login", "txn-4455", "4321", "gone"] {
            assert!(!warning.contains(secret), "{warning}");
        }
    }
}

#[test]
fn malformed_files() {
    for name in [
        "enpass-malformed.json",
        "chrome.csv",
        "dashlane.json",
        "protonpass.zip",
        "bitwarden.json",
    ] {
        let error = import_file(
            ImportSource::Enpass,
            &fixture(name),
            &ImportOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
    }
}

proptest::proptest! {
    /// No input makes the importer panic (`fuzz/` goes deeper).
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let _ = import_file(ImportSource::Enpass, &bytes, &ImportOptions::default());
        let _ = import_file(ImportSource::Enpass, text.as_bytes(), &ImportOptions::default());
        let json = format!("{{\"folders\":[{text}],\"items\":[{text}]}}");
        let _ = import_file(ImportSource::Enpass, json.as_bytes(), &ImportOptions::default());
    }
}
