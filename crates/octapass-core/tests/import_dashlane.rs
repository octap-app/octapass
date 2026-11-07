//! The Dashlane importer against the synthetic fixtures in `tests/import-fixtures/`.

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
        ImportSource::Dashlane,
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

fn assert_valid(result: &ImportResult) {
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
}

#[test]
fn zip_of_csv_files() {
    let result = import("dashlane.zip");
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "GitHub",
            "بنك الأمل",
            "Bücher",
            "Notes with quotes \"",
            "Wi-Fi 📶",
            "Visa",
            "Checking",
            "Passport (عمر خالد حداد)",
            "Driving licence (Jane Q Doe)",
            "Jane Doe"
        ]
    );
    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        [
            "\"future-feature.csv\" was skipped: Octa Pass doesn't know this Dashlane file.",
            "Row 7 skipped: no URL, username, password or notes."
        ]
    );

    let github = &result.items[0];
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Work"]);
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        ["https://github.com"]
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
    let extra = &details.custom_fields.as_ref().unwrap()[0];
    assert_eq!(
        (extra.label.as_str(), extra.value.as_str()),
        ("Username 2", "octo@example.com")
    );
    let arabic = &result.items[1];
    assert_eq!(arabic.overview.tags.as_deref().unwrap(), ["مالية"]);
    assert_eq!(login(arabic).password.as_deref(), Some("سر,مع\"علامات"));
    assert_eq!(
        login(&result.items[2]).password.as_deref(),
        Some("  leading and trailing  ")
    );

    let ItemDetails::SecureNote(note) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(
        note.notes,
        "Line one, with a comma\nLine two with \"quotes\"\nسطر بالعربية"
    );

    let ItemDetails::Card(card) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(card.cardholder.as_deref(), Some("JANE Q DOE"));
    assert_eq!(card.number.as_deref(), Some("4111111111111111"));
    assert_eq!(card.cvv.as_deref(), Some("123"));
    assert_eq!(card.expiry.as_deref(), Some("08/29"));
    assert_eq!(
        card.notes.as_deref(),
        Some("Issuing bank: Example Bank\nCountry: US\nTravel card\nCall before trips")
    );
    let ItemDetails::BankAccount(bank) = &result.items[6].details else {
        panic!()
    };
    assert_eq!(bank.account_holder.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(bank.routing_number.as_deref(), Some("021000021"));
    assert_eq!(bank.account_number.as_deref(), Some("000123456789"));
    assert_eq!(bank.bank_name.as_deref(), Some("Example Bank"));
    assert_eq!(bank.custom_fields.as_ref().unwrap()[0].value, "US");

    let ItemDetails::IdDocument(passport) = &result.items[7].details else {
        panic!()
    };
    assert_eq!(passport.document_type.as_deref(), Some("passport"));
    assert_eq!(passport.number.as_deref(), Some("N0000000"));
    assert_eq!(passport.full_name.as_deref(), Some("عمر خالد حداد"));
    assert_eq!(passport.issue_date.as_deref(), Some("2020-01-05"));
    assert_eq!(passport.expiry_date.as_deref(), Some("2030-01-04"));
    assert_eq!(passport.issuer.as_deref(), Some("عمّان"));
    let ItemDetails::IdDocument(license) = &result.items[8].details else {
        panic!()
    };
    assert_eq!(license.document_type.as_deref(), Some("driverLicense"));
    assert_eq!(license.custom_fields.as_ref().unwrap()[0].value, "CA");

    let me = &result.items[9];
    assert_eq!(me.overview.item_type, ItemType::Identity);
    let ItemDetails::Identity(me) = &me.details else {
        panic!()
    };
    assert_eq!(me.first_name.as_deref(), Some("Jane Q"));
    assert_eq!(me.last_name.as_deref(), Some("Doe"));
    assert_eq!(me.birth_date.as_deref(), Some("1990-02-03"));
    assert_eq!(me.email.as_deref(), Some("jane@example.com"));
    assert_eq!(me.phone.as_deref(), Some("+1 555 0100"));
    let address = me.address.as_ref().unwrap();
    assert_eq!(address.line1.as_deref(), Some("1 Main St, Apt 2"));
    assert_eq!(address.line2.as_deref(), Some("B, 2"));
    assert_eq!(address.region.as_deref(), Some("CA"));
    assert_eq!(address.postal_code.as_deref(), Some("90210"));
    let notes = me.notes.as_deref().unwrap();
    for line in [
        "Title: Ms",
        "Login: jdoe",
        "Place of birth: Zürich",
        "Job title: Engineer",
        "Email: jane.doe@work.example",
        "Address door code: 4711",
    ] {
        assert!(notes.lines().any(|l| l == line), "{line} in {notes}");
    }
}

/// One CSV file from the ZIP, dropped on its own.
#[test]
fn single_csv_file() {
    let result = import("dashlane-credentials.csv");
    assert_eq!(titles(&result), ["GitHub", "بنك الأمل", "Bücher"]);
    let result = import("dashlane-payments.csv");
    assert_eq!(result.items[0].overview.item_type, ItemType::Card);
}

#[test]
fn json() {
    let result = import("dashlane.json");
    let github = result
        .items
        .iter()
        .find(|item| item.overview.title == "GitHub")
        .unwrap();
    assert_eq!(
        github.overview.created_at.as_deref(),
        Some("2020-09-13T12:26:40Z")
    );
    assert_eq!(
        github.overview.updated_at.as_deref(),
        Some("2022-04-15T05:20:00Z")
    );
    assert_eq!(
        github.overview.last_used_at.as_deref(),
        Some("2023-11-14T22:13:20Z")
    );
    assert_eq!(
        github.overview.imported_from.as_ref().unwrap().id,
        "{5E1F2A3B-0000-4000-8000-000000000001}"
    );
    assert!(
        login(github)
            .custom_fields
            .iter()
            .flatten()
            .all(|f| f.label != "lastUse"),
        "dates aren't custom fields"
    );
    assert_valid(&result);
    assert_eq!(
        titles(&result),
        [
            "Home",
            "GitHub",
            "بنك الأمل",
            "Checking",
            "Personal email",
            "Jane Q Doe",
            "Visa",
            "PayPal",
            "Ideas 💡"
        ]
    );
    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        ["AUTHENTIFIANT entry 3 skipped: it has no fields."]
    );

    let github = &result.items[1];
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Work"]);
    let details = login(github);
    assert_eq!(details.username.as_deref(), Some("octo-cat"));
    assert_eq!(details.password.as_deref(), Some("pa,ss\"word 1"));
    let labels: Vec<&str> = details
        .custom_fields
        .as_ref()
        .unwrap()
        .iter()
        .map(|f| f.label.as_str())
        .collect();
    assert_eq!(labels, ["Email", "autoLogin"]);
    assert_eq!(
        login(&result.items[2]).username.as_deref(),
        Some("مستخدم@example.com")
    );

    let ItemDetails::Identity(home) = &result.items[0].details else {
        panic!()
    };
    assert_eq!(
        home.address.as_ref().unwrap().city.as_deref(),
        Some("Springfield")
    );
    let ItemDetails::Identity(jane) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(jane.birth_date.as_deref(), Some("1990-02-03"));
    assert_eq!(
        jane.notes.as_deref(),
        Some("Username: jdoe\nbirthPlace: Zürich")
    );
    let ItemDetails::Card(visa) = &result.items[6].details else {
        panic!()
    };
    assert_eq!(visa.expiry.as_deref(), Some("08/29"));
    assert_eq!(visa.cardholder.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(
        login(&result.items[7]).password.as_deref(),
        Some("pp-secret")
    );
    let ItemDetails::SecureNote(ideas) = &result.items[8].details else {
        panic!()
    };
    assert_eq!(ideas.notes, "Line one\nLine two");
}

#[test]
fn malformed_files() {
    for name in [
        "dashlane-malformed.json",
        "chrome.csv",
        "protonpass.zip",
        "enpass.json",
    ] {
        let error = import_file(
            ImportSource::Dashlane,
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
        let _ = import_file(ImportSource::Dashlane, &bytes, &ImportOptions::default());
        let _ = import_file(ImportSource::Dashlane, text.as_bytes(), &ImportOptions::default());
        for header in [
            "username,username2,username3,title,password,note,url,category,otpUrl",
            "type,account_name,account_holder,cc_number,code,expiration_month,expiration_year",
            "type,number,name,issue_date,expiration_date,place_of_issue,state",
            "type,title,first_name,middle_name,last_name,login,date_of_birth,email",
            "title,note",
        ] {
            let csv = format!("{header}\n{text}");
            let _ = import_file(ImportSource::Dashlane, csv.as_bytes(), &ImportOptions::default());
        }
        let json = format!("{{\"AUTHENTIFIANT\":[{text}],\"IDENTITY\":[{text}]}}");
        let _ = import_file(ImportSource::Dashlane, json.as_bytes(), &ImportOptions::default());
    }
}
