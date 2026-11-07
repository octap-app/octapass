//! The NordPass importer against the synthetic fixtures in `tests/import-fixtures/`.

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
fn csv() {
    let result = import_file(
        ImportSource::NordPass,
        &fixture("nordpass.csv"),
        &ImportOptions::default(),
    )
    .unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
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
            "Travel card",
            "ليلى حداد",
            "Diary",
            "Passport",
            "Bank account"
        ],
        "folder rows aren't items"
    );
    let types: Vec<ItemType> = result
        .items
        .iter()
        .map(|i| i.overview.item_type.clone())
        .collect();
    use ItemType::*;
    assert_eq!(
        types,
        [
            Login, Login, Card, Identity, SecureNote, SecureNote, SecureNote
        ]
    );

    let github = &result.items[0];
    assert_eq!(
        github.overview.urls.as_deref().unwrap(),
        [
            "https://github.com/login",
            "https://gist.github.com",
            "https://api.github.com"
        ]
    );
    assert_eq!(github.overview.tags.as_deref().unwrap(), ["Work"]);
    let details = login(github);
    assert_eq!(details.password.as_deref(), Some("np-pass,with \"quotes\""));
    assert_eq!(details.notes.as_deref(), Some("Deploy notes\nsecond line"));
    let fields = details.custom_fields.as_ref().unwrap();
    let summary: Vec<(&str, &str, bool)> = fields
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect();
    assert_eq!(
        summary,
        [
            ("Account ID", "12345", false),
            ("Recovery phrase", "orange piano seven", true),
            ("Created", "2026-02-27", false)
        ],
        "empty custom fields are dropped, dates converted"
    );

    let arabic = &result.items[1];
    assert_eq!(arabic.overview.tags.as_deref().unwrap(), ["عائلة"]);
    assert_eq!(
        login(arabic).notes.as_deref(),
        Some("ملاحظة بالعربية\nسطر ثاني")
    );

    let ItemDetails::Card(card) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(card.cardholder.as_deref(), Some("Jane Q. Doe"));
    assert_eq!(card.expiry.as_deref(), Some("03/30"));
    assert_eq!(card.cvv.as_deref(), Some("123"));
    assert_eq!(card.pin.as_deref(), Some("9876"));
    assert_eq!(
        card.notes.as_deref(),
        Some("ZIP code: 11118\nIssuer: Example Bank\nCard for trips")
    );

    let ItemDetails::Identity(identity) = &result.items[3].details else {
        panic!()
    };
    assert_eq!(identity.first_name.as_deref(), Some("ليلى"));
    assert_eq!(identity.last_name.as_deref(), Some("حداد"));
    assert_eq!(identity.phone.as_deref(), Some("+962791234567"));
    let address = identity.address.as_ref().unwrap();
    assert_eq!(address.city.as_deref(), Some("Amman"));
    assert_eq!(address.postal_code.as_deref(), Some("11118"));
    assert_eq!(address.country.as_deref(), Some("Jordan"));

    let ItemDetails::SecureNote(diary) = &result.items[4].details else {
        panic!()
    };
    assert_eq!(
        diary.notes,
        "Mood: calm\nDear diary,\nemoji 🔐 and \"quotes\""
    );
    let ItemDetails::SecureNote(passport) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(passport.notes, "Passport number: X1234567\nPassport scan");

    assert_eq!(result.skipped, 1);
    assert_eq!(
        result.warnings,
        [
            "Row 13 skipped: no URL, username, password or notes.",
            "NordPass exports don't include files: 1 document was imported as a secure note without its file.",
            "1 item of an unknown type was imported as a login, card or secure note."
        ]
    );
}

#[test]
fn malformed_and_wrong_files_are_errors() {
    for (name, bytes) in [
        ("nordpass-malformed.csv", fixture("nordpass-malformed.csv")),
        ("chrome.csv", fixture("chrome.csv")),
        ("bitwarden.json", fixture("bitwarden.json")),
        ("empty", Vec::new()),
    ] {
        let error =
            import_file(ImportSource::NordPass, &bytes, &ImportOptions::default()).unwrap_err();
        assert_eq!(error.code, Error::InvalidImportFile, "{name}");
        assert!(!error.detail.is_empty());
    }
}

proptest::proptest! {
    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), text in "\\PC{0,256}") {
        let options = ImportOptions::default();
        let _ = import_file(ImportSource::NordPass, &bytes, &options);
        let with_header = format!("name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n{text}");
        let _ = import_file(ImportSource::NordPass, with_header.as_bytes(), &options);
    }
}
