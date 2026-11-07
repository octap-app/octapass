//! Exports and importing them back: the Octa Pass JSON and encrypted exports round-trip exactly,
//! and the FIDO Credential Exchange Format (CXF) round-trips and reads other apps' files (the
//! test vectors in `tests/import-fixtures/cxf-*.json`, see the README there for their sources).

use std::path::PathBuf;

use octapass_core::Error;
use octapass_core::export::cxf::{self, CxfAccount};
use octapass_core::export::{ArchiveWriter, ExportDocument, ExportItem, ExportVault};
use octapass_core::import::{
    ImportOptions, ImportResult, ImportSource, import_file, import_octapass, relink,
};
use octapass_core::item::{Item, ItemDetails, ItemType, LoginDetails};
use octapass_core::kdf::KdfParams;
use octapass_core::passkey::{
    self, Caller, ClientData, CreationOptions, PasskeyRecord, RequestOptions,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Map, Value, json};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const IDENTITY_ID: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
const FILE_ID: &str = "0192f0c8-1c2d-7a00-8000-0000000000cc";

fn passkey() -> PasskeyRecord {
    let options: CreationOptions = serde_json::from_value(json!({
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": "dXNlcg", "name": "ليلى", "displayName": "Layla" },
        "challenge": "AAAA",
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    }))
    .unwrap();
    let caller = ClientData::Web(
        serde_json::from_value::<Caller>(json!({ "origin": "https://example.com" })).unwrap(),
    );
    passkey::create(&options, &caller, 0, &mut ChaCha20Rng::seed_from_u64(3))
        .unwrap()
        .record
}

fn item(id: &str, vault: &str, overview: Value, details: Value) -> ExportItem {
    ExportItem {
        id: id.into(),
        vault_id: vault.into(),
        created_at: "2026-01-02T03:04:05.000Z".into(),
        updated_at: "2026-02-03T04:05:06.000Z".into(),
        overview,
        details,
    }
}

fn vault(id: &str, name: &str, kind: &str) -> ExportVault {
    ExportVault {
        id: id.into(),
        name: name.into(),
        vault_type: kind.into(),
        extra: Map::new(),
    }
}

/// One item of every type, with the fields each type has, in two vaults of different types.
fn document(with_files: bool) -> ExportDocument {
    let passkey = serde_json::to_value(passkey().to_item()).unwrap();
    let mut items = vec![
        item(
            "0192f0c8-1c2d-7a00-8000-000000000001",
            "v1",
            json!({ "schemaVersion": 1, "title": "بنك الأمل", "type": "login", "urls": ["https://example.com/login", "androidapp://com.example.bank"], "subtitle": "ليلى", "tags": ["مالية", "work"], "favorite": true, "urlMatch": "host" }),
            json!({
                "schemaVersion": 1, "username": "ليلى", "password": " p,\"w\"\n ",
                "totp": "otpauth://totp/Example:layla?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60&issuer=Example",
                "notes": "سطر أول\nsecond line",
                "passkeys": [passkey],
                "recovery": { "email": "me@example.com", "emailSource": { "kind": "identity", "itemId": IDENTITY_ID }, "backupCodes": [{ "code": "a1b2", "used": false }], "twoFactorMethod": "totp" },
                "customFields": [{ "label": "PIN", "value": "1234", "hidden": true }, { "label": "Branch", "value": "Amman", "hidden": false }],
                "passwordHistory": [{ "password": "old", "changedAt": "2025-12-01T00:00:00.000Z" }],
                "futureField": { "kept": true }
            }),
        ),
        item(
            IDENTITY_ID,
            "v1",
            json!({ "schemaVersion": 1, "title": "Me", "type": "identity", "subtitle": "layla@example.com" }),
            json!({ "schemaVersion": 1, "firstName": "ليلى", "lastName": "Haddad", "email": "layla@example.com", "phone": "+962 7 9000 0000", "address": { "line1": "1 Rainbow St", "line2": "Flat 2", "city": "Amman", "region": "JO-AM", "postalCode": "11181", "country": "JO" }, "birthDate": "1990-04-15", "notes": "Main identity" }),
        ),
        item(
            "0192f0c8-1c2d-7a00-8000-000000000003",
            "v2",
            json!({ "schemaVersion": 1, "title": "Visa", "type": "card", "subtitle": "•••• 1111" }),
            json!({ "schemaVersion": 1, "cardholder": "Layla Haddad", "number": "4111111111111111", "expiry": "04/29", "cvv": "123", "pin": "0000", "brand": "Visa", "notes": "Joint card" }),
        ),
        item(
            "0192f0c8-1c2d-7a00-8000-000000000004",
            "v2",
            json!({ "schemaVersion": 1, "title": "Wi-Fi", "type": "secureNote", "tags": ["home"] }),
            json!({ "schemaVersion": 1, "notes": "SSID: home\nKey: secret" }),
        ),
        item(
            "0192f0c8-1c2d-7a00-8000-000000000005",
            "v1",
            json!({ "schemaVersion": 1, "title": "Router", "type": "password" }),
            json!({ "schemaVersion": 1, "password": "router-pw" }),
        ),
        item(
            "0192f0c8-1c2d-7a00-8000-000000000006",
            "v1",
            json!({ "schemaVersion": 1, "title": "addy.io", "type": "maskedEmailProvider" }),
            json!({ "schemaVersion": 1, "provider": "addy", "token": "t0k" }),
        ),
        item(
            "0192f0c8-1c2d-7a00-8000-000000000007",
            "v1",
            json!({ "schemaVersion": 1, "title": "Car", "type": "vehicle" }),
            json!({ "schemaVersion": 3, "plate": "XYZ" }),
        ),
    ];
    if with_files {
        items.push(item(
            "0192f0c8-1c2d-7a00-8000-000000000008",
            "v2",
            json!({ "schemaVersion": 1, "title": "Lease", "type": "document" }),
            json!({ "schemaVersion": 1, "notes": "Signed copy", "attachments": [{ "id": FILE_ID, "name": "عقد.pdf", "type": "application/pdf", "size": 5 }] }),
        ));
    }
    ExportDocument::new(
        "2026-10-24T00:00:00.000Z".into(),
        vec![
            vault("v1", "Personal", "personal"),
            vault("v2", "Family", "family"),
        ],
        items,
    )
}

/// Exports `items` again the way the app would after importing them: same ids, vaults and dates.
fn re_export(original: &ExportDocument, items: &[Item]) -> String {
    let items = original
        .items
        .iter()
        .zip(items)
        .map(|(old, new)| {
            let value = serde_json::to_value(new).unwrap();
            ExportItem {
                overview: value["overview"].clone(),
                details: value["details"].clone(),
                ..old.clone()
            }
        })
        .collect();
    ExportDocument::new(original.exported_at.clone(), original.vaults.clone(), items).to_json()
}

#[test]
fn octa_pass_json_import_then_export_is_identical() {
    let original = document(false);
    let text = original.to_json();
    let result = import_file(
        ImportSource::OctaPass,
        text.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(result.items.len(), original.items.len());
    assert_eq!(result.skipped, 0);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(re_export(&original, &result.items), text);
    // Passkeys still sign after the trip.
    let ItemDetails::Login(login) = &result.items[0].details else {
        panic!()
    };
    let record = PasskeyRecord::from_item(&login.passkeys.as_ref().unwrap()[0]).unwrap();
    assert_eq!(record, passkey());
}

#[test]
fn plaintext_json_reports_files_it_cannot_have() {
    let text = document(true).to_json();
    let result = import_file(
        ImportSource::OctaPass,
        text.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert!(result.files.is_empty());
    assert_eq!(
        result.warnings,
        ["1 attached file aren't in this export: only the encrypted export includes them."]
    );
}

fn encrypted(document: &ExportDocument, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut writer = ArchiveWriter::new("export password", KdfParams::DEFAULT, &mut rng).unwrap();
    let mut out = writer.add_items(document.to_json().as_bytes()).unwrap();
    for (id, data) in files {
        out.extend(writer.add_file(id, data).unwrap());
    }
    out.extend(writer.finish().unwrap());
    out
}

fn password(text: &str) -> ImportOptions {
    ImportOptions {
        password: Some(text.to_owned().into()),
        ..ImportOptions::default()
    }
}

#[test]
fn encrypted_export_round_trips_with_its_files() {
    let original = document(true);
    let file = encrypted(&original, &[(FILE_ID, b"%PDF-")]);
    let (result, files) = import_octapass(&file, &password("export password")).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(result.files.len(), 1);
    let listed = &result.files[0];
    assert_eq!(result.items[listed.item].overview.title, "Lease");
    assert_eq!(
        (listed.file_id.as_str(), listed.name.as_str()),
        (FILE_ID, "عقد.pdf")
    );
    assert_eq!(
        (listed.media_type.as_str(), listed.size),
        ("application/pdf", 5)
    );
    assert_eq!(files[0].0, FILE_ID);
    assert_eq!(files[0].1.as_slice(), b"%PDF-");

    // Re-attached under the same id (as an upload would, with a new key), it exports the same.
    let mut items = result.items.clone();
    let ItemDetails::Document(lease) = &mut items[listed.item].details else {
        panic!()
    };
    lease.attachments = Some(vec![
        serde_json::from_value(json!({ "id": FILE_ID, "name": "عقد.pdf", "type": "application/pdf", "size": 5, "key": "new" }))
            .unwrap(),
    ]);
    assert_eq!(re_export(&original, &items), original.to_json());
}

#[test]
fn encrypted_export_errors() {
    let file = encrypted(&document(true), &[(FILE_ID, &[7; 100_000])]);
    let err = |options: &ImportOptions| {
        import_file(ImportSource::OctaPass, &file, options)
            .unwrap_err()
            .code
    };
    assert_eq!(
        err(&ImportOptions::default()),
        Error::ImportPasswordRequired
    );
    assert_eq!(err(&password("wrong")), Error::WrongImportPassword);
    let mut damaged = file.clone();
    let at = damaged.len() - 3;
    damaged[at] ^= 1;
    assert_eq!(
        import_file(
            ImportSource::OctaPass,
            &damaged,
            &password("export password")
        )
        .unwrap_err()
        .code,
        Error::InvalidImportFile
    );
    // A file listed but missing from the archive is reported, not invented.
    let missing = encrypted(&document(true), &[]);
    // (A file this small is one chunk: damage there reads as a wrong password, as it must.)
    let result = import_file(
        ImportSource::OctaPass,
        &missing,
        &password("export password"),
    )
    .unwrap();
    assert!(result.files.is_empty());
    assert_eq!(
        result.warnings,
        ["1 attached file is missing from the export file."]
    );
    assert_eq!(
        import_file(
            ImportSource::OctaPass,
            b"{\"format\":\"other\"}",
            &ImportOptions::default()
        )
        .unwrap_err()
        .code,
        Error::InvalidImportFile
    );
}

#[test]
fn recovery_links_follow_the_new_ids() {
    let text = document(false).to_json();
    let mut result = import_file(
        ImportSource::OctaPass,
        text.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(result.source_ids[1], IDENTITY_ID);
    let new_ids: Vec<String> = (0..result.items.len())
        .map(|i| format!("new-{i}"))
        .collect();
    relink(&mut result.items, &result.source_ids, &new_ids);
    let ItemDetails::Login(login) = &result.items[0].details else {
        panic!()
    };
    let source = login
        .recovery
        .as_ref()
        .unwrap()
        .email_source
        .as_ref()
        .unwrap();
    assert_eq!(source.item_id.as_deref(), Some("new-1"));
}

// ---------- CXF ----------

fn account() -> CxfAccount {
    CxfAccount {
        id: "0192f0c8-1c2d-7a00-8000-0000000000ff".into(),
        username: "layla".into(),
        email: "layla@example.com".into(),
    }
}

fn import_cxf(bytes: &[u8]) -> ImportResult {
    let result = import_file(ImportSource::Cxf, bytes, &ImportOptions::default()).unwrap();
    for item in &result.items {
        assert_eq!(&Item::from_json(&item.to_json()).unwrap(), item);
    }
    result
}

fn login(item: &Item) -> &LoginDetails {
    match &item.details {
        ItemDetails::Login(details) => details,
        other => panic!("{} is not a login: {other:?}", item.overview.title),
    }
}

#[test]
fn cxf_export_follows_the_spec() {
    let export = cxf::export(
        &document(true),
        &account(),
        "octap.app",
        1_792_800_000,
    );
    let header: Value = serde_json::from_str(&export.json).unwrap();
    assert_eq!(header["version"], json!({ "major": 1, "minor": 0 }));
    assert_eq!(header["exporterRpId"], "octap.app");
    assert_eq!(header["exporterDisplayName"], "Octa Pass");
    assert_eq!(header["timestamp"], 1_792_800_000);
    let account = &header["accounts"][0];
    assert_eq!(account["email"], "layla@example.com");
    // Two vaults: one collection each.
    let collections: Vec<&str> = account["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    assert_eq!(collections, ["Personal", "Family"]);
    // The masked email connection and the unknown type stay out.
    assert_eq!(export.exported, 6);
    assert_eq!(export.skipped, 1);
    let bank = &account["items"][0];
    assert_eq!(bank["creationAt"], 1_767_323_045);
    assert_eq!(bank["favorite"], true);
    assert_eq!(
        bank["scope"],
        json!({ "urls": ["https://example.com/login"], "androidApps": [{ "bundleId": "com.example.bank" }] })
    );
    let kinds: Vec<&str> = bank["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["basic-auth", "totp", "passkey", "note", "custom-fields"]
    );
    assert_eq!(
        bank["credentials"][1],
        json!({ "type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 60, "digits": 8, "algorithm": "sha256", "username": "layla", "issuer": "Example" })
    );
    assert_eq!(
        bank["credentials"][0]["password"],
        json!({ "fieldType": "concealed-string", "value": " p,\"w\"\n " })
    );
    let card = &account["items"][2]["credentials"][0];
    assert_eq!(
        card["expiryDate"],
        json!({ "fieldType": "year-month", "value": "2029-04" })
    );
    assert_eq!(
        export.warnings,
        [
            "1 item had password history, which CXF can't hold.",
            "1 item had recovery info, which CXF can't hold.",
            "1 item had attached files, which aren't in a CXF file.",
            "1 item of a type CXF doesn't have weren't exported.",
            "The Octa Pass export keeps all of it."
        ]
    );
}

#[test]
fn cxf_for_another_app_holds_only_what_it_asked_for() {
    let types = ["basic-auth".to_owned(), "passkey".to_owned()];
    let export = cxf::export_for_app(&document(true), &account(), "octap.app", 0, &types);
    let header: Value = serde_json::from_str(&export.json).unwrap();
    let account = &header["accounts"][0];
    let items = account["items"].as_array().unwrap();
    assert_eq!(export.exported, items.len());
    assert!(export.exported > 0 && export.exported < 6);
    // Only the unknown type counts as skipped: the rest wasn't asked for.
    assert_eq!(export.skipped, 1);
    for item in items {
        for credential in item["credentials"].as_array().unwrap() {
            assert!(
                types
                    .iter()
                    .any(|t| t == credential["type"].as_str().unwrap())
            );
        }
    }
    let kinds: Vec<&str> = items[0]["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["basic-auth", "passkey"]);
    // Collections link only the items that are there.
    for collection in account["collections"].as_array().unwrap() {
        for linked in collection["items"].as_array().unwrap() {
            assert!(items.iter().any(|item| item["id"] == linked["item"]));
        }
    }
}

#[test]
fn cxf_round_trip_keeps_what_cxf_holds() {
    let original = document(false);
    let export = cxf::export(&original, &account(), "octap.app", 0);
    let result = import_cxf(export.json.as_bytes());
    let types: Vec<&ItemType> = result.items.iter().map(|i| &i.overview.item_type).collect();
    assert_eq!(
        types,
        // CXF has no password-only type: a Password comes back as a Login with the same fields.
        [
            &ItemType::Login,
            &ItemType::Identity,
            &ItemType::Card,
            &ItemType::SecureNote,
            &ItemType::Login
        ]
    );
    let source = |index: usize| {
        Item::from_json(
            &json!({ "overview": original.items[index].overview, "details": original.items[index].details })
                .to_string(),
        )
        .unwrap()
    };

    let (bank, before) = (&result.items[0], source(0));
    assert_eq!(bank.overview.title, before.overview.title);
    assert_eq!(bank.overview.urls, before.overview.urls);
    assert_eq!(bank.overview.favorite, Some(true));
    let mut tags = before.overview.tags.clone().unwrap();
    tags.push("Personal".into());
    assert_eq!(bank.overview.tags, Some(tags), "vaults come back as tags");
    let (got, want) = (login(bank), login(&before));
    assert_eq!(got.username, want.username);
    assert_eq!(got.password, want.password);
    assert_eq!(got.notes, want.notes);
    assert_eq!(got.custom_fields, want.custom_fields);
    assert_eq!(
        got.totp.as_deref(),
        Some(
            "otpauth://totp/Example:layla?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60&issuer=Example"
        )
    );
    let record = PasskeyRecord::from_item(&got.passkeys.as_ref().unwrap()[0]).unwrap();
    let mut original_passkey = passkey();
    original_passkey.created_at = "2026-01-02T03:04:05Z".into();
    assert_eq!(record, original_passkey);
    let request: RequestOptions = serde_json::from_value(json!({ "challenge": "AAAA" })).unwrap();
    let caller = ClientData::Web(
        serde_json::from_value::<Caller>(json!({ "origin": "https://example.com" })).unwrap(),
    );
    assert!(passkey::get(&request, &caller, &record).is_ok());

    // Identities, cards, notes and passwords come back field for field.
    for index in [1, 2, 3, 4] {
        let before = source(index);
        let after = &result.items[index];
        assert_eq!(after.overview.title, before.overview.title);
        assert_eq!(after.details, before.details, "{}", before.overview.title);
    }
}

#[test]
fn cxf_round_trip_keeps_imported_dates() {
    let mut original = document(false);
    original.items[2].overview["createdAt"] = json!("2019-05-06T07:08:09Z");
    original.items[2].overview["updatedAt"] = json!("2020-05-06T07:08:09Z");
    let export = cxf::export(&original, &account(), "octap.app", 0);
    let result = import_cxf(export.json.as_bytes());
    let card = &result.items[2].overview;
    assert_eq!(card.created_at.as_deref(), Some("2019-05-06T07:08:09Z"));
    assert_eq!(card.updated_at.as_deref(), Some("2020-05-06T07:08:09Z"));
    // Items without their own dates carry the sync record's.
    assert_eq!(
        result.items[1].overview.created_at.as_deref(),
        Some("2026-01-02T03:04:05Z")
    );
    assert!(
        card.imported_from
            .as_ref()
            .is_some_and(|from| from.source == "cxf")
    );
}

#[test]
fn cxf_spec_example() {
    let result = import_cxf(&fixture("cxf-spec-example.json"));
    let github = &result.items[0].overview;
    assert_eq!(github.created_at.as_deref(), Some("2024-01-13T10:40:00Z"));
    assert_eq!(github.updated_at.as_deref(), Some("2024-01-14T10:40:00Z"));
    assert_eq!(
        github.imported_from.as_ref().unwrap().id,
        "9OF-QjVDQo2Wp2xWPw6ZhA"
    );
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(
        titles,
        [
            "GitHub Login",
            "WebAuthn.io",
            "Visa Credit Card",
            "Wifi",
            "Home alarm",
            "Driver License",
            "House Address",
            "SSH Key",
            "ID card",
            "Passport",
            "John Doe",
            "API key",
            "Generated Password"
        ]
    );
    let github = login(&result.items[0]);
    assert_eq!(github.username.as_deref(), Some("johndoe"));
    assert_eq!(github.password.as_deref(), Some("securepassword123"));
    assert_eq!(
        github.totp.as_deref(),
        Some(
            "otpauth://totp/GitHub:jane.smith@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&issuer=GitHub"
        )
    );
    assert_eq!(
        result.items[0].overview.urls.as_ref().unwrap(),
        &["https://github.com"]
    );
    assert_eq!(
        result.items[0].overview.tags.as_ref().unwrap(),
        &["development", "git", "work", "Work Accounts"],
        "the item's tags, then its collection"
    );

    // The spec's passkey is a real P-256 key: it imports, with its extensions kept, and signs.
    let webauthn = login(&result.items[1]);
    assert_eq!(webauthn.username.as_deref(), Some("johndoe"));
    let record = PasskeyRecord::from_item(&webauthn.passkeys.as_ref().unwrap()[0]).unwrap();
    assert_eq!(record.rp_id, "webauthn.io");
    assert_eq!(record.created_at, "2024-01-13T10:40:00Z");
    assert!(record.extra["fido2Extensions"]["credBlob"].is_string());

    let ItemDetails::Card(visa) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(visa.number.as_deref(), Some("4111111111111111"));
    assert_eq!(visa.expiry.as_deref(), Some("08/27"));
    assert_eq!(
        (visa.cvv.as_deref(), visa.pin.as_deref()),
        (Some("123"), Some("0000"))
    );
    assert_eq!(visa.brand.as_deref(), Some("Visa"));
    assert_eq!(visa.notes.as_deref(), Some("Valid from: 2024-02"));

    let ItemDetails::SecureNote(wifi) = &result.items[3].details else {
        panic!()
    };
    assert!(
        wifi.notes
            .starts_with("Network: Home_Network\nPassword: mypassword123")
    );

    let ItemDetails::Identity(address) = &result.items[6].details else {
        panic!()
    };
    let lines = address.address.as_ref().unwrap();
    assert_eq!(lines.line1.as_deref(), Some("123 Main Street"));
    assert_eq!(lines.region.as_deref(), Some("US-CA"));
    assert_eq!(address.phone.as_deref(), Some("+1-555-123-4567"));

    // The spec's RSA key comes across as an SSH key, its dates in the notes.
    let ItemDetails::SshKey(ssh) = &result.items[7].details else {
        panic!()
    };
    assert_eq!(ssh.key_type.as_deref(), Some("ssh-rsa"));
    assert_eq!(ssh.comment.as_deref(), Some("Work SSH Key"));
    assert!(
        ssh.private_key
            .as_deref()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert!(ssh.fingerprint.as_deref().unwrap().starts_with("SHA256:"));
    assert!(
        ssh.notes
            .as_deref()
            .unwrap()
            .contains("Created: 2023-01-01")
    );

    // "ID card" twice: the file one can't come across, the identity document can.
    let ItemDetails::IdDocument(id_card) = &result.items[8].details else {
        panic!()
    };
    assert_eq!(id_card.document_type.as_deref(), Some("nationalId"));
    assert_eq!(id_card.birth_date.as_deref(), Some("1990-04-15"));
    assert_eq!(id_card.full_name.as_deref(), Some("Jane Doe"));
    assert_eq!(id_card.number.as_deref(), Some("123456789"));
    let ItemDetails::IdDocument(passport) = &result.items[9].details else {
        panic!()
    };
    assert_eq!(passport.document_type.as_deref(), Some("passport"));
    let ItemDetails::IdDocument(license) = &result.items[5].details else {
        panic!()
    };
    assert_eq!(license.document_type.as_deref(), Some("driverLicense"));

    let ItemDetails::Identity(name) = &result.items[10].details else {
        panic!()
    };
    assert_eq!(name.first_name.as_deref(), Some("John"));
    assert_eq!(name.last_name.as_deref(), Some("van Doe Smith"));

    let ItemDetails::ApiCredential(api) = &result.items[11].details else {
        panic!()
    };
    assert_eq!(
        api.key.as_deref(),
        Some("AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk")
    );
    assert_eq!(api.host.as_deref(), Some("https://api.example.com"));
    assert_eq!(result.items[12].overview.item_type, ItemType::Password);

    assert_eq!(result.skipped, 1, "the file-only item");
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("1 attached file couldn't be imported"))
    );
}

#[test]
fn cxf_from_dashlane() {
    let result = import_cxf(&fixture("cxf-dashlane.json"));
    let types: Vec<&ItemType> = result.items.iter().map(|i| &i.overview.item_type).collect();
    assert_eq!(types.len(), 12);
    let ItemDetails::Card(card) = &result.items[0].details else {
        panic!()
    };
    assert_eq!(
        result.items[0].overview.title, "Dashlane CC",
        "an empty title falls back to the cardholder"
    );
    assert_eq!(card.expiry.as_deref(), Some("10/28"));
    let adobe = login(&result.items[1]);
    assert_eq!(adobe.username.as_deref(), Some("dashlane@dashlane.com"));
    assert!(
        adobe
            .totp
            .as_deref()
            .unwrap()
            .contains("secret=JBSWY3DPEHPK3PXP")
    );
    assert_eq!(
        result.items[1].overview.urls.as_ref().unwrap(),
        &["https://adobe.com"]
    );
    assert_eq!(*types[2], ItemType::SecureNote);
    let person = result
        .items
        .iter()
        .find_map(|item| match &item.details {
            ItemDetails::Identity(person) if person.first_name.is_some() => Some(person),
            _ => None,
        })
        .unwrap();
    assert_eq!(person.first_name.as_deref(), Some("Dashlane Person"));
}

#[test]
fn cxf_from_1password() {
    let result = import_cxf(&fixture("cxf-1password.json"));
    assert_eq!(result.items.len(), 10);
    let facebook = result
        .items
        .iter()
        .find(|i| i.overview.title == "Facebook")
        .unwrap();
    let details = login(facebook);
    assert_eq!(details.username.as_deref(), Some("johndoe"));
    // 1Password keeps the one-time code as a custom field.
    assert!(
        details
            .totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    // Its many empty custom fields aren't imported.
    assert!(
        details
            .custom_fields
            .iter()
            .flatten()
            .all(|f| !f.value.is_empty())
    );
    let card = result
        .items
        .iter()
        .find(|i| i.overview.item_type == ItemType::Card)
        .unwrap();
    assert_eq!(card.overview.title, "Personal Credit Card");
}

#[test]
fn cxf_refuses_other_files_and_newer_versions() {
    let err = |text: &str| {
        import_file(
            ImportSource::Cxf,
            text.as_bytes(),
            &ImportOptions::default(),
        )
        .unwrap_err()
        .code
    };
    assert_eq!(err("{\"items\": 5}"), Error::InvalidImportFile);
    assert_eq!(err("[]"), Error::InvalidImportFile);
    assert_eq!(
        err(
            r#"{"version":{"major":2,"minor":0},"exporterRpId":"x","exporterDisplayName":"x","timestamp":0,"accounts":[]}"#
        ),
        Error::UnsupportedImport
    );
}

/// What `ASExportedCredentialData` encodes to (iOS and macOS 26 Credential Exchange, the Passwords
/// app's "Export Data to Another App"): `JSONEncoder` with `.secondsSince1970`, as the apps send it.
#[test]
fn cxf_from_apple_credential_exchange() {
    let result = import_cxf(&fixture("cxf-apple-passwords.json"));
    let titles: Vec<&str> = result
        .items
        .iter()
        .map(|i| i.overview.title.as_str())
        .collect();
    assert_eq!(
        titles,
        ["GitHub", "example.com", "Visa", "Home Wi-Fi", "Router"]
    );
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);

    let github = login(&result.items[0]);
    assert_eq!(
        (github.username.as_deref(), github.password.as_deref()),
        (Some("ada"), Some("pw-ada"))
    );
    assert!(
        github
            .totp
            .as_deref()
            .unwrap()
            .contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    );
    assert_eq!(
        result.items[0].overview.urls.as_ref().unwrap(),
        &["https://github.com"]
    );

    let record =
        PasskeyRecord::from_item(&login(&result.items[1]).passkeys.as_ref().unwrap()[0]).unwrap();
    assert_eq!(
        (record.rp_id.as_str(), record.created_at.as_str()),
        ("example.com", "2025-10-24T00:00:00Z")
    );

    let ItemDetails::Card(visa) = &result.items[2].details else {
        panic!()
    };
    assert_eq!(
        (visa.number.as_deref(), visa.expiry.as_deref()),
        (Some("4111111111111111"), Some("07/30"))
    );
    assert_eq!(result.items[4].overview.item_type, ItemType::SecureNote);
}

/// A real export from the Passwords app: `JSONEncoder` with `.secondsSince1970` writes a `Date` as a
/// `Double`, so the export's time and the items' dates carry fractions of a second. CXF dates are
/// whole seconds; the fraction is dropped.
#[test]
fn cxf_from_apple_with_fractional_dates() {
    let text = String::from_utf8(fixture("cxf-apple-passwords.json")).unwrap();
    let fractional = text
        .replace(
            "\"timestamp\" : 1761264000",
            "\"timestamp\" : 1761264000.734",
        )
        .replace(
            "\"creationAt\" : 1761264000",
            "\"creationAt\" : 1761264000.25",
        )
        .replace(
            "\"modifiedAt\" : 1761264000",
            "\"modifiedAt\" : 1761264000.999",
        );
    assert!(fractional.contains("1761264000.734") && fractional.contains("1761264000.25"));
    let result = import_cxf(fractional.as_bytes());
    assert_eq!(result.items.len(), 5);
    assert_eq!(result.items[0].overview.title, "GitHub");
    let record =
        PasskeyRecord::from_item(&login(&result.items[1]).passkeys.as_ref().unwrap()[0]).unwrap();
    assert_eq!(record.created_at, "2025-10-24T00:00:00Z");
    assert_eq!(
        result.items[0].overview.created_at.as_deref(),
        Some("2025-10-24T00:00:00Z")
    );
    assert_eq!(
        result.items[0].overview.updated_at.as_deref(),
        Some("2025-10-24T00:00:00Z")
    );

    // Not a date at all is still refused.
    let broken = text.replace("\"timestamp\" : 1761264000", "\"timestamp\" : \"soon\"");
    assert!(
        import_file(
            ImportSource::Cxf,
            broken.as_bytes(),
            &ImportOptions::default()
        )
        .is_err()
    );
}

#[test]
fn ssh_keys_round_trip_through_octa_pass_and_cxf() {
    use octapass_core::tools::ssh::{self, SshKeyKind};
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    let ed25519 = ssh::generate(SshKeyKind::Ed25519, "layla@laptop", &mut rng).unwrap();
    let p256 = ssh::generate(SshKeyKind::EcdsaP256, "", &mut rng).unwrap();
    let dsa = ssh::read_private_key(
        &String::from_utf8(
            std::fs::read(format!(
                "{}/tests/ssh-fixtures/dsa",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    let key_item = |id: &str, title: &str, key: &ssh::SshKey, extra: Value| {
        let mut details = json!({
            "schemaVersion": 1, "privateKey": key.private_key.as_str(), "publicKey": key.info.public_key,
            "keyType": key.info.key_type, "fingerprint": key.info.fingerprint,
        });
        if !key.info.comment.is_empty() {
            details["comment"] = key.info.comment.clone().into();
        }
        details
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        item(
            id,
            "0192f0c8-1c2d-7a00-8000-000000000001",
            json!({ "schemaVersion": 1, "title": title, "type": "sshKey", "subtitle": key.info.fingerprint }),
            details,
        )
    };
    let original = ExportDocument::new(
        "2026-10-25T00:00:00.000Z".into(),
        vec![vault(
            "0192f0c8-1c2d-7a00-8000-000000000001",
            "Personal",
            "personal",
        )],
        vec![
            key_item(
                "0192f0c8-1c2d-7a00-8000-000000000101",
                "GitHub",
                &ed25519,
                json!({ "passphrase": "on disk", "notes": "deploy key", "customFields": [{ "label": "Host", "value": "github.com", "hidden": false }] }),
            ),
            key_item(
                "0192f0c8-1c2d-7a00-8000-000000000102",
                "Server",
                &p256,
                json!({}),
            ),
            key_item(
                "0192f0c8-1c2d-7a00-8000-000000000103",
                "Old router",
                &dsa,
                json!({}),
            ),
        ],
    );

    // The Octa Pass export keeps every field.
    let text = original.to_json();
    let result = import_file(
        ImportSource::OctaPass,
        text.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert!(
        result
            .items
            .iter()
            .all(|i| i.overview.item_type == ItemType::SshKey)
    );
    assert_eq!(re_export(&original, &result.items), text);

    // CXF holds the usable keys, with the passphrase as a custom field.
    let export = cxf::export(&original, &account(), "octap.app", 0);
    assert_eq!((export.exported, export.skipped), (2, 1));
    assert!(
        export
            .warnings
            .iter()
            .any(|w| w.contains("1 SSH key of a kind CXF can't hold")),
        "{:?}",
        export.warnings
    );
    let json: Value = serde_json::from_str(&export.json).unwrap();
    let credential = &json["accounts"][0]["items"][0]["credentials"][0];
    assert_eq!(credential["type"], "ssh-key");
    assert_eq!(credential["keyType"], "ssh-ed25519");
    assert_eq!(credential["keyComment"], "layla@laptop");

    let result = import_cxf(export.json.as_bytes());
    assert_eq!(result.items.len(), 2);
    for (item, key) in result.items.iter().zip([&ed25519, &p256]) {
        let ItemDetails::SshKey(details) = &item.details else {
            panic!("{} is not an SSH key", item.overview.title)
        };
        assert_eq!(
            details.fingerprint.as_deref(),
            Some(key.info.fingerprint.as_str())
        );
        assert_eq!(
            item.overview.subtitle.as_deref(),
            Some(key.info.fingerprint.as_str())
        );
        assert_eq!(
            details.public_key.as_deref(),
            Some(key.info.public_key.as_str())
        );
        let read = ssh::read_private_key(details.private_key.as_deref().unwrap(), None).unwrap();
        assert_eq!(read.info.fingerprint, key.info.fingerprint);
    }
    let ItemDetails::SshKey(github) = &result.items[0].details else {
        panic!()
    };
    assert_eq!(github.comment.as_deref(), Some("layla@laptop"));
    assert_eq!(github.passphrase.as_deref(), Some("on disk"));
    assert_eq!(github.notes.as_deref(), Some("deploy key"));
    assert_eq!(github.custom_fields.as_ref().unwrap()[0].label, "Host");
}

/// One item of each type the field table and custom templates added.
fn typed_items() -> Vec<(&'static str, Value)> {
    vec![
        (
            "bankAccount",
            json!({ "schemaVersion": 1, "bankName": "Example Bank", "accountHolder": "Ada", "accountType": "savings", "iban": "DE89370400440532013000", "accountNumber": "0532013000", "routingNumber": "37040044", "swift": "COBADEFFXXX", "branch": "Main", "pin": " 0000 ", "notes": "joint", "customFields": [{ "label": "Online ID", "value": "x", "hidden": false }, { "label": "Word", "value": "y", "hidden": true }] }),
        ),
        (
            "apiCredential",
            json!({ "schemaVersion": 1, "credentialType": "bearerToken", "username": "ci", "key": "AKIA", "secret": "s3cret", "host": "api.example.com", "expiryDate": "2030-01-31", "notes": "n", "customFields": [{ "label": "Scope", "value": "read", "hidden": false }] }),
        ),
        (
            "softwareLicense",
            json!({ "schemaVersion": 1, "product": "Editor", "version": "4", "licenseKey": "AAAA-BBBB", "licensedTo": "Ada", "email": "a@example.com", "publisher": "Acme", "orderNumber": "42", "purchaseDate": "2026-01-01", "expiryDate": "2027-01-01" }),
        ),
        (
            "idDocument",
            json!({ "schemaVersion": 1, "documentType": "passport", "number": "X1234", "fullName": "Ada L", "birthDate": "1975-12-10", "issuer": "Ministry", "country": "JO", "issueDate": "2020-01-01", "expiryDate": "2030-01-01", "notes": "n", "customFields": [{ "label": "Class", "value": "B", "hidden": false }] }),
        ),
        (
            "idDocument",
            json!({ "schemaVersion": 1, "documentType": "other", "number": "T1", "fullName": "Ada L" }),
        ),
        (
            "cryptoWallet",
            json!({ "schemaVersion": 1, "walletName": "Hardware", "seedPhrase": "legal winner thank year", "passphrase": "p", "addresses": [{ "network": "bitcoin", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "label": "Savings" }, { "network": "ethereum", "address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359" }], "notes": "n" }),
        ),
        (
            "database",
            json!({ "schemaVersion": 1, "databaseType": "postgresql", "host": "db.example.com", "port": "5432", "database": "shop", "username": "app", "password": "pw", "connectionString": "postgres://app:pw@db/shop", "notes": "n", "customFields": [{ "label": "SID", "value": "x", "hidden": false }] }),
        ),
        (
            "custom",
            json!({ "schemaVersion": 1, "templateName": "Library card", "fields": [{ "label": "Member", "value": "42", "kind": "text" }, { "label": "PIN", "value": "1", "kind": "hidden" }, { "label": "Code", "value": "JBSWY3DPEHPK3PXP", "kind": "totp" }, { "label": "Blank", "value": "", "kind": "date" }], "notes": "n" }),
        ),
        (
            "custom",
            json!({ "schemaVersion": 1, "fields": [{ "label": "Plain", "value": "v", "kind": "text" }] }),
        ),
    ]
}

fn typed_document() -> ExportDocument {
    let mut document = document(false);
    document.items = typed_items()
        .into_iter()
        .enumerate()
        .map(|(i, (kind, details))| {
            item(
                &format!("0192f0c8-1c2d-7a00-8000-0000000001{i:02x}"),
                "v1",
                json!({ "schemaVersion": 1, "title": format!("{kind} {i}"), "type": kind }),
                details,
            )
        })
        .collect();
    document.items.push(item(
        "0192f0c8-1c2d-7a00-8000-0000000001ff",
        "v1",
        json!({ "schemaVersion": 1, "title": "Library card", "type": "customTemplate" }),
        json!({ "schemaVersion": 1, "fields": [{ "label": "Member", "kind": "text" }, { "label": "PIN", "kind": "hidden" }] }),
    ));
    document
}

#[test]
fn new_item_types_round_trip_through_the_octa_pass_exports() {
    let original = typed_document();
    let text = original.to_json();
    let result = import_file(
        ImportSource::OctaPass,
        text.as_bytes(),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(result.items.len(), original.items.len());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(re_export(&original, &result.items), text);

    let file = encrypted(&original, &[]);
    let (imported, _) = import_octapass(&file, &password("export password")).unwrap();
    assert_eq!(re_export(&original, &imported.items), text);
}

#[test]
fn new_item_types_round_trip_through_cxf() {
    let original = typed_document();
    let export = cxf::export(&original, &account(), "octap.app", 0);
    assert!(export.warnings.is_empty(), "{:?}", export.warnings);
    assert_eq!(export.skipped, 0);
    let result = import_cxf(export.json.as_bytes());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let expected = typed_items();
    // Templates hold no credentials, so they stay out.
    assert_eq!(result.items.len(), expected.len());
    for (item, (kind, details)) in result.items.iter().zip(expected) {
        assert_eq!(String::from(item.overview.item_type.clone()), kind);
        assert_eq!(
            serde_json::to_value(&item.details).unwrap(),
            details,
            "{kind}"
        );
    }
}

#[test]
fn cxf_never_reads_a_seed_phrase_into_the_list() {
    let export = cxf::export(&typed_document(), &account(), "octap.app", 0);
    let result = import_cxf(export.json.as_bytes());
    let wallet = result
        .items
        .iter()
        .find(|item| item.overview.item_type == ItemType::CryptoWallet)
        .unwrap();
    assert_eq!(wallet.overview.subtitle.as_deref(), Some("Hardware"));
}

#[test]
fn cxf_other_extensions_are_ignored() {
    let file = json!({
        "version": { "major": 1, "minor": 0 }, "exporterRpId": "x.example", "exporterDisplayName": "X", "timestamp": 1,
        "accounts": [{ "id": "AQ", "username": "", "email": "", "collections": [], "items": [{
            "id": "AQ", "title": "Loyalty", "credentials": [{
                "type": "custom-fields", "extensions": [{ "name": "other.example/thing", "itemType": "bankAccount" }],
                "fields": [{ "fieldType": "string", "value": "42", "label": "Member" }]
            }, {
                "type": "custom-fields", "extensions": [{ "name": cxf::ITEM_TYPE_EXTENSION, "itemType": "vehicle" }],
                "fields": [{ "fieldType": "string", "value": "XYZ", "label": "Plate" }]
            }]
        }] }]
    });
    let result = import_cxf(file.to_string().as_bytes());
    let ItemDetails::SecureNote(note) = &result.items[0].details else {
        panic!("{:?}", result.items)
    };
    assert_eq!(note.notes, "Member: 42\nPlate: XYZ");
}

#[test]
fn cxf_documents_with_a_person_and_extra_members() {
    let file = json!({
        "version": { "major": 1, "minor": 0 }, "exporterRpId": "x.example", "exporterDisplayName": "X", "timestamp": 1,
        "accounts": [{ "id": "AQ", "username": "", "email": "", "collections": [], "items": [{
            "id": "AQ", "title": "Me", "credentials": [
                { "type": "person-name", "given": { "fieldType": "string", "value": "Ada" } },
                { "type": "drivers-license",
                  "licenseNumber": { "fieldType": "concealed-string", "value": "D1" },
                  "licenseClass": { "fieldType": "string", "value": "B" },
                  "country": { "fieldType": "country-code", "value": "JO" },
                  "expiryDate": { "fieldType": "date", "value": "2030-02-01" },
                  "issueDate": { "fieldType": "year-month", "value": "2020-02" },
                  "somethingNew": { "fieldType": "string", "value": "kept" } }
            ]
        }] }]
    });
    let result = import_cxf(file.to_string().as_bytes());
    assert_eq!(result.items.len(), 2);
    let ItemDetails::IdDocument(license) = &result.items[0].details else {
        panic!()
    };
    assert_eq!(license.document_type.as_deref(), Some("driverLicense"));
    assert_eq!(license.number.as_deref(), Some("D1"));
    assert_eq!(license.expiry_date.as_deref(), Some("2030-02-01"));
    let kept: Vec<_> = license
        .custom_fields
        .iter()
        .flatten()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.hidden))
        .collect();
    assert_eq!(
        kept,
        [
            ("Issue date", "2020-02", false),
            ("Country", "JO", false),
            ("Class", "B", false),
            ("Something new", "kept", true)
        ]
    );
    assert_eq!(result.items[1].overview.item_type, ItemType::Identity);
}
