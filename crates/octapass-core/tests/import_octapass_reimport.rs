//! Importing an Octa Pass export into a vault that already holds its items: nothing is copied
//! again. Items match by their id (in any vault), else as duplicates in the target vault; the newer
//! version wins; recovery links and attached files follow the matches.

use octapass_core::export::{ArchiveWriter, ExportDocument, ExportItem, ExportVault};
use octapass_core::import::{
    ExistingItem, ImportOptions, ImportResult, ImportSource, import_file, import_octapass, relink,
};
use octapass_core::item::Item;
use octapass_core::kdf::KdfParams;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Map, Value, json};

const LOGIN: &str = "0192f0c8-1c2d-7a00-8000-000000000001";
const IDENTITY: &str = "0192f0c8-1c2d-7a00-8000-000000000002";
const LEASE: &str = "0192f0c8-1c2d-7a00-8000-000000000003";
const FILE: &str = "0192f0c8-1c2d-7a00-8000-0000000000cc";
const EXPORTED: &str = "2026-03-01T10:00:00.000Z";

fn login(password: &str) -> (Value, Value) {
    (
        json!({ "schemaVersion": 1, "title": "GitHub", "type": "login", "urls": ["https://github.com/login"], "subtitle": "octocat" }),
        json!({
            "schemaVersion": 1, "username": "octocat", "password": password,
            "recovery": { "email": "me@example.com", "emailSource": { "kind": "identity", "itemId": IDENTITY } }
        }),
    )
}

fn identity() -> (Value, Value) {
    (
        json!({ "schemaVersion": 1, "title": "Me", "type": "identity" }),
        json!({ "schemaVersion": 1, "firstName": "Layla", "email": "me@example.com" }),
    )
}

fn lease(attachments: Value) -> (Value, Value) {
    (
        json!({ "schemaVersion": 1, "title": "Lease", "type": "document" }),
        json!({ "schemaVersion": 1, "notes": "Signed copy", "attachments": attachments }),
    )
}

fn listed_file() -> Value {
    json!([{ "id": FILE, "name": "lease.pdf", "type": "application/pdf", "size": 5 }])
}

fn export(items: &[(&str, (Value, Value))]) -> ExportDocument {
    ExportDocument::new(
        EXPORTED.into(),
        vec![ExportVault {
            id: "personal".into(),
            name: "Personal".into(),
            vault_type: "personal".into(),
            extra: Map::new(),
        }],
        items
            .iter()
            .map(|(id, (overview, details))| ExportItem {
                id: (*id).into(),
                vault_id: "personal".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                updated_at: EXPORTED.into(),
                overview: overview.clone(),
                details: details.clone(),
            })
            .collect(),
    )
}

/// An item in the vault: `id` in `vault`, last changed at `updated`.
fn stored(
    id: &str,
    vault: &str,
    updated: &str,
    (overview, details): (Value, Value),
) -> ExistingItem {
    ExistingItem {
        id: id.into(),
        overview: serde_json::from_value(overview).unwrap(),
        details,
        vault_id: Some(vault.into()),
        updated_at: Some(updated.into()),
    }
}

fn into_personal(existing: Vec<ExistingItem>) -> ImportOptions {
    ImportOptions {
        existing_items: existing,
        vault_id: Some("personal".into()),
        now: Some("2026-11-04T00:00:00Z".into()),
        ..ImportOptions::default()
    }
}

fn json_import(document: &ExportDocument, options: &ImportOptions) -> ImportResult {
    import_file(
        ImportSource::OctaPass,
        document.to_json().as_bytes(),
        options,
    )
    .unwrap()
}

fn details(item: &Item) -> Value {
    serde_json::to_value(item).unwrap()["details"].clone()
}

#[test]
fn the_same_export_again_adds_nothing() {
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let vault = vec![
        stored(LOGIN, "personal", EXPORTED, login("pw-1")),
        stored(IDENTITY, "personal", EXPORTED, identity()),
    ];
    let result = json_import(&document, &into_personal(vault));
    assert!(result.items.is_empty(), "{:?}", result.items);
    assert!(result.updates.is_empty());
    assert_eq!(result.unchanged, 2);
    assert!(result.source_ids.is_empty());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
}

#[test]
fn an_empty_vault_gets_every_item_as_before() {
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let result = json_import(&document, &into_personal(Vec::new()));
    assert_eq!(result.items.len(), 2);
    assert_eq!(result.source_ids, [LOGIN, IDENTITY]);
    assert_eq!(result.unchanged, 0);
}

#[test]
fn a_newer_export_updates_the_item_and_keeps_the_old_password() {
    let document = export(&[(LOGIN, login("pw-2"))]);
    let vault = vec![stored(
        LOGIN,
        "personal",
        "2026-02-01T00:00:00Z",
        login("pw-1"),
    )];
    let result = json_import(&document, &into_personal(vault));
    assert!(result.items.is_empty());
    assert_eq!(result.updates.len(), 1);
    assert_eq!(result.updates[0].item_id, LOGIN);
    let details = details(&result.updates[0].item);
    assert_eq!(details["password"], "pw-2");
    assert_eq!(details["passwordHistory"][0]["password"], "pw-1");
}

#[test]
fn an_item_changed_in_the_vault_after_the_export_is_kept() {
    let document = export(&[(LOGIN, login("pw-1"))]);
    // Changed in the vault (a new password) the day after the export was made.
    let vault = vec![stored(
        LOGIN,
        "personal",
        "2026-03-02T00:00:00Z",
        login("pw-2"),
    )];
    let result = json_import(&document, &into_personal(vault));
    assert!(result.items.is_empty());
    assert!(result.updates.is_empty());
    assert_eq!(result.unchanged, 1);
    assert_eq!(
        result.warnings,
        [
            "1 item changed in the vault after this export was made, so the vault's version was kept."
        ]
    );
}

#[test]
fn a_deleted_item_comes_back_linked_to_the_vault_item() {
    // The identity is still in the vault; the login was deleted.
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let vault = vec![stored(IDENTITY, "personal", EXPORTED, identity())];
    let result = json_import(&document, &into_personal(vault));
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.source_ids, [LOGIN]);
    assert_eq!(result.unchanged, 1);
    assert_eq!(
        details(&result.items[0])["recovery"]["emailSource"]["itemId"],
        IDENTITY
    );
}

#[test]
fn another_account_recognises_the_items_it_imported_before() {
    // The first import gave the items new ids; the second finds them as duplicates.
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let first = json_import(&document, &into_personal(Vec::new()));
    let mut items = first.items.clone();
    let new_ids = ["new-login".to_owned(), "new-identity".to_owned()];
    relink(&mut items, &first.source_ids, &new_ids);
    let vault = items
        .iter()
        .zip(&new_ids)
        .map(|(item, id)| {
            let value = serde_json::to_value(item).unwrap();
            stored(
                id,
                "personal",
                "2026-11-04T00:00:00Z",
                (value["overview"].clone(), value["details"].clone()),
            )
        })
        .collect();
    let again = json_import(&document, &into_personal(vault));
    assert!(again.items.is_empty(), "{:?}", again.items);
    assert!(again.updates.is_empty(), "{:?}", again.updates);
    assert_eq!(again.unchanged, 2);
    assert!(again.warnings.is_empty(), "{:?}", again.warnings);
}

#[test]
fn a_new_item_links_to_the_duplicate_the_vault_already_has() {
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let vault = vec![stored("their-identity", "personal", EXPORTED, identity())];
    let result = json_import(&document, &into_personal(vault));
    assert_eq!(result.items.len(), 1);
    assert_eq!(
        details(&result.items[0])["recovery"]["emailSource"]["itemId"],
        "their-identity"
    );
}

#[test]
fn items_in_other_vaults_match_by_id_only() {
    // An export holds every vault and an import goes into one: the family vault's item is found
    // by its id, but a look-alike in another vault isn't taken for a duplicate.
    let document = export(&[(LOGIN, login("pw-1")), (IDENTITY, identity())]);
    let vault = vec![
        stored(LOGIN, "family", EXPORTED, login("pw-1")),
        stored("their-identity", "work", EXPORTED, identity()),
    ];
    let result = json_import(&document, &into_personal(vault));
    assert_eq!(result.unchanged, 1);
    assert_eq!(result.source_ids, [IDENTITY]);
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

fn with_password(mut options: ImportOptions) -> ImportOptions {
    options.password = Some("export password".to_owned().into());
    options
}

#[test]
fn files_go_to_the_vault_item_only_when_it_lacks_them() {
    let document = export(&[(LEASE, lease(listed_file()))]);
    let file = encrypted(&document, &[(FILE, b"%PDF-")]);

    // The vault's item still has the file: nothing to bring back.
    let has_it = json!([{ "id": FILE, "name": "lease.pdf", "type": "application/pdf", "size": 5, "key": "AQ" }]);
    let vault = vec![stored(LEASE, "personal", EXPORTED, lease(has_it))];
    let (result, _) = import_octapass(&file, &with_password(into_personal(vault))).unwrap();
    assert_eq!(result.unchanged, 1);
    assert!(result.files.is_empty() && result.existing_files.is_empty());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);

    // The file was removed from the vault's item: it's attached to that item again.
    let vault = vec![stored(LEASE, "personal", EXPORTED, lease(json!([])))];
    let (result, files) = import_octapass(&file, &with_password(into_personal(vault))).unwrap();
    assert!(result.items.is_empty());
    assert_eq!(result.existing_files.len(), 1);
    assert_eq!(result.existing_files[0].item_id, LEASE);
    assert_eq!(result.existing_files[0].file_id, FILE);
    assert_eq!(files[0].1.as_slice(), b"%PDF-");

    // Kept because the vault's version is newer: its files stay as they are too.
    let vault = vec![stored(
        LEASE,
        "personal",
        "2026-04-01T00:00:00Z",
        lease(json!([])),
    )];
    let (result, _) = import_octapass(&file, &with_password(into_personal(vault))).unwrap();
    assert!(result.existing_files.is_empty());
    assert_eq!(result.unchanged, 1);
}

#[test]
fn the_plain_export_counts_only_files_it_would_have_brought_back() {
    let document = export(&[(LEASE, lease(listed_file()))]);
    let has_it = json!([{ "id": FILE, "name": "lease.pdf", "type": "application/pdf", "size": 5, "key": "AQ" }]);
    let vault = vec![stored(LEASE, "personal", EXPORTED, lease(has_it))];
    let result = json_import(&document, &into_personal(vault));
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
}
