//! Saving while locked (plan 03): the Autofill service seals a login into the store's save inbox,
//! and the app's next unlock merges it.

use std::sync::Arc;

use octapass_core::kdf::KdfParams;
use octapass_ffi::{DeviceInfo, LocalStore};
use octapass_mobile_vault::model::SessionStatus;
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, Vault};
use zeroize::Zeroizing;

const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";

#[test]
fn the_apps_unlock_merges_what_was_saved_while_locked() {
    let dir = tempfile::tempdir().unwrap();
    let group = dir.path().join("group");
    let vault = Vault::new(
        Config {
            data_dir: group.clone(),
            temp_dir: dir.path().join("temp"),
            device: DeviceInfo {
                name: "Test Pixel".into(),
                platform: "android".into(),
            },
            pwned_passwords_url: "http://127.0.0.1:9".into(),
        },
        Arc::new(FakeNative::default()),
        Box::new(|_| {}),
    )
    .unwrap();
    // Creating the vault unlocks it, which pins the inbox key.
    vault
        .create_local_vault_with("Home", Zeroizing::new(STRONG.into()), KdfParams::DEFAULT)
        .unwrap();
    vault.lock();
    assert_eq!(vault.snapshot().session.status, SessionStatus::Locked);

    // The Autofill service, with the store locked.
    let accounts = octapass_mobile_vault::accounts::Accounts::load(&group).unwrap();
    let path = group.join(accounts.current().unwrap().store_file());
    let store = LocalStore::open(path.to_string_lossy().into_owned()).unwrap();
    assert!(store.inbox_accepts());
    store
        .add_to_inbox(
            "androidapp://com.example.app".into(),
            Some("ada".into()),
            "sealed-password-9".into(),
            Some("Example App".into()),
        )
        .unwrap();

    vault.unlock(Zeroizing::new(STRONG.into())).unwrap();
    let items = vault.list_items().unwrap();
    assert_eq!(items.len(), 1);
    let item = vault.get_item(&items[0].id).unwrap();
    assert_eq!(item.overview["title"], "Example App");
    assert_eq!(item.overview["tags"], serde_json::json!(["Unconfirmed"]));
    assert_eq!(item.details["password"], "sealed-password-9");
    let inbox = std::fs::read_to_string(format!("{}.inbox", path.display())).unwrap();
    assert!(inbox.contains("\"entries\":[]"));
}
