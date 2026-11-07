//! The desktop vault against the real sync server: sign-up, sign-in on a second device, lock and
//! unlock (master password and device), items, sync, conflicts, sign-out and account deletion.

use crate::common;

use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::{ItemDraft, SessionStatus};
use octapass_device_unlock::Error as UnlockError;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn sign_up_save_items_lock_and_unlock() {
    let server = server().await;
    let device = Device::new(&server);
    assert_eq!(device.status(), SessionStatus::SignedOut);
    let secret_key = device.sign_up(&server).await;
    assert!(secret_key.starts_with("OP1-"));
    assert_eq!(device.status(), SessionStatus::Unlocked);

    let vault_id = device.personal_vault();
    let saved = device
        .vault
        .save_item(login(&vault_id, "Example", "first password"))
        .await
        .unwrap();
    assert_eq!(saved.details["password"], "first password");
    assert_eq!(saved.overview["title"], "Example");
    let rows = device.vault.list_items().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        !serde_json::to_string(&rows)
            .unwrap()
            .contains("first password")
    );

    // An edit keeps the old password in the history and leaves unknown fields alone.
    let mut edit: ItemDraft = serde_json::from_value(json!({
        "id": saved.id, "vaultId": vault_id, "revision": saved.revision,
        "overview": saved.overview,
        "details": { "schemaVersion": 1, "username": "ada", "password": "second password", "fromTheFuture": [1, 2] },
    }))
    .unwrap();
    edit.overview["favorite"] = json!(true);
    let edited = device.vault.save_item(edit).await.unwrap();
    assert_eq!(edited.revision, saved.revision + 1);
    assert_eq!(
        edited.details["passwordHistory"][0]["password"],
        "first password"
    );
    assert_eq!(edited.details["fromTheFuture"], json!([1, 2]));

    device.vault.lock();
    assert_eq!(device.status(), SessionStatus::Locked);
    assert_eq!(
        device.vault.list_items().unwrap_err().code,
        ErrorCode::Locked
    );
    assert_eq!(
        device
            .vault
            .unlock(secret("wrong password"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    device.vault.sync().await.unwrap();
    assert_eq!(
        device.vault.get_item(&saved.id).unwrap().details["password"],
        "second password"
    );

    device.vault.delete_item(&saved.id).await.unwrap();
    assert!(
        device
            .vault
            .get_item(&saved.id)
            .unwrap()
            .deleted_at
            .is_some()
    );
    device.vault.restore_item(&saved.id).await.unwrap();
    assert!(
        device
            .vault
            .get_item(&saved.id)
            .unwrap()
            .deleted_at
            .is_none()
    );
    assert!(
        device.sync_failures().is_empty(),
        "{:?}",
        device.sync_failures()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_vault_opens_locked_after_a_restart_and_works_offline() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let saved = device
        .vault
        .save_item(login(&vault_id, "Offline", "pw"))
        .await
        .unwrap();

    let device = device.restart(&server);
    assert_eq!(device.status(), SessionStatus::Locked);
    drop(server);
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    assert_eq!(
        device.vault.get_item(&saved.id).unwrap().details["password"],
        "pw"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_device_needs_the_secret_key_and_sees_the_same_items() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let vault_id = first.personal_vault();
    let saved = first
        .vault
        .save_item(login(&vault_id, "Shared login", "pw"))
        .await
        .unwrap();

    let second = Device::new(&server);
    assert_eq!(
        second.sign_in(&server, None).await.unwrap_err().code,
        ErrorCode::SecretKeyRequired
    );
    assert_eq!(
        second
            .sign_in(&server, Some("OP1-not-a-key"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidSecretKey
    );
    second.sign_in(&server, Some(&secret_key)).await.unwrap();
    assert_eq!(
        second.vault.get_item(&saved.id).unwrap().details["password"],
        "pw"
    );
    assert_eq!(second.vault.snapshot().remembered_accounts.len(), 1);

    // Both edit the same revision: the second save becomes a conflicting copy.
    let edit = |password: &str| -> ItemDraft {
        let mut draft = login(&vault_id, "Shared login", password);
        draft.id = Some(saved.id.clone());
        draft.revision = Some(saved.revision);
        draft
    };
    first
        .vault
        .save_item(edit("from the first device"))
        .await
        .unwrap();
    let copy = second
        .vault
        .save_item(edit("from the second device"))
        .await
        .unwrap();
    assert_ne!(copy.id, saved.id);
    assert_eq!(copy.overview["title"], "Shared login (conflicting copy)");
    second.vault.sync().await.unwrap();
    assert_eq!(
        second.vault.get_item(&saved.id).unwrap().details["password"],
        "from the first device"
    );
    assert_eq!(second.vault.list_items().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_edit_is_saved_as_a_copy_before_reaching_the_server() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let saved = device
        .vault
        .save_item(login(&vault_id, "Bank", "pw"))
        .await
        .unwrap();
    let mut stale = login(&vault_id, "Bank", "other");
    stale.id = Some(saved.id.clone());
    stale.revision = Some(saved.revision - 1);
    let copy = device.vault.save_item(stale).await.unwrap();
    assert_eq!(copy.overview["title"], "Bank (conflicting copy)");
    assert_eq!(
        device.vault.get_item(&saved.id).unwrap().details["password"],
        "pw"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn device_unlock_releases_the_vault_with_the_device_lock() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let methods = device.vault.unlock_methods().await;
    assert!(methods.device_unlock_supported && !methods.device_unlock_enabled);
    assert_eq!(methods.label, "Touch ID");

    device.vault.enable_device_unlock().await.unwrap();
    assert!(device.vault.unlock_methods().await.device_unlock_enabled);
    device.vault.lock();
    device.vault.unlock_with_device().await.unwrap();
    assert_eq!(device.status(), SessionStatus::Unlocked);
    assert_eq!(
        device.unlock.prompts().len(),
        2,
        "one to turn it on, one to unlock"
    );

    device.vault.lock();
    device.unlock.refuse_prompts(Some(UnlockError::Cancelled));
    assert_eq!(
        device.vault.unlock_with_device().await.unwrap_err().code,
        ErrorCode::DeviceUnlockCancelled
    );
    assert!(
        device.vault.unlock_methods().await.device_unlock_enabled,
        "cancelling keeps it"
    );

    // The OS dropped the secret (new fingerprints on a biometry-only item): start over.
    device.unlock.refuse_prompts(None);
    device.unlock.invalidate(&format!("{}|{EMAIL}", server.url));
    assert_eq!(
        device.vault.unlock_with_device().await.unwrap_err().code,
        ErrorCode::DeviceUnlockFailed
    );
    assert!(!device.vault.unlock_methods().await.device_unlock_enabled);
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn device_unlock_asks_for_the_master_password_every_fourteen_days() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    device.vault.enable_device_unlock().await.unwrap();
    device.vault.lock();

    let state = device.dir.path().join("state.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    json["accounts"][0]["lastPasswordUnlockAt"] = json!("2026-01-01T00:00:00Z");
    std::fs::write(&state, serde_json::to_vec(&json).unwrap()).unwrap();
    let device = device.restart(&server);

    assert!(device.vault.unlock_methods().await.password_required);
    assert_eq!(
        device.vault.unlock_with_device().await.unwrap_err().code,
        ErrorCode::PasswordRequired
    );
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    device.vault.lock();
    assert!(!device.vault.unlock_methods().await.password_required);
    device.vault.unlock_with_device().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_without_a_lock_cant_turn_on_device_unlock() {
    let server = server().await;
    let device = Device::with_unlock(
        &server,
        octapass_device_unlock::fake::FakeDeviceUnlock::without_lock(),
    );
    device.sign_up(&server).await;
    assert!(!device.vault.unlock_methods().await.device_unlock_supported);
    assert_eq!(
        device.vault.enable_device_unlock().await.unwrap_err().code,
        ErrorCode::DeviceUnlockUnsupported
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_out_forgets_the_secret_key_and_device_unlock() {
    let server = server().await;
    let device = Device::new(&server);
    let secret_key = device.sign_up(&server).await;
    device.vault.enable_device_unlock().await.unwrap();
    device.vault.sign_out().await.unwrap();
    assert_eq!(device.status(), SessionStatus::SignedOut);
    assert!(device.vault.snapshot().remembered_accounts.is_empty());
    assert!(
        !device
            .unlock
            .is_enrolled(&format!("{}|{EMAIL}", server.url))
    );
    assert_eq!(
        device.sign_in(&server, None).await.unwrap_err().code,
        ErrorCode::SecretKeyRequired
    );
    device.sign_in(&server, Some(&secret_key)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_account_needs_the_password_and_wipes_this_device() {
    let server = server().await;
    let device = Device::new(&server);
    let secret_key = device.sign_up(&server).await;
    assert_eq!(
        device
            .vault
            .delete_account("someone@else.com", secret(PASSWORD))
            .await
            .unwrap_err()
            .code,
        ErrorCode::EmailMismatch
    );
    assert_eq!(
        device
            .vault
            .delete_account(EMAIL, secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    device
        .vault
        .delete_account(&EMAIL.to_uppercase(), secret(PASSWORD))
        .await
        .unwrap();
    assert_eq!(device.status(), SessionStatus::SignedOut);
    assert!(device.vault.snapshot().remembered_accounts.is_empty());
    assert_eq!(
        device
            .sign_in(&server, Some(&secret_key))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_up_twice_with_one_email_is_refused() {
    let server = server().await;
    Device::new(&server).sign_up(&server).await;
    let other = Device::new(&server);
    let started = other
        .vault
        .start_signup(&server.url, EMAIL, secret(PASSWORD))
        .await
        .unwrap();
    let code = started.dev_verification_code.unwrap();
    assert_eq!(
        other
            .vault
            .finish_signup(&started.signup_id, "000000x")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidVerificationCode
    );
    assert_eq!(
        other
            .vault
            .finish_signup(&started.signup_id, &code)
            .await
            .unwrap_err()
            .code,
        ErrorCode::EmailTaken
    );
    assert_eq!(
        other
            .vault
            .finish_signup("unknown", &code)
            .await
            .unwrap_err()
            .code,
        ErrorCode::SignupExpired
    );
}
