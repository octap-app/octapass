//! Vaults on this computer only, with the real sync server for Turn on sync.

use crate::common;

use common::{Device, EMAIL, PASSWORD, Server, login as login_draft, secret, server};
use octapass_core::kdf::KdfParams;
use octapass_desktop_vault::model::SessionStatus;
use octapass_desktop_vault::vault::RestoreSecret;
use octapass_desktop_vault::{ErrorCode, Event};
use octapass_device_unlock::fake::FakeDeviceUnlock;

const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";

async fn create(device: &Device, name: &str) -> String {
    device
        .vault
        .create_local_vault_with(name, secret(STRONG), KdfParams::DEFAULT)
        .await
        .unwrap()
        .to_string()
}

async fn personal(device: &Device) -> String {
    device.vault.list_vaults().unwrap()[0].id.clone()
}

fn device_with_chip(server: &Server) -> Device {
    let unlock = FakeDeviceUnlock::default();
    unlock.set_chip(true);
    Device::with_unlock(server, unlock)
}

#[tokio::test]
async fn a_local_vault_works_with_no_server_at_all() {
    let server = server().await;
    let device = Device::new(&server);
    assert_eq!(
        device.vault.snapshot().session.status,
        SessionStatus::SignedOut
    );
    let code = create(&device, "Home").await;
    assert_eq!(code.split('-').count(), 11, "the local Recovery Kit's code");

    let session = device.vault.snapshot().session;
    assert_eq!(session.status, SessionStatus::Unlocked);
    assert_eq!(session.email.as_deref(), Some("Home"));
    assert!(session.server_url.unwrap().starts_with("local:"));
    assert!(device.vault.snapshot().remembered_accounts.is_empty());

    let vault_id = personal(&device).await;
    let item = device
        .vault
        .save_item(login_draft(&vault_id, "Example", "pw-1"))
        .await
        .unwrap();
    assert_eq!(device.vault.list_items().unwrap().len(), 1);

    let mut edit = login_draft(&vault_id, "Example", "pw-2");
    edit.id = Some(item.id.clone());
    edit.revision = Some(item.revision);
    let edited = device.vault.save_item(edit).await.unwrap();
    assert_ne!(edited.revision, item.revision);
    assert_eq!(edited.details["password"], "pw-2");
    assert_eq!(
        edited.details["passwordHistory"][0]["password"], "pw-1",
        "the same history accounts keep"
    );

    device.vault.delete_item(&item.id).await.unwrap();
    assert!(
        device
            .vault
            .get_item(&item.id)
            .unwrap()
            .deleted_at
            .is_some()
    );
    device.vault.restore_item(&item.id).await.unwrap();
    assert!(
        device
            .vault
            .get_item(&item.id)
            .unwrap()
            .deleted_at
            .is_none()
    );

    // A sync has nothing to do; what needs an account says so.
    device.vault.sync().await.unwrap();
    assert_eq!(
        device.vault.secret_key().unwrap_err().code,
        ErrorCode::NeedsSync
    );
    assert_eq!(
        device.vault.two_step_status().await.unwrap_err().code,
        ErrorCode::NeedsSync
    );
    assert_eq!(
        device.vault.sign_out().await.unwrap_err().code,
        ErrorCode::NeedsSync,
        "signing out must never delete the only copy"
    );
    assert_eq!(
        device
            .vault
            .delete_account("Home", secret(STRONG))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NeedsSync
    );
    let summary = device.vault.account_summary().await.unwrap();
    assert_eq!((summary.item_count, summary.device_count), (1, 1));

    // It survives a restart, and the master password opens it.
    let device = device.restart(&server);
    let session = device.vault.snapshot().session;
    assert_eq!(session.status, SessionStatus::Locked);
    assert_eq!(session.email.as_deref(), Some("Home"));
    assert_eq!(
        device.vault.unlock(secret("wrong")).await.unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    device.vault.unlock(secret(STRONG)).await.unwrap();
    assert_eq!(
        device.vault.get_item(&item.id).unwrap().details["password"],
        "pw-2"
    );
    device
        .vault
        .confirm_master_password(secret(STRONG))
        .await
        .unwrap();
    assert_eq!(
        device
            .vault
            .confirm_master_password(secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test]
async fn a_vault_without_a_chip_needs_a_strong_password() {
    let server = server().await;
    let weak = Device::new(&server);
    assert_eq!(weak.vault.local_capabilities().await.min_score, 4);
    assert_eq!(
        weak.vault
            .create_local_vault_with("Home", secret("password123"), KdfParams::DEFAULT)
            .await
            .unwrap_err()
            .code,
        ErrorCode::WeakMasterPassword
    );
    assert!(weak.vault.local_vaults().is_empty());

    let chip = device_with_chip(&server);
    let capabilities = chip.vault.local_capabilities().await;
    assert!(capabilities.chip);
    assert_eq!(capabilities.min_score, 3);
    assert_eq!(
        chip.vault
            .create_local_vault_with("Home", secret("password123"), KdfParams::DEFAULT)
            .await
            .unwrap_err()
            .code,
        ErrorCode::WeakMasterPassword,
        "backups are only as strong as the password, chip or not"
    );
}

#[tokio::test]
async fn the_chip_binds_a_vault_to_this_computer() {
    let server = server().await;
    let device = device_with_chip(&server);
    create(&device, "Home").await;
    assert!(device.vault.local_vaults()[0].chip_bound);
    let tag = device.vault.local_vaults()[0].id.clone();
    let name = format!("local-vault|{tag}");
    assert!(device.unlock.has_chip_key(&name));

    device.vault.lock();
    device.vault.unlock(secret(STRONG)).await.unwrap();
    device.vault.lock();

    // A new logic board: the password alone opens nothing, and the backup is the way back.
    device.unlock.lose_chip_key(&name);
    assert_eq!(
        device.vault.unlock(secret(STRONG)).await.unwrap_err().code,
        ErrorCode::DeviceUnlockFailed
    );
}

#[tokio::test]
async fn device_unlock_opens_a_local_vault() {
    let server = server().await;
    let device = device_with_chip(&server);
    create(&device, "Home").await;
    device.vault.enable_device_unlock().await.unwrap();
    assert!(device.vault.unlock_methods().await.device_unlock_enabled);
    device.vault.confirm_with_device().await.unwrap();

    device.vault.lock();
    device.vault.unlock_with_device().await.unwrap();
    assert_eq!(
        device.vault.snapshot().session.status,
        SessionStatus::Unlocked
    );

    // A password change turns it off, as for accounts.
    device
        .vault
        .change_master_password(secret(STRONG), secret("quartz-meadow-lantern-fjord-pixel"))
        .await
        .unwrap();
    assert!(!device.vault.unlock_methods().await.device_unlock_enabled);
    device.vault.lock();
    assert_eq!(
        device.vault.unlock(secret(STRONG)).await.unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    device
        .vault
        .unlock(secret("quartz-meadow-lantern-fjord-pixel"))
        .await
        .unwrap();
}

#[tokio::test]
async fn backups_restore_elsewhere_with_the_password_or_the_recovery_code() {
    let server = server().await;
    let device = device_with_chip(&server);
    let code = create(&device, "Home").await;
    assert!(device.vault.local_vaults()[0].last_backup_at.is_none());
    let vault_id = personal(&device).await;
    let item = device
        .vault
        .save_item(login_draft(&vault_id, "Example", "pw-1"))
        .await
        .unwrap();
    let backup = device.vault.create_local_backup().unwrap();
    assert_eq!(&backup[..4], b"OPBK");
    assert!(device.vault.local_vaults()[0].last_backup_at.is_some());
    assert_eq!(device.vault.local_recovery_code().unwrap().as_str(), code);

    // Another computer, with no chip.
    let other = Device::new(&server);
    assert_eq!(
        other
            .vault
            .restore_local_vault(backup.clone(), RestoreSecret::Password(secret("wrong")))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidBackup
    );
    other
        .vault
        .restore_local_vault(backup.clone(), RestoreSecret::Password(secret(STRONG)))
        .await
        .unwrap();
    let restored = &other.vault.local_vaults()[0];
    assert_eq!(restored.name, "Home");
    assert!(!restored.chip_bound);
    assert!(restored.last_backup_at.is_some());
    assert_eq!(
        other.vault.get_item(&item.id).unwrap().details["password"],
        "pw-1"
    );

    // A forgotten password: the code opens it, and a new password takes over.
    let third = Device::new(&server);
    let new_password = "quartz-meadow-lantern-fjord-pixel";
    third
        .vault
        .restore_local_vault(
            backup,
            RestoreSecret::RecoveryCode {
                code: secret(&code),
                new_password: secret(new_password),
            },
        )
        .await
        .unwrap();
    third.vault.lock();
    third.vault.unlock(secret(new_password)).await.unwrap();
    assert_eq!(third.vault.list_items().unwrap().len(), 1);
}

#[tokio::test]
async fn automatic_backups_go_to_the_folder_and_keep_the_newest() {
    let server = server().await;
    let device = Device::new(&server);
    create(&device, "Home").await;
    let folder = tempfile::tempdir().unwrap();
    let foreign = folder.path().join("holiday.jpg");
    std::fs::write(&foreign, b"not ours").unwrap();

    let files = || {
        let mut names: Vec<String> = std::fs::read_dir(folder.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".octapass-backup"))
            .collect();
        names.sort();
        names
    };

    device
        .vault
        .set_backup_folder(Some(folder.path().to_string_lossy().into_owned()))
        .unwrap();
    assert_eq!(files().len(), 1, "the first backup is written at once");
    assert!(
        !files()[0].contains("Home"),
        "file names don't name the vault"
    );
    let info = device.vault.local_vaults().remove(0);
    assert!(info.backup_folder.is_some() && info.last_backup_at.is_some());

    // Nothing changed, nothing written; a change is written when it's forced or quiet.
    device.vault.auto_backup(true);
    assert_eq!(files().len(), 1);
    let vault_id = personal(&device).await;
    device
        .vault
        .save_item(login_draft(&vault_id, "Example", "pw-1"))
        .await
        .unwrap();
    device.vault.auto_backup(false);
    assert_eq!(files().len(), 1, "it waits for a quiet minute");

    for number in 0..9 {
        device
            .vault
            .save_item(login_draft(&vault_id, &format!("Item {number}"), "pw"))
            .await
            .unwrap();
        // Backups are named by the second.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        device.vault.auto_backup(true);
    }
    assert_eq!(files().len(), 7, "the seven newest stay");
    assert!(foreign.exists(), "other files are left alone");

    // Locking writes what's waiting.
    device
        .vault
        .save_item(login_draft(&vault_id, "Last", "pw"))
        .await
        .unwrap();
    let newest = files().pop().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    device.vault.lock();
    let after = files().pop().unwrap();
    assert_ne!(after, newest);
    let restored = Device::new(&server);
    restored
        .vault
        .restore_local_vault(
            std::fs::read(folder.path().join(&after)).unwrap(),
            RestoreSecret::Password(secret(STRONG)),
        )
        .await
        .unwrap();
    assert!(
        restored
            .vault
            .list_items()
            .unwrap()
            .iter()
            .any(|row| row.title == "Last")
    );

    // A folder that can't take its first backup isn't kept. One that goes later is reported,
    // and the vault goes on.
    device.vault.unlock(secret(STRONG)).await.unwrap();
    let working = folder.path().join("working");
    std::fs::create_dir(&working).unwrap();
    let working = working.to_string_lossy().into_owned();
    device
        .vault
        .set_backup_folder(Some(working.clone()))
        .unwrap();
    let gone = folder.path().join("gone");
    assert!(
        device
            .vault
            .set_backup_folder(Some(gone.to_string_lossy().into_owned()))
            .is_err()
    );
    assert_eq!(
        device.vault.local_vaults()[0].backup_folder,
        Some(working.clone())
    );
    std::fs::remove_dir_all(&working).unwrap();
    device
        .vault
        .save_item(login_draft(&vault_id, "Offline", "pw"))
        .await
        .unwrap();
    device.vault.auto_backup(true);
    assert!(
        device
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::BackupFailed { .. }))
    );
    assert_eq!(
        device
            .vault
            .list_items()
            .unwrap()
            .iter()
            .filter(|row| row.title == "Offline")
            .count(),
        1
    );
}

#[tokio::test]
async fn several_vaults_live_side_by_side() {
    let server = server().await;
    let device = Device::new(&server);
    create(&device, "Home").await;
    let vault_id = personal(&device).await;
    device
        .vault
        .save_item(login_draft(&vault_id, "Home login", "pw"))
        .await
        .unwrap();

    device.vault.leave_local_vault().unwrap();
    assert_eq!(
        device.vault.snapshot().session.status,
        SessionStatus::SignedOut
    );
    assert_eq!(device.vault.local_vaults().len(), 1);

    device
        .vault
        .create_local_vault_with(
            "Work",
            secret("quartz-meadow-lantern-fjord-pixel"),
            KdfParams::DEFAULT,
        )
        .await
        .unwrap();
    assert!(device.vault.list_items().unwrap().is_empty());
    let list = device.vault.local_vaults();
    assert_eq!(list.len(), 2);
    assert!(
        list.iter()
            .find(|vault| vault.name == "Work")
            .unwrap()
            .current
    );
    let home = list
        .iter()
        .find(|vault| vault.name == "Home")
        .unwrap()
        .id
        .clone();

    device.vault.switch_local_vault(&home).unwrap();
    let session = device.vault.snapshot().session;
    assert_eq!(session.status, SessionStatus::Locked);
    assert_eq!(session.email.as_deref(), Some("Home"));
    assert_eq!(
        device
            .vault
            .unlock(secret("quartz-meadow-lantern-fjord-pixel"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials,
        "each vault has its own password"
    );
    device.vault.unlock(secret(STRONG)).await.unwrap();
    assert_eq!(device.vault.list_items().unwrap().len(), 1);

    device.vault.rename_local_vault("Family").unwrap();
    assert_eq!(
        device.vault.snapshot().session.email.as_deref(),
        Some("Family")
    );

    assert_eq!(
        device
            .vault
            .delete_local_vault(secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    device
        .vault
        .delete_local_vault(secret(STRONG))
        .await
        .unwrap();
    let left = device.vault.local_vaults();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].name, "Work");
    assert!(left[0].current);
    assert_eq!(
        device.vault.snapshot().session.status,
        SessionStatus::Locked,
        "the other vault is next, locked"
    );
    assert!(
        !std::fs::read_dir(device.dir.path())
            .unwrap()
            .any(|file| file.unwrap().file_name().to_string_lossy().contains(&home)),
        "the deleted vault's file is gone"
    );
}

#[tokio::test]
async fn turning_on_sync_moves_the_vault_into_an_account() {
    let server = server().await;
    let device = device_with_chip(&server);
    create(&device, "Home").await;
    let vault_id = personal(&device).await;
    let kept = device
        .vault
        .save_item(login_draft(&vault_id, "Kept", "pw-kept"))
        .await
        .unwrap();
    let trashed = device
        .vault
        .save_item(login_draft(&vault_id, "Trashed", "pw-trashed"))
        .await
        .unwrap();
    device.vault.delete_item(&trashed.id).await.unwrap();
    let tag = device.vault.local_vaults()[0].id.clone();

    let started = device
        .vault
        .start_turn_on_sync(&server.url, EMAIL, secret(PASSWORD))
        .await
        .unwrap();
    assert_eq!(
        device
            .vault
            .finish_turn_on_sync(&started.signup_id, "000000")
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidVerificationCode,
    );
    assert_eq!(device.vault.local_vaults().len(), 1, "still local");
    assert!(
        device
            .vault
            .snapshot()
            .session
            .server_url
            .unwrap()
            .starts_with("local:")
    );

    let code = started.dev_verification_code.unwrap();
    let kit = device
        .vault
        .finish_turn_on_sync(&started.signup_id, &code)
        .await
        .unwrap();
    assert_eq!(kit.email, EMAIL);
    assert!(kit.secret_key.starts_with("OP1-"));

    // The device is a normal synced device, the local vault gone.
    let session = device.vault.snapshot().session;
    assert_eq!(session.status, SessionStatus::Unlocked);
    assert_eq!(session.email.as_deref(), Some(EMAIL));
    assert_eq!(session.server_url.as_deref(), Some(server.url.as_str()));
    assert!(device.vault.local_vaults().is_empty());
    assert!(!device.unlock.has_chip_key(&format!("local-vault|{tag}")));
    assert_eq!(
        device.vault.get_item(&kept.id).unwrap().details["password"],
        "pw-kept"
    );
    assert!(
        device
            .vault
            .get_item(&trashed.id)
            .unwrap()
            .deleted_at
            .is_some()
    );
    assert_eq!(device.vault.secret_key().unwrap(), kit.secret_key);

    // A new device signs in and reads what was never re-entered: the items went up as they were.
    let other = Device::new(&server);
    other
        .vault
        .sign_in(
            &server.url,
            EMAIL,
            secret(PASSWORD),
            Some(secret(&kit.secret_key)),
        )
        .await
        .unwrap();
    assert_eq!(
        other.vault.get_item(&kept.id).unwrap().details["password"],
        "pw-kept"
    );
    assert_eq!(other.vault.list_vaults().unwrap()[0].id, vault_id);
    assert!(
        other
            .vault
            .get_item(&trashed.id)
            .unwrap()
            .deleted_at
            .is_some()
    );

    // And it goes on as an account: changes sync both ways.
    let new = device
        .vault
        .save_item(login_draft(&vault_id, "After", "pw-after"))
        .await
        .unwrap();
    other.vault.sync().await.unwrap();
    assert_eq!(
        other.vault.get_item(&new.id).unwrap().details["password"],
        "pw-after"
    );
}

#[tokio::test]
async fn a_server_out_of_reach_leaves_the_vault_as_it_was() {
    let server = server().await;
    let device = Device::new(&server);
    create(&device, "Home").await;
    assert_eq!(
        device
            .vault
            .start_turn_on_sync("http://127.0.0.1:9", EMAIL, secret(PASSWORD))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ServerUnreachable
    );
    assert_eq!(device.vault.local_vaults().len(), 1);
    assert_eq!(device.status(), SessionStatus::Unlocked);
}

#[tokio::test]
async fn the_autofill_gate_asks_the_device_lock_on_every_fill() {
    let server = server().await;
    let device = device_with_chip(&server);
    create(&device, "Home").await;
    let vault = &device.vault;
    assert!(vault.fill_gate(), "on by default");

    // Device unlock isn't set up yet: nothing to verify with, so nothing to ask.
    vault.confirm_fill("fill").unwrap();
    assert!(
        device
            .unlock
            .prompts()
            .iter()
            .all(|reason| reason != "fill")
    );

    vault.enable_device_unlock().await.unwrap();
    vault.confirm_fill("fill").unwrap();
    vault.confirm_fill("fill").unwrap();
    let count = |device: &Device| {
        device
            .unlock
            .prompts()
            .iter()
            .filter(|reason| *reason == "fill")
            .count()
    };
    assert_eq!(count(&device), 2, "every fill asks");

    device
        .unlock
        .refuse_prompts(Some(octapass_device_unlock::Error::Cancelled));
    assert_eq!(
        vault.confirm_fill("fill").unwrap_err().code,
        ErrorCode::DeviceUnlockCancelled
    );
    device.unlock.refuse_prompts(None);

    // Off: filling works directly while unlocked, and the choice survives a restart.
    vault.set_fill_gate(false).unwrap();
    vault.confirm_fill("fill").unwrap();
    assert_eq!(count(&device), 3, "only the refused one more");
    let device = device.restart(&server);
    assert!(!device.vault.fill_gate());

    // A locked vault always asks: there's nothing to fill from.
    assert_eq!(
        device.vault.confirm_fill("fill").unwrap_err().code,
        ErrorCode::Locked
    );

    // The device lock that just opened it counts for that fill.
    device.vault.set_fill_gate(true).unwrap();
    device.vault.unlock_with_device().await.unwrap();
    let before = count(&device);
    device.vault.confirm_fill("fill").unwrap();
    assert_eq!(count(&device), before);
}

#[tokio::test]
async fn a_computer_with_no_lock_fills_without_a_prompt_while_unlocked() {
    let server = server().await;
    let device = Device::with_unlock(&server, FakeDeviceUnlock::without_lock());
    device
        .vault
        .create_local_vault_with("Home", secret(STRONG), KdfParams::DEFAULT)
        .await
        .unwrap();
    device.vault.confirm_fill("fill").unwrap();
    assert!(device.unlock.prompts().is_empty());
    assert!(!device.unlock.has_unprotected("anything"));

    // After a lock, only the master password opens it: nothing unguarded is kept.
    device.vault.lock();
    assert_eq!(
        device.vault.confirm_fill("fill").unwrap_err().code,
        ErrorCode::Locked
    );
    assert_eq!(
        device.vault.unlock_with_device().await.unwrap_err().code,
        ErrorCode::DeviceUnlockFailed
    );
    device.vault.unlock(secret(STRONG)).await.unwrap();
    device.vault.confirm_fill("fill").unwrap();
}
