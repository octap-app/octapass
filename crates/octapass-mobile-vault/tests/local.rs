//! Vaults on this phone only, with the real sync server for Turn on sync and `FakeNative` for the
//! Keychain, the chip and the backup folder.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use octapass_core::kdf::KdfParams;
use octapass_ffi::{DeviceInfo, LocalStore};
use octapass_mobile_vault::model::{ItemDraft, SessionStatus};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::vault::RestoreSecret;
use octapass_mobile_vault::{Config, ErrorCode, Event, Vault};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

struct Server {
    url: String,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app =
                octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            url
        });
        Self {
            url,
            _data: data,
            _runtime: runtime,
        }
    }
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    events: Arc<Mutex<Vec<Event>>>,
    dir: TempDir,
}

impl Phone {
    fn new(native: FakeNative) -> Self {
        Self::open(Arc::new(native), tempfile::tempdir().unwrap())
    }

    fn open(native: Arc<FakeNative>, dir: TempDir) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&events);
        let vault = Vault::new(
            Config {
                data_dir: dir.path().join("group"),
                temp_dir: dir.path().join("temp"),
                device: DeviceInfo {
                    name: "Test iPhone".into(),
                    platform: "ios".into(),
                },
                pwned_passwords_url: "http://127.0.0.1:9".into(),
            },
            native.clone(),
            Box::new(move |event| recorded.lock().unwrap().push(event)),
        )
        .unwrap();
        Self {
            vault,
            native,
            events,
            dir,
        }
    }

    fn restart(self) -> Self {
        Self::open(self.native, self.dir)
    }

    fn create(&self, name: &str) -> String {
        self.vault
            .create_local_vault_with(name, secret(STRONG), KdfParams::DEFAULT)
            .unwrap()
            .to_string()
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }

    fn vault_id(&self) -> String {
        self.vault.list_vaults().unwrap()[0].id.clone()
    }

    fn save(&self, title: &str, password: &str) -> String {
        self.vault
            .save_item(login(&self.vault_id(), title, password))
            .unwrap()
            .id
    }

    fn store(&self) -> Arc<LocalStore> {
        let accounts =
            octapass_mobile_vault::accounts::Accounts::load(&self.dir.path().join("group"))
                .unwrap();
        let account = accounts.current().unwrap();
        LocalStore::open(
            self.dir
                .path()
                .join("group")
                .join(account.store_file())
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap()
    }
}

fn login(vault_id: &str, title: &str, password: &str) -> ItemDraft {
    serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "login", "title": title, "urls": ["https://example.com"] },
        "details": { "schemaVersion": 1, "username": "ada", "password": password },
    }))
    .unwrap()
}

#[test]
fn a_local_vault_works_with_no_server_and_the_autofill_extension_reads_it() {
    let phone = Phone::new(FakeNative::default());
    assert_eq!(phone.status(), SessionStatus::SignedOut);
    let code = phone.create("Home");
    assert_eq!(code.split('-').count(), 11);
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    let session = phone.vault.snapshot();
    assert_eq!(session.session.email.as_deref(), Some("Home"));
    assert!(session.session.server_url.unwrap().starts_with("local:"));
    assert!(session.remembered_accounts.is_empty());

    let id = phone.save("Example", "pw-1");
    assert_eq!(phone.vault.list_items().unwrap().len(), 1);
    phone.vault.delete_item(&id).unwrap();
    assert!(phone.vault.get_item(&id).unwrap().deleted_at.is_some());
    phone.vault.restore_item(&id).unwrap();
    assert!(phone.vault.get_item(&id).unwrap().deleted_at.is_none());
    phone.vault.sync().unwrap();

    assert_eq!(
        phone.vault.secret_key().unwrap_err().code,
        ErrorCode::NeedsSync
    );
    assert_eq!(
        phone.vault.two_step_status().unwrap_err().code,
        ErrorCode::NeedsSync
    );
    assert_eq!(
        phone.vault.sign_out().unwrap_err().code,
        ErrorCode::NeedsSync,
        "signing out must never delete the only copy"
    );
    assert_eq!(phone.vault.account_summary().unwrap().device_count, 1);

    // AutoFill suggestions come from the same place as for accounts.
    assert!(!phone.native.identities.lock().unwrap().is_empty());

    // The AutoFill extension opens the store with the password and the chip's secret, and what
    // it saves shows in the app.
    let store = phone.store();
    assert!(store.is_local());
    let tag = phone.vault.local_vaults()[0].tag.clone();
    let accounts = std::fs::read_to_string(phone.dir.path().join("group/accounts.json")).unwrap();
    let accounts: serde_json::Value = serde_json::from_str(&accounts).unwrap();
    let context = accounts["accounts"][0]["local"]["chipContext"]
        .as_str()
        .expect("the extension reads the chip's context here")
        .to_owned();
    let context = octapass_core::encoding::b64_decode(&context).unwrap();
    let chip = phone
        .native
        .chip_keys
        .lock()
        .unwrap()
        .contains_key(&format!("chipKey.{tag}"));
    assert!(chip);
    let chip_secret = octapass_mobile_vault::Native::chip_secret(
        &*phone.native,
        &format!("chipKey.{tag}"),
        &context,
    )
    .unwrap();
    let extension = store
        .unlock_local(STRONG.into(), Some(chip_secret.to_vec()))
        .unwrap();
    let saved = extension
        .save_login(
            store.clone(),
            octapass_ffi::LoginDraft {
                item_id: None,
                title: Some("From AutoFill".into()),
                url: Some("https://autofill.example/".into()),
                username: Some("ada".into()),
                password: Some("pw-a".into()),
                totp: None,
            },
        )
        .unwrap();
    phone.vault.sync().unwrap();
    assert_eq!(
        phone.vault.get_item(&saved).unwrap().overview["title"],
        "From AutoFill"
    );

    // It survives a restart.
    let phone = phone.restart();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert_eq!(
        phone.vault.unlock(secret("wrong")).unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.unlock(secret(STRONG)).unwrap();
    assert_eq!(phone.vault.list_items().unwrap().len(), 2);
    phone.vault.confirm_user(Some(secret(STRONG))).unwrap();
}

#[test]
fn a_phone_without_a_chip_needs_a_strong_password() {
    let phone = Phone::new(FakeNative {
        chip: false,
        ..FakeNative::default()
    });
    let capabilities = phone.vault.local_capabilities();
    assert!(!capabilities.chip);
    assert_eq!(capabilities.min_score, 4);
    assert_eq!(
        phone
            .vault
            .create_local_vault_with("Home", secret("password123"), KdfParams::DEFAULT)
            .unwrap_err()
            .code,
        ErrorCode::WeakMasterPassword
    );
    assert!(phone.vault.local_vaults().is_empty());
    phone.create("Home");
    assert!(!phone.vault.local_vaults()[0].chip_bound);
    phone.vault.lock();
    phone.vault.unlock(secret(STRONG)).unwrap();

    let chip = Phone::new(FakeNative::default());
    assert_eq!(chip.vault.local_capabilities().min_score, 3);
    assert_eq!(
        chip.vault
            .create_local_vault_with("Home", secret("password123"), KdfParams::DEFAULT)
            .unwrap_err()
            .code,
        ErrorCode::WeakMasterPassword,
        "backups are only as strong as the password"
    );
}

#[test]
fn losing_the_chip_key_leaves_the_backup() {
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    phone.save("Example", "pw-1");
    let backup = std::fs::read(phone.vault.export_local_backup().unwrap()).unwrap();
    phone.vault.lock();
    phone.native.chip_keys.lock().unwrap().clear();
    assert_eq!(
        phone.vault.unlock(secret(STRONG)).unwrap_err().code,
        ErrorCode::DeviceUnlockFailed
    );

    let file = phone.dir.path().join("copy.octapass-backup");
    std::fs::write(&file, backup).unwrap();
    phone
        .vault
        .restore_local_vault(&file, RestoreSecret::Password(secret(STRONG)))
        .unwrap();
    assert_eq!(phone.vault.list_items().unwrap().len(), 1);
}

#[test]
fn device_unlock_and_a_new_password() {
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    phone.vault.enable_device_unlock().unwrap();
    assert!(phone.vault.unlock_methods().device_unlock_enabled);
    phone.vault.lock();
    phone.vault.unlock_with_device().unwrap();
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    let code = phone.vault.local_recovery_code().unwrap();

    let new = "quartz-meadow-lantern-fjord-pixel";
    assert_eq!(
        phone
            .vault
            .change_master_password(secret("wrong"), secret(new))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    phone
        .vault
        .change_master_password(secret(STRONG), secret(new))
        .unwrap();
    assert!(!phone.vault.unlock_methods().device_unlock_enabled);
    assert_eq!(phone.vault.local_recovery_code().unwrap(), code);
    phone.vault.lock();
    assert_eq!(
        phone.vault.unlock(secret(STRONG)).unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.unlock(secret(new)).unwrap();
}

#[test]
fn backups_restore_elsewhere_with_the_password_or_the_recovery_code() {
    let phone = Phone::new(FakeNative::default());
    let code = phone.create("Home");
    let id = phone.save("Example", "pw-1");
    let trashed = phone.save("Trashed", "pw-2");
    phone.vault.delete_item(&trashed).unwrap();
    assert!(phone.vault.local_vaults()[0].last_backup_at.is_none());
    let path = phone.vault.export_local_backup().unwrap();
    assert!(path.ends_with(".octapass-backup"));
    assert!(
        phone.vault.local_vaults()[0].last_backup_at.is_none(),
        "the user can still cancel"
    );
    let backup = phone.dir.path().join("kept.octapass-backup");
    std::fs::copy(&path, &backup).unwrap();
    phone.vault.delete_opened(Path::new(&path));
    assert!(!Path::new(&path).exists(), "no copy stays behind");
    phone.vault.local_backup_saved().unwrap();
    assert!(phone.vault.local_vaults()[0].last_backup_at.is_some());

    let other = Phone::new(FakeNative {
        chip: false,
        ..FakeNative::default()
    });
    assert_eq!(
        other
            .vault
            .restore_local_vault(&backup, RestoreSecret::Password(secret("wrong")))
            .unwrap_err()
            .code,
        ErrorCode::InvalidBackup
    );
    assert_eq!(
        other
            .vault
            .restore_local_vault(
                Path::new("/nonexistent"),
                RestoreSecret::Password(secret(STRONG))
            )
            .unwrap_err()
            .code,
        ErrorCode::Unexpected
    );
    other
        .vault
        .restore_local_vault(&backup, RestoreSecret::Password(secret(STRONG)))
        .unwrap();
    let info = &other.vault.local_vaults()[0];
    assert_eq!(info.name, "Home");
    assert!(!info.chip_bound);
    assert_eq!(
        other.vault.get_item(&id).unwrap().details["password"],
        "pw-1"
    );
    assert!(other.vault.get_item(&trashed).unwrap().deleted_at.is_some());

    let third = Phone::new(FakeNative::default());
    let new = "quartz-meadow-lantern-fjord-pixel";
    third
        .vault
        .restore_local_vault(
            &backup,
            RestoreSecret::RecoveryCode {
                code: secret(&code),
                new_password: secret(new),
            },
        )
        .unwrap();
    third.vault.lock();
    third.vault.unlock(secret(new)).unwrap();
    assert_eq!(third.vault.list_items().unwrap().len(), 2);
}

#[test]
fn automatic_backups_go_to_the_folder_and_keep_the_newest() {
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    let folder = "bookmark";
    let files = |phone: &Phone| {
        let mut names: Vec<String> = phone
            .native
            .backup_folders
            .lock()
            .unwrap()
            .get(folder)
            .map(|files| files.keys().cloned().collect())
            .unwrap_or_default();
        names.sort();
        names
    };
    phone
        .native
        .backup_folders
        .lock()
        .unwrap()
        .entry(folder.into())
        .or_default()
        .insert("holiday.jpg".into(), b"not ours".to_vec());

    phone
        .vault
        .set_backup_folder(Some((folder.into(), "iCloud Drive".into())))
        .unwrap();
    assert_eq!(
        files(&phone).len(),
        2,
        "the first backup is written at once"
    );
    let info = phone.vault.local_vaults().remove(0);
    assert_eq!(info.backup_folder_name.as_deref(), Some("iCloud Drive"));
    assert!(info.last_backup_at.is_some());
    assert!(!info.backup_due);

    // Nothing changed, nothing written.
    phone.vault.auto_backup();
    assert_eq!(files(&phone).len(), 2);

    // A folder that can't take its first backup isn't kept.
    *phone.native.backup_folder_fails.lock().unwrap() = true;
    assert!(
        phone
            .vault
            .set_backup_folder(Some(("other".into(), "Dropbox".into())))
            .is_err()
    );
    *phone.native.backup_folder_fails.lock().unwrap() = false;
    assert_eq!(
        phone.vault.local_vaults()[0].backup_folder_name.as_deref(),
        Some("iCloud Drive")
    );

    for number in 0..9 {
        phone.save(&format!("Item {number}"), "pw");
        // Backups are named by the second.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        phone.vault.auto_backup();
    }
    let names = files(&phone);
    assert_eq!(names.len(), 8, "the seven newest, and the other file");
    assert!(names.contains(&"holiday.jpg".to_owned()));
    assert!(names.iter().all(|name| !name.contains("Home")));

    // Locking writes what's waiting. A folder out of reach is reported and changes nothing.
    phone.save("Last", "pw");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    *phone.native.backup_folder_fails.lock().unwrap() = true;
    phone.vault.auto_backup();
    assert!(phone.events.lock().unwrap().iter().any(
        |event| matches!(event, Event::SyncFailed { message } if message.contains("Automatic backup"))
    ));
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    *phone.native.backup_folder_fails.lock().unwrap() = false;
    phone.vault.lock();
    assert_eq!(files(&phone).len(), 8);
    let newest = files(&phone)
        .into_iter()
        .rfind(|name| name.starts_with("octapass-"))
        .unwrap();
    let contents = phone.native.backup_folders.lock().unwrap()[folder][&newest].clone();
    let path = phone.dir.path().join("newest.octapass-backup");
    std::fs::write(&path, contents).unwrap();
    let other = Phone::new(FakeNative::default());
    other
        .vault
        .restore_local_vault(&path, RestoreSecret::Password(secret(STRONG)))
        .unwrap();
    assert_eq!(other.vault.list_items().unwrap().len(), 10);
}

#[test]
fn several_vaults_live_side_by_side() {
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    phone.save("Home login", "pw");

    phone.vault.leave_local_vault().unwrap();
    assert_eq!(phone.status(), SessionStatus::SignedOut);
    assert_eq!(phone.vault.local_vaults().len(), 1);
    assert!(phone.native.identities.lock().unwrap().is_empty());

    let work = "quartz-meadow-lantern-fjord-pixel";
    phone
        .vault
        .create_local_vault_with("Work", secret(work), KdfParams::DEFAULT)
        .unwrap();
    assert!(phone.vault.list_items().unwrap().is_empty());
    let list = phone.vault.local_vaults();
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
        .tag
        .clone();

    phone.vault.switch_local_vault(&home).unwrap();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert_eq!(
        phone.vault.snapshot().session.email.as_deref(),
        Some("Home")
    );
    assert_eq!(
        phone.vault.unlock(secret(work)).unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.unlock(secret(STRONG)).unwrap();
    assert_eq!(phone.vault.list_items().unwrap().len(), 1);

    phone.vault.rename_local_vault("Family").unwrap();
    assert_eq!(
        phone.vault.snapshot().session.email.as_deref(),
        Some("Family")
    );
    let phone = phone.restart();
    assert_eq!(
        phone.vault.snapshot().session.email.as_deref(),
        Some("Family")
    );
    phone.vault.unlock(secret(STRONG)).unwrap();

    assert_eq!(
        phone
            .vault
            .delete_local_vault(secret("wrong"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.delete_local_vault(secret(STRONG)).unwrap();
    let left = phone.vault.local_vaults();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].name, "Work");
    assert_eq!(phone.status(), SessionStatus::Locked);
    let group = phone.dir.path().join("group");
    let files: Vec<String> = std::fs::read_dir(group)
        .unwrap()
        .map(|file| file.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        !files.iter().any(|file| file.contains(&home)),
        "the deleted vault's files are gone: {files:?}"
    );
    assert!(
        !phone
            .native
            .chip_keys
            .lock()
            .unwrap()
            .contains_key(&format!("chipKey.{home}"))
    );
}

#[test]
fn turning_on_sync_moves_the_vault_into_an_account() {
    let server = Server::start();
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    let kept = phone.save("Kept", "pw-kept");
    let trashed = phone.save("Trashed", "pw-trashed");
    phone.vault.delete_item(&trashed).unwrap();
    let vault_id = phone.vault_id();
    let tag = phone.vault.local_vaults()[0].tag.clone();

    let started = phone
        .vault
        .start_turn_on_sync(&server.url, EMAIL, secret(PASSWORD))
        .unwrap();
    assert_eq!(
        phone
            .vault
            .finish_turn_on_sync(&started.signup_id, "000000")
            .unwrap_err()
            .code,
        ErrorCode::InvalidVerificationCode
    );
    assert_eq!(phone.vault.local_vaults().len(), 1, "still local");
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    let kit = phone
        .vault
        .finish_turn_on_sync(
            &started.signup_id,
            &started.dev_verification_code.clone().unwrap(),
        )
        .unwrap();
    assert_eq!(kit.email, EMAIL);
    let session = phone.vault.snapshot().session;
    assert_eq!(session.status, SessionStatus::Unlocked);
    assert_eq!(session.email.as_deref(), Some(EMAIL));
    assert!(session.server_url.unwrap().starts_with("http://"));
    assert!(phone.vault.local_vaults().is_empty());
    assert!(
        !phone
            .native
            .chip_keys
            .lock()
            .unwrap()
            .contains_key(&format!("chipKey.{tag}"))
    );
    assert_eq!(
        phone.vault.get_item(&kept).unwrap().details["password"],
        "pw-kept"
    );
    assert!(phone.vault.get_item(&trashed).unwrap().deleted_at.is_some());
    assert_eq!(phone.vault.secret_key().unwrap(), kit.secret_key);
    assert!(!phone.store().has_pending_changes(), "everything went up");

    // A new device signs in and reads what was never re-entered.
    let other = Phone::new(FakeNative::default());
    other
        .vault
        .sign_in(
            &server.url,
            EMAIL,
            secret(PASSWORD),
            Some(secret(&kit.secret_key)),
        )
        .unwrap();
    assert_eq!(
        other.vault.get_item(&kept).unwrap().details["password"],
        "pw-kept"
    );
    assert_eq!(other.vault_id(), vault_id);
    assert!(other.vault.get_item(&trashed).unwrap().deleted_at.is_some());

    // And it goes on as an account: changes sync both ways.
    let after = phone.save("After", "pw-after");
    other.vault.sync().unwrap();
    assert_eq!(
        other.vault.get_item(&after).unwrap().details["password"],
        "pw-after"
    );
}

#[test]
fn a_server_out_of_reach_leaves_the_vault_as_it_was() {
    let phone = Phone::new(FakeNative::default());
    phone.create("Home");
    assert_eq!(
        phone
            .vault
            .start_turn_on_sync("http://127.0.0.1:9", EMAIL, secret(PASSWORD))
            .unwrap_err()
            .code,
        ErrorCode::ServerUnreachable
    );
    assert_eq!(phone.vault.local_vaults().len(), 1);
    assert_eq!(phone.status(), SessionStatus::Unlocked);
}
