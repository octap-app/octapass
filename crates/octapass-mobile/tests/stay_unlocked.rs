//! Stay unlocked while logged in to this phone (plan 18), through `OctaPassVault` as the native
//! apps call it, on a vault on this phone only: on by default, opening without a prompt, no lock
//! in the background, "Lock now" holding, turning it off, and a phone without a passcode.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use octapass_mobile::platform::{CredentialIdentity, DeviceLock, NativePlatform, VaultObserver};
use octapass_mobile::vault::{
    DevicePlatform, SessionSnapshot, SessionStatus, SyncState, VaultConfig,
};
use octapass_mobile::{ErrorCode, OctaPassVault, Result, VaultError};
use tempfile::TempDir;

const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";

/// The Keychain and the device lock, in memory. `stay_unlocked` is the item plan 18 adds.
struct Platform {
    passcode: bool,
    secrets: Mutex<HashMap<String, String>>,
    device_secrets: Mutex<HashMap<String, Vec<u8>>>,
    stay_unlocked: Mutex<HashMap<String, Vec<u8>>>,
    prompts: Mutex<u32>,
}

impl Platform {
    fn new(passcode: bool) -> Arc<Self> {
        Arc::new(Self {
            passcode,
            secrets: Mutex::default(),
            device_secrets: Mutex::default(),
            stay_unlocked: Mutex::default(),
            prompts: Mutex::new(0),
        })
    }

    fn keys(&self) -> usize {
        self.stay_unlocked.lock().unwrap().len()
    }
}

impl NativePlatform for Platform {
    fn secret(&self, name: String) -> Result<Option<String>> {
        Ok(self.secrets.lock().unwrap().get(&name).cloned())
    }

    fn set_secret(&self, name: String, value: String) -> Result<()> {
        self.secrets.lock().unwrap().insert(name, value);
        Ok(())
    }

    fn delete_secret(&self, name: String) -> Result<()> {
        self.secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn device_lock(&self) -> DeviceLock {
        DeviceLock {
            available: self.passcode,
            label: "Face ID".into(),
        }
    }

    fn store_device_secret(&self, name: String, secret: Vec<u8>) -> Result<()> {
        self.device_secrets.lock().unwrap().insert(name, secret);
        Ok(())
    }

    fn device_secret(&self, name: String, _reason: String) -> Result<Vec<u8>> {
        *self.prompts.lock().unwrap() += 1;
        self.device_secrets
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .ok_or_else(|| VaultError::new(ErrorCode::DeviceUnlockFailed, "no secret"))
    }

    fn delete_device_secret(&self, name: String) -> Result<()> {
        self.device_secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn verify_user(&self, _reason: String) -> Result<()> {
        Err(octapass_mobile::VaultError::new(
            octapass_mobile::ErrorCode::DeviceUnlockUnsupported,
            "not in tests",
        ))
    }

    fn store_stay_unlocked_key(&self, name: String, key: Vec<u8>) -> Result<()> {
        if !self.passcode {
            return Err(ErrorCode::DeviceUnlockUnsupported.into());
        }
        self.stay_unlocked.lock().unwrap().insert(name, key);
        Ok(())
    }

    fn stay_unlocked_key(&self, name: String) -> Result<Option<Vec<u8>>> {
        Ok(self.stay_unlocked.lock().unwrap().get(&name).cloned())
    }

    fn delete_stay_unlocked_key(&self, name: String) -> Result<()> {
        self.stay_unlocked.lock().unwrap().remove(&name);
        Ok(())
    }

    fn set_credential_identities(&self, _identities: Vec<CredentialIdentity>) -> Result<()> {
        Ok(())
    }

    fn chip_available(&self) -> bool {
        false
    }

    fn create_chip_key(&self, _name: String) -> Result<Option<octapass_mobile::platform::ChipKey>> {
        Ok(None)
    }

    fn chip_secret(&self, _name: String, _context: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn delete_chip_key(&self, _name: String) -> Result<()> {
        Ok(())
    }

    fn low_memory(&self) -> bool {
        true
    }

    fn backup_folder_files(&self, _folder: String) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn write_backup_file(&self, _folder: String, _name: String, _source: String) -> Result<()> {
        Ok(())
    }

    fn delete_backup_file(&self, _folder: String, _name: String) -> Result<()> {
        Ok(())
    }
}

struct Events;

impl VaultObserver for Events {
    fn session_changed(&self, _snapshot: SessionSnapshot) {}
    fn items_changed(&self) {}
    fn sync_changed(&self, _state: SyncState) {}
    fn sharing_changed(&self) {}
}

struct Phone {
    vault: Arc<OctaPassVault>,
    platform: Arc<Platform>,
    dir: TempDir,
    runtime: tokio::runtime::Runtime,
}

impl Phone {
    fn new(passcode: bool) -> Self {
        Self::open(Platform::new(passcode), tempfile::tempdir().unwrap())
    }

    fn open(platform: Arc<Platform>, dir: TempDir) -> Self {
        let vault = OctaPassVault::new(
            VaultConfig {
                data_dir: dir.path().join("group").to_string_lossy().into(),
                temp_dir: dir.path().join("tmp").to_string_lossy().into(),
                device_name: "Test iPhone".into(),
                platform: DevicePlatform::Ios,
                pwned_passwords_url: "http://127.0.0.1:9".into(),
                web_vault_url: "https://vault.octap.app".into(),
                default_server_url: "https://vault.octap.app".into(),
                cache_dir: dir.path().join("icons").to_string_lossy().into(),
            },
            platform.clone(),
            Arc::new(Events),
        )
        .unwrap();
        Self {
            vault,
            platform,
            dir,
            runtime: tokio::runtime::Runtime::new().unwrap(),
        }
    }

    /// The app was closed and started again.
    fn restart(self) -> Self {
        Self::open(self.platform, self.dir)
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().status
    }

    fn create(&self) {
        self.runtime
            .block_on(
                self.vault
                    .clone()
                    .create_local_vault("Home".into(), STRONG.into()),
            )
            .unwrap();
    }

    fn open_without_prompt(&self) -> bool {
        self.runtime
            .block_on(self.vault.clone().unlock_stay_unlocked())
            .unwrap()
    }

    fn unlock(&self) {
        self.runtime
            .block_on(self.vault.clone().unlock(STRONG.into()))
            .unwrap();
    }

    /// The key is made on a thread of its own after an unlock.
    fn wait_for_keys(&self, count: usize) {
        let start = Instant::now();
        while self.platform.keys() != count {
            assert!(start.elapsed() < Duration::from_secs(10), "no key");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn a_new_install_stays_unlocked_without_a_prompt() {
    let phone = Phone::new(true);
    assert!(phone.vault.settings().stay_unlocked);
    phone.create();
    phone.wait_for_keys(1);
    let status = phone.vault.stay_unlocked_status();
    assert!(status.on && status.available && status.enrolled && !status.password_required);

    // The app goes to the background with "lock in the background" picked: it stays open.
    let mut settings = phone.vault.settings();
    settings.lock_on_background = true;
    phone.vault.update_settings(settings).unwrap();
    phone.vault.app_did_enter_background();
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    // Closed and opened again: unlocked with no prompt.
    let phone = phone.restart();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert!(phone.open_without_prompt());
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    assert_eq!(*phone.platform.prompts.lock().unwrap(), 0);
}

#[test]
fn lock_now_holds_until_the_user_unlocks() {
    let phone = Phone::new(true);
    phone.create();
    phone.wait_for_keys(1);
    phone.vault.lock();
    assert!(!phone.open_without_prompt());
    assert_eq!(phone.status(), SessionStatus::Locked);
    phone.unlock();
    phone.vault.lock();
    // Still held: only the user's own unlock ends it, and it's in memory only.
    assert!(!phone.open_without_prompt());
    let phone = phone.restart();
    assert!(phone.open_without_prompt());
}

#[test]
fn turned_off_it_locks_as_before() {
    let phone = Phone::new(true);
    phone.create();
    phone.wait_for_keys(1);
    let mut settings = phone.vault.settings();
    settings.stay_unlocked = false;
    settings.lock_on_background = true;
    phone.vault.update_settings(settings).unwrap();
    assert_eq!(phone.platform.keys(), 0);
    phone.vault.app_did_enter_background();
    assert_eq!(phone.status(), SessionStatus::Locked);
    let phone = phone.restart();
    assert!(!phone.vault.settings().stay_unlocked);
    assert!(!phone.open_without_prompt());

    // On again: the key comes back at the next unlock.
    phone.unlock();
    let mut settings = phone.vault.settings();
    settings.stay_unlocked = true;
    phone.vault.update_settings(settings).unwrap();
    assert_eq!(phone.platform.keys(), 1);
}

#[test]
fn a_phone_without_a_passcode_falls_back() {
    let phone = Phone::new(false);
    phone.create();
    let status = phone.vault.stay_unlocked_status();
    assert!(status.on && !status.available && !status.enrolled);
    let mut settings = phone.vault.settings();
    settings.lock_on_background = true;
    phone.vault.update_settings(settings).unwrap();
    phone.vault.app_did_enter_background();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert!(!phone.open_without_prompt());
    assert_eq!(phone.platform.keys(), 0);
}
