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

    /// Stay unlocked's keys, not the autofill gate's fill keys kept in the same kind of item.
    fn keys(&self) -> usize {
        self.stay_unlocked
            .lock()
            .unwrap()
            .keys()
            .filter(|name| name.starts_with("stayUnlocked."))
            .count()
    }

    /// The autofill gate's fill keys (plan 03).
    fn fill_keys(&self) -> Vec<Vec<u8>> {
        self.stay_unlocked
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.starts_with("unlockedFill."))
            .map(|(_, key)| key.clone())
            .collect()
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

// ---------- The autofill gate (plan 03), with stay unlocked off ----------

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// When the fill key stops working: the 8 bytes after its format byte.
fn deadline(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[1..9].try_into().unwrap())
}

impl Phone {
    /// The fill key is written on a thread of its own after an unlock.
    fn wait_for_fill_keys(&self, count: usize) {
        let start = Instant::now();
        while self.platform.fill_keys().len() != count {
            assert!(start.elapsed() < Duration::from_secs(10), "fill keys");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn change(&self, change: impl FnOnce(&mut octapass_mobile::local::Settings)) {
        let mut settings = self.vault.settings();
        change(&mut settings);
        self.vault.update_settings(settings).unwrap();
    }

    fn enable_device_unlock(&self) {
        self.runtime
            .block_on(self.vault.clone().enable_device_unlock())
            .unwrap();
    }

    /// The store as the AutoFill extension or the Android services open it: on its own.
    fn extension_store(&self) -> Arc<octapass_ffi::LocalStore> {
        let file = std::fs::read_dir(self.dir.path().join("group"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "opstore"))
            .unwrap();
        octapass_ffi::LocalStore::open(file.to_string_lossy().into_owned()).unwrap()
    }
}

/// Stay unlocked off and device unlock on: the gate has the device lock to ask with.
fn gated_phone() -> Phone {
    let phone = Phone::new(true);
    phone.create();
    phone.change(|settings| settings.stay_unlocked = false);
    phone.enable_device_unlock();
    phone.wait_for_fill_keys(0);
    phone
}

#[test]
fn the_autofill_gate_is_on_by_default_and_every_fill_asks() {
    let phone = gated_phone();
    assert!(phone.vault.settings().device_auth_on_autofill);
    assert!(phone.platform.fill_keys().is_empty());
    assert!(!phone.vault.fills_without_prompt());
}

#[test]
fn with_the_gate_off_fills_work_only_while_the_app_is_unlocked() {
    let phone = gated_phone();
    phone.change(|settings| settings.device_auth_on_autofill = false);
    let keys = phone.platform.fill_keys();
    assert_eq!(keys.len(), 1);
    assert!(phone.vault.fills_without_prompt());
    // The extension opens its own store with it, and nothing asks.
    let prompts = *phone.platform.prompts.lock().unwrap();
    assert!(
        phone
            .extension_store()
            .unlock_fill_key(keys[0].clone())
            .unwrap()
            .is_some()
    );
    assert_eq!(*phone.platform.prompts.lock().unwrap(), prompts);

    // Locked: a locked vault always asks.
    phone.vault.lock();
    assert!(phone.platform.fill_keys().is_empty());
    assert!(!phone.vault.fills_without_prompt());
    // Unlocked again: back.
    phone.unlock();
    phone.wait_for_fill_keys(1);

    // Locked in the background.
    phone.change(|settings| settings.lock_on_background = true);
    phone.vault.app_did_enter_background();
    assert!(phone.platform.fill_keys().is_empty());

    // On again: every fill asks.
    phone.unlock();
    phone.wait_for_fill_keys(1);
    phone.change(|settings| settings.device_auth_on_autofill = true);
    assert!(phone.platform.fill_keys().is_empty());
}

#[test]
fn the_fill_key_lasts_as_long_as_the_lock_timer() {
    let phone = gated_phone();
    phone.change(|settings| {
        settings.device_auth_on_autofill = false;
        settings.auto_lock_minutes = 1;
    });
    let until = deadline(&phone.platform.fill_keys()[0]);
    let now = now_ms();
    assert!(
        until <= now + 60_000 && until + 5_000 > now + 60_000,
        "the timer's minute"
    );

    // In the background the app may never run before the timer is up: the deadline stands in.
    phone.vault.app_did_enter_background();
    assert!(deadline(&phone.platform.fill_keys()[0]) <= now_ms() + 60_000);

    // "Only when the app is closed": the longest timer, since the extension can't tell.
    phone.change(|settings| settings.auto_lock_minutes = 0);
    let until = deadline(&phone.platform.fill_keys()[0]);
    assert!(until <= now_ms() + 240 * 60_000 && until > now_ms() + 239 * 60_000);
}

#[test]
fn a_restarted_app_leaves_no_fill_key() {
    let phone = gated_phone();
    phone.change(|settings| settings.device_auth_on_autofill = false);
    assert_eq!(phone.platform.fill_keys().len(), 1);
    // The app was killed without locking: its next start is locked, so the key goes.
    let phone = phone.restart();
    assert!(phone.platform.fill_keys().is_empty());
    assert!(
        !phone.vault.settings().device_auth_on_autofill,
        "the switch is kept"
    );
}

#[test]
fn stay_unlocked_replaces_the_fill_key() {
    let phone = gated_phone();
    phone.change(|settings| settings.device_auth_on_autofill = false);
    assert_eq!(phone.platform.fill_keys().len(), 1);
    phone.change(|settings| settings.stay_unlocked = true);
    assert!(phone.platform.fill_keys().is_empty());
    assert_eq!(phone.platform.keys(), 1, "stay unlocked's own key fills");
}

#[test]
fn without_device_unlock_an_unlocked_vault_fills_without_a_prompt() {
    // Lockless (plan 03): nothing to ask with, whatever the switch says.
    let phone = Phone::new(true);
    phone.create();
    phone.change(|settings| settings.stay_unlocked = false);
    phone.wait_for_fill_keys(1);
    assert!(phone.vault.settings().device_auth_on_autofill);
    // Device unlock on: the gate asks again.
    phone.enable_device_unlock();
    assert!(phone.platform.fill_keys().is_empty());
}

#[test]
fn a_phone_without_a_passcode_keeps_no_fill_key() {
    let phone = Phone::new(false);
    phone.create();
    phone.change(|settings| {
        settings.stay_unlocked = false;
        settings.device_auth_on_autofill = false;
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(phone.platform.fill_keys().is_empty());
    assert!(!phone.vault.fills_without_prompt());
}
