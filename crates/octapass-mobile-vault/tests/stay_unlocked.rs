//! Stay unlocked while logged in to this phone (plan 18), on a vault on this phone only, with
//! `FakeNative` for the Keychain and the device lock. The 14-day check is tested in `octapass-ffi`
//! (`store::stay_unlocked`), where the store's clock can be moved.

use std::sync::Arc;

use octapass_core::kdf::KdfParams;
use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::SessionStatus;
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, DeviceLock, ErrorCode, Vault};
use tempfile::TempDir;
use zeroize::Zeroizing;

const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";
const NEW_STRONG: &str = "plucky-otter-saxophone-nebula-fig";

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    dir: TempDir,
}

impl Phone {
    fn new(native: FakeNative) -> Self {
        Self::open(Arc::new(native), tempfile::tempdir().unwrap())
    }

    fn open(native: Arc<FakeNative>, dir: TempDir) -> Self {
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
            Box::new(|_| {}),
        )
        .unwrap();
        Self { vault, native, dir }
    }

    /// The app was closed and opened again.
    fn restart(self) -> Self {
        Self::open(self.native, self.dir)
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }

    fn keys(&self) -> usize {
        self.native.stay_unlocked.lock().unwrap().len()
    }
}

fn with_vault(native: FakeNative) -> Phone {
    let phone = Phone::new(native);
    phone
        .vault
        .create_local_vault_with("Home", secret(STRONG), KdfParams::DEFAULT)
        .unwrap();
    phone
}

#[test]
fn a_started_app_opens_without_a_prompt_only_while_it_is_on() {
    let phone = with_vault(FakeNative::default());
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    let status = phone.vault.stay_unlocked_status();
    assert!(status.available && !status.enrolled && !status.password_required);

    phone.vault.enable_stay_unlocked().unwrap();
    assert!(phone.vault.stay_unlocked_status().enrolled);
    let phone = phone.restart();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert!(phone.vault.unlock_stay_unlocked().unwrap());
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    // No prompt was shown: the device-unlock secret was never asked for.
    assert!(phone.native.device_secrets.lock().unwrap().is_empty());

    // Off: the next start asks as before.
    phone.vault.disable_stay_unlocked().unwrap();
    let phone = phone.restart();
    assert!(!phone.vault.unlock_stay_unlocked().unwrap());
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert!(!phone.vault.stay_unlocked_status().enrolled);
}

#[test]
fn a_phone_without_a_passcode_falls_back() {
    let no_lock = FakeNative {
        lock: DeviceLock {
            available: false,
            label: "Passcode".into(),
        },
        ..FakeNative::default()
    };
    let phone = with_vault(no_lock);
    assert!(!phone.vault.stay_unlocked_status().available);
    assert_eq!(
        phone.vault.enable_stay_unlocked().unwrap_err().code,
        ErrorCode::DeviceUnlockUnsupported
    );
    assert_eq!(phone.keys(), 0);
}

#[test]
fn a_key_left_after_the_passcode_went_is_deleted_not_used() {
    let phone = with_vault(FakeNative::default());
    phone.vault.enable_stay_unlocked().unwrap();
    let key = phone.native.stay_unlocked.lock().unwrap().clone();
    // The passcode was removed, but the platform kept the item (it shouldn't).
    let no_lock = FakeNative {
        lock: DeviceLock {
            available: false,
            label: "Passcode".into(),
        },
        ..FakeNative::default()
    };
    *no_lock.stay_unlocked.lock().unwrap() = key;
    let phone = Phone::open(Arc::new(no_lock), phone.dir);
    assert!(!phone.vault.unlock_stay_unlocked().unwrap());
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert_eq!(phone.keys(), 0);
}

#[test]
fn a_master_password_change_deletes_the_key() {
    let phone = with_vault(FakeNative::default());
    phone.vault.enable_stay_unlocked().unwrap();
    assert_eq!(phone.keys(), 1);
    phone
        .vault
        .change_master_password(secret(STRONG), secret(NEW_STRONG))
        .unwrap();
    assert_eq!(phone.keys(), 0);
    let phone = phone.restart();
    assert!(!phone.vault.unlock_stay_unlocked().unwrap());
}

#[test]
fn a_key_that_no_longer_opens_the_vault_is_deleted() {
    let phone = with_vault(FakeNative::default());
    phone.vault.enable_stay_unlocked().unwrap();
    for key in phone.native.stay_unlocked.lock().unwrap().values_mut() {
        key[1] ^= 1;
    }
    let phone = phone.restart();
    assert!(!phone.vault.unlock_stay_unlocked().unwrap());
    assert_eq!(phone.keys(), 0);
}

#[test]
fn turning_device_unlock_off_keeps_stay_unlocked() {
    let phone = with_vault(FakeNative::default());
    phone.vault.enable_device_unlock().unwrap();
    phone.vault.enable_stay_unlocked().unwrap();
    phone.vault.disable_device_unlock().unwrap();
    assert_eq!(phone.keys(), 1);
    assert!(phone.native.device_secrets.lock().unwrap().is_empty());
}

// ---------- The fill key: the autofill gate off (plan 03) ----------

fn fill_keys(phone: &Phone) -> Vec<Vec<u8>> {
    phone
        .native
        .stay_unlocked
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, _)| name.starts_with("unlockedFill."))
        .map(|(_, key)| key.clone())
        .collect()
}

/// The store as the AutoFill extension or the Android services open it: on its own.
fn extension_store(phone: &Phone) -> Arc<octapass_ffi::LocalStore> {
    let file = std::fs::read_dir(phone.dir.path().join("group"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "opstore"))
        .unwrap();
    octapass_ffi::LocalStore::open(file.to_string_lossy().into_owned()).unwrap()
}

fn in_a_minute() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    u64::try_from(now.as_millis()).unwrap() + 60_000
}

#[test]
fn the_fill_key_fills_while_the_app_is_unlocked_and_goes_when_it_locks() {
    let phone = with_vault(FakeNative::default());
    assert!(!phone.vault.has_fill_key());
    phone.vault.store_fill_key(in_a_minute()).unwrap();
    assert!(phone.vault.has_fill_key());
    let keys = fill_keys(&phone);
    assert_eq!(keys.len(), 1);
    // The extension opens the store with it and no prompt.
    let store = extension_store(&phone);
    assert!(store.unlock_fill_key(keys[0].clone()).unwrap().is_some());
    assert!(phone.native.device_secrets.lock().unwrap().is_empty());
    // It's not stay unlocked's key: that switch's state is untouched.
    assert!(!phone.vault.stay_unlocked_status().enrolled);

    // Locking (Lock now, the timer, the background) deletes it: the next fill asks.
    phone.vault.lock();
    assert!(fill_keys(&phone).is_empty());
    assert!(!phone.vault.has_fill_key());
}

#[test]
fn the_fill_key_is_turned_off_and_ends_with_the_device_keys() {
    let phone = with_vault(FakeNative::default());
    phone.vault.store_fill_key(in_a_minute()).unwrap();
    phone.vault.delete_fill_key();
    assert!(fill_keys(&phone).is_empty());

    phone.vault.store_fill_key(in_a_minute()).unwrap();
    phone
        .vault
        .change_master_password(secret(STRONG), secret(NEW_STRONG))
        .unwrap();
    assert!(fill_keys(&phone).is_empty(), "a password change ends it");

    phone.vault.store_fill_key(in_a_minute()).unwrap();
    phone.vault.delete_local_vault(secret(NEW_STRONG)).unwrap();
    assert!(fill_keys(&phone).is_empty(), "forgetting the vault ends it");
}

#[test]
fn a_phone_without_a_passcode_keeps_no_fill_key() {
    let no_lock = FakeNative {
        lock: DeviceLock {
            available: false,
            label: "Passcode".into(),
        },
        ..FakeNative::default()
    };
    let phone = with_vault(no_lock);
    assert_eq!(
        phone.vault.store_fill_key(in_a_minute()).unwrap_err().code,
        ErrorCode::DeviceUnlockUnsupported
    );
    assert!(fill_keys(&phone).is_empty());
}

#[test]
fn a_locked_vault_keeps_no_fill_key() {
    let phone = with_vault(FakeNative::default());
    phone.vault.lock();
    assert_eq!(
        phone.vault.store_fill_key(in_a_minute()).unwrap_err().code,
        ErrorCode::Locked
    );
}
