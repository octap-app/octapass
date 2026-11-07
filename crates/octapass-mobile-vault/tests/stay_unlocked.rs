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
