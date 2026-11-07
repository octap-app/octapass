//! What the vault needs from the phone, implemented in Swift and Kotlin: the Keychain or
//! Keystore, the device lock, and the system's AutoFill suggestions. And what the app hears
//! about without asking: [`VaultObserver`].
//!
//! Every callback runs on a vault thread, never the main one, so the platform side may block
//! (a Face ID or fingerprint prompt waits for the user). Observers hop to the main thread
//! themselves before touching UI.

use std::path::Path;
use std::sync::Arc;

use octapass_mobile_vault::model::FileSource;
use octapass_mobile_vault::native::NativeFile;
use octapass_mobile_vault::{DeviceLock as VaultDeviceLock, ErrorCode as Code, Native};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::vault::{SessionSnapshot, SyncState};

/// The device's own lock, as device unlock sees it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLock {
    /// Face ID, Touch ID, a fingerprint, a face or at least a passcode is set up.
    pub available: bool,
    /// What people call it here, in English: "Face ID", "Touch ID", "Passcode", "Fingerprint"
    /// or "Screen lock". The UI translates it.
    pub label: String,
}

/// What the system's credential lists need (`ASCredentialIdentityStore` on iOS, the Credential
/// Manager entries on Android), so suggestions show before the vault is unlocked. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialIdentity {
    /// One per saved URL of a login with a password.
    Password {
        item_id: String,
        url: String,
        user: String,
    },
    Passkey {
        item_id: String,
        rp_id: String,
        user_name: String,
        credential_id: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// One per saved URL of a login with a one-time code secret.
    OneTimeCode {
        item_id: String,
        url: String,
        label: String,
    },
}

/// Implemented by the app.
#[uniffi::export(with_foreign)]
pub trait NativePlatform: Send + Sync {
    /// A Keychain (Keystore-backed) item shared with the autofill extension, readable without a
    /// prompt while the phone is unlocked: the Secret Key, the refresh token, the trusted-device
    /// token. `None` when there's none.
    fn secret(&self, name: String) -> Result<Option<String>>;
    fn set_secret(&self, name: String, value: String) -> Result<()>;
    fn delete_secret(&self, name: String) -> Result<()>;

    fn device_lock(&self) -> DeviceLock;
    /// Keeps the 32-byte device-unlock secret behind the device's lock: on iOS
    /// `[.biometryCurrentSet, .or, .devicePasscode]`, on Android a Keystore key that needs
    /// `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` (plan 03).
    fn store_device_secret(&self, name: String, secret: Vec<u8>) -> Result<()>;
    /// Asks for Face ID / the fingerprint or the passcode, showing `reason`, then returns the
    /// secret. Throw `deviceUnlockCancelled` when the user cancels, `deviceUnlockFailed` when the
    /// secret is gone (a new face or finger was enrolled).
    fn device_secret(&self, name: String, reason: String) -> Result<Vec<u8>>;
    fn delete_device_secret(&self, name: String) -> Result<()>;
    /// Asks for Touch ID or the device's password, showing `reason`, with no secret behind it:
    /// the desktop services' approval (the browser extension's unlock, the CLI, an SSH
    /// signature; plan 19). On the Mac `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`,
    /// where the system's sentence continues "Octa Pass is trying to …". Throw
    /// `deviceUnlockCancelled` when the user cancels and `deviceUnlockUnsupported` without a lock.
    /// The phones never call it.
    fn verify_user(&self, reason: String) -> Result<()>;

    /// Stay unlocked (plan 18): keeps `key` where the phone's own lock guards it and nothing
    /// asks for it, shared with the autofill extension or services. iOS: a Keychain item in the
    /// app group with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and no access-control
    /// flags (iOS deletes it when the passcode is removed). Android: encrypted by a Keystore key,
    /// StrongBox where available, with `setUnlockedDeviceRequired(true)` and no
    /// user-authentication requirement. Throw `deviceUnlockUnsupported` without a passcode or
    /// secure lock screen.
    fn store_stay_unlocked_key(&self, name: String, key: Vec<u8>) -> Result<()>;
    /// The key, with no prompt. `None` when there's none or the phone dropped it.
    fn stay_unlocked_key(&self, name: String) -> Result<Option<Vec<u8>>>;
    /// Succeeds when there was none.
    fn delete_stay_unlocked_key(&self, name: String) -> Result<()>;

    /// Replaces what the system suggests in the QuickType bar, the passkey sheet or Credential
    /// Manager.
    fn set_credential_identities(&self, identities: Vec<CredentialIdentity>) -> Result<()>;

    /// New local vaults can be bound to this phone's chip: the Secure Enclave, the Android
    /// Keystore. False on a Simulator.
    fn chip_available(&self) -> bool;
    /// Makes a non-exportable chip key for a local vault, usable with no prompt and on this
    /// device only. `None` when there's no chip. See [`ChipKey`].
    fn create_chip_key(&self, name: String) -> Result<Option<ChipKey>>;
    /// The same 32 bytes `create_chip_key` returned, from the key and its `context`. Throw
    /// `deviceUnlockFailed` when the key is gone.
    fn chip_secret(&self, name: String, context: Vec<u8>) -> Result<Vec<u8>>;
    fn delete_chip_key(&self, name: String) -> Result<()>;
    /// Argon2id at 256 MiB won't fit: true on iOS (the AutoFill extension gets about 120 MiB) and
    /// on a low-memory Android phone.
    fn low_memory(&self) -> bool;

    /// The names of the files in a backup folder the user picked. `folder` is what the app gave
    /// `setBackupFolder`: a security-scoped bookmark on iOS, a tree URI on Android.
    fn backup_folder_files(&self, folder: String) -> Result<Vec<String>>;
    /// Copies the file at `source` into the folder as `name`, replacing one with that name.
    fn write_backup_file(&self, folder: String, name: String, source: String) -> Result<()>;
    fn delete_backup_file(&self, folder: String, name: String) -> Result<()>;
}

/// A new key in the device chip.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChipKey {
    /// What the chip works from; the vault keeps it next to the store. Not a secret. iOS: the
    /// public half of a P-256 key whose private half was thrown away, for ECDH with the Secure
    /// Enclave key. Android: 32 random bytes, for HMAC with a Keystore key.
    pub context: Vec<u8>,
    /// 32 bytes: SHA-256 over what the chip returned.
    pub secret: Vec<u8>,
}

/// What the app hears about without asking. Called on a vault thread.
#[uniffi::export(with_foreign)]
pub trait VaultObserver: Send + Sync {
    /// Signed in or out, locked or unlocked, or the remembered accounts changed.
    fn session_changed(&self, snapshot: SessionSnapshot);
    /// Items changed here or elsewhere: reload what's on screen.
    fn items_changed(&self);
    fn sync_changed(&self, state: SyncState);
    /// Members, families, invitations, share links or emergency contacts changed.
    fn sharing_changed(&self);
}

/// The vault crate's view of the app.
pub(crate) struct Bridge(pub Arc<dyn NativePlatform>);

/// What the vault crate knows of the platform's errors.
fn vault_error(error: VaultError) -> octapass_mobile_vault::VaultError {
    let VaultError::Failed { code, reason } = error;
    let code = match code {
        ErrorCode::DeviceUnlockCancelled => Code::DeviceUnlockCancelled,
        ErrorCode::DeviceUnlockFailed => Code::DeviceUnlockFailed,
        ErrorCode::DeviceUnlockUnsupported => Code::DeviceUnlockUnsupported,
        ErrorCode::PasswordRequired => Code::PasswordRequired,
        _ => Code::Unexpected,
    };
    octapass_mobile_vault::VaultError::new(code, reason)
}

impl Native for Bridge {
    fn secret(&self, name: &str) -> octapass_mobile_vault::Result<Option<Zeroizing<String>>> {
        Ok(self
            .0
            .secret(name.into())
            .map_err(vault_error)?
            .map(Zeroizing::new))
    }

    fn set_secret(&self, name: &str, value: &str) -> octapass_mobile_vault::Result<()> {
        self.0
            .set_secret(name.into(), value.into())
            .map_err(vault_error)
    }

    fn delete_secret(&self, name: &str) -> octapass_mobile_vault::Result<()> {
        self.0.delete_secret(name.into()).map_err(vault_error)
    }

    fn device_lock(&self) -> VaultDeviceLock {
        let lock = self.0.device_lock();
        VaultDeviceLock {
            available: lock.available,
            label: lock.label,
        }
    }

    fn store_device_secret(&self, name: &str, secret: &[u8]) -> octapass_mobile_vault::Result<()> {
        self.0
            .store_device_secret(name.into(), secret.to_vec())
            .map_err(vault_error)
    }

    fn device_secret(
        &self,
        name: &str,
        reason: &str,
    ) -> octapass_mobile_vault::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            self.0
                .device_secret(name.into(), reason.into())
                .map_err(vault_error)?,
        ))
    }

    fn delete_device_secret(&self, name: &str) -> octapass_mobile_vault::Result<()> {
        self.0
            .delete_device_secret(name.into())
            .map_err(vault_error)
    }

    fn verify_user(&self, reason: &str) -> octapass_mobile_vault::Result<()> {
        self.0.verify_user(reason.into()).map_err(vault_error)
    }

    fn store_stay_unlocked_key(&self, name: &str, key: &[u8]) -> octapass_mobile_vault::Result<()> {
        self.0
            .store_stay_unlocked_key(name.into(), key.to_vec())
            .map_err(vault_error)
    }

    fn stay_unlocked_key(
        &self,
        name: &str,
    ) -> octapass_mobile_vault::Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .0
            .stay_unlocked_key(name.into())
            .map_err(vault_error)?
            .map(Zeroizing::new))
    }

    fn delete_stay_unlocked_key(&self, name: &str) -> octapass_mobile_vault::Result<()> {
        self.0
            .delete_stay_unlocked_key(name.into())
            .map_err(vault_error)
    }

    fn set_credential_identities(
        &self,
        identities: &[octapass_ffi::CredentialIdentity],
    ) -> octapass_mobile_vault::Result<()> {
        use octapass_ffi::CredentialIdentity as Ffi;
        let identities = identities
            .iter()
            .cloned()
            .map(|identity| match identity {
                Ffi::Password { item_id, url, user } => {
                    CredentialIdentity::Password { item_id, url, user }
                }
                Ffi::Passkey {
                    item_id,
                    rp_id,
                    user_name,
                    credential_id,
                    user_handle,
                } => CredentialIdentity::Passkey {
                    item_id,
                    rp_id,
                    user_name,
                    credential_id,
                    user_handle,
                },
                Ffi::OneTimeCode {
                    item_id,
                    url,
                    label,
                } => CredentialIdentity::OneTimeCode {
                    item_id,
                    url,
                    label,
                },
            })
            .collect();
        self.0
            .set_credential_identities(identities)
            .map_err(vault_error)
    }

    fn chip_available(&self) -> bool {
        self.0.chip_available()
    }

    fn create_chip_key(
        &self,
        name: &str,
    ) -> octapass_mobile_vault::Result<Option<octapass_mobile_vault::ChipKey>> {
        Ok(self
            .0
            .create_chip_key(name.into())
            .map_err(vault_error)?
            .map(|key| octapass_mobile_vault::ChipKey {
                context: key.context,
                secret: Zeroizing::new(key.secret),
            }))
    }

    fn chip_secret(
        &self,
        name: &str,
        context: &[u8],
    ) -> octapass_mobile_vault::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            self.0
                .chip_secret(name.into(), context.to_vec())
                .map_err(vault_error)?,
        ))
    }

    fn delete_chip_key(&self, name: &str) -> octapass_mobile_vault::Result<()> {
        self.0.delete_chip_key(name.into()).map_err(vault_error)
    }

    fn low_memory(&self) -> bool {
        self.0.low_memory()
    }

    fn backup_folder_files(&self, folder: &str) -> octapass_mobile_vault::Result<Vec<String>> {
        self.0
            .backup_folder_files(folder.into())
            .map_err(vault_error)
    }

    fn write_backup_file(
        &self,
        folder: &str,
        name: &str,
        source: &Path,
    ) -> octapass_mobile_vault::Result<()> {
        self.0
            .write_backup_file(
                folder.into(),
                name.into(),
                source.to_string_lossy().into_owned(),
            )
            .map_err(vault_error)
    }

    fn delete_backup_file(&self, folder: &str, name: &str) -> octapass_mobile_vault::Result<()> {
        self.0
            .delete_backup_file(folder.into(), name.into())
            .map_err(vault_error)
    }

    // The native apps pick and show files with their own UI and hand the vault paths
    // (`addAttachment`, `openAttachment`), so the vault never asks for these.

    fn file_sources(&self) -> Vec<FileSource> {
        Vec::new()
    }

    fn pick_files(
        &self,
        _source: FileSource,
        _into: &Path,
    ) -> octapass_mobile_vault::Result<Vec<NativeFile>> {
        Err(octapass_mobile_vault::VaultError::unexpected(
            "the native apps use their own picker",
        ))
    }

    fn pick_image(&self, _into: &Path) -> octapass_mobile_vault::Result<Option<NativeFile>> {
        Err(octapass_mobile_vault::VaultError::unexpected(
            "the native apps use their own picker",
        ))
    }

    fn open_file(
        &self,
        _path: &Path,
        _name: &str,
        _media_type: &str,
    ) -> octapass_mobile_vault::Result<()> {
        Err(Code::NoFileViewer.into())
    }
}
