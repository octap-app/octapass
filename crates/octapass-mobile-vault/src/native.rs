//! What the vault needs from the phone itself. The native apps implement it through
//! `crates/octapass-mobile`'s platform callbacks (the Keychain or Keystore, the device lock, the
//! system pickers and viewer); tests use [`fake::FakeNative`].

use std::path::{Path, PathBuf};

use octapass_ffi::CredentialIdentity;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::model::FileSource;

/// A file the system picker chose, copied into the folder the vault asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFile {
    pub path: PathBuf,
    pub name: String,
    /// Empty when the system doesn't know.
    pub media_type: String,
}

/// Items another password manager on the phone handed over.
pub struct ReceivedCredentials {
    /// CXF: a `Header`, or a single `Account`.
    pub json: Zeroizing<String>,
    /// The app's name, as the phone shows it.
    pub from: String,
}

/// A new key in the device chip (plan 03, *Local mode keys*).
pub struct ChipKey {
    /// What the chip works from: kept next to the vault, not a secret.
    pub context: Vec<u8>,
    /// `hw_secret`: 32 bytes the chip alone can produce again from the context.
    pub secret: Zeroizing<Vec<u8>>,
}

/// The device's own lock, as device unlock sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLock {
    /// Face ID, Touch ID or at least a passcode is set up.
    pub available: bool,
    /// What people call it here: "Face ID", "Touch ID" or "Passcode".
    pub label: String,
}

pub trait Native: Send + Sync {
    /// A secret in the Keychain, shared with the AutoFill extension and readable without a
    /// prompt while the device is unlocked (the Secret Key, the refresh token).
    fn secret(&self, name: &str) -> Result<Option<Zeroizing<String>>>;
    fn set_secret(&self, name: &str, value: &str) -> Result<()>;
    fn delete_secret(&self, name: &str) -> Result<()>;

    fn device_lock(&self) -> DeviceLock;
    /// Keeps the device-unlock secret behind Face ID / Touch ID or the device passcode
    /// (`[.biometryCurrentSet, .or, .devicePasscode]`, plan 03).
    fn store_device_secret(&self, name: &str, secret: &[u8]) -> Result<()>;
    /// Asks for Face ID / Touch ID or the passcode, then returns the secret. Fails with
    /// `deviceUnlockCancelled` when the user cancels, and `deviceUnlockFailed` when the secret is
    /// gone (a new face or fingerprint was enrolled).
    fn device_secret(&self, name: &str, reason: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn delete_device_secret(&self, name: &str) -> Result<()>;

    /// Asks for Touch ID or the device password, saying `reason`, with no secret behind it: the
    /// desktop services' approval for the browser extension or the CLI (plan 19, phase 3). Fails
    /// with `deviceUnlockCancelled` when the user cancels, and `deviceUnlockUnsupported` where
    /// there's no lock to ask (the phones never call it).
    fn verify_user(&self, _reason: &str) -> Result<()> {
        Err(ErrorCode::DeviceUnlockUnsupported.into())
    }

    /// Stay unlocked (plan 18): keeps the stay-unlocked key where the phone's own lock guards it
    /// and nothing asks for it. iOS: a Keychain item with
    /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and no access-control flags, shared with
    /// the AutoFill extension. Android: encrypted by a Keystore key (StrongBox where available)
    /// with `setUnlockedDeviceRequired(true)` and no user-authentication requirement.
    fn store_stay_unlocked_key(&self, _name: &str, _key: &[u8]) -> Result<()> {
        Err(ErrorCode::DeviceUnlockUnsupported.into())
    }
    /// The key, without a prompt. `None` when there is none, or the phone dropped it (its
    /// passcode was removed).
    fn stay_unlocked_key(&self, _name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(None)
    }
    /// Succeeds when there was none.
    fn delete_stay_unlocked_key(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    /// Replaces what the system suggests in the QuickType bar and the passkey sheet.
    fn set_credential_identities(&self, identities: &[CredentialIdentity]) -> Result<()>;

    /// Shows the system's list of password managers on the phone that can hand over their items
    /// (Android's credential transfer), and returns what the chosen one handed over, in the
    /// FIDO Credential Exchange Format. `None` when the user backs out. Phones without such a
    /// list fail with `unexpected`.
    fn receive_credentials(&self) -> Result<Option<ReceivedCredentials>> {
        Err(VaultError::unexpected(
            "this phone can't receive items from other apps",
        ))
    }

    /// Whether [`create_chip_key`](Self::create_chip_key) can work here: Secure Enclave, Android
    /// Keystore. Simulators have none.
    fn chip_available(&self) -> bool {
        false
    }

    /// Makes a non-exportable key in the device chip for a local vault. It needs no prompt: it
    /// only ever works together with the master password. `None` when there's no chip.
    fn create_chip_key(&self, _name: &str) -> Result<Option<ChipKey>> {
        Ok(None)
    }

    /// `hw_secret` again, from the chip key and the context it gave. Fails with
    /// `deviceUnlockFailed` when the key is gone.
    fn chip_secret(&self, _name: &str, _context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(ErrorCode::DeviceUnlockFailed.into())
    }

    fn delete_chip_key(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    /// Argon2id at 256 MiB doesn't fit here: an iOS AutoFill extension gets about 120 MiB, a
    /// low-memory phone less.
    fn low_memory(&self) -> bool {
        true
    }

    /// The file names in a backup folder the user picked.
    fn backup_folder_files(&self, _folder: &str) -> Result<Vec<String>> {
        Err(VaultError::unexpected("this app has no backup folders"))
    }

    /// Copies the file at `source` into a backup folder as `name`, replacing one with that name.
    fn write_backup_file(&self, _folder: &str, _name: &str, _source: &Path) -> Result<()> {
        Err(VaultError::unexpected("this app has no backup folders"))
    }

    fn delete_backup_file(&self, _folder: &str, _name: &str) -> Result<()> {
        Err(VaultError::unexpected("this app has no backup folders"))
    }

    /// Where files can be picked from here: the camera only on a device that has one.
    fn file_sources(&self) -> Vec<FileSource>;
    /// Shows the system picker for `source` and copies what the user chose into `into`, a new
    /// folder in the app's private storage. Empty when they cancel.
    fn pick_files(&self, source: FileSource, into: &Path) -> Result<Vec<NativeFile>>;
    /// Shows the photo library for one image, to read its QR codes, and copies it into `into`
    /// as a PNG, JPEG, WebP or GIF: a photo stored in another format (HEIC) is converted to
    /// JPEG. `None` when the user cancels.
    fn pick_image(&self, into: &Path) -> Result<Option<NativeFile>>;
    /// Shows a decrypted file in the system viewer (Quick Look on iOS, the app the user picks on
    /// Android), which can also share it. Returns once the viewer is closed; the vault then
    /// deletes the file. Fails with `noFileViewer` when nothing on the phone opens it.
    fn open_file(&self, path: &Path, name: &str, media_type: &str) -> Result<()>;
}

#[cfg(any(test, feature = "fake"))]
pub mod fake {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// An in-memory Keychain and device lock.
    pub struct FakeNative {
        pub lock: DeviceLock,
        pub secrets: Mutex<HashMap<String, String>>,
        pub device_secrets: Mutex<HashMap<String, Vec<u8>>>,
        /// Stay-unlocked keys (plan 18), by name.
        pub stay_unlocked: Mutex<HashMap<String, Vec<u8>>>,
        /// The next device prompt is cancelled.
        pub cancel_next_prompt: Mutex<bool>,
        /// What every device prompt said, in order.
        pub prompts: Mutex<Vec<String>>,
        pub identities: Mutex<Vec<CredentialIdentity>>,
        /// What the next `pick_files` "chooses": names, types and contents.
        pub picks: Mutex<Vec<(String, String, Vec<u8>)>>,
        /// What the viewer showed.
        pub opened: Mutex<Vec<Opened>>,
        /// What the next `receive_credentials` hands over: the app's name and the CXF. `None`
        /// backs out.
        pub received: Mutex<Option<(String, String)>>,
        /// This phone has a chip.
        pub chip: bool,
        /// The chip's keys, by name.
        pub chip_keys: Mutex<HashMap<String, [u8; 32]>>,
        /// The backup folders' files, by folder and name.
        pub backup_folders: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
        /// The folder is out of reach (a cloud drive that's offline).
        pub backup_folder_fails: Mutex<bool>,
    }

    /// A file the fake viewer showed, and where it was.
    #[derive(Debug, Clone)]
    pub struct Opened {
        pub name: String,
        pub media_type: String,
        pub contents: Vec<u8>,
        pub path: PathBuf,
    }

    impl Default for FakeNative {
        fn default() -> Self {
            Self {
                lock: DeviceLock {
                    available: true,
                    label: "Face ID".into(),
                },
                secrets: Mutex::default(),
                device_secrets: Mutex::default(),
                stay_unlocked: Mutex::default(),
                cancel_next_prompt: Mutex::new(false),
                prompts: Mutex::default(),
                identities: Mutex::default(),
                picks: Mutex::default(),
                opened: Mutex::default(),
                received: Mutex::default(),
                chip: true,
                chip_keys: Mutex::default(),
                backup_folders: Mutex::default(),
                backup_folder_fails: Mutex::new(false),
            }
        }
    }

    impl FakeNative {
        pub fn secret_names(&self) -> Vec<String> {
            self.secrets.lock().unwrap().keys().cloned().collect()
        }
    }

    impl Native for FakeNative {
        fn secret(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(self
                .secrets
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(Zeroizing::new))
        }

        fn set_secret(&self, name: &str, value: &str) -> Result<()> {
            self.secrets
                .lock()
                .unwrap()
                .insert(name.into(), value.into());
            Ok(())
        }

        fn delete_secret(&self, name: &str) -> Result<()> {
            self.secrets.lock().unwrap().remove(name);
            Ok(())
        }

        fn device_lock(&self) -> DeviceLock {
            self.lock.clone()
        }

        fn store_device_secret(&self, name: &str, secret: &[u8]) -> Result<()> {
            self.device_secrets
                .lock()
                .unwrap()
                .insert(name.into(), secret.to_vec());
            Ok(())
        }

        fn device_secret(&self, name: &str, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.prompts.lock().unwrap().push(reason.into());
            if std::mem::take(&mut *self.cancel_next_prompt.lock().unwrap()) {
                return Err(ErrorCode::DeviceUnlockCancelled.into());
            }
            self.device_secrets
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| VaultError::new(ErrorCode::DeviceUnlockFailed, "no device secret"))
        }

        fn delete_device_secret(&self, name: &str) -> Result<()> {
            self.device_secrets.lock().unwrap().remove(name);
            Ok(())
        }

        fn verify_user(&self, reason: &str) -> Result<()> {
            if !self.lock.available {
                return Err(ErrorCode::DeviceUnlockUnsupported.into());
            }
            self.prompts.lock().unwrap().push(reason.into());
            if std::mem::take(&mut *self.cancel_next_prompt.lock().unwrap()) {
                return Err(ErrorCode::DeviceUnlockCancelled.into());
            }
            Ok(())
        }

        fn store_stay_unlocked_key(&self, name: &str, key: &[u8]) -> Result<()> {
            if !self.lock.available {
                return Err(ErrorCode::DeviceUnlockUnsupported.into());
            }
            self.stay_unlocked
                .lock()
                .unwrap()
                .insert(name.into(), key.to_vec());
            Ok(())
        }

        fn stay_unlocked_key(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .stay_unlocked
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(Zeroizing::new))
        }

        fn delete_stay_unlocked_key(&self, name: &str) -> Result<()> {
            self.stay_unlocked.lock().unwrap().remove(name);
            Ok(())
        }

        fn set_credential_identities(&self, identities: &[CredentialIdentity]) -> Result<()> {
            *self.identities.lock().unwrap() = identities.to_vec();
            Ok(())
        }

        fn receive_credentials(&self) -> Result<Option<ReceivedCredentials>> {
            Ok(self
                .received
                .lock()
                .unwrap()
                .take()
                .map(|(from, json)| ReceivedCredentials {
                    json: Zeroizing::new(json),
                    from,
                }))
        }

        fn chip_available(&self) -> bool {
            self.chip
        }

        fn create_chip_key(&self, name: &str) -> Result<Option<ChipKey>> {
            if !self.chip {
                return Ok(None);
            }
            let key: [u8; 32] = rand_core::RngCore::next_u64(&mut rand_core::OsRng)
                .to_be_bytes()
                .repeat(4)
                .try_into()
                .expect("32 bytes");
            self.chip_keys.lock().unwrap().insert(name.into(), key);
            let context = vec![5u8; 65];
            let secret = self.chip_secret(name, &context)?;
            Ok(Some(ChipKey { context, secret }))
        }

        fn chip_secret(&self, name: &str, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            use sha2::{Digest, Sha256};
            let keys = self.chip_keys.lock().unwrap();
            let key = keys
                .get(name)
                .ok_or_else(|| VaultError::new(ErrorCode::DeviceUnlockFailed, "no chip key"))?;
            Ok(Zeroizing::new(
                Sha256::digest([key.as_slice(), context].concat()).to_vec(),
            ))
        }

        fn delete_chip_key(&self, name: &str) -> Result<()> {
            self.chip_keys.lock().unwrap().remove(name);
            Ok(())
        }

        fn low_memory(&self) -> bool {
            true
        }

        fn backup_folder_files(&self, folder: &str) -> Result<Vec<String>> {
            let folders = self.backup_folders.lock().unwrap();
            Ok(folders
                .get(folder)
                .map(|files| files.keys().cloned().collect())
                .unwrap_or_default())
        }

        fn write_backup_file(&self, folder: &str, name: &str, source: &Path) -> Result<()> {
            if *self.backup_folder_fails.lock().unwrap() {
                return Err(VaultError::unexpected("the folder is out of reach"));
            }
            let contents =
                std::fs::read(source).map_err(|error| VaultError::unexpected(error.to_string()))?;
            self.backup_folders
                .lock()
                .unwrap()
                .entry(folder.into())
                .or_default()
                .insert(name.into(), contents);
            Ok(())
        }

        fn delete_backup_file(&self, folder: &str, name: &str) -> Result<()> {
            if let Some(files) = self.backup_folders.lock().unwrap().get_mut(folder) {
                files.remove(name);
            }
            Ok(())
        }

        fn file_sources(&self) -> Vec<FileSource> {
            vec![FileSource::Files, FileSource::Photos]
        }

        fn pick_files(&self, _source: FileSource, into: &Path) -> Result<Vec<NativeFile>> {
            let picks = std::mem::take(&mut *self.picks.lock().unwrap());
            picks
                .into_iter()
                .enumerate()
                .map(|(index, (name, media_type, contents))| {
                    let path = into.join(format!("{index}-{name}"));
                    std::fs::write(&path, contents)
                        .map_err(|error| VaultError::unexpected(error.to_string()))?;
                    Ok(NativeFile {
                        path,
                        name,
                        media_type,
                    })
                })
                .collect()
        }

        fn pick_image(&self, into: &Path) -> Result<Option<NativeFile>> {
            let mut picks = self.picks.lock().unwrap();
            if picks.is_empty() {
                return Ok(None);
            }
            let (name, media_type, contents) = picks.remove(0);
            let path = into.join(&name);
            std::fs::write(&path, contents)
                .map_err(|error| VaultError::unexpected(error.to_string()))?;
            Ok(Some(NativeFile {
                path,
                name,
                media_type,
            }))
        }

        fn open_file(&self, path: &Path, name: &str, media_type: &str) -> Result<()> {
            let contents =
                std::fs::read(path).map_err(|error| VaultError::unexpected(error.to_string()))?;
            self.opened.lock().unwrap().push(Opened {
                name: name.into(),
                media_type: media_type.into(),
                contents,
                path: path.to_owned(),
            });
            Ok(())
        }
    }
}
