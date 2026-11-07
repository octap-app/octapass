//! Octa Pass Safe for the native apps (plan 16 §4): `SafeDrive` is an open Safe, which Android's
//! DocumentsProvider and the apps' own screens use. It lives only while the vault is unlocked: the
//! app locks it when the vault locks, and after that every call throws `Locked`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use octapass_files::safe::sync::block_on_ready;
use octapass_files::safe::{Entry, Safe, SafeError, Warning};
use zeroize::Zeroizing;

use crate::background::background;
use crate::error::{ErrorCode, Result, VaultError};
use crate::vault::OctaPassVault;

fn failure(error: SafeError) -> VaultError {
    match error {
        SafeError::Locked => VaultError::from(ErrorCode::Locked),
        SafeError::NotFound => ErrorCode::NotFound.into(),
        SafeError::Exists
        | SafeError::IsFolder
        | SafeError::NotFolder
        | SafeError::NotEmpty
        | SafeError::InvalidName
        | SafeError::InvalidMove => ErrorCode::NotAllowed.into(),
        other => VaultError::unexpected(other.to_string()),
    }
}

/// The top folder of every Safe.
#[uniffi::export]
pub fn safe_root_id() -> String {
    octapass_files::safe::ROOT_ID.to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SafeItem {
    pub item_id: String,
    pub safe_id: String,
    pub name: String,
    /// Whether its encrypted blobs go through the server to the account's other devices.
    pub sync: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SafeEntry {
    pub id: String,
    pub parent: String,
    pub name: String,
    pub folder: bool,
    pub size: u64,
    /// Milliseconds since 1970.
    pub modified: u64,
}

impl From<Entry> for SafeEntry {
    fn from(entry: Entry) -> Self {
        Self {
            id: entry.id,
            parent: entry.parent,
            name: entry.name,
            folder: entry.folder,
            size: entry.size,
            modified: entry.modified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SafeWarning {
    Damaged,
    RolledBack,
    Missing,
    Orphaned { name: String },
}

impl From<Warning> for SafeWarning {
    fn from(warning: Warning) -> Self {
        match warning {
            Warning::DamagedBlob { .. } => Self::Damaged,
            Warning::RolledBack { .. } => Self::RolledBack,
            Warning::Missing { .. } => Self::Missing,
            Warning::Orphaned { name } => Self::Orphaned { name },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SafeSyncSummary {
    /// Copies kept because a file changed on two devices.
    pub conflicts: Vec<String>,
    /// Files too big for this server, which stay on this device.
    pub too_big: Vec<String>,
}

/// An open Safe.
#[derive(uniffi::Object)]
pub struct SafeDrive {
    safe: Arc<Safe>,
}

#[uniffi::export]
impl SafeDrive {
    /// Opens a Safe with its key directly, for the iPhone's Files extension, which gets the key
    /// from the app while the vault is unlocked (plan 03 History, 2026-11-04). The app itself uses
    /// `OctaPassVault.openSafe`.
    #[uniffi::constructor]
    pub fn open_with_key(folder: String, safe_id: String, key: Vec<u8>) -> Result<Arc<Self>> {
        let path = PathBuf::from(folder).join(folder_name(&safe_id)?);
        let bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::unexpected("a Safe key is 32 bytes"))?;
        let key = octapass_core::keys::SymmetricKey::from_bytes(bytes);
        Ok(Arc::new(Self {
            safe: open_at(&path, &safe_id, &key)?,
        }))
    }

    pub fn is_locked(&self) -> bool {
        self.safe.is_locked()
    }

    /// Flushes open files and drops every key. Every later call throws `Locked`.
    pub fn lock(&self) -> Result<()> {
        self.safe.lock().map_err(failure)
    }

    pub fn warnings(&self) -> Result<Vec<SafeWarning>> {
        Ok(self
            .safe
            .warnings()
            .map_err(failure)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn entry(&self, id: String) -> Result<SafeEntry> {
        Ok(self.safe.entry(&id).map_err(failure)?.into())
    }

    pub fn list(&self, folder: String) -> Result<Vec<SafeEntry>> {
        Ok(self
            .safe
            .list(&folder)
            .map_err(failure)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn create_file(&self, folder: String, name: String) -> Result<SafeEntry> {
        Ok(self
            .safe
            .create_file(&folder, &name)
            .map_err(failure)?
            .into())
    }

    pub fn create_folder(&self, folder: String, name: String) -> Result<SafeEntry> {
        Ok(self
            .safe
            .create_folder(&folder, &name)
            .map_err(failure)?
            .into())
    }

    pub fn rename(&self, id: String, folder: String, name: String) -> Result<()> {
        self.safe.rename(&id, &folder, &name).map_err(failure)
    }

    /// Deletes a file, or a folder and everything in it.
    pub fn remove(&self, id: String) -> Result<()> {
        self.safe.remove_all(&id).map_err(failure)
    }

    /// Replaces a file's contents with those of the file at `path`, as one new revision.
    pub async fn import_file(self: Arc<Self>, id: String, path: String) -> Result<u64> {
        background(move || {
            let mut input =
                fs::File::open(&path).map_err(|error| VaultError::unexpected(error.to_string()))?;
            self.safe.import(&id, &mut input).map_err(failure)
        })
        .await
    }

    /// Decrypts a file to `path`. The caller owns that plaintext and removes it when it's done.
    pub async fn export_file(self: Arc<Self>, id: String, path: String) -> Result<u64> {
        background(move || {
            let mut output = fs::File::create(&path)
                .map_err(|error| VaultError::unexpected(error.to_string()))?;
            self.safe.export(&id, &mut output).map_err(failure)
        })
        .await
    }

    /// Part of a file, decrypted, for streaming.
    pub fn read(&self, id: String, offset: u64, size: u32) -> Result<Vec<u8>> {
        Ok(self
            .safe
            .read(&id, offset, size as usize)
            .map_err(failure)?
            .to_vec())
    }

    /// Changes part of a file. What's written waits in the engine's staging file, sealed under a
    /// throwaway key, so no plaintext reaches the disk. `flush` makes it a new revision.
    pub fn write(&self, id: String, offset: u64, data: Vec<u8>) -> Result<()> {
        let data = Zeroizing::new(data);
        self.safe.write(&id, offset, &data).map_err(failure)
    }

    /// Cuts or extends a file to `size`, in staging like `write`.
    pub fn truncate(&self, id: String, size: u64) -> Result<()> {
        self.safe.truncate(&id, size).map_err(failure)
    }

    /// Seals what was written to a file as a new revision. Locking does this too.
    pub fn flush(&self, id: String) -> Result<()> {
        self.safe.flush(&id).map_err(failure)
    }
}

fn item(info: octapass_mobile_vault::vault::safes::SafeInfo) -> SafeItem {
    SafeItem {
        item_id: info.item_id,
        safe_id: info.safe_id,
        name: info.name,
        sync: info.sync,
    }
}

/// A Safe's id names its folder, and it comes from an item, which in a shared vault someone else
/// wrote: nothing in it may lead out of the folder the app picked.
fn folder_name(safe_id: &str) -> Result<&str> {
    let plain = !safe_id.is_empty()
        && safe_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    plain
        .then_some(safe_id)
        .ok_or_else(|| ErrorCode::NotFound.into())
}

fn open_at(
    folder: &Path,
    safe_id: &str,
    key: &octapass_core::keys::SymmetricKey,
) -> Result<Arc<Safe>> {
    let safe = if folder.join("safe.json").exists() {
        Safe::open(folder, key)
    } else {
        Safe::create(folder, safe_id, key)
    }
    .map_err(failure)?;
    Ok(Arc::new(safe))
}

#[uniffi::export]
impl OctaPassVault {
    /// The Safes on this device: every synced one, and those kept here. A Safe kept on another
    /// device isn't listed, though its item syncs with the vault. `folder` is where the app keeps
    /// Safes (as for `open_safe`): one made before Safes named their device lists only where its
    /// folder is, or everywhere without it.
    #[uniffi::method(default(folder = None))]
    pub async fn list_safes(self: Arc<Self>, folder: Option<String>) -> Result<Vec<SafeItem>> {
        self.run(move |this| {
            let folder = folder.map(PathBuf::from);
            Ok(this
                .vault
                .list_safes(folder.as_deref())?
                .into_iter()
                .map(item)
                .collect())
        })
        .await
    }

    pub async fn create_safe(self: Arc<Self>, name: String, sync: bool) -> Result<SafeItem> {
        self.run(move |this| Ok(item(this.vault.create_safe(&name, sync)?)))
            .await
    }

    /// Opens a Safe kept under `folder`, which the app picks (its own private storage), making it
    /// on first use.
    pub async fn open_safe(
        self: Arc<Self>,
        item_id: String,
        folder: String,
    ) -> Result<Arc<SafeDrive>> {
        self.run(move |this| {
            let vault = &this.vault;
            let safes = vault.list_safes(Some(Path::new(&folder)))?;
            let info = safes
                .iter()
                .find(|safe| safe.item_id == item_id)
                .ok_or(ErrorCode::NotFound)?;
            let key = vault.safe_key(&item_id)?;
            let path = PathBuf::from(&folder).join(folder_name(&info.safe_id)?);
            Ok(Arc::new(SafeDrive {
                safe: open_at(&path, &info.safe_id, &key)?,
            }))
        })
        .await
    }

    /// A Safe's key, for the iPhone's Files extension: the app keeps it in the shared Keychain only
    /// while the vault is unlocked (plan 03 History, 2026-11-04). Never shown, never synced.
    pub async fn safe_key(self: Arc<Self>, item_id: String) -> Result<Vec<u8>> {
        self.run(move |this| Ok(this.vault.safe_key(&item_id)?.as_bytes().to_vec()))
            .await
    }

    /// Deletes a Safe: its item (and key) goes to the trash, and its folder under `folder` goes now.
    /// Lock its drive first.
    pub async fn delete_safe(self: Arc<Self>, item_id: String, folder: String) -> Result<()> {
        self.run(move |this| {
            let info = this
                .vault
                .list_safes(Some(Path::new(&folder)))?
                .into_iter()
                .find(|safe| safe.item_id == item_id)
                .ok_or(ErrorCode::NotFound)?;
            this.vault.delete_safe(&item_id)?;
            let path = PathBuf::from(&folder).join(folder_name(&info.safe_id)?);
            if path.exists() {
                fs::remove_dir_all(&path)
                    .map_err(|error| VaultError::unexpected(error.to_string()))?;
            }
            Ok(())
        })
        .await
    }

    /// Sends and fetches a synced Safe's changes through the server.
    pub async fn sync_safe(
        self: Arc<Self>,
        item_id: String,
        drive: Arc<SafeDrive>,
    ) -> Result<SafeSyncSummary> {
        self.run(move |this| {
            let remote = this.vault.safe_remote(&item_id)?;
            let report = block_on_ready(drive.safe.sync(&remote)).map_err(failure)?;
            Ok(SafeSyncSummary {
                conflicts: report.conflicts,
                too_big: report.too_big,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::keys::SymmetricKey;

    use super::*;

    #[test]
    fn a_drive_opens_with_its_key_alone() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().to_string_lossy().into_owned();
        let safe_id = "33333333-3333-4333-8333-333333333333".to_owned();
        let drive = SafeDrive::open_with_key(folder.clone(), safe_id.clone(), vec![3; 32]).unwrap();
        drive.create_folder(safe_root_id(), "Scans".into()).unwrap();
        drive.lock().unwrap();
        let again = SafeDrive::open_with_key(folder.clone(), safe_id.clone(), vec![3; 32]).unwrap();
        assert_eq!(again.list(safe_root_id()).unwrap().len(), 1);
        assert!(SafeDrive::open_with_key(folder.clone(), "../up".into(), vec![3; 32]).is_err());
        assert!(SafeDrive::open_with_key(folder, safe_id, vec![3; 31]).is_err());
    }

    #[test]
    fn a_drive_stops_working_once_locked() {
        let dir = tempfile::tempdir().unwrap();
        let key = SymmetricKey::from_bytes([1; 32]);
        let drive = SafeDrive {
            safe: open_at(
                &dir.path().join("s"),
                "11111111-1111-4111-8111-111111111111",
                &key,
            )
            .unwrap(),
        };
        let file = drive.create_file(safe_root_id(), "a.txt".into()).unwrap();
        assert_eq!(drive.list(safe_root_id()).unwrap(), vec![file.clone()]);
        drive.lock().unwrap();
        assert!(drive.is_locked());
        let error = drive.list(safe_root_id()).unwrap_err();
        assert!(format!("{error:?}").contains("Locked"), "{error:?}");
    }

    #[test]
    fn writes_show_at_once_and_stay_after_a_flush() {
        let dir = tempfile::tempdir().unwrap();
        let key = SymmetricKey::from_bytes([2; 32]);
        let folder = dir.path().join("s");
        let safe_id = "22222222-2222-4222-8222-222222222222";
        let drive = SafeDrive {
            safe: open_at(&folder, safe_id, &key).unwrap(),
        };
        let file = drive.create_file(safe_root_id(), "a.txt".into()).unwrap();
        drive
            .write(file.id.clone(), 0, b"hello world".to_vec())
            .unwrap();
        assert_eq!(drive.read(file.id.clone(), 6, 100).unwrap(), b"world");
        drive.truncate(file.id.clone(), 5).unwrap();
        drive.flush(file.id.clone()).unwrap();
        assert_eq!(drive.entry(file.id.clone()).unwrap().size, 5);
        drive.lock().unwrap();

        let again = SafeDrive {
            safe: open_at(&folder, safe_id, &key).unwrap(),
        };
        assert_eq!(again.read(file.id, 0, 100).unwrap(), b"hello");
    }

    #[test]
    fn a_safe_id_stays_inside_the_folder() {
        assert!(folder_name("11111111-1111-4111-8111-111111111111").is_ok());
        for bad in ["", "..", "../other", "/data/x", "a/b"] {
            assert!(folder_name(bad).is_err(), "{bad}");
        }
    }
}
