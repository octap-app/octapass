//! What the desktop app keeps on disk, in its per-user data directory:
//!
//! - `state.json`: the signed-in accounts on this device (email, server, Secret Key, the account
//!   bundle, which is public keys and ciphertext only, the refresh token, the trusted-device
//!   token that skips two-step sign-in, and the device unlock record: the account key wrapped by
//!   the device secret, never the secret itself).
//! - `vault-<tag>.json`: each account's encrypted vaults and items as the server sent them, so
//!   the vault opens offline.
//! - `notes-<tag>.json`: what each account remembers about sharing on this device: the
//!   fingerprints the user compared with people, and which item each share link was made from.
//! - `local-<tag>.vault`: each local vault, the core's encrypted `LocalVault` blob.
//!
//! Files are written atomically and readable only by the user.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use octapass_core::account::AccountBundle;
use octapass_device_unlock::account_tag;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::cache::VaultCache;
use crate::error::{Result, VaultError};

/// Identifies an account on this device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKey {
    pub server_url: String,
    pub email: String,
}

/// How a local vault's server URL starts: `local:<tag>`. It stands in for a server, which it
/// doesn't have, so a session looks the same to the UI.
pub const LOCAL_SCHEME: &str = "local:";

impl AccountKey {
    pub fn is_local(&self) -> bool {
        self.server_url.starts_with(LOCAL_SCHEME)
    }

    /// The non-secret key device unlock and file names are derived from.
    pub fn id(&self) -> String {
        format!("{}|{}", self.server_url, self.email)
    }
}

/// The account key wrapped by a device secret (`octapass_core::device`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedAsk {
    pub device_salt: String,
    pub wrapped_ask: String,
    pub enabled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccount {
    #[serde(flatten)]
    pub key: AccountKey,
    /// Text form (`OP1-…`), as on the Recovery Kit.
    pub secret_key: String,
    pub bundle: AccountBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Sent with every sign-in from this device so it skips two-step sign-in. It outlives an
    /// expired session, not a sign-out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device_token: Option<String>,
    /// When the master password last unlocked this account here (the 14-day rule).
    pub last_password_unlock_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_unlock: Option<WrappedAsk>,
}

/// What this computer remembers about a local vault, next to its file. Nothing here is secret.
/// The name shows on the lock screen, so it's outside the vault's encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredLocal {
    #[serde(flatten)]
    pub key: AccountKey,
    /// Random; names the vault's file and chip key.
    pub tag: String,
    pub name: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<String>,
    /// The `changed_at` the newest backup holds (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backed_up_at: Option<u64>,
    /// The last change (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<u64>,
    /// Where automatic backups go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_folder: Option<String>,
    /// What the chip key works from, base64url: set when the vault is bound to the chip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_context: Option<String>,
    /// When the master password last unlocked it here (the 14-day rule).
    pub last_password_unlock_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_unlock: Option<WrappedAsk>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceState {
    #[serde(default)]
    pub accounts: Vec<StoredAccount>,
    /// Vaults on this computer only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locals: Vec<StoredLocal>,
    /// The account the app opens on, locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<AccountKey>,
    /// Plan 03's autofill gate on this computer. Missing means on. Never synced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_on_fill: Option<bool>,
    /// Plan 18's "Stay unlocked" on this computer. Never synced. Missing until the app decides
    /// (its migration reads the lock settings the web view kept); missing reads as off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stay_unlocked: Option<bool>,
    /// The account key wrapped by each account's stay-unlocked secret, by `AccountKey::id`. The
    /// secret itself is in the system key store (`DeviceUnlock::store_unprotected`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub stay_unlocked_keys: std::collections::BTreeMap<String, WrappedAsk>,
}

impl DeviceState {
    pub fn account(&self, key: &AccountKey) -> Option<&StoredAccount> {
        self.accounts.iter().find(|account| &account.key == key)
    }

    pub fn account_mut(&mut self, key: &AccountKey) -> Option<&mut StoredAccount> {
        self.accounts.iter_mut().find(|account| &account.key == key)
    }

    pub fn local(&self, key: &AccountKey) -> Option<&StoredLocal> {
        self.locals.iter().find(|local| &local.key == key)
    }

    pub fn local_mut(&mut self, key: &AccountKey) -> Option<&mut StoredLocal> {
        self.locals.iter_mut().find(|local| &local.key == key)
    }

    pub fn upsert_local(&mut self, local: StoredLocal) {
        self.locals.retain(|existing| existing.key != local.key);
        self.locals.push(local);
    }

    pub fn upsert(&mut self, account: StoredAccount) {
        self.accounts.retain(|existing| existing.key != account.key);
        self.accounts.push(account);
    }

    pub fn remove(&mut self, key: &AccountKey) {
        self.accounts.retain(|account| &account.key != key);
        if self.current.as_ref() == Some(key) {
            self.current = None;
        }
    }
}

/// An account's sharing notes. None is a secret, and none is sent anywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingNotes {
    /// Account id → the fingerprint digits the user compared with that person. A member whose
    /// keys change no longer matches, so they show as not verified again.
    #[serde(default)]
    pub verified: BTreeMap<String, String>,
    /// Share link id → the item it was made from, to name the link in the list.
    #[serde(default)]
    pub share_links: BTreeMap<String, String>,
    /// What this device pinned about the key log (plan 03).
    #[serde(default)]
    pub key_log: octapass_core::transparency::client::LogState,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load_state(&self) -> Result<DeviceState> {
        Ok(self.read(&self.dir.join("state.json"))?.unwrap_or_default())
    }

    pub fn save_state(&self, state: &DeviceState) -> Result<()> {
        self.write(&self.dir.join("state.json"), state)
    }

    pub fn load_cache(&self, key: &AccountKey) -> Result<VaultCache> {
        Ok(self.read(&self.cache_path(key))?.unwrap_or_default())
    }

    pub fn save_cache(&self, key: &AccountKey, cache: &VaultCache) -> Result<()> {
        self.write(&self.cache_path(key), cache)
    }

    /// Deletes everything kept for the account but its entry in `state.json`.
    pub fn delete_cache(&self, key: &AccountKey) -> Result<()> {
        for path in [self.cache_path(key), self.notes_path(key)] {
            match fs::remove_file(path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(io_error(error));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn local_path(&self, tag: &str) -> PathBuf {
        self.dir.join(format!("local-{tag}.vault"))
    }

    pub fn read_local(&self, tag: &str) -> Result<Vec<u8>> {
        fs::read(self.local_path(tag)).map_err(io_error)
    }

    pub fn write_local(&self, tag: &str, bytes: &[u8]) -> Result<()> {
        create_private_dir(&self.dir)?;
        let path = self.local_path(tag);
        let temporary = path.with_extension("vault.tmp");
        let mut file = private_file(&temporary)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, path).map_err(io_error)
    }

    pub fn delete_local(&self, tag: &str) -> Result<()> {
        match fs::remove_file(self.local_path(tag)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(io_error(error)),
            _ => Ok(()),
        }
    }

    pub fn load_notes(&self, key: &AccountKey) -> Result<SharingNotes> {
        Ok(self.read(&self.notes_path(key))?.unwrap_or_default())
    }

    pub fn update_notes(
        &self,
        key: &AccountKey,
        change: impl FnOnce(&mut SharingNotes),
    ) -> Result<()> {
        let mut notes = self.load_notes(key)?;
        change(&mut notes);
        self.write(&self.notes_path(key), &notes)
    }

    fn cache_path(&self, key: &AccountKey) -> PathBuf {
        self.dir
            .join(format!("vault-{}.json", account_tag(&key.id())))
    }

    fn notes_path(&self, key: &AccountKey) -> PathBuf {
        self.dir
            .join(format!("notes-{}.json", account_tag(&key.id())))
    }

    fn read<T: DeserializeOwned>(&self, path: &Path) -> Result<Option<T>> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| VaultError::unexpected(format!("{}: {error}", path.display()))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }

    fn write<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        create_private_dir(&self.dir)?;
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(value).expect("state serializes");
        let mut file = private_file(&temporary)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, path).map_err(io_error)
    }
}

fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("storage: {error}"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_error)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<()> {
    // The per-user application data folder is already private to the user on Windows.
    fs::create_dir_all(dir).map_err(io_error)
}

fn private_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(email: &str) -> AccountKey {
        AccountKey {
            server_url: "https://vault.octap.app".into(),
            email: email.into(),
        }
    }

    #[test]
    fn a_missing_store_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("nested"));
        assert!(store.load_state().unwrap().accounts.is_empty());
        assert_eq!(
            store.load_cache(&key("a@example.com")).unwrap(),
            VaultCache::default()
        );
        store.delete_cache(&key("a@example.com")).unwrap();
    }

    #[test]
    fn state_round_trips_and_caches_are_per_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let state = DeviceState {
            accounts: Vec::new(),
            locals: Vec::new(),
            current: Some(key("a@example.com")),
            ask_on_fill: None,
            stay_unlocked: None,
            stay_unlocked_keys: Default::default(),
        };
        store.save_state(&state).unwrap();
        assert_eq!(
            store.load_state().unwrap().current,
            Some(key("a@example.com"))
        );

        store
            .save_cache(&key("a@example.com"), &VaultCache::default())
            .unwrap();
        assert_ne!(
            store.cache_path(&key("a@example.com")),
            store.cache_path(&key("b@example.com"))
        );
        assert!(
            !store
                .cache_path(&key("a@example.com"))
                .to_string_lossy()
                .contains('@')
        );
        store.delete_cache(&key("a@example.com")).unwrap();
        assert!(!store.cache_path(&key("a@example.com")).exists());
    }

    #[test]
    fn sharing_notes_are_per_account_and_go_with_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let (a, b) = (key("a@example.com"), key("b@example.com"));
        store
            .update_notes(&a, |notes| {
                notes.verified.insert("acct".into(), "0001 0002".into());
            })
            .unwrap();
        assert_eq!(store.load_notes(&a).unwrap().verified["acct"], "0001 0002");
        assert_eq!(store.load_notes(&b).unwrap(), SharingNotes::default());
        store.delete_cache(&a).unwrap();
        assert_eq!(store.load_notes(&a).unwrap(), SharingNotes::default());
    }

    #[test]
    fn a_state_from_before_local_vaults_still_reads() {
        let state: DeviceState = serde_json::from_str(r#"{"accounts":[]}"#).unwrap();
        assert!(state.locals.is_empty());
        assert!(!serde_json::to_string(&state).unwrap().contains("locals"));
    }

    #[cfg(unix)]
    #[test]
    fn local_vault_files_are_private_and_replaced_whole() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        store.write_local("t", b"one").unwrap();
        store.write_local("t", b"two").unwrap();
        assert_eq!(store.read_local("t").unwrap(), b"two");
        let path = dir.path().join("local-t.vault");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        store.delete_local("t").unwrap();
        store.delete_local("t").unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("data"));
        store.save_state(&DeviceState::default()).unwrap();
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.path().join("data")), 0o700);
        assert_eq!(mode(dir.path().join("data/state.json")), 0o600);
    }
}
