//! The local store: one file per account with everything the app and its autofill extensions
//! need to unlock and fill offline, shared through the App Group (iOS) or app storage (Android).
//!
//! It holds exactly what the server holds for the account (the account bundle, wrapped vault
//! keys and encrypted items), plus this device's device-unlock record. Every secret in it is a
//! core ciphertext envelope; nothing is decrypted to disk. See `README.md` for the byte layout.
//!
//! Writers take an exclusive lock on `<file>.lock`, re-read the file, change it and replace it
//! atomically, so the app and an extension writing at the same time never lose each other's
//! changes. Readers use the copy loaded at `open` (or the last `reload`).

mod codec;
// Saving while locked (plan 03): the save inbox next to the store.
mod inbox;
mod local;
// Stay unlocked while logged in (plan 18): the key the app keeps behind the phone's own lock.
mod stay_unlocked;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use octapass_api::{ItemRecord, SyncResponse, VaultRecord, VaultRole, VaultType};
use octapass_core::account::AccountBundle;
use octapass_core::kdf::{AccountKeys, KdfAlgorithm, KdfParams};
use octapass_core::secret_key::SecretKey;
use octapass_core::session::{EncryptedItem, Session as CoreSession};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use self::codec::{Reader, Writer};
pub use self::local::LOCAL_SERVER_PREFIX;
use crate::error::{OctaPassError, Result};
use crate::now_ms;
use crate::session::Session;

const MAGIC: &[u8; 4] = b"OPLS";
/// Version 2 added the account's ML-KEM key and key record, and the key log pins. Version 1 stores
/// still open, and are rewritten at the next save.
const VERSION: u8 = 2;
const OLDEST_VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 32;

/// The master password is required again this long after it was last used (plan 03).
pub(crate) const PASSWORD_INTERVAL_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Whether an item still has to be uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncState {
    Synced,
    /// Changed here; upload with `If-Match` on the stored revision.
    Changed,
    /// Created here; upload with `If-None-Match: *`.
    New,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredItem {
    pub record: ItemRecord,
    pub sync: SyncState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceUnlockRecord {
    pub device_salt: Vec<u8>,
    pub wrapped_ask: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreData {
    pub server_url: String,
    pub account: AccountBundle,
    /// When the master password last unlocked this account here (Unix ms).
    pub password_unlocked_at: u64,
    pub device_unlock: Option<DeviceUnlockRecord>,
    pub vaults: BTreeMap<String, VaultRecord>,
    /// By item id (UUIDs, unique across vaults).
    pub items: BTreeMap<String, StoredItem>,
    /// What this device pinned about the key log, as JSON. Empty until the first check.
    pub key_log: String,
}

/// Device unlock as the unlock screen needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct DeviceUnlockStatus {
    pub enabled: bool,
    /// The 14-day master password rule is due: unlock with the password first.
    pub password_required: bool,
}

#[derive(uniffi::Object)]
pub struct LocalStore {
    path: PathBuf,
    data: Mutex<StoreData>,
    /// Items whose waiting upload is bookkeeping, not an edit (a one-time code's counter moving),
    /// so the version it replaces stays out of the item's history. Lost on restart, which at worst
    /// adds one history entry.
    bookkeeping: Mutex<HashSet<String>>,
}

#[uniffi::export]
impl LocalStore {
    /// Creates (or replaces) the store at `path` for the account of a session that was just
    /// signed in with the master password. Fill it with `OctaPassServer.sync`.
    #[uniffi::constructor]
    pub fn create(path: String, server_url: String, session: Arc<Session>) -> Result<Arc<Self>> {
        let account = session.with(|core| Ok(core.bundle().clone()))?;
        let data = StoreData {
            server_url,
            account,
            password_unlocked_at: now_ms(),
            device_unlock: None,
            vaults: BTreeMap::new(),
            items: BTreeMap::new(),
            key_log: String::new(),
        };
        let store = Self {
            path: PathBuf::from(path),
            data: Mutex::new(data.clone()),
            bookkeeping: Mutex::default(),
        };
        let _lock = store.lock_file()?;
        write_atomically(&store.path, &data.encode()?)?;
        Ok(Arc::new(store))
    }

    /// Opens an existing store. Fails with `InvalidStore` if it's missing or damaged.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>> {
        let path = PathBuf::from(path);
        let data = read(&path)?.ok_or(OctaPassError::InvalidStore)?;
        Ok(Arc::new(Self {
            path,
            data: Mutex::new(data),
            bookkeeping: Mutex::default(),
        }))
    }

    /// Re-reads the file, to see what the app or another extension wrote since `open`.
    pub fn reload(&self) -> Result<()> {
        *self.data() = read(&self.path)?.ok_or(OctaPassError::InvalidStore)?;
        Ok(())
    }

    pub fn email(&self) -> String {
        self.data().account.email.clone()
    }

    pub fn account_id(&self) -> Option<String> {
        self.data().account.account_id.clone()
    }

    pub fn server_url(&self) -> String {
        self.data().server_url.clone()
    }

    /// Items changed here that `OctaPassServer.uploadPending` still has to send.
    pub fn has_pending_changes(&self) -> bool {
        self.data()
            .items
            .values()
            .any(|item| item.sync != SyncState::Synced)
    }

    /// Unlocks with the master password and the Secret Key kept on this device. Runs Argon2id
    /// (about a second): call it off the main thread. Restarts the 14-day device-unlock clock.
    pub fn unlock_with_password(
        &self,
        password: String,
        secret_key: String,
    ) -> Result<Arc<Session>> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let account = self.data().account.clone();
        let keys = AccountKeys::derive(
            &password,
            &secret_key,
            &account.email,
            &account.account_salt_bytes()?,
            &account.kdf,
        )?;
        let session = CoreSession::unlock(account, &keys.auk)?;
        self.mutate(|data| {
            data.password_unlocked_at = now_ms();
            Ok(())
        })?;
        Ok(Session::new(session))
    }

    /// Unlocks with the 32-byte device secret released by Face ID / Touch ID / fingerprint or the
    /// device passcode (see `enableDeviceUnlock`). Fails with `PasswordRequired` when device
    /// unlock is off or the master password is due, and `DeviceUnlockFailed` when the secret
    /// doesn't open the account.
    pub fn unlock_with_device(&self, device_secret: Vec<u8>) -> Result<Arc<Session>> {
        let device_secret = Zeroizing::new(device_secret);
        let data = self.data().clone();
        let device = match &data.device_unlock {
            Some(device) if !password_due(&data) => device,
            _ => return Err(OctaPassError::PasswordRequired),
        };
        let session = CoreSession::unlock_with_device_key(
            data.account.clone(),
            &device_secret,
            &device.device_salt,
            &device.wrapped_ask,
        )?;
        Ok(Session::new(session))
    }

    /// Turns on device unlock: wraps the account key with `device_secret`, 32 random bytes the
    /// app keeps behind the device's lock (a Keychain item with `.biometryCurrentSet` or
    /// `.devicePasscode`, or an Android Keystore key that needs `BIOMETRIC_STRONG` or
    /// `DEVICE_CREDENTIAL`). Only the wrapped key is stored here; the secret never is.
    pub fn enable_device_unlock(
        &self,
        session: Arc<Session>,
        device_secret: Vec<u8>,
    ) -> Result<()> {
        let device_secret = Zeroizing::new(device_secret);
        self.check_account(&session)?;
        let device =
            session.with(|core| Ok(core.enable_device_unlock(&device_secret, &mut OsRng)?))?;
        self.mutate(|data| {
            data.device_unlock = Some(DeviceUnlockRecord {
                device_salt: device.device_salt.to_vec(),
                wrapped_ask: device.wrapped_ask.clone(),
            });
            Ok(())
        })
    }

    /// Turns device unlock off. Also do this on sign-out, master password change and key
    /// rotation (plan 03), and delete the app's device secret.
    pub fn disable_device_unlock(&self) -> Result<()> {
        self.mutate(|data| {
            data.device_unlock = None;
            Ok(())
        })
    }

    pub fn device_unlock_status(&self) -> DeviceUnlockStatus {
        let data = self.data();
        DeviceUnlockStatus {
            enabled: data.device_unlock.is_some(),
            password_required: password_due(&data),
        }
    }
}

impl LocalStore {
    /// Unlocks with the account key another app wrapped for this one under `device_secret`
    /// (`Session::wrap_for_device_secret`), not with this store's own device-unlock record (Rust
    /// only): the other half of the desktop app's session for the extension and the CLI.
    pub fn unlock_with_device_wrap(
        &self,
        device_secret: &[u8],
        device_salt: &[u8],
        wrapped_ask: &str,
    ) -> Result<Arc<Session>> {
        let account = self.data().account.clone();
        let session =
            CoreSession::unlock_with_device_key(account, device_secret, device_salt, wrapped_ask)?;
        Ok(Session::new(session))
    }

    /// Marks an item's waiting upload as bookkeeping, or not (Rust-only, for the apps).
    pub fn set_bookkeeping(&self, item_id: &str, on: bool) {
        let mut set = self
            .bookkeeping
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if on {
            set.insert(item_id.to_owned());
        } else {
            set.remove(item_id);
        }
    }

    /// The item has changes here that the server doesn't have yet.
    pub fn has_waiting_upload(&self, item_id: &str) -> bool {
        self.data()
            .items
            .get(item_id)
            .is_some_and(|item| item.sync != SyncState::Synced && !self.is_bookkeeping(item_id))
    }

    pub(crate) fn is_bookkeeping(&self, item_id: &str) -> bool {
        self.bookkeeping
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(item_id)
    }

    pub(crate) fn data(&self) -> MutexGuard<'_, StoreData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Changes the store under the file lock, starting from what's on disk now.
    pub(crate) fn mutate<R>(&self, change: impl FnOnce(&mut StoreData) -> Result<R>) -> Result<R> {
        let _lock = self.lock_file()?;
        let mut data = read(&self.path)?.ok_or(OctaPassError::InvalidStore)?;
        let result = change(&mut data)?;
        write_atomically(&self.path, &data.encode()?)?;
        *self.data() = data;
        Ok(result)
    }

    /// Fails unless the store and the session belong to the same account.
    pub(crate) fn check_account(&self, session: &Session) -> Result<()> {
        let key = self.data().account.public_sign_key.clone();
        session.with(|core| {
            if core.bundle().public_sign_key == key {
                Ok(())
            } else {
                Err(OctaPassError::InvalidStore)
            }
        })
    }

    fn lock_file(&self) -> Result<File> {
        let mut path = self.path.clone().into_os_string();
        path.push(".lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        file.lock()?;
        Ok(file)
    }
}

impl StoreData {
    /// `vaultId:revision` for every vault, for `GET /v1/sync?since=…`.
    pub fn sync_cursor(&self) -> String {
        self.vaults
            .values()
            .map(|vault| format!("{}:{}", vault.id, vault.revision))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether `vault` has a new key while items here are still wrapped under the one this store
    /// knows. Only the key that wrapped them can move them, so the new record waits until an
    /// upload meets `vault-key-changed` (see `Session::rekey_vault`): a sync can run while locked.
    fn rekey_pending(&self, vault: &VaultRecord) -> bool {
        self.vaults.get(&vault.id).is_some_and(|known| {
            known.wrapped_vault_key != vault.wrapped_vault_key
                && self
                    .items
                    .values()
                    .any(|item| item.record.vault_id == vault.id && item.sync != SyncState::Synced)
        })
    }

    /// Applies a sync response. Items changed here and not uploaded yet are kept as they are
    /// (uploading them resolves any conflict), and nothing goes back to an older revision, in
    /// case another process synced in the meantime. A vault waiting for `rekey_vault` stays as it
    /// was, so the next sync brings it again.
    pub fn apply_sync(&mut self, response: SyncResponse) {
        let accessible: BTreeSet<&str> = response.vaults.iter().map(|v| v.id.as_str()).collect();
        let waiting: BTreeSet<String> = response
            .vaults
            .iter()
            .filter(|vault| self.rekey_pending(vault))
            .map(|vault| vault.id.clone())
            .collect();
        self.items
            .retain(|_, item| accessible.contains(item.record.vault_id.as_str()));
        for deleted in &response.deleted {
            if self.items.get(&deleted.item_id).is_some_and(|item| {
                item.sync == SyncState::Synced
                    && item.record.revision <= deleted.revision
                    && !waiting.contains(&item.record.vault_id)
            }) {
                self.items.remove(&deleted.item_id);
            }
        }
        for record in response.items {
            if waiting.contains(&record.vault_id) {
                continue;
            }
            let keep_local = self.items.get(&record.id).is_some_and(|item| {
                item.sync != SyncState::Synced || item.record.revision > record.revision
            });
            if !keep_local {
                self.items.insert(
                    record.id.clone(),
                    StoredItem {
                        record,
                        sync: SyncState::Synced,
                    },
                );
            }
        }
        let mut vaults = BTreeMap::new();
        for mut vault in response.vaults {
            if waiting.contains(&vault.id)
                && let Some(known) = self.vaults.get(&vault.id)
            {
                vaults.insert(vault.id.clone(), known.clone());
                continue;
            }
            if let Some(known) = self.vaults.get(&vault.id) {
                vault.revision = vault.revision.max(known.revision);
            }
            vaults.insert(vault.id.clone(), vault);
        }
        self.vaults = vaults;
    }

    /// Stores an item encrypted on this device, to upload later. `base` is the stored version
    /// the change started from (`None` for a new item): its revision goes into `If-Match`, so a
    /// change made elsewhere in the meantime becomes a conflict instead of being overwritten.
    pub fn put_local(
        &mut self,
        vault_id: &str,
        item_id: &str,
        item: EncryptedItem,
        base: Option<&StoredItem>,
        now: &str,
    ) {
        let current = self.items.get(item_id);
        let (sync, revision) = match (current, base) {
            (Some(current), _) if current.sync == SyncState::New => (SyncState::New, 0),
            // Uploaded since `base` was read: the upload had exactly `base`'s content.
            (Some(current), Some(base)) if base.sync == SyncState::New => {
                (SyncState::Changed, current.record.revision)
            }
            (Some(_), Some(base)) => (SyncState::Changed, base.record.revision),
            // New, or purged on the server meanwhile: create it again.
            _ => (SyncState::New, 0),
        };
        let record = ItemRecord {
            id: item_id.to_owned(),
            vault_id: vault_id.to_owned(),
            revision,
            encrypted_item_key: item.encrypted_item_key,
            overview: item.overview,
            details: item.details,
            updated_at: now.to_owned(),
            deleted_at: base.and_then(|base| base.record.deleted_at.clone()),
        };
        self.items
            .insert(item_id.to_owned(), StoredItem { record, sync });
    }

    /// The vault new items go into: the personal vault.
    pub fn personal_vault(&self) -> Result<&VaultRecord> {
        self.vaults
            .values()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .ok_or(OctaPassError::ReadOnlyVault)
    }

    pub fn writable_vault(&self, vault_id: &str) -> Result<&VaultRecord> {
        self.vaults
            .get(vault_id)
            .filter(|vault| vault.role != VaultRole::Read)
            .ok_or(OctaPassError::ReadOnlyVault)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.encode_as(VERSION)
    }

    fn encode_as(&self, version: u8) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        w.raw(MAGIC);
        w.u8(version);
        w.str(&self.server_url)?;

        let account = &self.account;
        w.opt_str(account.account_id.as_deref())?;
        w.str(&account.email)?;
        w.u32(account.kdf.memory_kib);
        w.u32(account.kdf.iterations);
        w.u32(account.kdf.parallelism);
        for value in [
            &account.account_salt,
            &account.wrapped_ask,
            &account.public_enc_key,
            &account.public_sign_key,
            &account.wrapped_private_keys,
            &account.recovery_wrapped_ask,
        ] {
            w.b64(value)?;
        }
        if version >= 2 {
            w.opt_str(account.wrapped_pq_private_key.as_deref())?;
            let record = account
                .key_record
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| OctaPassError::InvalidStore)?;
            w.opt_str(record.as_deref())?;
            w.str(&self.key_log)?;
        }

        w.u64(self.password_unlocked_at);
        match &self.device_unlock {
            Some(device) => {
                w.u8(1);
                w.bytes(&device.device_salt)?;
                w.b64(&device.wrapped_ask)?;
            }
            None => w.u8(0),
        }

        w.len(self.vaults.len())?;
        for vault in self.vaults.values() {
            w.id(&vault.id)?;
            w.u8(match vault.vault_type {
                VaultType::Personal => 0,
                VaultType::Shared => 1,
                VaultType::Family => 2,
            });
            w.u8(match vault.role {
                VaultRole::Owner => 0,
                VaultRole::Write => 1,
                VaultRole::Read => 2,
                VaultRole::Manage => 3,
            });
            w.u64(vault.revision);
            w.b64(&vault.wrapped_vault_key)?;
            w.opt_str(vault.key_id.as_deref())?;
            let grant = vault
                .grant
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| OctaPassError::InvalidStore)?;
            w.opt_str(grant.as_deref())?;
        }

        w.len(self.items.len())?;
        for item in self.items.values() {
            let record = &item.record;
            w.id(&record.id)?;
            w.id(&record.vault_id)?;
            w.u8(match item.sync {
                SyncState::Synced => 0,
                SyncState::Changed => 1,
                SyncState::New => 2,
            });
            w.u64(record.revision);
            w.b64(&record.encrypted_item_key)?;
            w.b64(&record.overview)?;
            w.b64(&record.details)?;
            w.str(&record.updated_at)?;
            w.opt_str(record.deleted_at.as_deref())?;
        }

        let mut bytes = w.into_bytes();
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let (body, checksum) = bytes
            .split_at_checked(bytes.len().saturating_sub(CHECKSUM_LEN))
            .ok_or(OctaPassError::InvalidStore)?;
        if checksum.len() != CHECKSUM_LEN || Sha256::digest(body).as_slice() != checksum {
            return Err(OctaPassError::InvalidStore);
        }
        let mut r = Reader::new(body);
        if r.raw(MAGIC.len())? != MAGIC {
            return Err(OctaPassError::InvalidStore);
        }
        let version = r.u8()?;
        if !(OLDEST_VERSION..=VERSION).contains(&version) {
            return Err(OctaPassError::InvalidStore);
        }
        let server_url = r.str()?;
        let mut account = AccountBundle {
            account_id: r.opt_str()?,
            email: r.str()?,
            kdf: KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                memory_kib: r.u32()?,
                iterations: r.u32()?,
                parallelism: r.u32()?,
            },
            account_salt: r.b64()?,
            wrapped_ask: r.b64()?,
            public_enc_key: r.b64()?,
            public_sign_key: r.b64()?,
            wrapped_private_keys: r.b64()?,
            recovery_wrapped_ask: r.b64()?,
            wrapped_pq_private_key: None,
            key_record: None,
        };
        let mut key_log = String::new();
        if version >= 2 {
            account.wrapped_pq_private_key = r.opt_str()?;
            account.key_record = r
                .opt_str()?
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|_| OctaPassError::InvalidStore)?;
            key_log = r.str()?;
        }
        let password_unlocked_at = r.u64()?;
        let device_unlock = match r.u8()? {
            0 => None,
            1 => Some(DeviceUnlockRecord {
                device_salt: r.bytes()?.to_vec(),
                wrapped_ask: r.b64()?,
            }),
            _ => return Err(OctaPassError::InvalidStore),
        };

        let mut vaults = BTreeMap::new();
        for _ in 0..r.count(16 + 2 + 8 + 4 + 2)? {
            let id = r.id()?;
            let vault_type = match r.u8()? {
                0 => VaultType::Personal,
                1 => VaultType::Shared,
                2 => VaultType::Family,
                _ => return Err(OctaPassError::InvalidStore),
            };
            let role = match r.u8()? {
                0 => VaultRole::Owner,
                1 => VaultRole::Write,
                2 => VaultRole::Read,
                3 => VaultRole::Manage,
                _ => return Err(OctaPassError::InvalidStore),
            };
            let revision = r.u64()?;
            let wrapped_vault_key = r.b64()?;
            let key_id = r.opt_str()?;
            let grant = r
                .opt_str()?
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|_| OctaPassError::InvalidStore)?;
            let vault = VaultRecord {
                id: id.clone(),
                vault_type,
                role,
                revision,
                wrapped_vault_key,
                key_id,
                grant,
                // Not kept in this cache: a vault opens the same with or without it.
                org_id: None,
            };
            vaults.insert(id, vault);
        }

        let mut items = BTreeMap::new();
        for _ in 0..r.count(16 + 16 + 1 + 8 + 4 * 4 + 1)? {
            let id = r.id()?;
            let vault_id = r.id()?;
            let sync = match r.u8()? {
                0 => SyncState::Synced,
                1 => SyncState::Changed,
                2 => SyncState::New,
                _ => return Err(OctaPassError::InvalidStore),
            };
            let record = ItemRecord {
                id: id.clone(),
                vault_id,
                revision: r.u64()?,
                encrypted_item_key: r.b64()?,
                overview: r.b64()?,
                details: r.b64()?,
                updated_at: r.str()?,
                deleted_at: r.opt_str()?,
            };
            items.insert(id, StoredItem { record, sync });
        }
        if !r.is_empty() {
            return Err(OctaPassError::InvalidStore);
        }
        Ok(Self {
            server_url,
            account,
            password_unlocked_at,
            device_unlock,
            vaults,
            items,
            key_log,
        })
    }
}

fn password_due(data: &StoreData) -> bool {
    now_ms().saturating_sub(data.password_unlocked_at) >= PASSWORD_INTERVAL_MS
}

/// The store at `path`, or `None` if there is no file.
fn read(path: &Path) -> Result<Option<StoreData>> {
    match fs::read(path) {
        Ok(bytes) => StoreData::decode(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Writes next to the file and renames over it, so readers never see half a file.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temporary = path.to_path_buf().into_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use octapass_api::DeletedItem;
    use octapass_core::kdf::KdfParams;

    use super::*;

    const VAULT: &str = "0192f0c8-0000-7000-8000-000000000001";
    const ITEM: &str = "0192f0c8-0000-7000-8000-000000000002";
    /// A minimal version 1 envelope (57 bytes) in base64url.
    const ENVELOPE: &str =
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn vault(revision: u64) -> VaultRecord {
        VaultRecord {
            id: VAULT.into(),
            vault_type: VaultType::Personal,
            revision,
            wrapped_vault_key: ENVELOPE.into(),
            role: VaultRole::Owner,
            key_id: None,
            grant: None,
            org_id: None,
        }
    }

    fn record(revision: u64, overview: &str) -> ItemRecord {
        ItemRecord {
            id: ITEM.into(),
            vault_id: VAULT.into(),
            revision,
            encrypted_item_key: ENVELOPE.into(),
            overview: overview.into(),
            details: ENVELOPE.into(),
            updated_at: "2026-10-24T00:00:00.000Z".into(),
            deleted_at: None,
        }
    }

    fn data() -> StoreData {
        StoreData {
            server_url: "https://vault.example.com/".into(),
            account: AccountBundle {
                account_id: Some(VAULT.into()),
                email: "a@example.com".into(),
                kdf: KdfParams::DEFAULT,
                account_salt: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                wrapped_ask: ENVELOPE.into(),
                public_enc_key: "AQ".into(),
                public_sign_key: "Ag".into(),
                wrapped_private_keys: ENVELOPE.into(),
                recovery_wrapped_ask: ENVELOPE.into(),
                wrapped_pq_private_key: None,
                key_record: None,
            },
            password_unlocked_at: 1_761_177_600_000,
            device_unlock: Some(DeviceUnlockRecord {
                device_salt: vec![7; 16],
                wrapped_ask: ENVELOPE.into(),
            }),
            vaults: BTreeMap::from([(VAULT.into(), vault(3))]),
            items: BTreeMap::from([(
                ITEM.into(),
                StoredItem {
                    record: ItemRecord {
                        deleted_at: Some("2026-10-25T00:00:00.000Z".into()),
                        ..record(2, ENVELOPE)
                    },
                    sync: SyncState::Changed,
                },
            )]),
            key_log: String::new(),
        }
    }

    #[test]
    fn a_version_1_store_still_opens() {
        let data = data();
        let bytes = data.encode_as(1).unwrap();
        assert_eq!(bytes[4], 1);
        assert_eq!(StoreData::decode(&bytes), Ok(data));
    }

    #[test]
    fn the_account_s_ml_kem_key_and_the_log_pins_are_kept() {
        let mut data = data();
        data.account.wrapped_pq_private_key = Some(ENVELOPE.into());
        data.key_log = r#"{"checkedAt":1}"#.into();
        let bytes = data.encode().unwrap();
        assert_eq!(StoreData::decode(&bytes), Ok(data));
    }

    fn sync(
        vaults: Vec<VaultRecord>,
        items: Vec<ItemRecord>,
        deleted: Vec<DeletedItem>,
    ) -> SyncResponse {
        SyncResponse {
            vaults,
            items,
            deleted,
            has_more: false,
        }
    }

    #[test]
    fn the_file_round_trips_and_is_compact() {
        let data = data();
        let bytes = data.encode().unwrap();
        assert_eq!(&bytes[..5], b"OPLS\x02");
        assert_eq!(StoreData::decode(&bytes).unwrap(), data);
        // Raw ciphertext and ids instead of the API's base64 JSON.
        let records: Vec<&ItemRecord> = data.items.values().map(|item| &item.record).collect();
        let json = serde_json::to_vec(&(&data.account, &data.vaults, records)).unwrap();
        assert!(
            bytes.len() * 4 < json.len() * 3,
            "{} vs {} bytes",
            bytes.len(),
            json.len()
        );
    }

    #[test]
    fn shared_and_family_vaults_keep_their_grant_and_key_id() {
        let mut data = data();
        let mut family = vault(9);
        family.vault_type = VaultType::Family;
        family.role = VaultRole::Manage;
        family.key_id = Some("a2V5LWlk".into());
        family.grant = Some(octapass_api::VaultGrant {
            granted_by: "0192f0a0-0000-7000-8000-000000000001".into(),
            granter_public_sign_key: ENVELOPE.into(),
            granted_at: 1_761_000_000_000,
            signature: ENVELOPE.into(),
        });
        data.vaults.insert(family.id.clone(), family);
        assert_eq!(StoreData::decode(&data.encode().unwrap()).unwrap(), data);
    }

    #[test]
    fn damaged_or_foreign_files_are_refused() {
        let bytes = data().encode().unwrap();
        for damaged in [
            bytes[..bytes.len() - 1].to_vec(),
            [&bytes[..40], &[bytes[40] ^ 1], &bytes[41..]].concat(),
            b"OPLS".to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                StoreData::decode(&damaged),
                Err(OctaPassError::InvalidStore)
            );
        }
        // A later format version (with a valid checksum) is refused too.
        let mut future = bytes[..bytes.len() - CHECKSUM_LEN].to_vec();
        future[4] = VERSION + 1;
        let checksum = Sha256::digest(&future);
        future.extend_from_slice(&checksum);
        assert_eq!(StoreData::decode(&future), Err(OctaPassError::InvalidStore));
    }

    #[test]
    fn sync_keeps_local_changes_and_never_goes_back() {
        let mut data = data();
        data.apply_sync(sync(vec![vault(2)], vec![record(5, "AAAA")], Vec::new()));
        assert_eq!(
            data.vaults[VAULT].revision, 3,
            "the cursor never moves back"
        );
        assert_eq!(
            data.items[ITEM].sync,
            SyncState::Changed,
            "a local change waits for its upload"
        );

        data.items.get_mut(ITEM).unwrap().sync = SyncState::Synced;
        data.apply_sync(sync(vec![vault(6)], vec![record(1, "AAAA")], Vec::new()));
        assert_eq!(
            data.items[ITEM].record.revision, 2,
            "an older record is ignored"
        );
        data.apply_sync(sync(vec![vault(6)], vec![record(6, "AAAA")], Vec::new()));
        assert_eq!(data.items[ITEM].record.overview, "AAAA");
        assert_eq!(data.sync_cursor(), format!("{VAULT}:6"));

        let deleted = DeletedItem {
            vault_id: VAULT.into(),
            item_id: ITEM.into(),
            revision: 7,
        };
        data.apply_sync(sync(vec![vault(7)], Vec::new(), vec![deleted]));
        assert!(data.items.is_empty());
    }

    #[test]
    fn losing_access_to_a_vault_drops_its_items() {
        let mut data = data();
        data.apply_sync(sync(Vec::new(), Vec::new(), Vec::new()));
        assert!(data.vaults.is_empty() && data.items.is_empty());
        assert_eq!(data.sync_cursor(), "");
    }

    #[test]
    fn local_changes_remember_what_they_started_from() {
        let item = || EncryptedItem {
            encrypted_item_key: ENVELOPE.into(),
            overview: "BBBB".into(),
            details: ENVELOPE.into(),
        };
        let mut data = data();
        data.items.clear();
        data.put_local(VAULT, ITEM, item(), None, "now");
        assert_eq!(
            (data.items[ITEM].sync, data.items[ITEM].record.revision),
            (SyncState::New, 0)
        );
        let base = data.items[ITEM].clone();
        data.put_local(VAULT, ITEM, item(), Some(&base), "now");
        assert_eq!(data.items[ITEM].sync, SyncState::New, "still not uploaded");

        // Uploaded by another process (revision 4) while this one edited the New version.
        data.items.get_mut(ITEM).unwrap().sync = SyncState::Synced;
        data.items.get_mut(ITEM).unwrap().record.revision = 4;
        data.put_local(VAULT, ITEM, item(), Some(&base), "now");
        assert_eq!(
            (data.items[ITEM].sync, data.items[ITEM].record.revision),
            (SyncState::Changed, 4)
        );

        // Edited from revision 4 while another device's revision 9 arrived: upload with 4.
        let base = data.items[ITEM].clone();
        data.items.get_mut(ITEM).unwrap().record.revision = 9;
        data.items.get_mut(ITEM).unwrap().sync = SyncState::Synced;
        data.put_local(VAULT, ITEM, item(), Some(&base), "now");
        assert_eq!(data.items[ITEM].record.revision, 4);
    }

    #[test]
    fn password_is_due_after_fourteen_days() {
        let mut data = data();
        data.password_unlocked_at = now_ms();
        assert!(!password_due(&data));
        data.password_unlocked_at = now_ms() - PASSWORD_INTERVAL_MS;
        assert!(password_due(&data));
    }
}
