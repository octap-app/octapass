//! A store with no server behind it: a vault on this device only (plan 03, *Local mode keys*).
//!
//! The phones keep local vaults in the store rather than in the core's `LocalVault` blob, because
//! that's the file the AutoFill extensions read and write. The account bundle holds the local
//! salt, the Argon2id parameters and the ASK wrapped by the Local Unlock Key, the server URL is
//! `local:<vault id>`, and every item stays `New`: nothing was ever uploaded, so turning on sync
//! is the ordinary upload of a new store. Everything else a `LocalVault` holds (the backup key and
//! recovery code) is in the seed, which the app keeps next to the store.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use octapass_api::{ItemRecord, VaultRecord, VaultRole, VaultType};
use octapass_core::account::AccountBundle;
use octapass_core::local::{self, LocalItem, LocalVault};
use octapass_core::session::{EncryptedItem, Session as CoreSession};
use zeroize::Zeroizing;

use super::{LocalStore, StoreData, StoredItem, SyncState, read, write_atomically};
use crate::error::{OctaPassError, Result};
use crate::session::Session;
use crate::{now_ms, parse_timestamp, timestamp};

/// Stands in for the server URL of a local vault: `local:<vault id>`.
pub const LOCAL_SERVER_PREFIX: &str = "local:";

fn record(vault_id: &str, item: &LocalItem) -> StoredItem {
    StoredItem {
        record: ItemRecord {
            id: item.id.clone(),
            vault_id: vault_id.to_owned(),
            revision: 0,
            encrypted_item_key: item.encrypted.encrypted_item_key.clone(),
            overview: item.encrypted.overview.clone(),
            details: item.encrypted.details.clone(),
            updated_at: timestamp(item.updated_at),
            deleted_at: item.deleted_at.map(timestamp),
        },
        sync: SyncState::New,
    }
}

#[uniffi::export]
impl LocalStore {
    /// A vault on this device only, with no server behind it.
    pub fn is_local(&self) -> bool {
        self.data().server_url.starts_with(LOCAL_SERVER_PREFIX)
    }

    /// Unlocks a local vault with the master password and, when it's bound to this device's
    /// chip, the chip's secret. Runs Argon2id: call it off the main thread. Restarts the 14-day
    /// device-unlock clock. A wrong password fails with `LoginFailed`.
    pub fn unlock_local(
        &self,
        password: String,
        chip_secret: Option<Vec<u8>>,
    ) -> Result<Arc<Session>> {
        let password = Zeroizing::new(password);
        let chip_secret = chip_secret.map(Zeroizing::new);
        let account = self.data().account.clone();
        let session =
            local::unlock_session(account, &password, chip_secret.as_deref().map(|s| &s[..]))?;
        self.mutate(|data| {
            data.password_unlocked_at = now_ms();
            Ok(())
        })?;
        Ok(Session::new(session))
    }
}

/// For the apps' vault crate.
impl LocalStore {
    /// Creates the store of a local vault at `path`, with the vault's items.
    pub fn create_local(path: String, server_url: String, vault: &LocalVault) -> Result<Arc<Self>> {
        let session = vault.session()?;
        let personal = vault.personal_vault();
        let items = vault
            .items()
            .iter()
            .map(|item| (item.id.clone(), record(&personal.id, item)))
            .collect();
        let vault_record = VaultRecord {
            id: personal.id.clone(),
            vault_type: VaultType::Personal,
            revision: 0,
            wrapped_vault_key: personal.wrapped_vault_key.clone(),
            role: VaultRole::Owner,
            key_id: None,
            grant: None,
            org_id: None,
        };
        let data = StoreData {
            server_url,
            account: session.bundle().clone(),
            password_unlocked_at: now_ms(),
            device_unlock: None,
            vaults: [(personal.id.clone(), vault_record)].into(),
            items,
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

    /// The bundle after the master password changed: a new salt and wrapped ASK.
    pub fn set_local_account(&self, account: AccountBundle) -> Result<()> {
        self.mutate(|data| {
            data.account = account;
            data.password_unlocked_at = now_ms();
            Ok(())
        })
    }

    /// Moves an item to the trash, or out of it with `None`. Local vaults keep the trash here,
    /// not on a server.
    pub fn set_local_trashed(&self, item_id: &str, deleted_at: Option<u64>) -> Result<()> {
        self.mutate(|data| {
            let item = data
                .items
                .get_mut(item_id)
                .ok_or(OctaPassError::ItemNotFound)?;
            item.record.deleted_at = deleted_at.map(timestamp);
            Ok(())
        })
    }

    /// Removes what has been in the trash for 30 days. Returns how many went.
    pub fn purge_local_trash(&self, now: u64) -> Result<usize> {
        self.mutate(|data| {
            let before = data.items.len();
            data.items.retain(|_, item| {
                item.record
                    .deleted_at
                    .as_deref()
                    .and_then(parse_timestamp)
                    .is_none_or(|at| now.saturating_sub(at) < local::TRASH_RETENTION_MS)
            });
            Ok(before - data.items.len())
        })
    }

    /// The items of a local vault, as `LocalVault` keeps them. An item created by the AutoFill
    /// extension or here carries its creation time in its UUIDv7 id.
    pub fn local_items(&self) -> Vec<LocalItem> {
        self.data()
            .items
            .values()
            .map(|stored| {
                let record = &stored.record;
                let updated_at = parse_timestamp(&record.updated_at).unwrap_or(0);
                LocalItem {
                    id: record.id.clone(),
                    encrypted: EncryptedItem {
                        encrypted_item_key: record.encrypted_item_key.clone(),
                        overview: record.overview.clone(),
                        details: record.details.clone(),
                    },
                    created_at: created_at(&record.id).unwrap_or(updated_at),
                    updated_at,
                    deleted_at: record.deleted_at.as_deref().and_then(parse_timestamp),
                }
            })
            .collect()
    }

    /// When this vault last changed (Unix ms), for automatic backups: the newest edit or trashing.
    pub fn last_changed_at(&self) -> u64 {
        self.data()
            .items
            .values()
            .flat_map(|stored| {
                let record = &stored.record;
                [
                    Some(record.updated_at.as_str()),
                    record.deleted_at.as_deref(),
                ]
            })
            .flatten()
            .filter_map(parse_timestamp)
            .max()
            .unwrap_or(0)
    }

    /// Takes in a local vault's items as new ones to upload, for turning on sync. The vault's
    /// personal vault id is kept, so they're already encrypted for where they're going. Run a
    /// sync next: it brings the vault record.
    pub fn adopt_local_items(&self, local: &LocalStore) -> Result<()> {
        let items = local.data().items.clone();
        self.mutate(|data| {
            data.items.extend(items.into_iter().map(|(id, mut item)| {
                item.record.revision = 0;
                item.sync = SyncState::New;
                (id, item)
            }));
            Ok(())
        })
    }

    /// Items this vault has in the trash, as the upload for turning on sync can't say so.
    pub fn trashed_item_ids(&self) -> Vec<String> {
        self.data()
            .items
            .values()
            .filter(|stored| stored.record.deleted_at.is_some())
            .map(|stored| stored.record.id.clone())
            .collect()
    }

    /// Reads a store's file without keeping it open.
    pub fn exists(path: &str) -> bool {
        matches!(read(&PathBuf::from(path)), Ok(Some(_)))
    }
}

/// A UUIDv7 starts with its creation time in milliseconds.
fn created_at(id: &str) -> Option<u64> {
    let hex: String = id
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(12)
        .collect();
    (hex.len() == 12)
        .then(|| u64::from_str_radix(&hex, 16).ok())
        .flatten()
}

impl Session {
    /// A session over a local vault's keys, right after creating or restoring it.
    pub fn from_local_vault(vault: &LocalVault) -> Result<Arc<Self>> {
        Ok(Self::new(vault.session()?))
    }

    /// The local vault this session has open, put back together from its seed and the store:
    /// for a backup, a password change or turning on sync.
    pub fn local_vault(&self, store: &LocalStore, seed: &[u8]) -> Result<LocalVault> {
        store.check_account(self)?;
        let items = store.local_items();
        self.with(|core: &mut CoreSession| {
            let mut vault = LocalVault::from_seed(seed, core)?;
            vault.set_items(items);
            Ok(vault)
        })
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::backup::BACKUP_KDF;
    use octapass_core::kdf::KdfParams;
    use octapass_core::local::DeviceProtection;
    use rand_core::OsRng;

    use super::*;
    use crate::items::LoginDraft;

    const PASSWORD: &str = "vexed-kiwi-trumpet-galaxy-oboe";
    const CHIP: [u8; 32] = [7; 32];

    fn local_vault(chip: Option<&[u8]>) -> LocalVault {
        LocalVault::create_with_backup_kdf(
            PASSWORD,
            DeviceProtection {
                kdf: KdfParams::DEFAULT,
                hardware_secret: chip,
            },
            KdfParams::DEFAULT,
            now_ms(),
            &mut OsRng,
        )
        .unwrap()
    }

    fn draft(url: &str) -> LoginDraft {
        LoginDraft {
            item_id: None,
            title: Some("Example".into()),
            url: Some(url.into()),
            username: Some("ada".into()),
            password: Some("pw-1".into()),
            totp: None,
        }
    }

    #[test]
    fn a_local_store_unlocks_with_the_password_and_the_chip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.opstore").to_string_lossy().into_owned();
        let vault = local_vault(Some(&CHIP));
        let id = vault.vault_id().to_owned();
        let store = LocalStore::create_local(path.clone(), format!("local:{id}"), &vault).unwrap();
        assert!(store.is_local());
        assert_eq!(BACKUP_KDF.iterations, 4);

        // The AutoFill extension opens the same file.
        let extension = LocalStore::open(path).unwrap();
        assert!(extension.is_local());
        let session = extension
            .unlock_local(PASSWORD.into(), Some(CHIP.to_vec()))
            .unwrap();
        assert!(matches!(
            extension.unlock_local("wrong".into(), Some(CHIP.to_vec())),
            Err(OctaPassError::LoginFailed)
        ));
        assert!(matches!(
            extension.unlock_local(PASSWORD.into(), None),
            Err(OctaPassError::LoginFailed)
        ));

        let item = session
            .save_login(extension.clone(), draft("https://example.com/in"))
            .unwrap();
        let matched = session
            .match_logins(extension.clone(), "https://example.com/".into())
            .unwrap();
        assert_eq!(matched[0].item.item_id, item);

        // Device unlock is the same record as for accounts.
        extension
            .enable_device_unlock(session.clone(), vec![3; 32])
            .unwrap();
        let by_device = extension.unlock_with_device(vec![3; 32]).unwrap();
        assert_eq!(
            by_device.get_item(extension, item).unwrap().title,
            "Example"
        );
    }

    #[test]
    fn a_backup_holds_what_the_store_holds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.opstore").to_string_lossy().into_owned();
        let mut vault = local_vault(None);
        vault.set_name(Some("Home".into()));
        let seed = vault.seed(&mut OsRng).unwrap();
        let store = LocalStore::create_local(path, "local:x".into(), &vault).unwrap();
        let session = Session::from_local_vault(&vault).unwrap();

        let kept = session
            .save_login(store.clone(), draft("https://a.example/"))
            .unwrap();
        let trashed = session
            .save_login(store.clone(), draft("https://b.example/"))
            .unwrap();
        let at = now_ms();
        store.set_local_trashed(&trashed, Some(at)).unwrap();
        assert!(store.last_changed_at() >= at);
        assert_eq!(store.trashed_item_ids(), vec![trashed.clone()]);

        let whole = session.local_vault(&store, &seed).unwrap();
        assert_eq!(whole.name(), Some("Home"));
        let listed = whole.list().unwrap();
        assert_eq!(listed.len(), 2);
        let gone = listed.iter().find(|item| item.id == trashed).unwrap();
        assert_eq!(gone.deleted_at, Some(at));
        let live = listed.iter().find(|item| item.id == kept).unwrap();
        assert!(live.created_at > 0 && live.created_at <= live.updated_at + 1);

        assert_eq!(store.purge_local_trash(at + 1).unwrap(), 0);
        assert_eq!(
            store
                .purge_local_trash(at + local::TRASH_RETENTION_MS)
                .unwrap(),
            1
        );
        assert!(store.trashed_item_ids().is_empty());
    }

    #[test]
    fn a_restored_vault_keeps_its_items_as_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.opstore").to_string_lossy().into_owned();
        let mut vault = local_vault(None);
        let item: octapass_core::item::Item = octapass_core::item::Item::from_json(
            r#"{"overview":{"title":"A","type":"login"},"details":{"password":"pw"}}"#,
        )
        .unwrap();
        vault.add_item(&item, now_ms(), &mut OsRng).unwrap();
        let store = LocalStore::create_local(path, "local:x".into(), &vault).unwrap();
        assert!(store.has_pending_changes());
    }
}
