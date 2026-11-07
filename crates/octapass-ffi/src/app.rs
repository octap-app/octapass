//! Rust-only access for the phone apps' own Rust side (`crates/octapass-mobile-vault`): every
//! item type as the core models it, the trash, the vaults, attachment keys, and how uploads settle
//! conflicts. None of it is exported to Swift or Kotlin; the autofill extensions only need the
//! fill-oriented API.

use octapass_api::{ItemRecord, VaultRecord};
use octapass_core::account::new_id;
use octapass_core::attachment::{Decryptor, Encryptor};
use octapass_core::item::Item as CoreItem;
use rand_core::OsRng;
use serde_json::Value;

use crate::error::{OctaPassError, Result};
use crate::session::{Session, decrypt, encrypt, open_vault};
use crate::store::{LocalStore, SyncState};
use crate::{now_ms, timestamp};

/// An item from the store with its plaintext.
#[derive(Debug, Clone)]
pub struct DecryptedItem {
    /// The encrypted record as stored: ids, revision, `updatedAt`, `deletedAt`.
    pub record: ItemRecord,
    /// Saved here and not uploaded yet.
    pub pending: bool,
    pub item: CoreItem,
}

impl LocalStore {
    /// The vaults the account can open, as of the last sync.
    pub fn vaults(&self) -> Vec<VaultRecord> {
        self.data().vaults.values().cloned().collect()
    }

    /// Every item record as stored, the ones no session here can open included: a key rotation
    /// re-wraps them all.
    pub fn item_records(&self) -> Vec<ItemRecord> {
        self.data()
            .items
            .values()
            .map(|stored| stored.record.clone())
            .collect()
    }
}

impl Session {
    /// Runs `f` on the unlocked keys: what the native apps' API needs beyond items (shared
    /// vaults' grants, key rotation, emergency access). Fails with `Locked` after `lock()`.
    pub fn with_keys<R>(
        &self,
        f: impl FnOnce(&mut octapass_core::session::Session) -> Result<R>,
    ) -> Result<R> {
        self.with(f)
    }

    /// Every item in the store, the trash included. Items that don't decrypt (damaged, or from a
    /// vault this session can't open) are left out, so one bad item never hides the others.
    pub fn decrypt_items(&self, store: &LocalStore) -> Result<Vec<DecryptedItem>> {
        self.with_store(store, |core, data| {
            Ok(data
                .items
                .values()
                .filter_map(|stored| {
                    Some(DecryptedItem {
                        item: decrypt(core, data, &stored.record).ok()?,
                        record: stored.record.clone(),
                        pending: stored.sync != SyncState::Synced,
                    })
                })
                .collect())
        })
    }

    pub fn decrypt_item(&self, store: &LocalStore, item_id: &str) -> Result<DecryptedItem> {
        self.with_store(store, |core, data| {
            let stored = data.items.get(item_id).ok_or(OctaPassError::ItemNotFound)?;
            Ok(DecryptedItem {
                item: decrypt(core, data, &stored.record)?,
                record: stored.record.clone(),
                pending: stored.sync != SyncState::Synced,
            })
        })
    }

    /// Saves an item of any type to the store, to upload with `OctaPassServer::upload_pending`.
    /// `item_id` is `None` for a new item in `vault_id`; an existing item stays in its vault.
    /// Returns the item id.
    pub fn save_item(
        &self,
        store: &LocalStore,
        vault_id: &str,
        item_id: Option<&str>,
        item: &CoreItem,
    ) -> Result<String> {
        let now = timestamp(now_ms());
        let (vault_id, item_id, base, encrypted) = self.with_store(store, |core, data| {
            let (vault_id, item_id, base) = match item_id {
                Some(item_id) => {
                    let base = data.items.get(item_id).ok_or(OctaPassError::ItemNotFound)?;
                    (
                        base.record.vault_id.clone(),
                        item_id.to_owned(),
                        Some(base.clone()),
                    )
                }
                None => (vault_id.to_owned(), new_id(now_ms(), &mut OsRng), None),
            };
            let encrypted = encrypt(core, data, &vault_id, &item_id, item, base.as_ref())?;
            Ok((vault_id, item_id, base, encrypted))
        })?;
        store.mutate(|data| {
            data.put_local(&vault_id, &item_id, encrypted, base.as_ref(), &now);
            Ok(())
        })?;
        Ok(item_id)
    }
}

/// What an upload does with an item that changed both here and on the server
/// ([`crate::OctaPassServer::upload_pending_resolving`]). It gets the item id, this device's
/// version and the server's (`None` when the server sent none).
pub type Resolve<'a> = &'a dyn Fn(&str, &CoreItem, Option<&CoreItem>) -> Resolution;

/// How a conflict is settled. The server's version is always kept as the base.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    /// Saved over the server's version and uploaded on top of it.
    pub merged: Option<CoreItem>,
    /// Saved next to it as "<title> (conflicting copy)".
    pub copy: Option<CoreItem>,
}

impl Resolution {
    /// The usual way: this device's version becomes a copy, without the attachments, whose keys
    /// are bound to the original item.
    pub fn copy(local: &CoreItem) -> Self {
        Self {
            merged: None,
            copy: Some(without_attachments(local)),
        }
    }
}

/// `item` with no `attachments` in its details.
pub fn without_attachments(item: &CoreItem) -> CoreItem {
    let mut details = serde_json::to_value(&item.details).expect("items serialize");
    let removed = details
        .as_object_mut()
        .and_then(|fields| fields.remove("attachments"));
    match removed {
        Some(_) => {
            CoreItem::from_parts(item.overview.clone(), details).unwrap_or_else(|_| item.clone())
        }
        None => item.clone(),
    }
}

/// The entries in `item`'s `attachments`, as JSON.
pub fn attachments_of(item: &CoreItem) -> Vec<Value> {
    let details = serde_json::to_value(&item.details).expect("items serialize");
    match details.get("attachments") {
        Some(Value::Array(list)) => list.clone(),
        _ => Vec::new(),
    }
}

/// `item` with `list` as its attachments (none when it's empty).
pub fn with_attachments(item: &CoreItem, list: Vec<Value>) -> Result<CoreItem> {
    let mut details = serde_json::to_value(&item.details).expect("items serialize");
    if let Some(fields) = details.as_object_mut() {
        if list.is_empty() {
            fields.remove("attachments");
        } else {
            fields.insert("attachments".into(), Value::Array(list));
        }
    }
    Ok(CoreItem::from_parts(item.overview.clone(), details)?)
}

impl Session {
    /// Starts a file for a stored item (`octapass_core::attachment`): a fresh file key wrapped by
    /// the item key, and the encryptor. The item may not be uploaded yet; its key is in the store.
    pub fn new_attachment(
        &self,
        store: &LocalStore,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(String, Encryptor)> {
        self.with_store(store, |core, data| {
            let stored = data.items.get(item_id).ok_or(OctaPassError::ItemNotFound)?;
            let record = &stored.record;
            data.writable_vault(&record.vault_id)?;
            open_vault(core, data, &record.vault_id)?;
            Ok(core.new_attachment(
                &record.vault_id,
                &record.id,
                &record.encrypted_item_key,
                attachment_id,
                &mut OsRng,
            )?)
        })
    }

    /// Decrypts an item record this device kept aside (an earlier version of a stored item).
    pub fn decrypt_record(&self, store: &LocalStore, record: &ItemRecord) -> Result<CoreItem> {
        self.with_store(store, |core, data| decrypt(core, data, record))
    }

    /// A decryptor for one of a stored item's files, from the wrapped key in its details.
    pub fn open_attachment(
        &self,
        store: &LocalStore,
        item_id: &str,
        attachment_id: &str,
        wrapped_key: &str,
    ) -> Result<Decryptor> {
        self.with_store(store, |core, data| {
            let stored = data.items.get(item_id).ok_or(OctaPassError::ItemNotFound)?;
            let record = &stored.record;
            open_vault(core, data, &record.vault_id)?;
            Ok(core.open_attachment(
                &record.vault_id,
                &record.id,
                &record.encrypted_item_key,
                attachment_id,
                wrapped_key,
            )?)
        })
    }
}
