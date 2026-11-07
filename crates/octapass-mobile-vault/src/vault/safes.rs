//! Octa Pass Safes on the phone (plan 16 §4), the same items and blobs as the desktop app's
//! `vault/safes.rs`: a `fileSafe` item in the personal vault holds the key, and a synced Safe's
//! blobs are attachments of that item, which its details don't list.
//!
//! The item reaches every device with the vault, but a Safe kept on one device has its files only
//! there: its item names that device (`device`, this install's id), and other devices leave it
//! out of their list. One made before Safes named their device lists where its folder is.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use octapass_api::{AttachmentsResponse, VaultType};
use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::keys::SymmetricKey;
use octapass_core::safe::new_object_id;
use octapass_ffi::HttpMethod;
use octapass_files::safe::SafeError;
use octapass_files::safe::sync::{Remote, RemoteBlob};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

use super::{Unlocked, Vault};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, require};

pub const SAFE_ITEM_TYPE: &str = "fileSafe";

/// A Safe, as its vault item says. The key is only read to open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeInfo {
    pub item_id: String,
    pub safe_id: String,
    pub name: String,
    pub sync: bool,
    /// For a Safe kept on one device, the install that has it (`Vault::this_device`). None for a
    /// synced Safe, and for one made before Safes named their device.
    pub device: Option<String>,
}

/// The file in the data folder that holds this install's id.
const DEVICE_ID_FILE: &str = "device-id";

fn is_safe(item: &Item) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(SAFE_ITEM_TYPE)
}

fn info(item: &Item) -> Option<SafeInfo> {
    Some(SafeInfo {
        item_id: item.id.clone(),
        // The id names the Safe's folder on each device, so only a UUID is taken.
        safe_id: octapass_core::account::parse_id(item.detail("safeId")?).ok()?,
        name: item.title().to_owned(),
        sync: item.details.get("sync").and_then(Value::as_bool) == Some(true),
        device: item
            .detail("device")
            .and_then(|id| octapass_core::account::parse_id(id).ok()),
    })
}

impl Vault {
    /// The Safes this device has: every synced one, and those kept here. `folder` is the app's
    /// Safes folder: a Safe made before Safes named their device lists only where its folder is,
    /// or everywhere when the caller doesn't say.
    pub fn list_safes(&self, folder: Option<&Path>) -> Result<Vec<SafeInfo>> {
        let mine = self.this_device().ok();
        let mut safes: Vec<SafeInfo> = self
            .live_items()?
            .iter()
            .filter(|item| is_safe(item))
            .filter_map(info)
            .filter(|safe| {
                safe.sync
                    || match &safe.device {
                        Some(device) => mine.as_ref() == Some(device),
                        // The id is a UUID (`info`), so it stays inside the folder.
                        None => folder.is_none_or(|folder| {
                            folder.join(&safe.safe_id).join("safe.json").exists()
                        }),
                    }
            })
            .collect();
        safes.sort_by_key(|safe| safe.name.to_lowercase());
        Ok(safes)
    }

    /// This install's id, made on first use, which a Safe kept on this device names. Random and
    /// not a secret; it only leaves the device inside the vault's encrypted items.
    pub fn this_device(&self) -> Result<String> {
        let path = self.config.data_dir.join(DEVICE_ID_FILE);
        if let Ok(text) = fs::read_to_string(&path)
            && let Ok(id) = octapass_core::account::parse_id(text.trim())
        {
            return Ok(id);
        }
        let id = new_object_id(&mut OsRng);
        let written = path.with_extension("new");
        fs::create_dir_all(&self.config.data_dir)
            .and_then(|()| fs::write(&written, &id))
            .and_then(|()| fs::rename(&written, &path))
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        Ok(id)
    }

    pub fn create_safe(&self, name: &str, sync: bool) -> Result<SafeInfo> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::unexpected("a Safe needs a name"));
        }
        let vault = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .ok_or(ErrorCode::NotFound)?;
        let key = SymmetricKey::generate(&mut OsRng);
        let mut details = json!({
            "schemaVersion": 1,
            "safeId": new_object_id(&mut OsRng),
            "key": b64_encode(key.as_bytes()),
            "sync": sync,
        });
        if !sync {
            details["device"] = Value::String(self.this_device()?);
        }
        let draft = ItemDraft {
            id: None,
            vault_id: vault.id,
            revision: None,
            overview: json!({ "schemaVersion": 1, "type": SAFE_ITEM_TYPE, "title": name }),
            details,
        };
        let item = self.save_item(draft)?;
        info(&item).ok_or_else(|| VaultError::unexpected("the new Safe's item didn't read back"))
    }

    fn safe_item(&self, item_id: &str) -> Result<Item> {
        let item = self.get_item(item_id)?;
        require(is_safe(&item), ErrorCode::NotFound)?;
        Ok(item)
    }

    pub fn safe_key(&self, item_id: &str) -> Result<SymmetricKey> {
        let item = self.safe_item(item_id)?;
        let encoded = item.detail("key").ok_or(ErrorCode::NotFound)?;
        Ok(SymmetricKey::from_bytes(
            b64_decode_array(encoded).map_err(|_| ErrorCode::NotFound)?,
        ))
    }

    /// Deletes a Safe: its item goes to the trash, which takes the key with it. Its synced blobs go
    /// when the trash is emptied. The caller removes its folder on this device.
    pub fn delete_safe(&self, item_id: &str) -> Result<()> {
        self.safe_item(item_id)?;
        self.delete_item(item_id)
    }

    /// Where a Safe's blobs sync to.
    pub fn safe_remote(self: &Arc<Self>, item_id: &str) -> Result<SafeRemote> {
        let item = self.safe_item(item_id)?;
        let max_blob = self.storage_usage()?.max_file_bytes;
        Ok(SafeRemote {
            vault: Arc::clone(self),
            vault_id: item.vault_id,
            item_id: item.id,
            max_blob,
        })
    }

    fn blob_url(&self, unlocked: &Unlocked, vault_id: &str, item_id: &str, blob: &str) -> String {
        format!(
            "{}v1/vaults/{vault_id}/items/{item_id}/attachments/{blob}",
            unlocked.server.base_url()
        )
    }
}

/// A Safe's blobs on the Octa Pass server.
pub struct SafeRemote {
    vault: Arc<Vault>,
    vault_id: String,
    item_id: String,
    max_blob: u64,
}

fn remote_error(error: impl std::fmt::Display) -> SafeError {
    SafeError::Remote(error.to_string())
}

impl SafeRemote {
    fn run<T>(
        &self,
        call: impl FnOnce(&Vault, &Unlocked) -> Result<T>,
    ) -> octapass_files::safe::Result<T> {
        let unlocked = self.vault.unlocked().map_err(remote_error)?;
        let _io = self.vault.io();
        call(&self.vault, &unlocked).map_err(remote_error)
    }
}

impl Remote for SafeRemote {
    async fn list(&self) -> octapass_files::safe::Result<Vec<RemoteBlob>> {
        self.run(|vault, unlocked| {
            let url = format!(
                "{}v1/vaults/{}/items/{}/attachments",
                unlocked.server.base_url(),
                self.vault_id,
                self.item_id
            );
            let listed: AttachmentsResponse = vault.with_token(unlocked, |token| {
                vault.http.json(HttpMethod::Get, url.clone(), token, &[])
            })?;
            Ok(listed
                .attachments
                .into_iter()
                .map(|record| RemoteBlob {
                    id: record.id,
                    size: record.size,
                })
                .collect())
        })
    }

    async fn get(&self, id: &str) -> octapass_files::safe::Result<Vec<u8>> {
        self.run(|vault, unlocked| {
            let url = vault.blob_url(unlocked, &self.vault_id, &self.item_id, id);
            let mut source =
                vault.with_token(unlocked, |token| vault.http.download(url.clone(), token))?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut source, &mut bytes).map_err(|error| {
                VaultError::new(ErrorCode::ServerUnreachable, error.to_string())
            })?;
            Ok(bytes)
        })
    }

    async fn put(&self, id: &str, bytes: Vec<u8>) -> octapass_files::safe::Result<()> {
        // The upload reads from a file. These bytes are ciphertext, so a temporary one is fine.
        let mut name = [0u8; 12];
        OsRng.fill_bytes(&mut name);
        let path = std::env::temp_dir().join(format!("octapass-blob-{}", b64_encode(&name)));
        fs::write(&path, bytes)?;
        let sent = self.run(|vault, unlocked| {
            let url = vault.blob_url(unlocked, &self.vault_id, &self.item_id, id);
            vault.with_token(unlocked, |token| {
                vault.http.upload_file(url.clone(), token, &path)
            })
        });
        let _ = fs::remove_file(&path);
        sent
    }

    async fn delete(&self, id: &str) -> octapass_files::safe::Result<()> {
        self.run(|vault, unlocked| {
            let url = vault.blob_url(unlocked, &self.vault_id, &self.item_id, id);
            vault.with_token(unlocked, |token| {
                vault.http.call(HttpMethod::Delete, url.clone(), token)
            })?;
            Ok(())
        })
    }

    fn max_blob(&self) -> u64 {
        self.max_blob
    }
}
