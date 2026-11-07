//! What files need from the vault (plan 16 §4): the account's age keys for `octapass encrypt`, and
//! Octa Pass Safes.
//!
//! A Safe's key is a `fileSafe` item in the personal vault, so it follows the vault everywhere: it
//! syncs to the account's devices, can't be read while locked, and survives vault key rotation and
//! password changes. Apps keep these items out of their lists.
//!
//! A Safe's optional sync stores its blobs as **attachments of that item**. They're encrypted
//! already, their names are random, the server's quota and clean-up apply as for any attachment,
//! and the item's encrypted details don't list them: `octapass_files::safe::sync` keeps track.

use std::sync::Arc;

use octapass_api::VaultType;
use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::keys::SymmetricKey;
use octapass_core::safe::new_object_id;
use octapass_core::tools::age::{AccountFileKeys, account_recipient};
use octapass_files::safe::SafeError;
use octapass_files::safe::sync::{Remote, RemoteBlob};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{Value, json};

use super::Vault;
use super::sharing::check_fingerprint;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, require};

pub const SAFE_ITEM_TYPE: &str = "fileSafe";

/// A Safe, as a vault item says it. The key isn't here: it's only read to open the Safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeInfo {
    pub item_id: String,
    pub vault_id: String,
    pub safe_id: String,
    pub name: String,
    /// Whether its blobs go through the server to other devices.
    pub sync: bool,
}

/// Someone to encrypt a file for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecipient {
    pub email: String,
    /// `age1…`
    pub recipient: String,
    pub fingerprint: String,
    /// Whether the user compared the fingerprint with its owner. Until then the key is only as
    /// trustworthy as the server that handed it out.
    pub verified: bool,
}

fn is_safe(item: &Item) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(SAFE_ITEM_TYPE)
}

fn info(item: &Item) -> Option<SafeInfo> {
    Some(SafeInfo {
        item_id: item.id.clone(),
        vault_id: item.vault_id.clone(),
        // The id names the Safe's folder on each device, so only a UUID is taken.
        safe_id: octapass_core::account::parse_id(item.detail("safeId")?).ok()?,
        name: item.title().to_owned(),
        sync: item.details.get("sync").and_then(Value::as_bool) == Some(true),
    })
}

fn remote_error(error: VaultError) -> SafeError {
    SafeError::Remote(error.to_string())
}

impl Vault {
    /// The account's age keys. Needs the vault unlocked.
    pub fn file_keys(&self) -> Result<AccountFileKeys> {
        self.with_unlocked(|unlocked| {
            AccountFileKeys::derive(unlocked.session.key_pairs())
                .map_err(|_| VaultError::unexpected("the account's keys aren't age keys"))
        })
    }

    /// Finds another account to encrypt a file for, by email.
    pub async fn file_recipient(&self, email: &str) -> Result<FileRecipient> {
        let account = self.lookup_account(email).await?;
        check_fingerprint(&account)?;
        let key = self.account_key()?;
        let verified = self
            .store
            .load_notes(&key)?
            .verified
            .get(&account.account_id)
            == Some(&account.fingerprint.digits);
        Ok(FileRecipient {
            recipient: account_recipient(&b64_decode_array(&account.public_enc_key)?),
            email: account.email,
            fingerprint: account.fingerprint.digits,
            verified,
        })
    }

    /// The Safes in this account, less those another device keeps to itself.
    pub fn list_safes(&self) -> Result<Vec<SafeInfo>> {
        let mut safes: Vec<SafeInfo> = self
            .live_items()?
            .iter()
            .filter(|item| is_safe(item))
            // A Safe the phone or Mac app keeps on one device names that device; its files are
            // there only. This app never names one, so a named one is another device's.
            .filter(|item| {
                item.details.get("sync").and_then(Value::as_bool) == Some(true)
                    || item.detail("device").is_none()
            })
            .filter_map(info)
            .collect();
        safes.sort_by_key(|safe| safe.name.to_lowercase());
        Ok(safes)
    }

    fn safe_item(&self, item_id: &str) -> Result<Item> {
        let item = self.get_item(item_id)?;
        require(is_safe(&item), ErrorCode::NotFound)?;
        Ok(item)
    }

    /// A Safe's key, to open it with.
    pub fn safe_key(&self, item_id: &str) -> Result<SymmetricKey> {
        let item = self.safe_item(item_id)?;
        let encoded = item.detail("key").ok_or(ErrorCode::NotFound)?;
        Ok(SymmetricKey::from_bytes(b64_decode_array(encoded)?))
    }

    /// Makes a new Safe: a random key and id, kept in an item in the personal vault. Its folder is
    /// made by whoever opens it.
    pub async fn create_safe(&self, name: &str, sync: bool) -> Result<SafeInfo> {
        let name = name.trim();
        require(!name.is_empty(), ErrorCode::NotAllowed)?;
        let vault = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .ok_or(ErrorCode::NotFound)?;
        let key = SymmetricKey::generate(&mut OsRng);
        let draft = ItemDraft {
            id: None,
            vault_id: vault.id,
            revision: None,
            overview: json!({ "schemaVersion": 1, "type": SAFE_ITEM_TYPE, "title": name }),
            details: json!({
                "schemaVersion": 1,
                "safeId": new_object_id(&mut OsRng),
                "key": b64_encode(key.as_bytes()),
                "sync": sync,
            }),
        };
        let item = self.save_item(draft).await?;
        info(&item).ok_or_else(|| VaultError::unexpected("the new Safe's item didn't read back"))
    }

    /// Turns sync on or off for a Safe. Blobs already on the server stay until the Safe goes.
    pub async fn set_safe_sync(&self, item_id: &str, sync: bool) -> Result<SafeInfo> {
        let item = self.safe_item(item_id)?;
        let mut details = item.details.clone();
        details["sync"] = json!(sync);
        let saved = self
            .save_item(ItemDraft {
                id: Some(item.id.clone()),
                vault_id: item.vault_id.clone(),
                revision: Some(item.revision),
                overview: item.overview.clone(),
                details,
            })
            .await?;
        info(&saved).ok_or_else(|| VaultError::unexpected("the Safe's item didn't read back"))
    }

    /// Deletes a Safe: its item goes to the trash, which takes the key with it. Its synced blobs go
    /// when the trash is emptied, as attachments do. The caller removes its folder on this device.
    pub async fn delete_safe(&self, item_id: &str) -> Result<()> {
        self.safe_item(item_id)?;
        self.delete_item(item_id).await
    }

    /// Where a Safe's blobs sync to.
    pub fn safe_remote(self: &Arc<Self>, item_id: &str) -> Result<SafeRemote> {
        let item = self.safe_item(item_id)?;
        Ok(SafeRemote {
            vault: Arc::clone(self),
            vault_id: item.vault_id,
            item_id: item.id,
            max_blob: u64::MAX,
        })
    }

    async fn blob_ids(&self, ids: (&str, &str)) -> Result<Vec<RemoteBlob>> {
        let _io = self.io.lock().await;
        let key = self.account_key()?;
        let listed = self
            .authed(&key, |api, token| async move {
                api.list_attachments(&token, ids).await
            })
            .await??;
        Ok(listed
            .attachments
            .into_iter()
            .map(|record| RemoteBlob {
                id: record.id,
                size: record.size,
            })
            .collect())
    }

    async fn get_blob(&self, ids: (&str, &str, &str)) -> Result<Vec<u8>> {
        let _io = self.io.lock().await;
        let key = self.account_key()?;
        let response = self
            .authed(&key, |api, token| async move {
                api.download_attachment(&token, ids).await
            })
            .await??;
        Ok(response
            .bytes()
            .await
            .map_err(|_| VaultError::from(ErrorCode::ServerUnreachable))?
            .to_vec())
    }

    async fn put_blob(&self, ids: (&str, &str, &str), bytes: Vec<u8>) -> Result<()> {
        let _io = self.io.lock().await;
        let key = self.account_key()?;
        let len = bytes.len() as u64;
        self.authed(&key, |api, token| {
            let bytes = bytes.clone();
            async move { api.upload_attachment(&token, ids, len, bytes.into()).await }
        })
        .await??;
        Ok(())
    }

    async fn delete_blob(&self, ids: (&str, &str, &str)) -> Result<()> {
        let _io = self.io.lock().await;
        let key = self.account_key()?;
        match self
            .authed(&key, |api, token| async move {
                api.delete_attachment(&token, ids).await
            })
            .await?
        {
            Err(error) if error.is(octapass_api::problem::types::NOT_FOUND) => Ok(()),
            other => Ok(other?),
        }
    }
}

/// A Safe's blobs on the Octa Pass server.
pub struct SafeRemote {
    vault: Arc<Vault>,
    vault_id: String,
    item_id: String,
    max_blob: u64,
}

impl SafeRemote {
    /// Asks the server the largest file it takes.
    pub async fn with_server_limit(mut self) -> Result<Self> {
        self.max_blob = self.vault.storage_usage().await?.max_file_bytes;
        Ok(self)
    }

    fn ids<'a>(&'a self, blob: &'a str) -> (&'a str, &'a str, &'a str) {
        (&self.vault_id, &self.item_id, blob)
    }
}

impl Remote for SafeRemote {
    async fn list(&self) -> octapass_files::safe::Result<Vec<RemoteBlob>> {
        self.vault
            .blob_ids((&self.vault_id, &self.item_id))
            .await
            .map_err(remote_error)
    }

    async fn get(&self, id: &str) -> octapass_files::safe::Result<Vec<u8>> {
        self.vault
            .get_blob(self.ids(id))
            .await
            .map_err(remote_error)
    }

    async fn put(&self, id: &str, bytes: Vec<u8>) -> octapass_files::safe::Result<()> {
        self.vault
            .put_blob(self.ids(id), bytes)
            .await
            .map_err(remote_error)
    }

    async fn delete(&self, id: &str) -> octapass_files::safe::Result<()> {
        self.vault
            .delete_blob(self.ids(id))
            .await
            .map_err(remote_error)
    }

    fn max_blob(&self) -> u64 {
        self.max_blob
    }
}
