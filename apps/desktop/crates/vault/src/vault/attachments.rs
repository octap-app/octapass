//! Attachments: files encrypted here under a key of their own, which the item key wraps
//! (`octapass_core::attachment`). Uploads stream the ciphertext as it's made; the file's name,
//! media type, size and wrapped key go in the item's details, so the server never sees them.

use std::sync::Arc;

use futures_util::stream;
use octapass_api::problem::types;
use octapass_api::{ItemRecord, VaultRole};
use octapass_core::account::new_id;
use octapass_core::attachment::{self, Encryptor};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::{Vault, decrypt};
use crate::api::{ApiError, Precondition};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, now, require, unix_ms};
use crate::store::AccountKey;

/// Plaintext encrypted per step of an upload.
const SLICE: usize = 1024 * 1024;
/// A write racing other devices' edits of the same item; after this many conflicts, give up.
const ATTEMPTS: usize = 3;

/// `StorageUsage` in `packages/vault-client`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsage {
    pub attachment_bytes: u64,
    pub max_attachment_bytes: u64,
    pub max_file_bytes: u64,
}

/// The ciphertext of `file`, produced a slice at a time as the request body is sent.
fn encrypting_body(encryptor: Encryptor, file: Arc<Vec<u8>>) -> reqwest::Body {
    let mut encryptor = Some(encryptor);
    let mut offset = 0;
    let pieces = std::iter::from_fn(move || {
        let current = encryptor.as_mut()?;
        if offset < file.len() {
            let end = (offset + SLICE).min(file.len());
            let piece = current.push(&file[offset..end]);
            offset = end;
            Some(piece)
        } else {
            Some(encryptor.take()?.finish())
        }
    });
    reqwest::Body::wrap_stream(stream::iter(pieces))
}

fn attachments(item: &Item) -> Vec<Value> {
    item.details
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn attachment_id(entry: &Value) -> Option<&str> {
    entry.get("id").and_then(Value::as_str)
}

impl Vault {
    /// Encrypts and uploads a file, then lists it in the item's details.
    pub async fn add_attachment(
        &self,
        item_id: &str,
        name: &str,
        media_type: &str,
        file: Vec<u8>,
    ) -> Result<Item> {
        let _io = self.io.lock().await;
        let (key, record) = self.writable_record(item_id)?;
        require(record.deleted_at.is_none(), ErrorCode::NotFound)?;
        let usage = self
            .authed(&key, |api, token| async move { api.usage(&token).await })
            .await??;
        let stored = attachment::encrypted_len(file.len() as u64);
        require(stored <= usage.max_file_bytes, ErrorCode::FileTooLarge)?;
        // The quota is the vault owner's, so only our own vaults can be checked here.
        let owner = self.with_unlocked(|unlocked| {
            let vault = unlocked.cache.vault(&record.vault_id);
            Ok(vault.is_some_and(|vault| vault.role == VaultRole::Owner))
        })?;
        require(
            !owner || usage.attachment_bytes + stored <= usage.max_attachment_bytes,
            ErrorCode::QuotaExceeded,
        )?;

        let id = new_id(unix_ms(now()), &mut OsRng);
        let size = file.len();
        let wrapped_key = self
            .upload(&key, &record, &id, Arc::new(file), stored)
            .await?;
        let entry =
            json!({ "id": id, "name": name, "type": media_type, "size": size, "key": wrapped_key });
        let added = self
            .update_attachments(&key, item_id, |list| list.push(entry.clone()))
            .await;
        if added.is_err() {
            // Listed nowhere, so nothing could open it: take it back off the server.
            let ids = (record.vault_id.as_str(), record.id.as_str(), id.as_str());
            let _ = self
                .authed(&key, |api, token| async move {
                    api.delete_attachment(&token, ids).await
                })
                .await;
        }
        added
    }

    /// Uploads under a fresh file key, encrypting as it sends. A retry after the access token
    /// expired encrypts again under a new key. Returns the wrapped file key that was used.
    async fn upload(
        &self,
        key: &AccountKey,
        record: &ItemRecord,
        id: &str,
        file: Arc<Vec<u8>>,
        stored: u64,
    ) -> Result<String> {
        let ids = (record.vault_id.as_str(), record.id.as_str(), id);
        let api = self.api(&key.server_url);
        let mut renew = false;
        loop {
            let token = self.access_token(key, renew).await?;
            let (wrapped_key, encryptor) = self.with_unlocked(|unlocked| {
                Ok(unlocked.session.new_attachment(
                    ids.0,
                    ids.1,
                    &record.encrypted_item_key,
                    ids.2,
                    &mut OsRng,
                )?)
            })?;
            let body = encrypting_body(encryptor, file.clone());
            match api.upload_attachment(&token, ids, stored, body).await {
                Ok(_) => return Ok(wrapped_key),
                Err(error) if error.is_unauthorized() && !renew => renew = true,
                Err(error) => {
                    if error.is_account_deleted() {
                        self.forget(key)?;
                    }
                    return Err(error.into());
                }
            }
        }
    }

    /// Downloads and decrypts a file. Nothing is returned unless the whole file checks out.
    pub async fn get_attachment(&self, item_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        let (key, record, wrapped_key, size) = self.with_unlocked(|unlocked| {
            let record = unlocked.cache.item(item_id).ok_or(ErrorCode::NotFound)?;
            let item = decrypt(&unlocked.session, record)?;
            let entry = attachments(&item)
                .into_iter()
                .find(|entry| self::attachment_id(entry) == Some(attachment_id))
                .ok_or(ErrorCode::NotFound)?;
            let wrapped_key = entry.get("key").and_then(Value::as_str).unwrap_or_default();
            let size = entry
                .get("size")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            Ok((
                unlocked.key.clone(),
                record.clone(),
                wrapped_key.to_owned(),
                size,
            ))
        })?;
        let mut decryptor = self.with_unlocked(|unlocked| {
            Ok(unlocked.session.open_attachment(
                &record.vault_id,
                &record.id,
                &record.encrypted_item_key,
                attachment_id,
                &wrapped_key,
            )?)
        })?;
        let ids = (record.vault_id.as_str(), record.id.as_str(), attachment_id);
        let mut response = {
            let _io = self.io.lock().await;
            self.authed(&key, |api, token| async move {
                api.download_attachment(&token, ids).await
            })
            .await??
        };
        let network = |error: reqwest::Error| {
            VaultError::from(ApiError::Network(error.without_url().to_string()))
        };
        let damaged =
            |_| VaultError::new(ErrorCode::ServerError, "the file could not be decrypted");
        let mut file = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            file.extend_from_slice(&decryptor.push(&chunk).map_err(damaged)?);
        }
        file.extend_from_slice(&decryptor.finish().map_err(damaged)?);
        Ok(file)
    }

    /// Takes a file off the item, then deletes it from the server.
    pub async fn remove_attachment(&self, item_id: &str, attachment_id: &str) -> Result<Item> {
        let _io = self.io.lock().await;
        let (key, record) = self.writable_record(item_id)?;
        let item = self
            .update_attachments(&key, item_id, |list| {
                list.retain(|entry| self::attachment_id(entry) != Some(attachment_id));
            })
            .await?;
        let ids = (record.vault_id.as_str(), record.id.as_str(), attachment_id);
        match self
            .authed(&key, |api, token| async move {
                api.delete_attachment(&token, ids).await
            })
            .await?
        {
            Err(error) if error.is(octapass_api::problem::types::NOT_FOUND) => {}
            other => other?,
        }
        Ok(item)
    }

    pub async fn storage_usage(&self) -> Result<StorageUsage> {
        let _io = self.io.lock().await;
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        let usage = self
            .authed(&key, |api, token| async move { api.usage(&token).await })
            .await??;
        Ok(StorageUsage {
            attachment_bytes: usage.attachment_bytes,
            max_attachment_bytes: usage.max_attachment_bytes,
            max_file_bytes: usage.max_file_bytes,
        })
    }

    /// Rewrites the item's attachment list on top of the server's current version, never as a
    /// conflicting copy: a copy couldn't open the files, which are bound to this item and its
    /// key. The caller holds `io`.
    async fn update_attachments(
        &self,
        key: &AccountKey,
        item_id: &str,
        change: impl Fn(&mut Vec<Value>),
    ) -> Result<Item> {
        for attempt in 1..=ATTEMPTS {
            let (record, item) = self.with_unlocked(|unlocked| {
                let record = unlocked
                    .cache
                    .item(item_id)
                    .ok_or(ErrorCode::NotFound)?
                    .clone();
                let item = decrypt(&unlocked.session, &record)?;
                Ok((record, item))
            })?;
            let mut list = attachments(&item);
            change(&mut list);
            let mut details: Map<String, Value> =
                item.details.as_object().cloned().unwrap_or_default();
            if list.is_empty() {
                details.remove("attachments");
            } else {
                details.insert("attachments".into(), Value::Array(list));
            }
            let draft = ItemDraft {
                id: Some(record.id.clone()),
                vault_id: record.vault_id.clone(),
                revision: Some(record.revision),
                overview: item.overview,
                details: Value::Object(details),
            };
            let precondition = Precondition::Revision(record.revision);
            match self
                .put(
                    key,
                    &draft,
                    &record.id,
                    Some(&record.encrypted_item_key),
                    precondition,
                )
                .await?
            {
                Ok(()) => {
                    self.sync_locked().await?;
                    return self.get_item(item_id);
                }
                // A rotation re-wrapped the item key: go again from the rotated record.
                Err(error) if error.is(types::VAULT_KEY_CHANGED) && attempt < ATTEMPTS => {
                    self.sync_locked().await?;
                }
                Err(ApiError::Problem { problem, .. })
                    if problem.current.is_some() && attempt < ATTEMPTS =>
                {
                    self.with_unlocked(|unlocked| {
                        unlocked
                            .cache
                            .upsert(problem.current.expect("checked above"));
                        Ok(())
                    })?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        unreachable!("the last attempt returns")
    }
}
