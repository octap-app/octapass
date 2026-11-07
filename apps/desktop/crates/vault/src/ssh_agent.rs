//! What the desktop app's SSH agent needs from the vault: the keys to offer, and one signature at
//! a time. Private keys stay in the vault and are read for the length of the call. Asking the user
//! happens before [`Vault::ssh_agent_sign`], in the app.

use std::sync::Arc;

use octapass_core::tools::ssh;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::model::Item;
use crate::vault::{Vault, blocking};

/// A key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKey {
    pub item_id: String,
    pub title: String,
    /// The public key's wire form: what SSH names it by.
    pub blob: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
    pub key_type: String,
}

fn agent_key(item: &Item) -> Option<AgentKey> {
    if item.overview.get("type").and_then(Value::as_str) != Some("sshKey")
        || item.details.get("sshAgent") == Some(&Value::Bool(false))
    {
        return None;
    }
    item.detail("privateKey")?;
    let public = item.detail("publicKey")?;
    let info = ssh::read_public_key(public).ok()?;
    info.usable.then_some(())?;
    Some(AgentKey {
        item_id: item.id.clone(),
        title: item.title().to_owned(),
        blob: ssh::public_key_blob(public).ok()?,
        comment: item.detail("comment").unwrap_or_default().to_owned(),
        fingerprint: info.fingerprint,
        key_type: info.key_type,
    })
}

impl Vault {
    /// The keys to offer, by title. Fails with `locked` while locked: the agent asks then.
    pub fn ssh_agent_keys(&self) -> Result<Vec<AgentKey>> {
        let mut keys: Vec<AgentKey> = self.live_items()?.iter().filter_map(agent_key).collect();
        keys.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.item_id.cmp(&b.item_id))
        });
        Ok(keys)
    }

    /// Signs `data` with the key `blob` names. The caller has the user's approval. Returns the
    /// signature in SSH's wire form.
    pub async fn ssh_agent_sign(&self, blob: &[u8], data: Vec<u8>, flags: u32) -> Result<Vec<u8>> {
        let item = self
            .live_items()?
            .into_iter()
            .find(|item| agent_key(item).is_some_and(|key| key.blob == blob))
            .ok_or(ErrorCode::NotFound)?;
        let private_key = item
            .detail("privateKey")
            .map(|key| Zeroizing::new(key.to_owned()))
            .ok_or(ErrorCode::NotFound)?;
        // RSA takes a moment.
        blocking(move || Ok(ssh::sign(&private_key, &data, flags)?)).await
    }

    /// Asks the device lock to approve something. `Ok(false)` when the device has no lock to ask:
    /// the app then asks in a window of its own.
    pub async fn approve_with_device(self: &Arc<Self>, reason: String) -> Result<bool> {
        let device_unlock = Arc::clone(&self.device_unlock);
        blocking(move || {
            let can_ask = device_unlock
                .capabilities()
                .is_ok_and(|capabilities| capabilities.method.is_some());
            if can_ask {
                device_unlock.verify_user(&reason)?;
            }
            Ok(can_ask)
        })
        .await
    }

    /// Opens the vault with the device lock, for a request that arrived while it was locked.
    pub async fn ssh_agent_unlock(self: &Arc<Self>) -> Result<()> {
        self.unlock_with_device().await
    }
}
