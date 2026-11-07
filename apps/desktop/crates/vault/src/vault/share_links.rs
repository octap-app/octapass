//! One-time share links (plan 06), as `packages/vault-client/src/remote/shareLinks.ts` does
//! them. The item snapshot is encrypted here under a random key that only ever travels in the
//! link's `#` fragment; the server stores the ciphertext and counts views.

use octapass_api::problem::types;
use octapass_api::{CreateShareLinkResponse, ShareLinkResponse, ShareLinksResponse};
use octapass_core::sharing::share_link;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::Duration;
use zeroize::Zeroizing;

use super::sharing::segment;
use super::{Event, Vault, blocking, normalize_server_url};
use crate::api::Method;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{ItemDraft, now, rfc3339};

const MIN_HOURS: u32 = 1;
const MAX_HOURS: u32 = 30 * 24;
const MAX_VIEWS: u32 = 100;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkOptions {
    /// 1 to 720 (30 days).
    pub expires_in_hours: u32,
    /// 1 to 100.
    pub max_views: u32,
    /// Also needed to open the link; sent separately.
    #[serde(default)]
    pub passphrase: Option<String>,
}

/// A new link. `key` belongs only in the link's fragment, which browsers never send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedShareLink {
    pub id: String,
    pub key: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkInfo {
    pub id: String,
    /// The item it was made from, while it still exists in this vault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_title: Option<String>,
    pub expires_at: String,
    pub max_views: u32,
    pub views: u32,
    pub passphrase_required: bool,
    pub created_at: String,
}

/// A shared item, decrypted here.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SharedItem {
    pub overview: Value,
    pub details: Value,
}

/// The item as it is now, without its old passwords, the favourite and pinned flags or files (which a link
/// can't open): a copy of the current secret, not its history.
fn snapshot(overview: &Value, details: &Value) -> ItemDraft {
    let (mut overview, mut details) = (overview.clone(), details.clone());
    if let Some(fields) = overview.as_object_mut() {
        fields.remove("favorite");
        fields.remove("pinned");
    }
    if let Some(fields) = details.as_object_mut() {
        fields.remove("passwordHistory");
        fields.remove("attachments");
    }
    ItemDraft {
        id: None,
        vault_id: String::new(),
        revision: None,
        overview,
        details,
    }
}

impl Vault {
    /// Encrypts a snapshot of the item for a link. With a passphrase this runs Argon2id.
    pub async fn create_share_link(
        &self,
        item_id: &str,
        options: ShareLinkOptions,
    ) -> Result<CreatedShareLink> {
        if !(MIN_HOURS..=MAX_HOURS).contains(&options.expires_in_hours)
            || !(1..=MAX_VIEWS).contains(&options.max_views)
        {
            return Err(VaultError::new(
                ErrorCode::ServerError,
                "Share links last 1 hour to 30 days and allow 1 to 100 views.",
            ));
        }
        let item = self.get_item(item_id)?;
        if item.deleted_at.is_some() || item.is_vault_info() {
            return Err(ErrorCode::NotFound.into());
        }
        let snapshot = snapshot(&item.overview, &item.details).to_core()?;
        let passphrase = options
            .passphrase
            .filter(|passphrase| !passphrase.is_empty())
            .map(Zeroizing::new);
        let link = blocking(move || {
            Ok(share_link::create(
                &snapshot,
                passphrase.as_ref().map(|p| p.as_str()),
                &mut OsRng,
            )?)
        })
        .await?;
        let expires_at = now() + Duration::hours(options.expires_in_hours.into());
        let body = json!({
            "ciphertext": link.ciphertext,
            "expiresAt": rfc3339(expires_at),
            "maxViews": options.max_views,
            "passphraseRequired": link.passphrase_required,
        });
        let key = self.account_key()?;
        let created: CreateShareLinkResponse = {
            let _io = self.io.lock().await;
            self.server(&key, Method::POST, "/v1/share-links", Some(body))
                .await??
        };
        self.store.update_notes(&key, |notes| {
            notes.share_links.insert(created.id.clone(), item_id.into());
        })?;
        self.emit(Event::SharingChanged);
        Ok(CreatedShareLink {
            id: created.id,
            key: link.key,
            expires_at: created.expires_at,
        })
    }

    pub async fn list_share_links(&self) -> Result<Vec<ShareLinkInfo>> {
        let key = self.account_key()?;
        let response: ShareLinksResponse = {
            let _io = self.io.lock().await;
            self.server(&key, Method::GET, "/v1/share-links", None)
                .await??
        };
        let mut sources = self.store.load_notes(&key)?.share_links;
        // Links the server no longer has were used up, expired or revoked elsewhere.
        let before = sources.len();
        sources.retain(|id, _| response.links.iter().any(|link| link.id == *id));
        if sources.len() != before {
            self.store
                .update_notes(&key, |notes| notes.share_links = sources.clone())?;
        }
        Ok(response
            .links
            .into_iter()
            .map(|link| {
                let item = sources
                    .get(&link.id)
                    .and_then(|item_id| self.get_item(item_id).ok());
                ShareLinkInfo {
                    item_title: item.as_ref().map(|item| item.title().to_owned()),
                    item_id: item.map(|item| item.id),
                    id: link.id,
                    expires_at: link.expires_at,
                    max_views: link.max_views,
                    views: link.views,
                    passphrase_required: link.passphrase_required,
                    created_at: link.created_at,
                }
            })
            .collect())
    }

    pub async fn revoke_share_link(&self, id: &str) -> Result<()> {
        let key = self.account_key()?;
        {
            let _io = self.io.lock().await;
            let path = format!("/v1/share-links/{}", segment(id));
            match self
                .server::<Value>(&key, Method::DELETE, &path, None)
                .await?
            {
                // Already gone: used up or expired meanwhile, which is what revoking wanted.
                Err(error) if error.is(types::NOT_FOUND) => {}
                other => {
                    other?;
                }
            }
        }
        self.store.update_notes(&key, |notes| {
            notes.share_links.remove(id);
        })?;
        self.emit(Event::SharingChanged);
        Ok(())
    }

    /// Works signed out. Counts a view; `notFound` once a link is used up, expired or revoked.
    pub async fn fetch_share_link(&self, server_url: &str, id: &str) -> Result<ShareLinkResponse> {
        let server_url = normalize_server_url(server_url)?;
        let path = format!("/v1/share-links/{}", segment(id));
        Ok(self.api(&server_url).view_share_link(&path).await?)
    }

    /// Decrypts a link's ciphertext here: `wrongPassphrase` or `invalidShareLink`.
    pub async fn open_share_link(
        &self,
        ciphertext: String,
        key: String,
        passphrase: Option<Zeroizing<String>>,
    ) -> Result<SharedItem> {
        let item = blocking(move || {
            let passphrase = passphrase
                .as_ref()
                .map(|p| p.as_str())
                .filter(|p| !p.is_empty());
            Ok(share_link::open(&ciphertext, &key, passphrase)?)
        })
        .await?;
        Ok(SharedItem {
            overview: serde_json::to_value(&item.overview).expect("items serialize"),
            details: serde_json::to_value(&item.details).expect("items serialize"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_leaves_out_history_files_and_the_favourite_flag() {
        let draft = snapshot(
            &json!({ "type": "login", "title": "Bank", "favorite": true }),
            &json!({
                "password": "now",
                "passwordHistory": [{ "password": "before", "changedAt": "2026-01-01T00:00:00Z" }],
                "attachments": [{ "id": "f" }],
            }),
        );
        assert_eq!(draft.overview, json!({ "type": "login", "title": "Bank" }));
        assert_eq!(draft.details, json!({ "password": "now" }));
    }
}
