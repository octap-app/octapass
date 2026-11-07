//! A service account at work: a CI job or server reading its one vault from the token alone. No
//! account, no device and nothing on disk: everything is fetched, decrypted here, and dropped when
//! the process ends.

use octapass_api::problem::types;
use octapass_api::{
    ItemRecord, PutItemRequest, RevisionResponse, ServiceAccountChallengeRequest,
    ServiceAccountChallengeResponse, ServiceAccountSessionRequest, ServiceAccountSessionResponse,
    SyncResponse, VaultRecord, VaultRole,
};
use octapass_core::account::new_id;
use octapass_core::service_account::{ServiceAccountToken, ServiceVault};
use octapass_core::session::EncryptedItem;
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::SignedGrant;
use rand_core::OsRng;
use reqwest::Client;
use serde_json::Value;

use crate::api::{Api, ApiError, Method, Precondition};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, ItemSummary, Vault as VaultView, now, unix_ms, vault_names};
use crate::vault::service_accounts::parse_token;

const MAX_PAGES: usize = 1000;

/// One vault, opened by a service account: read once, in full, at the start of a command.
pub struct ServiceSession {
    token: ServiceAccountToken,
    api: Api,
    access_token: String,
    opened: ServiceVault,
    vault: VaultView,
    records: Vec<ItemRecord>,
    items: Vec<Item>,
}

fn refused(error: ApiError) -> VaultError {
    if error.is(types::UNAUTHORIZED) {
        return VaultError::new(
            ErrorCode::ServiceAccountRefused,
            "The server refused this service account: it was revoked, it expired, or the token is wrong.",
        );
    }
    error.into()
}

impl ServiceSession {
    /// Signs in with the token and reads the vault. Every call is one entry in the security log.
    pub async fn open(http: Client, token_text: &str) -> Result<Self> {
        let token = parse_token(token_text)?;
        let api = Api::new(http, token.server_url());
        let access_token = sign_in(&api, &token).await?;
        let (record, records) = fetch(&api, &access_token).await?;
        let grant = grant_of(&record, token.id())?;
        let opened = token.open_grant(&grant).map_err(|_| {
            VaultError::new(
                ErrorCode::ServiceAccountNeedsNewToken,
                "This token can't verify the vault's key. Someone other than its creator rotated the key, or the server sent a key the creator didn't sign. The creator can issue a new token.",
            )
        })?;
        let mut items = Vec::with_capacity(records.len());
        for item in &records {
            if item.deleted_at.is_some() {
                continue;
            }
            let plaintext = opened
                .decrypt_item(&item.id, &encrypted(item))
                .map_err(VaultError::from)?;
            items.push(Item::new(item, &plaintext));
        }
        let names = vault_names(&items);
        items.retain(|item| !item.is_vault_info());
        Ok(Self {
            vault: VaultView::new(&record, &names, false),
            token,
            api,
            access_token,
            opened,
            records,
            items,
        })
    }

    pub fn id(&self) -> &str {
        self.token.id()
    }

    pub fn can_write(&self) -> bool {
        self.opened.role() == Role::Write
    }

    pub fn vaults(&self) -> Vec<VaultView> {
        vec![self.vault.clone()]
    }

    pub fn summaries(&self) -> Vec<ItemSummary> {
        self.items.iter().map(ItemSummary::from).collect()
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    pub fn item(&self, id: &str) -> Result<Item> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Saves an item, for a service account with the `write` role.
    pub async fn save_item(&self, draft: &ItemDraft) -> Result<u64> {
        if !self.can_write() {
            return Err(ErrorCode::ReadOnlyVault.into());
        }
        let core = draft.to_core()?;
        let existing = draft.id.as_deref().and_then(|id| {
            self.records
                .iter()
                .find(|record| record.id == id)
                .map(|record| record.encrypted_item_key.as_str())
        });
        let id = draft
            .id
            .clone()
            .unwrap_or_else(|| new_id(unix_ms(now()), &mut OsRng));
        let encrypted = self
            .opened
            .encrypt_item(&id, &core, existing, &mut OsRng)
            .map_err(VaultError::from)?;
        let body = PutItemRequest {
            encrypted_item_key: encrypted.encrypted_item_key,
            overview: encrypted.overview,
            details: encrypted.details,
            skip_history: false,
        };
        let path = format!("/v1/service-accounts/items/{id}");
        let precondition = match draft.revision {
            Some(revision) => Precondition::Revision(revision),
            None => Precondition::Create,
        };
        let written: RevisionResponse = self
            .api
            .put_json(&path, &self.access_token, precondition, &body)
            .await
            .map_err(refused)?;
        Ok(written.revision)
    }
}

async fn sign_in(api: &Api, token: &ServiceAccountToken) -> Result<String> {
    let id = token.id().to_owned();
    let challenge: ServiceAccountChallengeResponse = api
        .post_public(
            "/v1/service-accounts/challenge",
            &ServiceAccountChallengeRequest {
                service_account_id: id.clone(),
            },
        )
        .await?;
    let signature = token
        .keys()
        .sign_challenge(&id, &challenge.challenge)
        .map_err(VaultError::from)?;
    let session: ServiceAccountSessionResponse = api
        .post_public(
            "/v1/service-accounts/session",
            &ServiceAccountSessionRequest {
                service_account_id: id,
                challenge: challenge.challenge,
                signature,
            },
        )
        .await
        .map_err(refused)?;
    Ok(session.access_token)
}

async fn fetch(api: &Api, access_token: &str) -> Result<(VaultRecord, Vec<ItemRecord>)> {
    let mut path = "/v1/service-accounts/sync".to_owned();
    let mut items = Vec::new();
    for _ in 0..MAX_PAGES {
        let page: SyncResponse = api
            .call(Method::GET, &path, access_token, None::<&Value>)
            .await
            .map_err(refused)?;
        let vault = page
            .vaults
            .into_iter()
            .next()
            .ok_or_else(|| VaultError::from(ErrorCode::NotFound))?;
        items.extend(page.items);
        if !page.has_more {
            return Ok((vault, items));
        }
        path = format!(
            "/v1/service-accounts/sync?since={}:{}",
            vault.id, vault.revision
        );
    }
    Err(VaultError::unexpected("too many pages"))
}

fn grant_of(record: &VaultRecord, service_account_id: &str) -> Result<SignedGrant> {
    let grant = record
        .grant
        .as_ref()
        .ok_or_else(|| VaultError::from(ErrorCode::UntrustedVault))?;
    Ok(SignedGrant {
        vault_id: record.id.clone(),
        recipient_account_id: service_account_id.to_owned(),
        role: match record.role {
            VaultRole::Read => Role::Read,
            VaultRole::Write => Role::Write,
            VaultRole::Manage => Role::Manage,
            VaultRole::Owner => Role::Owner,
        },
        wrapped_vault_key: record.wrapped_vault_key.clone(),
        granted_by: grant.granted_by.clone(),
        granted_at: grant.granted_at,
        signature: grant.signature.clone(),
    })
}

fn encrypted(record: &ItemRecord) -> EncryptedItem {
    EncryptedItem {
        encrypted_item_key: record.encrypted_item_key.clone(),
        overview: record.overview.clone(),
        details: record.details.clone(),
    }
}
