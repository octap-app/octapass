//! Past versions of an item, counter-based one-time codes and the user's equivalent domains, as
//! the desktop vault does them. Reading past versions needs the network; a counter moves here at
//! once and uploads with the next sync, and a conflict that's only about the counter merges
//! (`merge_hotp_counter`, in `octapass-ffi`'s upload).

use octapass_api::{ItemHistoryResponse, VaultType};
use octapass_core::item::{EquivalentDomainsDetails, restored_version};
use octapass_core::matching::{self, MatchOptions, user_equivalents};
use octapass_core::tools::totp::{self, HotpCode, is_hotp};
use octapass_ffi::HttpMethod;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Vault;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft};

const EQUIVALENT_DOMAINS: &str = "equivalentDomains";

/// A past version of an item, from its encrypted history.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemVersion {
    pub revision: u64,
    pub updated_at: String,
    pub overview: Value,
    pub details: Value,
}

/// What Settings → Equivalent domains shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivalentDomains {
    pub groups: Vec<Vec<String>>,
    pub defaults: Vec<Vec<String>>,
    pub excluded_defaults: Vec<String>,
    /// What saving refused; empty otherwise.
    pub rejected: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivalentDomainsInput {
    pub groups: Vec<Vec<String>>,
    pub excluded_defaults: Vec<String>,
}

fn invalid_code(_: octapass_core::Error) -> VaultError {
    VaultError::unexpected("invalid one-time code")
}

impl Vault {
    /// The item's past versions, newest first. A version that can't be opened is left out.
    pub fn item_versions(&self, id: &str) -> Result<Vec<ItemVersion>> {
        let unlocked = self.unlocked()?;
        let decrypted = unlocked.session.decrypt_item(&unlocked.store, id)?;
        let record = decrypted.record;
        let url = format!(
            "{}v1/vaults/{}/items/{}/history",
            unlocked.server.base_url(),
            record.vault_id,
            record.id
        );
        let history: ItemHistoryResponse = {
            let _io = self.io();
            self.with_token(&unlocked, |token| {
                self.http
                    .json::<ItemHistoryResponse>(HttpMethod::Get, url.clone(), token, &[])
            })?
        };
        Ok(history
            .revisions
            .into_iter()
            .filter_map(|version| {
                let mut past = record.clone();
                past.overview = version.overview;
                past.details = version.details;
                let item = unlocked
                    .session
                    .decrypt_record(&unlocked.store, &past)
                    .ok()?;
                Some(ItemVersion {
                    revision: version.revision,
                    updated_at: version.updated_at,
                    overview: serde_json::to_value(&item.overview).ok()?,
                    details: serde_json::to_value(&item.details).ok()?,
                })
            })
            .collect())
    }

    /// Makes a past version current, as an ordinary edit: what it replaces joins the history.
    pub fn restore_item_version(&self, id: &str, revision: u64) -> Result<Item> {
        let versions = self.item_versions(id)?;
        let version = versions
            .iter()
            .find(|version| version.revision == revision)
            .ok_or(ErrorCode::NotFound)?;
        let current = self.get_item(id)?;
        let (overview, details) = restored_version(
            &current.overview,
            &current.details,
            &version.overview,
            &version.details,
        );
        self.save_item(ItemDraft {
            id: Some(current.id),
            vault_id: current.vault_id,
            revision: Some(current.revision),
            overview,
            details,
        })
    }

    /// Saves the moved counter of the item's HOTP code, then gives the code.
    pub fn next_hotp_code(&self, id: &str) -> Result<HotpCode> {
        // Start from the newest counter when there's a connection, so a code another device just
        // used isn't given out again. Offline, the code is still given; that's the point of it.
        let _ = self.sync();
        let mut code = None;
        self.update_totp(id, |totp| {
            let (next, stored) = totp::next_hotp_code(totp).map_err(invalid_code)?;
            code = Some(next);
            Ok(stored)
        })?;
        code.ok_or(ErrorCode::NotFound.into())
    }

    /// Brings the item's HOTP code back in step with the site. Not an edit: no history entry.
    pub fn set_hotp_counter(&self, id: &str, counter: u64) -> Result<Item> {
        self.update_totp(id, |totp| {
            totp::with_hotp_counter(totp, counter).map_err(invalid_code)
        })
    }

    fn update_totp(
        &self,
        id: &str,
        change: impl FnOnce(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Item> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, id)?;
        let totp = item
            .details
            .get("totp")
            .and_then(Value::as_str)
            .filter(|totp| is_hotp(totp))
            .ok_or(ErrorCode::NotFound)?;
        let stored = change(totp)?;
        let mut details = item.details.clone();
        details["totp"] = json!(stored.as_str());
        let saved = self.save_item_as_bookkeeping(ItemDraft {
            id: Some(item.id.clone()),
            vault_id: item.vault_id.clone(),
            revision: Some(item.revision),
            overview: item.overview.clone(),
            details,
        })?;
        Ok(saved)
    }

    fn equivalent_items(&self) -> Result<Vec<Item>> {
        Ok(self
            .live_items()?
            .into_iter()
            .filter(|item| {
                item.overview.get("type").and_then(Value::as_str) == Some(EQUIVALENT_DOMAINS)
            })
            .collect())
    }

    /// The match options for the user's equivalent domains.
    pub fn match_options(&self) -> Result<MatchOptions> {
        let settings: Vec<EquivalentDomainsDetails> = self
            .equivalent_items()?
            .into_iter()
            .filter_map(|item| serde_json::from_value(item.details).ok())
            .collect();
        Ok(user_equivalents(&settings))
    }

    pub fn equivalent_domains(&self) -> Result<EquivalentDomains> {
        let options = self.match_options()?;
        Ok(EquivalentDomains {
            groups: options.equivalent_domains,
            defaults: matching::DEFAULT_EQUIVALENT_DOMAINS
                .iter()
                .map(|group| group.iter().map(|d| (*d).to_owned()).collect())
                .collect(),
            excluded_defaults: options.excluded_defaults,
            rejected: Vec::new(),
        })
    }

    /// Saves the list, cleaned by the core, in the hidden item; extra copies go to the trash.
    pub fn save_equivalent_domains(
        &self,
        input: EquivalentDomainsInput,
    ) -> Result<EquivalentDomains> {
        let cleaned = matching::clean_equivalent_groups(&input.groups);
        let list = json!({
            "schemaVersion": 1,
            "groups": cleaned.groups,
            "excludedDefaults": input.excluded_defaults,
        });
        let mut copies = self.equivalent_items()?.into_iter();
        match copies.next() {
            Some(first) => {
                let mut details = first.details.clone();
                details["groups"] = list["groups"].clone();
                details["excludedDefaults"] = list["excludedDefaults"].clone();
                self.save_item(ItemDraft {
                    id: Some(first.id),
                    vault_id: first.vault_id,
                    revision: Some(first.revision),
                    overview: first.overview,
                    details,
                })?;
            }
            None => {
                let unlocked = self.unlocked()?;
                let personal = unlocked
                    .store
                    .vaults()
                    .into_iter()
                    .find(|vault| vault.vault_type == VaultType::Personal)
                    .ok_or(ErrorCode::NotFound)?;
                self.save_item(ItemDraft {
                    id: None,
                    vault_id: personal.id,
                    revision: None,
                    overview: json!({ "schemaVersion": 1, "type": EQUIVALENT_DOMAINS, "title": "Equivalent domains" }),
                    details: list,
                })?;
            }
        }
        for copy in copies {
            self.delete_item(&copy.id)?;
        }
        Ok(EquivalentDomains {
            rejected: cleaned.rejected,
            ..self.equivalent_domains()?
        })
    }
}
