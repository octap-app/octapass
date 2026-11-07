//! Past versions of an item, counter-based one-time codes and the user's equivalent domains. The
//! same rules as `@octapass/vault-client`'s engine (plans 01 and 04).

use octapass_api::VaultType;
use octapass_api::problem::Problem;
use octapass_core::item::{EquivalentDomainsDetails, restored_version};
use octapass_core::matching::{self, MatchOptions, user_equivalents};
use octapass_core::rules;
use octapass_core::tools::generator::RandomOptions;
use octapass_core::tools::totp::{self, HotpCode, is_hotp};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Vault, decrypt};
use crate::api::{ApiError, Precondition};
use crate::error::{ErrorCode, Result};
use crate::model::{Item, ItemDraft};

/// How often a code's counter is tried again when other devices keep getting there first.
const ATTEMPTS: usize = 5;
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

impl Vault {
    /// The item's past versions, newest first. A version that can't be opened is left out.
    pub async fn item_versions(&self, id: &str) -> Result<Vec<ItemVersion>> {
        let (key, record) = self.with_unlocked(|unlocked| {
            let record = unlocked.cache.item(id).ok_or(ErrorCode::NotFound)?.clone();
            Ok((unlocked.key.clone(), record))
        })?;
        let (vault_id, item_id) = (record.vault_id.clone(), record.id.clone());
        let history = self
            .authed(&key, |api, token| {
                let (vault_id, item_id) = (vault_id.clone(), item_id.clone());
                async move { api.item_history(&token, &vault_id, &item_id).await }
            })
            .await??;
        self.with_unlocked(|unlocked| {
            Ok(history
                .revisions
                .into_iter()
                .filter_map(|version| {
                    let mut past = record.clone();
                    past.overview = version.overview;
                    past.details = version.details;
                    let item = decrypt(&unlocked.session, &past).ok()?;
                    Some(ItemVersion {
                        revision: version.revision,
                        updated_at: version.updated_at,
                        overview: item.overview,
                        details: item.details,
                    })
                })
                .collect())
        })
    }

    /// Makes a past version current, as an ordinary edit: what it replaces joins the history.
    pub async fn restore_item_version(&self, id: &str, revision: u64) -> Result<Item> {
        let versions = self.item_versions(id).await?;
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
        .await
    }

    /// Saves the moved counter of the item's HOTP code, then gives the code.
    pub async fn next_hotp_code(&self, id: &str) -> Result<HotpCode> {
        let mut code = None;
        self.update_totp(id, |totp| {
            let (next, stored) = totp::next_hotp_code(totp)?;
            code = Some(next);
            Ok(stored)
        })
        .await?;
        code.ok_or(ErrorCode::NotFound.into())
    }

    /// Brings the item's HOTP code back in step with the site. Not an edit: no history entry.
    pub async fn set_hotp_counter(&self, id: &str, counter: u64) -> Result<Item> {
        self.update_totp(id, |totp| Ok(totp::with_hotp_counter(totp, counter)?))
            .await
    }

    /// Writes a code change that isn't an edit: no history entry and no conflicting copy. It runs
    /// again on whatever is current when another device got there first.
    async fn update_totp(
        &self,
        id: &str,
        mut change: impl FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Item> {
        let _io = self.io.lock().await;
        for attempt in 1..=ATTEMPTS {
            let (key, record) = self.writable_record(id)?;
            let item = self.with_unlocked(|unlocked| decrypt(&unlocked.session, &record))?;
            let totp = item
                .detail("totp")
                .filter(|totp| is_hotp(totp))
                .ok_or(ErrorCode::NotFound)?;
            let stored = change(totp)?;
            let mut details = item.details.clone();
            details["totp"] = json!(stored.as_str());
            let draft = ItemDraft {
                id: Some(item.id.clone()),
                vault_id: item.vault_id.clone(),
                revision: Some(item.revision),
                overview: item.overview.clone(),
                details,
            };
            let precondition = Precondition::Revision(record.revision);
            let put = self
                .put_with(
                    &key,
                    &draft,
                    id,
                    Some(&record.encrypted_item_key),
                    precondition,
                    true,
                )
                .await?;
            match put {
                Ok(()) => {
                    self.sync_locked().await?;
                    return self.get_item(id);
                }
                Err(ApiError::Problem { problem, .. })
                    if attempt < ATTEMPTS && problem.current.is_some() =>
                {
                    let Problem { current, .. } = *problem;
                    self.with_unlocked(|unlocked| {
                        unlocked.cache.upsert(current.expect("checked above"));
                        Ok(())
                    })?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(ErrorCode::NotFound.into())
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
    pub async fn save_equivalent_domains(
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
                })
                .await?;
            }
            None => {
                let vault_id = self
                    .list_vaults()?
                    .into_iter()
                    .find(|vault| vault.vault_type == VaultType::Personal)
                    .ok_or(ErrorCode::NotFound)?
                    .id;
                self.save_item(ItemDraft {
                    id: None,
                    vault_id,
                    revision: None,
                    overview: json!({ "schemaVersion": 1, "type": EQUIVALENT_DOMAINS, "title": "Equivalent domains" }),
                    details: list,
                })
                .await?;
            }
        }
        for copy in copies {
            self.delete_item(&copy.id).await?;
        }
        Ok(EquivalentDomains {
            rejected: cleaned.rejected,
            ..self.equivalent_domains()?
        })
    }

    /// A password in `options`, adjusted to what the password rules dataset knows about `url`.
    pub fn generate_password_for_site(
        &self,
        url: &str,
        options: &RandomOptions,
    ) -> Result<Zeroizing<String>> {
        Ok(rules::generate_for_site(url, None, options, &mut OsRng)?)
    }
}
