//! Passkeys as encrypted items: the [`Session`] creates them inside a login and signs with them
//! without the private key ever leaving the core, except inside the item's encrypted details.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::authenticator::{self, matches};
use super::json::{AuthenticationResponse, CreationOptions, RegistrationResponse, RequestOptions};
use super::origin::ClientData;
use super::record::PasskeyRecord;
use crate::error::{Error, Result};
use crate::item::{Item, ItemDetails, ItemOverview, ItemType, LoginDetails, SCHEMA_VERSION};
use crate::session::{EncryptedItem, Session};

/// An encrypted item the host thinks may hold passkeys for the site (e.g. logins whose URLs
/// match it).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub vault_id: String,
    pub item_id: String,
    pub item: EncryptedItem,
}

/// Where a new passkey goes: into an existing login (`item` set) or a new one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub vault_id: String,
    pub item_id: String,
    #[serde(default)]
    pub item: Option<EncryptedItem>,
}

/// A passkey the user can pick, without its private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyMatch {
    pub vault_id: String,
    pub item_id: String,
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    pub created_at: String,
}

impl Session {
    /// Creates a passkey and stores it in `target`: appended to the existing login, or in a new
    /// login titled after the relying party. A passkey for the same site and user handle in that
    /// login is replaced, as an authenticator overwrites a discoverable credential.
    ///
    /// `others` are the user's other items for this site: if any of them (or the target) holds a
    /// credential in `excludeCredentials`, this fails with [`Error::PasskeyExcluded`].
    pub fn create_passkey(
        &self,
        options: &CreationOptions,
        client: &ClientData,
        target: &Target,
        others: &[Candidate],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(RegistrationResponse, EncryptedItem)> {
        // Refuse a foreign origin before decrypting anything.
        let origin = client.relying(options.rp.id.as_deref())?.origin;
        let existing = match &target.item {
            Some(item) => Some(self.decrypt_item(&target.vault_id, &target.item_id, item)?),
            None => None,
        };
        for other in others {
            let item = self.decrypt_item(&other.vault_id, &other.item_id, &other.item)?;
            if holds_excluded(&item, options) {
                return Err(Error::PasskeyExcluded);
            }
        }
        if existing
            .as_ref()
            .is_some_and(|item| holds_excluded(item, options))
        {
            return Err(Error::PasskeyExcluded);
        }

        let new = authenticator::create(options, client, now_ms, rng)?;
        let item = match existing {
            Some(mut item) => {
                let ItemDetails::Login(details) = &mut item.details else {
                    return Err(Error::InvalidItem);
                };
                let passkeys = details.passkeys.get_or_insert_with(Vec::new);
                passkeys.retain(|passkey| {
                    PasskeyRecord::from_item(passkey).is_none_or(|old| {
                        old.rp_id != new.record.rp_id || old.user_handle != new.record.user_handle
                    })
                });
                passkeys.push(new.record.to_item());
                item
            }
            None => new_login(options, &origin, &new.record),
        };
        let encrypted = self.encrypt_item(
            &target.vault_id,
            &target.item_id,
            &item,
            target
                .item
                .as_ref()
                .map(|item| item.encrypted_item_key.as_str()),
            rng,
        )?;
        Ok((new.credential, encrypted))
    }

    /// The passkeys in `candidates` that can answer this request, for the user to pick from.
    pub fn find_passkeys(
        &self,
        options: &RequestOptions,
        client: &ClientData,
        candidates: &[Candidate],
    ) -> Result<Vec<PasskeyMatch>> {
        let rp_id = client.relying(options.rp_id.as_deref())?.rp_id;
        let mut found = Vec::new();
        for candidate in candidates {
            let item =
                self.decrypt_item(&candidate.vault_id, &candidate.item_id, &candidate.item)?;
            for record in records(&item) {
                if matches(options, &rp_id, &record) {
                    found.push(PasskeyMatch {
                        vault_id: candidate.vault_id.clone(),
                        item_id: candidate.item_id.clone(),
                        credential_id: record.credential_id.clone(),
                        rp_id: record.rp_id.clone(),
                        user_name: record.user_name.clone(),
                        user_display_name: record.user_display_name.clone(),
                        created_at: record.created_at.clone(),
                    });
                }
            }
        }
        Ok(found)
    }

    /// Signs in with the passkey `credential_id` stored in `candidate`.
    pub fn get_assertion(
        &self,
        options: &RequestOptions,
        client: &ClientData,
        candidate: &Candidate,
        credential_id: &str,
    ) -> Result<AuthenticationResponse> {
        let item = self.decrypt_item(&candidate.vault_id, &candidate.item_id, &candidate.item)?;
        let record = records(&item)
            .find(|record| record.credential_id == credential_id)
            .ok_or(Error::PasskeyNotFound)?;
        authenticator::get(options, client, &record)
    }
}

/// The full passkey records of a login; other items and display-only entries have none.
fn records(item: &Item) -> impl Iterator<Item = PasskeyRecord> + '_ {
    let passkeys = match &item.details {
        ItemDetails::Login(details) => details.passkeys.as_deref().unwrap_or_default(),
        _ => &[],
    };
    passkeys.iter().filter_map(PasskeyRecord::from_item)
}

fn holds_excluded(item: &Item, options: &CreationOptions) -> bool {
    records(item).any(|record| {
        record
            .credential_id_bytes()
            .is_ok_and(|id| options.excludes(&id))
    })
}

/// A login for the new passkey, titled after the relying party, with the page's origin (or
/// `https://<rpId>` for platform client data) as its URL.
fn new_login(options: &CreationOptions, origin: &str, record: &PasskeyRecord) -> Item {
    let title = match options.rp.name.trim() {
        "" => record.rp_id.clone(),
        name => name.to_owned(),
    };
    Item {
        overview: ItemOverview {
            schema_version: SCHEMA_VERSION,
            title,
            item_type: ItemType::Login,
            urls: Some(vec![origin.to_owned()]),
            subtitle: None,
            tags: None,
            favorite: None,
            created_at: None,
            updated_at: None,
            last_used_at: None,
            imported_from: None,
            extra: Default::default(),
        },
        details: ItemDetails::Login(LoginDetails {
            schema_version: SCHEMA_VERSION,
            username: Some(record.user_name.clone()).filter(|name| !name.is_empty()),
            password: None,
            totp: None,
            notes: None,
            passkeys: Some(vec![record.to_item()]),
            recovery: None,
            custom_fields: None,
            password_history: None,
            password_changed_at: None,
            http_realm: None,
            extra: Default::default(),
        }),
    }
}
