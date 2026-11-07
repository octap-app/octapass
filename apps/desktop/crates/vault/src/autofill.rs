//! What the macOS AutoFill extension asks of the vault, through the app (`src-tauri/src/autofill.rs`):
//! the logins for the sites the system names, a chosen login's password or one-time code, and
//! passkeys. The keys stay here; the extension gets only the answer it fills.
//!
//! Passkeys use [`ClientData::Hash`]: macOS verified the calling app or site and wrote the client
//! data itself, so only its hash is signed, as on iOS and Android (plan 14). The core still
//! requires the `rpId` and refuses public suffixes. A new passkey is saved (and uploaded) before
//! the extension hands it to the site, so a passkey the site accepted is never lost.

use octapass_api::{VaultRole, VaultType};
use octapass_core::account::new_id;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::item::Passkey;
use octapass_core::matching::{self, MatchOptions};
use octapass_core::passkey::{
    Candidate, ClientData, CreationOptions, CredentialDescriptor, CredentialParameters,
    ExtensionInputs, PasskeyRecord, RelyingPartyEntity, RequestOptions, Target, UserEntity,
};
use octapass_core::session::EncryptedItem;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, now, require, unix_ms};
use crate::tools::{AutoTypeItem, CopyField};
use crate::vault::{Unlocked, Vault, decrypt};

const PUBLIC_KEY: &str = "public-key";

/// A login the extension can list. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFillLogin {
    pub item_id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The saved URL that matched, or the login's first one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The site is `http` and the login was saved for `https`, or the other way: warn (plan 03).
    pub scheme_mismatch: bool,
    pub has_totp: bool,
}

impl AutoFillLogin {
    fn new(item: &Item, url: Option<String>, scheme_mismatch: bool) -> Self {
        let rules = AutoTypeItem::new(item);
        Self {
            item_id: item.id.clone(),
            title: item.title().to_owned(),
            username: item.detail("username").map(str::to_owned),
            url: url.or_else(|| rules.urls.first().cloned()),
            scheme_mismatch,
            has_totp: item.detail("totp").is_some(),
        }
    }
}

/// A saved passkey the user can pick. No private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFillPasskey {
    pub item_id: String,
    pub rp_id: String,
    pub user_name: String,
    /// base64url, as are all the binary fields here.
    pub credential_id: String,
    pub user_handle: String,
}

/// What `ASPasskeyAssertionCredential` needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFillAssertion {
    pub item_id: String,
    pub credential_id: String,
    pub user_handle: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// `ASPasskeyCredentialRequest` for a new passkey, in the core's terms.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreation {
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: String,
    /// COSE algorithm identifiers, the site's preference first.
    #[serde(default)]
    pub algorithms: Vec<i64>,
    #[serde(default)]
    pub excluded: Vec<String>,
    pub client_data_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFillRegistration {
    pub item_id: String,
    pub credential_id: String,
    pub attestation_object: String,
}

/// What the extension registers with `ASCredentialIdentityStore`, so logins and passkeys show in
/// the system's suggestions. Names and ids, never a password or key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identities {
    pub passwords: Vec<PasswordIdentity>,
    pub passkeys: Vec<AutoFillPasskey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordIdentity {
    pub item_id: String,
    pub username: String,
    /// The hosts the login was saved for.
    pub hosts: Vec<String>,
}

impl Vault {
    /// Logins for the sites the system named (`https://<domain>` or a full URL), best match first,
    /// each login once.
    pub fn autofill_logins(&self, urls: &[String]) -> Result<Vec<AutoFillLogin>> {
        let items = self.live_logins()?;
        let candidates: Vec<matching::Candidate> = items
            .iter()
            .map(|item| {
                let rules = AutoTypeItem::new(item);
                matching::Candidate {
                    id: item.id.clone(),
                    urls: rules.urls,
                    url_match: rules.url_match,
                }
            })
            .collect();
        let options = self.match_options()?;
        let mut found: Vec<AutoFillLogin> = Vec::new();
        for url in urls {
            let Ok(matches) = matching::match_items(url, &candidates, &options) else {
                continue;
            };
            for hit in matches {
                if found.iter().any(|login| login.item_id == hit.id) {
                    continue;
                }
                if let Some(item) = items.iter().find(|item| item.id == hit.id) {
                    found.push(AutoFillLogin::new(item, Some(hit.url), hit.scheme_mismatch));
                }
            }
        }
        Ok(found)
    }

    /// Every login whose title, user name or URL contains `query` (all of them when it's empty),
    /// to fill a site that matches none.
    pub fn autofill_search(&self, query: &str) -> Result<Vec<AutoFillLogin>> {
        let needle = query.trim().to_lowercase();
        Ok(self
            .live_logins()?
            .iter()
            .filter(|item| {
                needle.is_empty() || {
                    let rules = AutoTypeItem::new(item);
                    std::iter::once(item.title())
                        .chain(item.detail("username"))
                        .chain(rules.urls.iter().map(String::as_str))
                        .any(|text| text.to_lowercase().contains(&needle))
                }
            })
            .map(|item| AutoFillLogin::new(item, None, false))
            .collect())
    }

    /// The user name (empty when there's none) and password the user picked.
    pub fn autofill_password(&self, id: &str) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
        let username = match self.copy_value(id, CopyField::Username) {
            Err(error) if error.code == ErrorCode::NotFound => Zeroizing::new(String::new()),
            other => other?,
        };
        Ok((username, self.copy_value(id, CopyField::Password)?))
    }

    pub fn autofill_code(&self, id: &str) -> Result<Zeroizing<String>> {
        self.copy_value(id, CopyField::Code)
    }

    /// The passkeys for `rp_id` that may answer (only those in `allowed`, when it isn't empty).
    pub fn autofill_passkeys(
        &self,
        rp_id: &str,
        client_data_hash: &str,
        allowed: &[String],
    ) -> Result<Vec<AutoFillPasskey>> {
        let options = request_options(rp_id, allowed);
        let client = client_data(client_data_hash)?;
        self.with_unlocked(|unlocked| {
            let candidates = passkey_items(unlocked)
                .into_iter()
                .map(|(record, _)| candidate(record))
                .collect::<Vec<_>>();
            let found = unlocked
                .session
                .find_passkeys(&options, &client, &candidates)?;
            let handles = records_by_id(unlocked);
            Ok(found
                .into_iter()
                .map(|found| AutoFillPasskey {
                    user_handle: handles
                        .iter()
                        .find(|record| record.credential_id == found.credential_id)
                        .map(|record| record.user_handle.clone())
                        .unwrap_or_default(),
                    item_id: found.item_id,
                    rp_id: found.rp_id,
                    user_name: found.user_name,
                    credential_id: found.credential_id,
                })
                .collect())
        })
    }

    /// Signs the system's client data hash with the passkey `credential_id`.
    pub fn autofill_assertion(
        &self,
        rp_id: &str,
        client_data_hash: &str,
        allowed: &[String],
        credential_id: &str,
    ) -> Result<AutoFillAssertion> {
        let options = request_options(rp_id, allowed);
        let client = client_data(client_data_hash)?;
        let wanted = b64_encode(&b64_decode(credential_id).map_err(invalid)?);
        self.with_unlocked(|unlocked| {
            let (record, _) = passkey_items(unlocked)
                .into_iter()
                .find(|(_, item)| records(item).any(|record| record.credential_id == wanted))
                .ok_or(ErrorCode::NotFound)?;
            let item_id = record.id.clone();
            let signed =
                unlocked
                    .session
                    .get_assertion(&options, &client, &candidate(record), &wanted)?;
            Ok(AutoFillAssertion {
                item_id,
                credential_id: signed.raw_id,
                user_handle: signed.response.user_handle,
                authenticator_data: signed.response.authenticator_data,
                signature: signed.response.signature,
            })
        })
    }

    /// Creates a passkey and saves it: in the login that already has one for this site and user,
    /// else in the user's login for the site with the same user name, else in a new login in the
    /// personal vault. Fails with `passkeyExcluded` when the site already knows one of the user's
    /// passkeys.
    pub async fn autofill_register(
        &self,
        request: PasskeyCreation,
    ) -> Result<AutoFillRegistration> {
        let client = client_data(&request.client_data_hash)?;
        let options = creation_options(&request)?;
        let rp_id = request.rp_id.to_ascii_lowercase();
        let user_handle = b64_encode(&b64_decode(&request.user_handle).map_err(invalid)?);
        let (credential, draft) = self.with_unlocked(|unlocked| {
            let writable = |vault_id: &str| {
                unlocked
                    .cache
                    .vault(vault_id)
                    .is_some_and(|vault| vault.role != VaultRole::Read)
            };
            let site = format!("https://{rp_id}");
            let logins: Vec<(&octapass_api::ItemRecord, Item)> = unlocked
                .cache
                .items
                .iter()
                .filter(|record| record.deleted_at.is_none())
                .filter_map(|record| Some((record, decrypt(&unlocked.session, record).ok()?)))
                .filter(|(_, item)| item.is_login_like())
                .collect();
            let for_site = |item: &Item| {
                let rules = AutoTypeItem::new(item);
                let candidate = matching::Candidate {
                    id: item.id.clone(),
                    urls: rules.urls,
                    url_match: rules.url_match,
                };
                // Passkeys follow WebAuthn, not the 2026-11-05 default: any part of the domain.
                let options = MatchOptions {
                    default_mode: matching::MatchMode::BaseDomain,
                    ..MatchOptions::default()
                };
                matching::match_items(&site, &[candidate], &options)
                    .is_ok_and(|found| !found.is_empty())
            };
            let same_user = |item: &Item| {
                item.detail("username")
                    .is_some_and(|name| name.eq_ignore_ascii_case(&request.user_name))
            };
            let target = logins
                .iter()
                .find(|(record, item)| {
                    writable(&record.vault_id)
                        && records(item).any(|p| p.rp_id == rp_id && p.user_handle == user_handle)
                })
                .or_else(|| {
                    logins.iter().find(|(record, item)| {
                        writable(&record.vault_id) && same_user(item) && for_site(item)
                    })
                });
            let others: Vec<Candidate> = logins
                .iter()
                .filter(|(record, item)| {
                    target.is_none_or(|(target, _)| target.id != record.id)
                        && records(item).any(|p| p.rp_id == rp_id)
                })
                .map(|(record, _)| candidate(record))
                .collect();
            let (vault_id, item_id) = match target {
                Some((record, _)) => (record.vault_id.clone(), record.id.clone()),
                None => {
                    let personal = unlocked
                        .cache
                        .vaults
                        .iter()
                        .find(|vault| vault.vault_type == VaultType::Personal)
                        .ok_or(ErrorCode::NotFound)?;
                    // An id to encrypt with; saving the new login gives it its own.
                    (personal.id.clone(), new_id(unix_ms(now()), &mut OsRng))
                }
            };
            let (credential, encrypted) = unlocked.session.create_passkey(
                &options,
                &client,
                &Target {
                    vault_id: vault_id.clone(),
                    item_id: item_id.clone(),
                    item: target.map(|(record, _)| encrypted(record)),
                },
                &others,
                unix_ms(now()),
                &mut OsRng,
            )?;
            let plain = unlocked
                .session
                .decrypt_item(&vault_id, &item_id, &encrypted)?;
            let draft = ItemDraft {
                id: target.map(|(record, _)| record.id.clone()),
                vault_id,
                revision: target.map(|(record, _)| record.revision),
                overview: serde_json::to_value(&plain.overview).map_err(unexpected)?,
                details: serde_json::to_value(&plain.details).map_err(unexpected)?,
            };
            Ok((credential, draft))
        })?;
        let saved = self.save_item(draft).await?;
        Ok(AutoFillRegistration {
            item_id: saved.id,
            credential_id: credential.raw_id,
            attestation_object: credential.response.attestation_object,
        })
    }

    /// Every login with a user name and website, and every passkey, for the system's suggestions.
    pub fn autofill_identities(&self) -> Result<Identities> {
        let mut identities = Identities::default();
        for item in self.live_logins()? {
            let hosts: Vec<String> = AutoTypeItem::new(&item)
                .urls
                .iter()
                .filter_map(|url| matching::Site::parse(url).ok().map(|site| site.host))
                .collect();
            if let Some(username) = item.detail("username")
                && !hosts.is_empty()
            {
                identities.passwords.push(PasswordIdentity {
                    item_id: item.id.clone(),
                    username: username.to_owned(),
                    hosts,
                });
            }
            identities
                .passkeys
                .extend(records(&item).map(|record| AutoFillPasskey {
                    item_id: item.id.clone(),
                    rp_id: record.rp_id.clone(),
                    user_name: record.user_name.clone(),
                    credential_id: record.credential_id.clone(),
                    user_handle: record.user_handle.clone(),
                }));
        }
        Ok(identities)
    }

    fn live_logins(&self) -> Result<Vec<Item>> {
        Ok(self
            .live_items()?
            .into_iter()
            .filter(Item::is_login_like)
            .collect())
    }
}

/// The full passkey records of a login (display-only entries can't sign).
fn records(item: &Item) -> impl Iterator<Item = PasskeyRecord> + '_ {
    item.details
        .get("passkeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value::<Passkey>(value.clone()).ok())
        .filter_map(|passkey| PasskeyRecord::from_item(&passkey))
}

/// Live items holding at least one passkey, with their records.
fn passkey_items(unlocked: &Unlocked) -> Vec<(&octapass_api::ItemRecord, Item)> {
    unlocked
        .cache
        .items
        .iter()
        .filter(|record| record.deleted_at.is_none())
        .filter_map(|record| Some((record, decrypt(&unlocked.session, record).ok()?)))
        .filter(|(_, item)| item.is_login_like() && records(item).next().is_some())
        .collect()
}

fn records_by_id(unlocked: &Unlocked) -> Vec<PasskeyRecord> {
    passkey_items(unlocked)
        .iter()
        .flat_map(|(_, item)| records(item).collect::<Vec<_>>())
        .collect()
}

fn encrypted(record: &octapass_api::ItemRecord) -> EncryptedItem {
    EncryptedItem {
        encrypted_item_key: record.encrypted_item_key.clone(),
        overview: record.overview.clone(),
        details: record.details.clone(),
    }
}

fn candidate(record: &octapass_api::ItemRecord) -> Candidate {
    Candidate {
        vault_id: record.vault_id.clone(),
        item_id: record.id.clone(),
        item: encrypted(record),
    }
}

fn invalid<E>(_: E) -> VaultError {
    VaultError::unexpected("passkeyInvalidRequest")
}

fn unexpected(error: impl std::fmt::Display) -> VaultError {
    VaultError::unexpected(error.to_string())
}

fn client_data(hash: &str) -> Result<ClientData> {
    let hash: [u8; 32] = b64_decode(hash)
        .map_err(invalid)?
        .try_into()
        .map_err(invalid)?;
    Ok(ClientData::Hash(hash))
}

fn descriptors(ids: &[String]) -> Vec<CredentialDescriptor> {
    ids.iter()
        .map(|id| CredentialDescriptor {
            kind: PUBLIC_KEY.into(),
            id: id.clone(),
        })
        .collect()
}

/// The system hashed the client data itself, so the challenge is in that hash, not here.
fn request_options(rp_id: &str, allowed: &[String]) -> RequestOptions {
    RequestOptions {
        challenge: String::new(),
        rp_id: Some(rp_id.to_owned()),
        allow_credentials: descriptors(allowed),
        extensions: Default::default(),
    }
}

fn creation_options(request: &PasskeyCreation) -> Result<CreationOptions> {
    require(!request.rp_id.is_empty(), ErrorCode::NotFound)?;
    Ok(CreationOptions {
        rp: RelyingPartyEntity {
            id: Some(request.rp_id.clone()),
            name: request.rp_id.clone(),
        },
        user: UserEntity {
            id: request.user_handle.clone(),
            name: request.user_name.clone(),
            display_name: request.user_name.clone(),
        },
        challenge: String::new(),
        pub_key_cred_params: request
            .algorithms
            .iter()
            .map(|&alg| CredentialParameters {
                kind: PUBLIC_KEY.into(),
                alg,
            })
            .collect(),
        exclude_credentials: descriptors(&request.excluded),
        extensions: ExtensionInputs::default(),
    })
}
