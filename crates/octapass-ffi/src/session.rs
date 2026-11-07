//! The unlocked account. It holds the keys; the items come from a [`LocalStore`], whose vault
//! keys it opens as the store's vaults change: personal vaults with the account key, shared and
//! family vaults once their grant verifies. `lock()` zeroes every key at once, without waiting for
//! Swift's or Kotlin's memory management to free the object.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use octapass_api::{ItemRecord, VaultRecord, VaultRole, VaultType};
use octapass_core::Error as CoreError;
use octapass_core::account::new_id;
use octapass_core::item::{Item as CoreItem, ItemDetails, ItemType};
use octapass_core::matching::user_equivalents;
use octapass_core::session::{EncryptedItem, Session as CoreSession};
use octapass_core::sharing::Role;
use octapass_core::sharing::vault::{GrantSignature, ItemKey, SyncedVault};
use octapass_core::tools::totp::is_hotp;
use rand_core::OsRng;

use crate::error::{OctaPassError, Result};
use crate::items::{self, Item, ItemSummary, LoginDraft};
use crate::matching::{MatchQuality, match_overviews, other_parts};
use crate::store::{LocalStore, StoreData, StoredItem, SyncState};
use crate::tools::TotpCode;
use crate::{now_ms, timestamp, unix_seconds};

#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<Option<Keys>>,
}

/// The account's keys, and what each open vault key was opened from.
struct Keys {
    core: CoreSession,
    /// Vault id → the wrapped key and role it was opened from. A rotation or a new role changes
    /// them, and the vault opens again.
    opened: HashMap<String, (String, VaultRole)>,
    /// Shared and family vaults whose grant didn't verify: their items stay closed.
    untrusted: BTreeSet<String>,
}

impl Keys {
    /// Opens the store's vaults that are new or changed, and closes the ones it no longer has
    /// (this account was removed, or the vault was deleted).
    fn open_vaults(&mut self, data: &StoreData) {
        let gone: Vec<String> = self
            .opened
            .keys()
            .filter(|id| !data.vaults.contains_key(*id))
            .cloned()
            .collect();
        for id in gone {
            self.core.close_vault(&id);
            self.opened.remove(&id);
        }
        self.untrusted.retain(|id| data.vaults.contains_key(id));
        for vault in data.vaults.values() {
            let current = (vault.wrapped_vault_key.clone(), vault.role);
            if self.opened.get(&vault.id) == Some(&current) {
                continue;
            }
            let opened = self.core.open_synced_vault(&synced_vault(vault));
            if opened.is_ok() || vault.vault_type == VaultType::Personal {
                self.untrusted.remove(&vault.id);
            } else {
                self.untrusted.insert(vault.id.clone());
            }
            self.opened.insert(vault.id.clone(), current);
        }
    }

    /// Takes `vault`'s rotated record into the store and moves the changes waiting there onto the
    /// new key, which needs the old key to still be open.
    fn rekey(&mut self, data: &mut StoreData, vault: &VaultRecord) -> Result<()> {
        self.open_vaults(data);
        let pending: Vec<ItemKey> = data
            .items
            .values()
            .filter(|item| item.record.vault_id == vault.id && item.sync != SyncState::Synced)
            .map(|item| ItemKey {
                item_id: item.record.id.clone(),
                encrypted_item_key: item.record.encrypted_item_key.clone(),
            })
            .collect();
        let moved = self
            .core
            .rekey_synced_vault(&synced_vault(vault), &pending, &mut OsRng);
        // Whatever happened, the next `open_vaults` works out what's open from the store.
        self.opened.remove(&vault.id);
        for item in moved? {
            if let Some(stored) = data.items.get_mut(&item.item_id) {
                stored.record.encrypted_item_key = item.encrypted_item_key;
            }
        }
        // The old revision: the rotated items are still to come from the next sync.
        let revision = data.vaults.get(&vault.id).map(|known| known.revision);
        let mut record = vault.clone();
        record.revision = revision.unwrap_or(record.revision);
        data.vaults.insert(vault.id.clone(), record);
        Ok(())
    }
}

impl Session {
    /// Takes the account's key record, and lets the vaults that didn't open try again with the
    /// key it brings. Returns the bundle to store.
    pub(crate) fn adopt_key_record(
        &self,
        keys: octapass_core::transparency::publish::PublishKeys,
    ) -> Result<octapass_core::account::AccountBundle> {
        let mut inner = self.inner.lock().expect("session lock poisoned");
        let keys_held = inner.as_mut().ok_or(OctaPassError::Locked)?;
        keys_held.core.adopt_key_record(keys)?;
        for id in std::mem::take(&mut keys_held.untrusted) {
            keys_held.opened.remove(&id);
        }
        Ok(keys_held.core.bundle().clone())
    }
}

/// What the core needs from a `VaultRecord` to open its key.
pub(crate) fn synced_vault(vault: &VaultRecord) -> SyncedVault<'_> {
    SyncedVault {
        id: &vault.id,
        personal: vault.vault_type == VaultType::Personal,
        role: match vault.role {
            VaultRole::Read => Role::Read,
            VaultRole::Write => Role::Write,
            VaultRole::Manage => Role::Manage,
            VaultRole::Owner => Role::Owner,
        },
        wrapped_vault_key: &vault.wrapped_vault_key,
        grant: vault.grant.as_ref().map(|grant| GrantSignature {
            granted_by: &grant.granted_by,
            granter_public_sign_key: &grant.granter_public_sign_key,
            granted_at: grant.granted_at,
            signature: &grant.signature,
        }),
    }
}

/// A login that can fill the page or app asking.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginMatch {
    pub item: ItemSummary,
    /// The saved URL that matched.
    pub url: String,
    pub quality: MatchQuality,
    /// The page and the saved URL disagree on `http` vs `https`: warn before filling an `http`
    /// page.
    pub scheme_mismatch: bool,
}

/// A login saved for another part of the site asking (`shop.example.com` on
/// `login.example.com`). Not a suggestion: list these behind one entry ("Logins for other parts of
/// example.com") and fill one only when the user picks it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OtherLogin {
    pub item: ItemSummary,
    /// The saved URL on the other part.
    pub url: String,
    /// That URL's host to show: Unicode, without a leading `www.`.
    pub host: String,
    /// The registrable domain the site and the login share, to show ("example.com").
    pub site: String,
    /// As in `LoginMatch`.
    pub scheme_mismatch: bool,
    /// The login's vault can be changed, so after filling it the app may offer to add the site
    /// (`websiteForPage`) with `saveLogin`.
    pub can_add_website: bool,
}

/// What the system's credential lists need (`ASCredentialIdentityStore` on iOS, the Credential
/// Manager entries on Android), so suggestions show before the vault is unlocked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialIdentity {
    /// One per saved URL of a login with a password.
    Password {
        item_id: String,
        url: String,
        user: String,
    },
    Passkey {
        item_id: String,
        rp_id: String,
        user_name: String,
        credential_id: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// One per saved URL of a login with a TOTP secret (iOS 18 one-time codes).
    OneTimeCode {
        item_id: String,
        url: String,
        label: String,
    },
}

impl Session {
    pub(crate) fn new(session: CoreSession) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(Keys {
                core: session,
                opened: HashMap::new(),
                untrusted: BTreeSet::new(),
            })),
        })
    }

    fn keys<R>(&self, f: impl FnOnce(&mut Keys) -> Result<R>) -> Result<R> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(inner.as_mut().ok_or(OctaPassError::Locked)?)
    }

    /// Runs `f` on the unlocked keys, or fails with `Locked`.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut CoreSession) -> Result<R>) -> Result<R> {
        self.keys(|keys| f(&mut keys.core))
    }

    /// Runs `f` with the keys and the store's current contents, after checking they belong to
    /// the same account. The store's vaults are opened first.
    pub(crate) fn with_store<R>(
        &self,
        store: &LocalStore,
        f: impl FnOnce(&mut CoreSession, &StoreData) -> Result<R>,
    ) -> Result<R> {
        store.check_account(self)?;
        let data = store.data();
        self.keys(|keys| {
            keys.open_vaults(&data);
            f(&mut keys.core, &data)
        })
    }

    /// Takes a vault's rotated record into `store`, moving the changes waiting there from the old
    /// key to the new one in the same write.
    pub(crate) fn rekey_vault(&self, store: &LocalStore, vault: &VaultRecord) -> Result<()> {
        store.check_account(self)?;
        store.mutate(|data| self.keys(|keys| keys.rekey(data, vault)))
    }

    /// The shared and family vaults in `store` whose grant didn't verify (Rust only). Their keys
    /// aren't used: show a warning instead of their items.
    pub fn untrusted_vaults(&self, store: &LocalStore) -> Result<BTreeSet<String>> {
        store.check_account(self)?;
        let data = store.data();
        self.keys(|keys| {
            keys.open_vaults(&data);
            Ok(keys.untrusted.clone())
        })
    }

    /// The account key wrapped as for device unlock, under `device_secret`, without storing
    /// anything (Rust only). The desktop app hands the key to the browser extension and the CLI
    /// this way, under a secret derived for that one request (plans 05 and 13).
    pub fn wrap_for_device_secret(
        &self,
        device_secret: &[u8],
    ) -> Result<octapass_core::device::DeviceUnlock> {
        self.with(|core| Ok(core.enable_device_unlock(device_secret, &mut OsRng)?))
    }
}

/// Fails unless the vault's key is open: `invalid_grant` for a shared or family vault whose grant
/// didn't verify. [`Session::with_store`] opened every vault it could.
pub(crate) fn open_vault(core: &mut CoreSession, data: &StoreData, vault_id: &str) -> Result<()> {
    let vault = data
        .vaults
        .get(vault_id)
        .ok_or(OctaPassError::ItemNotFound)?;
    match core.is_vault_open(vault_id) {
        true => Ok(()),
        false if vault.vault_type == VaultType::Personal => Err(CoreError::VaultNotOpen.into()),
        false => Err(CoreError::InvalidGrant.into()),
    }
}

pub(crate) fn encrypted(record: &ItemRecord) -> EncryptedItem {
    EncryptedItem {
        encrypted_item_key: record.encrypted_item_key.clone(),
        overview: record.overview.clone(),
        details: record.details.clone(),
    }
}

pub(crate) fn decrypt(
    core: &mut CoreSession,
    data: &StoreData,
    record: &ItemRecord,
) -> Result<CoreItem> {
    open_vault(core, data, &record.vault_id)?;
    Ok(core.decrypt_item(&record.vault_id, &record.id, &encrypted(record))?)
}

/// Encrypts `item` into `vault_id`, reusing the item key of `base` (the stored version).
pub(crate) fn encrypt(
    core: &mut CoreSession,
    data: &StoreData,
    vault_id: &str,
    item_id: &str,
    item: &CoreItem,
    base: Option<&StoredItem>,
) -> Result<EncryptedItem> {
    data.writable_vault(vault_id)?;
    open_vault(core, data, vault_id)?;
    let key = base.map(|base| base.record.encrypted_item_key.as_str());
    Ok(core.encrypt_item(vault_id, item_id, item, key, &mut OsRng)?)
}

/// Every item that isn't in the trash, decrypted. Items that don't decrypt (damaged, or from a
/// vault this session can't open) are left out, so one bad item never breaks autofill.
pub(crate) fn live_items<'a>(
    core: &mut CoreSession,
    data: &'a StoreData,
) -> Vec<(&'a StoredItem, CoreItem)> {
    data.items
        .values()
        .filter(|stored| stored.record.deleted_at.is_none())
        .filter_map(|stored| Some((stored, decrypt(core, data, &stored.record).ok()?)))
        .collect()
}

#[uniffi::export]
impl Session {
    /// Zeroes the account key and every vault key now. Every later call fails with `Locked`.
    pub fn lock(&self) {
        *self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    pub fn is_locked(&self) -> bool {
        self.with(|_| Ok(())).is_err()
    }

    pub fn email(&self) -> Result<String> {
        self.with(|core| Ok(core.bundle().email.clone()))
    }

    pub fn account_id(&self) -> Result<Option<String>> {
        self.with(|core| Ok(core.bundle().account_id.clone()))
    }

    /// Every item outside the trash, by title.
    pub fn list_items(&self, store: Arc<LocalStore>) -> Result<Vec<ItemSummary>> {
        self.with_store(&store, |core, data| {
            let mut items: Vec<ItemSummary> = live_items(core, data)
                .iter()
                // Masked email tokens are settings, not something to list or fill.
                .filter(|(_, item)| {
                    !matches!(
                        item.overview.item_type,
                        ItemType::MaskedEmailProvider | ItemType::EquivalentDomains
                    )
                })
                .map(|(stored, item)| {
                    items::summary(&stored.record.id, &stored.record.vault_id, item)
                })
                .collect();
            items.sort_by_cached_key(|item| item.title.to_lowercase());
            Ok(items)
        })
    }

    /// One item with all its fields, secrets included: call it only to fill or show them.
    pub fn get_item(&self, store: Arc<LocalStore>, item_id: String) -> Result<Item> {
        self.with_store(&store, |core, data| {
            let stored = data
                .items
                .get(&item_id)
                .ok_or(OctaPassError::ItemNotFound)?;
            let item = decrypt(core, data, &stored.record)?;
            Ok(items::full(
                &stored.record.id,
                &stored.record.vault_id,
                &item,
            ))
        })
    }

    /// Creates a login in the personal vault, or updates one (`draft.itemId`). The change is
    /// saved to the store right away and uploaded by `OctaPassServer.uploadPending`. Returns the
    /// item id.
    pub fn save_login(&self, store: Arc<LocalStore>, draft: LoginDraft) -> Result<String> {
        let now = timestamp(now_ms());
        let (vault_id, item_id, base, encrypted) = self.with_store(&store, |core, data| {
            let (vault_id, item_id, base, item) = match &draft.item_id {
                Some(item_id) => {
                    let base = data.items.get(item_id).ok_or(OctaPassError::ItemNotFound)?;
                    let mut item = decrypt(core, data, &base.record)?;
                    items::update_login(&mut item, &draft, &now)?;
                    (
                        base.record.vault_id.clone(),
                        item_id.clone(),
                        Some(base.clone()),
                        item,
                    )
                }
                None => (
                    data.personal_vault()?.id.clone(),
                    new_id(now_ms(), &mut OsRng),
                    None,
                    items::new_login(&draft)?,
                ),
            };
            let encrypted = encrypt(core, data, &vault_id, &item_id, &item, base.as_ref())?;
            Ok((vault_id, item_id, base, encrypted))
        })?;
        store.mutate(|data| {
            data.put_local(&vault_id, &item_id, encrypted, base.as_ref(), &now);
            Ok(())
        })?;
        Ok(item_id)
    }

    /// The logins that may fill `url` (a website address, or `androidapp://<package>`), best
    /// first: the same host, a domain above it (nearest first), a host below it, then equivalent
    /// domains. Logins for other parts of the domain are in `other_logins`.
    pub fn match_logins(&self, store: Arc<LocalStore>, url: String) -> Result<Vec<LoginMatch>> {
        self.with_store(&store, |core, data| {
            let all = live_items(core, data);
            let options =
                user_equivalents(all.iter().filter_map(|(_, item)| match &item.details {
                    ItemDetails::EquivalentDomains(details) => Some(details),
                    _ => None,
                }));
            let logins: Vec<(&StoredItem, CoreItem)> = all
                .into_iter()
                .filter(|(_, item)| items::login_details(item).is_some())
                .collect();
            let found = match_overviews(
                &url,
                logins
                    .iter()
                    .map(|(stored, item)| (stored.record.id.as_str(), &item.overview)),
                &options,
            )?;
            Ok(found
                .into_iter()
                .filter_map(|found| {
                    let (stored, item) = logins
                        .iter()
                        .find(|(stored, _)| stored.record.id == found.id)?;
                    Some(LoginMatch {
                        item: items::summary(&stored.record.id, &stored.record.vault_id, item),
                        url: found.url,
                        quality: found.quality,
                        scheme_mismatch: found.scheme_mismatch,
                    })
                })
                .collect())
        })
    }

    /// The logins saved for other parts of `url`'s registrable domain, which `match_logins`
    /// leaves out, sorted by host (plan 05, *Filling rules*). Empty for an Android app. After the
    /// user fills one, offer to add `websiteForPage(url)` to it with `saveLogin` (`itemId` and
    /// `url` only) when `canAddWebsite`.
    pub fn other_logins(&self, store: Arc<LocalStore>, url: String) -> Result<Vec<OtherLogin>> {
        self.with_store(&store, |core, data| {
            let all = live_items(core, data);
            let options =
                user_equivalents(all.iter().filter_map(|(_, item)| match &item.details {
                    ItemDetails::EquivalentDomains(details) => Some(details),
                    _ => None,
                }));
            let logins: Vec<(&StoredItem, CoreItem)> = all
                .into_iter()
                .filter(|(_, item)| items::login_details(item).is_some())
                .collect();
            let found = other_parts(
                &url,
                logins
                    .iter()
                    .map(|(stored, item)| (stored.record.id.as_str(), &item.overview)),
                &options,
            )?;
            Ok(found
                .into_iter()
                .filter_map(|part| {
                    let (stored, item) = logins
                        .iter()
                        .find(|(stored, _)| stored.record.id == part.id)?;
                    Some(OtherLogin {
                        item: items::summary(&stored.record.id, &stored.record.vault_id, item),
                        url: part.url,
                        host: part.host,
                        site: part.site,
                        scheme_mismatch: part.scheme_mismatch,
                        can_add_website: data.writable_vault(&stored.record.vault_id).is_ok(),
                    })
                })
                .collect())
        })
    }

    /// The current one-time code of a login with a TOTP secret.
    pub fn totp_code(&self, store: Arc<LocalStore>, item_id: String) -> Result<TotpCode> {
        let item = self.get_item(store, item_id)?;
        let secret = item
            .login
            .and_then(|login| login.totp)
            .ok_or(OctaPassError::InvalidTotp)?;
        crate::tools::totp_code(secret, unix_seconds())
    }

    /// Every password, passkey and one-time code the system may suggest. Register them after
    /// each sync, and clear them on lock-out or sign-out as the platform requires.
    pub fn credential_identities(&self, store: Arc<LocalStore>) -> Result<Vec<CredentialIdentity>> {
        self.with_store(&store, |core, data| {
            let mut identities = Vec::new();
            for (stored, item) in live_items(core, data) {
                let Some(login) = items::login_details(&item) else {
                    continue;
                };
                let item_id = &stored.record.id;
                let urls = item.overview.urls.as_deref().unwrap_or_default();
                if login.password.as_deref().is_some_and(|p| !p.is_empty()) {
                    identities.extend(urls.iter().map(|url| CredentialIdentity::Password {
                        item_id: item_id.clone(),
                        url: url.clone(),
                        user: login.username.clone().unwrap_or_default(),
                    }));
                }
                // A counter-based code changes the item when used, which AutoFill can't save.
                if login
                    .totp
                    .as_deref()
                    .is_some_and(|t| !t.is_empty() && !is_hotp(t))
                {
                    identities.extend(urls.iter().map(|url| CredentialIdentity::OneTimeCode {
                        item_id: item_id.clone(),
                        url: url.clone(),
                        label: item.overview.title.clone(),
                    }));
                }
                for passkey in items::passkey_records(&item) {
                    let (Ok(credential_id), Ok(user_handle)) = (
                        passkey.credential_id_bytes(),
                        octapass_core::encoding::b64_decode(&passkey.user_handle),
                    ) else {
                        continue;
                    };
                    identities.push(CredentialIdentity::Passkey {
                        item_id: item_id.clone(),
                        rp_id: passkey.rp_id.clone(),
                        user_name: passkey.user_name.clone(),
                        credential_id,
                        user_handle,
                    });
                }
            }
            Ok(identities)
        })
    }
}
