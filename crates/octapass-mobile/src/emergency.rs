//! Emergency access (plan 06), as `packages/vault-client/src/remote/emergency.ts` does it. The
//! grantor seals their account key, or one vault's key, to a trusted contact. The server hands it
//! over only after a waiting period the grantor didn't cut short with a denial; then the contact
//! opens the grantor's vaults read-only, on this phone.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use octapass_api::{
    EmergencyContactRecord, EmergencyContactsResponse, EmergencyReleaseResponse, ItemRecord,
    SyncResponse, VaultType as ApiType,
};
use octapass_core::account::AccountBundle;
use octapass_core::session::{EncryptedItem, Session as CoreSession};
use octapass_core::sharing::emergency::EmergencyScope as CoreScope;
use octapass_core::sharing::grant::SignedGrant;
use octapass_mobile_vault::model::Item as StoredItem;
use octapass_mobile_vault::vault::Access;
use rand_core::OsRng;
use serde_json::{Value, json};

use crate::api::{Method, Refused, Server, segment};
use crate::error::{ErrorCode, Result, VaultError, not_allowed, require};
use crate::items::{Item, attachments, is_vault_info};
use crate::sharing::{
    AccountLookup, Vault, VaultRole, VaultType, default_vault_name, fingerprint_of,
};
use crate::vault::{Ctx, created_at};

const MIN_WAIT_DAYS: u32 = 1;
const MAX_WAIT_DAYS: u32 = 30;
/// A renewal races key rotations by other members; after this many `vault-key-changed`, give up.
const KEY_ATTEMPTS: usize = 2;
const MAX_PAGES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum EmergencyScope {
    /// Every vault the grantor can open.
    Account,
    Vault {
        vault_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EmergencyAccessLevel {
    View,
    Takeover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EmergencyStatus {
    Idle,
    Requested,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyContact {
    pub id: String,
    pub grantor_id: String,
    pub grantor_email: String,
    pub contact_id: String,
    pub contact_email: String,
    pub scope: EmergencyScope,
    pub access_level: EmergencyAccessLevel,
    /// 1 to 30.
    pub wait_days: u32,
    pub status: EmergencyStatus,
    pub requested_at: Option<String>,
    /// When a pending request releases the key unless the grantor denies it.
    pub releases_at: Option<String>,
    pub released_at: Option<String>,
    pub created_at: String,
    /// A vault scope: the vault's key was rotated, and the contact's copy opens nothing new until
    /// the grantor renews it.
    pub key_stale: bool,
    /// The family's organiser holds this: they can reset the account, and can't read it.
    pub organiser_recovery: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyContacts {
    /// Contacts the user chose.
    pub granted: Vec<EmergencyContact>,
    /// People who chose the user as their contact.
    pub received: Vec<EmergencyContact>,
}

/// A grantor's vaults, opened read-only by their contact after release.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyVaultView {
    pub contact: EmergencyContact,
    pub vaults: Vec<Vault>,
    pub items: Vec<Item>,
}

impl From<octapass_api::EmergencyScope> for EmergencyScope {
    fn from(scope: octapass_api::EmergencyScope) -> Self {
        match scope {
            octapass_api::EmergencyScope::Account => Self::Account,
            octapass_api::EmergencyScope::Vault { vault_id } => Self::Vault { vault_id },
        }
    }
}

impl From<EmergencyContactRecord> for EmergencyContact {
    fn from(record: EmergencyContactRecord) -> Self {
        Self {
            id: record.id,
            grantor_id: record.grantor_id,
            grantor_email: record.grantor_email,
            contact_id: record.contact_id,
            contact_email: record.contact_email,
            scope: record.scope.into(),
            access_level: match record.access_level {
                octapass_api::EmergencyAccessLevel::View => EmergencyAccessLevel::View,
                octapass_api::EmergencyAccessLevel::Takeover => EmergencyAccessLevel::Takeover,
            },
            wait_days: record.wait_days,
            status: match record.status {
                octapass_api::EmergencyStatus::Idle => EmergencyStatus::Idle,
                octapass_api::EmergencyStatus::Requested => EmergencyStatus::Requested,
                octapass_api::EmergencyStatus::Released => EmergencyStatus::Released,
            },
            requested_at: record.requested_at,
            releases_at: record.releases_at,
            released_at: record.released_at,
            created_at: record.created_at,
            key_stale: record.key_stale,
            organiser_recovery: record.organiser_recovery,
        }
    }
}

fn encrypted(record: &ItemRecord) -> EncryptedItem {
    EncryptedItem {
        encrypted_item_key: record.encrypted_item_key.clone(),
        overview: record.overview.clone(),
        details: record.details.clone(),
    }
}

/// Decrypted, or left out when tampered with, as the vault index does.
fn decrypt(core: &CoreSession, record: &ItemRecord) -> Option<StoredItem> {
    let item = core
        .decrypt_item(&record.vault_id, &record.id, &encrypted(record))
        .ok()?;
    Some(StoredItem {
        id: record.id.clone(),
        vault_id: record.vault_id.clone(),
        revision: record.revision,
        created_at: created_at(&record.id).unwrap_or_else(|| record.updated_at.clone()),
        updated_at: record.updated_at.clone(),
        deleted_at: record.deleted_at.clone(),
        overview: serde_json::to_value(&item.overview).expect("items serialize"),
        details: serde_json::to_value(&item.details).expect("items serialize"),
    })
}

/// Opens the grantor's vaults in their own session, as their apps would: personal ones with the
/// account key, shared ones once their grant verifies.
fn open_vaults(core: &mut CoreSession, sync: &SyncResponse, grantor_id: &str) {
    for vault in &sync.vaults {
        let _ = match (&vault.vault_type, &vault.grant) {
            (ApiType::Personal, _) => core.open_vault(&vault.id, &vault.wrapped_vault_key),
            (_, Some(grant)) => (|| {
                let signed = SignedGrant {
                    vault_id: vault.id.clone(),
                    recipient_account_id: grantor_id.into(),
                    role: VaultRole::from(vault.role).core(),
                    wrapped_vault_key: vault.wrapped_vault_key.clone(),
                    granted_by: grant.granted_by.clone(),
                    granted_at: grant.granted_at,
                    signature: grant.signature.clone(),
                };
                let key =
                    octapass_core::encoding::b64_decode_array(&grant.granter_public_sign_key)?;
                core.open_shared_vault(&signed, &key)
            })(),
            (_, None) => continue,
        };
    }
}

fn grantor_session(access: &Access, release: &EmergencyReleaseResponse) -> Result<CoreSession> {
    let grantor = release
        .grantor
        .clone()
        .ok_or_else(|| VaultError::new(ErrorCode::ServerError, "no grantor account"))?;
    let bundle: AccountBundle =
        serde_json::from_value(serde_json::to_value(grantor).expect("bundles serialize"))
            .map_err(|_| VaultError::new(ErrorCode::ServerError, "invalid grantor account"))?;
    Ok(access
        .session()
        .with_keys(|me| Ok(me.open_emergency_account(bundle, &release.sealed_key)?))?)
}

impl Ctx<'_> {
    fn emergency_server<'a>(&'a self, access: &'a Access<'a>) -> Server<'a> {
        Server {
            api: self.api,
            access,
        }
    }

    pub fn list_emergency_contacts(&self) -> Result<EmergencyContacts> {
        let access = self.vault.access()?;
        let response: EmergencyContactsResponse = self
            .emergency_server(&access)
            .get("v1/emergency-contacts")?;
        Ok(EmergencyContacts {
            granted: response.granted.into_iter().map(Into::into).collect(),
            received: response.received.into_iter().map(Into::into).collect(),
        })
    }

    pub fn add_emergency_contact(
        &self,
        account: &AccountLookup,
        wait_days: u32,
        access_level: EmergencyAccessLevel,
        scope: &EmergencyScope,
    ) -> Result<EmergencyContact> {
        if !(MIN_WAIT_DAYS..=MAX_WAIT_DAYS).contains(&wait_days) {
            return Err(VaultError::new(
                ErrorCode::InvalidInput,
                "the waiting period is 1 to 30 days",
            ));
        }
        let actual = fingerprint_of(&account.public_enc_key, &account.public_sign_key)?;
        require(
            actual.digits == account.fingerprint.digits,
            ErrorCode::UntrustedVault,
        )?;
        let core_scope = match scope {
            EmergencyScope::Account => CoreScope::Account,
            EmergencyScope::Vault { vault_id } => CoreScope::Vault {
                vault_id: vault_id.clone(),
            },
        };
        let access = self.vault.access()?;
        if let EmergencyScope::Vault { vault_id } = scope {
            // Sealing a vault's key needs it open.
            require(
                !self.shared.open(&access).contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            if !access
                .session()
                .with_keys(|core| Ok(core.is_vault_open(vault_id)))?
            {
                let personal = access
                    .store()
                    .vaults()
                    .into_iter()
                    .find(|v| v.id == *vault_id)
                    .ok_or(ErrorCode::NotFound)?;
                access.session().with_keys(|core| {
                    Ok(core.open_vault(vault_id, &personal.wrapped_vault_key)?)
                })?;
            }
        }
        let public = octapass_core::encoding::b64_decode_array(&account.public_enc_key)?;
        let pq_key = self
            .looked_up_recipient(account, octapass_core::sharing::Role::Read)?
            .public_pq_key;
        let sealed = access.session().with_keys(|core| {
            Ok(core.seal_for_emergency_contact(
                &account.account_id,
                &public,
                pq_key.as_ref(),
                &core_scope,
                &mut OsRng,
            )?)
        })?;
        let body = json!({
            "contactAccountId": account.account_id,
            "sealedKey": sealed,
            "scope": serde_json::to_value(&core_scope).expect("scopes serialize"),
            "accessLevel": match access_level {
                EmergencyAccessLevel::View => "view",
                EmergencyAccessLevel::Takeover => "takeover",
            },
            "waitDays": wait_days,
        });
        let contact: EmergencyContactRecord = self
            .emergency_server(&access)
            .post("v1/emergency-contacts", &body)?;
        self.sharing_changed();
        Ok(contact.into())
    }

    /// As the grantor, after a rotation: seals the vault's current key to the contact again.
    /// `account` is a lookup whose fingerprint the user compared: sealing to whichever key a
    /// server names, by itself, would let a server collect the vault key.
    pub fn renew_emergency_key(&self, id: &str, account: &AccountLookup) -> Result<()> {
        let actual = fingerprint_of(&account.public_enc_key, &account.public_sign_key)?;
        require(
            actual.digits == account.fingerprint.digits,
            ErrorCode::UntrustedVault,
        )?;
        let public = octapass_core::encoding::b64_decode_array(&account.public_enc_key)?;
        let pq_key = self
            .looked_up_recipient(account, octapass_core::sharing::Role::Read)?
            .public_pq_key;
        let contact = {
            let access = self.vault.access()?;
            let contacts: EmergencyContactsResponse = self
                .emergency_server(&access)
                .get("v1/emergency-contacts")?;
            contacts
                .granted
                .into_iter()
                .find(|contact| contact.id == id)
                .ok_or(ErrorCode::NotFound)?
        };
        let octapass_api::EmergencyScope::Vault { vault_id } = contact.scope else {
            return Err(ErrorCode::NotAllowed.into());
        };
        require(
            contact.contact_id == account.account_id,
            ErrorCode::NotAllowed,
        )?;
        let scope = CoreScope::Vault {
            vault_id: vault_id.clone(),
        };
        for attempt in 1..=KEY_ATTEMPTS {
            self.sync_and_open()?;
            let access = self.vault.access()?;
            let (sealed, key_id) = access.session().with_keys(|core| {
                Ok((
                    core.seal_for_emergency_contact(
                        &account.account_id,
                        &public,
                        pq_key.as_ref(),
                        &scope,
                        &mut OsRng,
                    )?,
                    core.vault_key_id(&vault_id)?,
                ))
            })?;
            let body = json!({ "sealedKey": sealed, "keyId": key_id });
            let renewed: std::result::Result<Value, Refused> = self
                .emergency_server(&access)
                .call_unless(
                    Method::Put,
                    &format!("v1/emergency-contacts/{}/key", segment(id)),
                    Some(&body),
                    "vault-key-changed",
                )
                .map_err(not_allowed)?;
            match renewed {
                Ok(_) => break,
                Err(Refused) if attempt < KEY_ATTEMPTS => {}
                Err(Refused) => {
                    return Err(VaultError::new(
                        ErrorCode::ServerError,
                        "the vault's key kept changing",
                    ));
                }
            }
        }
        self.sharing_changed();
        Ok(())
    }

    /// As a family member: lets the organiser help recover this account (plan 06). `account` is
    /// the organiser, from a lookup whose fingerprint the user compared.
    pub fn enable_organiser_recovery(
        &self,
        account: &AccountLookup,
        wait_days: u32,
    ) -> Result<EmergencyContact> {
        if !(MIN_WAIT_DAYS..=MAX_WAIT_DAYS).contains(&wait_days) {
            return Err(VaultError::new(
                ErrorCode::InvalidInput,
                "the waiting period is 1 to 30 days",
            ));
        }
        let actual = fingerprint_of(&account.public_enc_key, &account.public_sign_key)?;
        require(
            actual.digits == account.fingerprint.digits,
            ErrorCode::UntrustedVault,
        )?;
        let family = self.require_family()?;
        require(
            family.organiser_id == account.account_id,
            ErrorCode::NotAllowed,
        )?;
        let public = octapass_core::encoding::b64_decode_array(&account.public_enc_key)?;
        let pq_key = self
            .looked_up_recipient(account, octapass_core::sharing::Role::Read)?
            .public_pq_key;
        let access = self.vault.access()?;
        let sealed = access.session().with_keys(|core| {
            Ok(core.seal_for_emergency_contact(
                &account.account_id,
                &public,
                pq_key.as_ref(),
                &CoreScope::Account,
                &mut OsRng,
            )?)
        })?;
        let body = json!({ "sealedKey": sealed, "waitDays": wait_days });
        let contact: EmergencyContactRecord = self
            .emergency_server(&access)
            .post(
                &format!("v1/families/{}/organiser-recovery", segment(&family.id)),
                &body,
            )
            .map_err(not_allowed)?;
        self.sharing_changed();
        Ok(contact.into())
    }

    /// Either side: removes a contact, or steps down as one.
    pub fn remove_emergency_contact(&self, id: &str) -> Result<()> {
        let access = self.vault.access()?;
        self.emergency_server(&access)
            .delete(&format!("v1/emergency-contacts/{}", segment(id)))?;
        self.sharing_changed();
        Ok(())
    }

    /// `request`, `deny` or `approve`.
    pub fn emergency_action(&self, id: &str, action: &str) -> Result<()> {
        let access = self.vault.access()?;
        self.emergency_server(&access)
            .call::<Value>(
                Method::Post,
                &format!("v1/emergency-contacts/{}/{action}", segment(id)),
                None::<&()>,
            )
            .map_err(not_allowed)?;
        self.sharing_changed();
        Ok(())
    }

    fn release(&self, access: &Access, id: &str) -> Result<EmergencyReleaseResponse> {
        self.emergency_server(access)
            .get(&format!("v1/emergency-contacts/{}/release", segment(id)))
            .map_err(not_allowed)
    }

    fn sync_all(&self, access: &Access, id: &str) -> Result<SyncResponse> {
        let mut merged = SyncResponse {
            vaults: Vec::new(),
            items: Vec::new(),
            deleted: Vec::new(),
            has_more: false,
        };
        let mut since = String::new();
        for _ in 0..MAX_PAGES {
            let path = format!("v1/emergency-contacts/{}/sync{since}", segment(id));
            let page: SyncResponse = self
                .emergency_server(access)
                .get(&path)
                .map_err(not_allowed)?;
            merged.vaults = page.vaults;
            merged.items.extend(page.items);
            if !page.has_more {
                return Ok(merged);
            }
            let cursor: Vec<String> = merged
                .vaults
                .iter()
                .map(|vault| format!("{}:{}", vault.id, vault.revision))
                .collect();
            since = format!("?since={}", cursor.join(","));
        }
        Err(VaultError::new(
            ErrorCode::ServerError,
            "too many sync pages",
        ))
    }

    /// As the contact, once released: the grantor's vaults in scope, read-only.
    pub fn open_emergency_access(&self, id: &str) -> Result<EmergencyVaultView> {
        let access = self.vault.access()?;
        let release = self.release(&access, id)?;
        let sync = self.sync_all(&access, id)?;
        let contact = release.contact.clone();
        let live = |record: &&ItemRecord| record.deleted_at.is_none();
        match &contact.scope {
            octapass_api::EmergencyScope::Account => {
                let mut grantor = grantor_session(&access, &release)?;
                open_vaults(&mut grantor, &sync, &contact.grantor_id);
                let decrypted: Vec<StoredItem> = sync
                    .items
                    .iter()
                    .filter(live)
                    .filter_map(|record| decrypt(&grantor, record))
                    .collect();
                let vaults = sync
                    .vaults
                    .iter()
                    .map(|vault| {
                        let vault_type = VaultType::from(vault.vault_type);
                        let name = vault_name(&decrypted, &vault.id)
                            .unwrap_or_else(|| default_vault_name(vault_type).into());
                        Vault {
                            id: vault.id.clone(),
                            name,
                            vault_type,
                            role: VaultRole::Read,
                            untrusted: !grantor.is_vault_open(&vault.id),
                        }
                    })
                    .collect();
                let items = decrypted
                    .iter()
                    .filter(|item| !is_vault_info(item))
                    .map(Item::from)
                    .collect();
                Ok(EmergencyVaultView {
                    contact: contact.into(),
                    vaults,
                    items,
                })
            }
            octapass_api::EmergencyScope::Vault { vault_id } => {
                let vault = sync
                    .vaults
                    .iter()
                    .find(|vault| vault.id == *vault_id)
                    .ok_or(ErrorCode::NotFound)?;
                access.session().with_keys(|me| {
                    Ok(me.open_emergency_vault(
                        &contact.grantor_id,
                        vault_id,
                        &release.sealed_key,
                    )?)
                })?;
                let decrypted: Vec<StoredItem> = access.session().with_keys(|me| {
                    Ok(sync
                        .items
                        .iter()
                        .filter(live)
                        .filter(|record| record.vault_id == *vault_id)
                        .filter_map(|record| decrypt(me, record))
                        .collect())
                })?;
                let vault_type = VaultType::from(vault.vault_type);
                let vault = Vault {
                    id: vault_id.clone(),
                    name: vault_name(&decrypted, vault_id)
                        .unwrap_or_else(|| default_vault_name(vault_type).into()),
                    vault_type,
                    role: VaultRole::Read,
                    untrusted: false,
                };
                Ok(EmergencyVaultView {
                    contact: contact.into(),
                    vaults: vec![vault],
                    items: decrypted
                        .iter()
                        .filter(|item| !is_vault_info(item))
                        .map(Item::from)
                        .collect(),
                })
            }
        }
    }

    /// As the contact, once released: decrypts one of the grantor's files into private storage
    /// and returns its path, as `openAttachment` does. Checks the release again, so a denial or
    /// removal stops it.
    pub fn open_emergency_attachment(
        &self,
        id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<PathBuf> {
        let access = self.vault.access()?;
        let release = self.release(&access, id)?;
        let sync = self.sync_all(&access, id)?;
        let record = sync
            .items
            .iter()
            .find(|record| record.id == item_id && record.deleted_at.is_none())
            .ok_or(ErrorCode::NotFound)?;
        let contact = &release.contact;
        type Opened = Option<(StoredItem, octapass_core::attachment::Decryptor)>;
        let open = |core: &CoreSession| -> std::result::Result<Opened, octapass_core::Error> {
            let Some(item) = decrypt(core, record) else {
                return Ok(None);
            };
            let wrapped = item
                .details
                .get("attachments")
                .and_then(Value::as_array)
                .and_then(|list| {
                    list.iter().find(|entry| {
                        entry.get("id").and_then(Value::as_str) == Some(attachment_id)
                    })
                })
                .map(|entry| {
                    entry
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                });
            let Some(wrapped) = wrapped else {
                return Ok(None);
            };
            let decryptor = core.open_attachment(
                &record.vault_id,
                &record.id,
                &record.encrypted_item_key,
                attachment_id,
                &wrapped,
            )?;
            Ok(Some((item, decryptor)))
        };
        let opened = match &contact.scope {
            octapass_api::EmergencyScope::Account => {
                let mut grantor = grantor_session(&access, &release)?;
                open_vaults(&mut grantor, &sync, &contact.grantor_id);
                open(&grantor)?
            }
            octapass_api::EmergencyScope::Vault { vault_id } => {
                require(record.vault_id == *vault_id, ErrorCode::NotFound)?;
                access.session().with_keys(|me| {
                    me.open_emergency_vault(&contact.grantor_id, vault_id, &release.sealed_key)?;
                    Ok(open(me)?)
                })?
            }
        };
        let (item, mut decryptor) = opened.ok_or(ErrorCode::NotFound)?;
        let name = attachments(&item.details)
            .into_iter()
            .find(|file| file.id == attachment_id)
            .map(|file| file.name)
            .unwrap_or_default();
        let url = Server {
            api: self.api,
            access: &access,
        }
        .url(&format!(
            "v1/emergency-contacts/{}/vaults/{}/items/{}/attachments/{}",
            segment(id),
            segment(&record.vault_id),
            segment(&record.id),
            segment(attachment_id)
        ));
        let mut source = access.authorized(|token| self.api.download(&url, token))?;
        let path = self.vault.new_opened_path(&name)?;
        let folder = path.parent().expect("a file in a folder").to_owned();
        let written = (|| -> Result<()> {
            let partial = folder.join(".partial");
            let mut file = fs::File::create(&partial).map_err(io_error)?;
            let mut buffer = vec![0u8; 1024 * 1024];
            let damaged =
                |_| VaultError::new(ErrorCode::ServerError, "the file could not be decrypted");
            loop {
                let read = source.read(&mut buffer).map_err(|error| {
                    VaultError::new(ErrorCode::ServerUnreachable, error.to_string())
                })?;
                if read == 0 {
                    break;
                }
                file.write_all(&decryptor.push(&buffer[..read]).map_err(damaged)?)
                    .map_err(io_error)?;
            }
            file.write_all(&decryptor.finish().map_err(damaged)?)
                .map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            // Only a whole, verified file gets its name.
            fs::rename(&partial, &path).map_err(io_error)
        })();
        match written {
            Ok(()) => Ok(path),
            Err(error) => {
                let _ = fs::remove_dir_all(&folder);
                Err(error)
            }
        }
    }
}

fn vault_name(items: &[StoredItem], vault_id: &str) -> Option<String> {
    items
        .iter()
        .filter(|item| item.vault_id == vault_id && is_vault_info(item))
        .max_by_key(|item| item.revision)
        .map(|item| item.title().to_owned())
        .filter(|name| !name.is_empty())
}

fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("files: {error}"))
}
