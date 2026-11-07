//! Shared vaults, their members and keys, families, devices and the security log (plan 15), as
//! the web vault does them in `packages/vault-client/src/remote/sharing.ts`. Every vault key a
//! member gets is sealed to their public key and signed in this process; the server only stores
//! grants and checks who may give them.
//!
//! People are found by email, and the UI shows their fingerprint, computed here from the public
//! keys the server returned, for the user to compare with them out of band. Sharing with a
//! lookup checks its keys still give the fingerprint the user saw.

use octapass_api::problem::types;
use octapass_api::{
    AccountLookupResponse, DeviceRecord, FamiliesResponse, FamilyInvite, MemberRecord,
    MembersResponse, VaultRecord, VaultRole, VaultType,
};
use octapass_core::account::new_id;
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::Role;
use octapass_core::sharing::fingerprint::fingerprint;
use octapass_core::sharing::grant::Recipient;
use octapass_core::sharing::vault::ItemKey;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::key_log::{KeyCheck, Offered, core_record};
use super::{Event, Vault, decrypt};
use crate::api::{ApiResult, Method};
use crate::error::{ErrorCode, Result, VaultError, not_allowed};
use crate::model::{
    Item, ItemDraft, VAULT_INFO_TYPE, Vault as VaultView, default_vault_name, now, require, unix_ms,
};
use crate::store::AccountKey;

/// A rotation races other members' writes; after this many `vault-changed` answers, give up.
const ROTATION_ATTEMPTS: usize = 3;
/// A grant races key rotations by other members; after this many `vault-key-changed`, give up.
const GRANT_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintEmoji {
    pub emoji: String,
    /// The word to say for it, in English.
    pub name: String,
}

/// An account's public keys in a form people compare out of band: in person, or on a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Six groups of four digits.
    pub digits: String,
    pub emoji: Vec<FingerprintEmoji>,
}

/// Someone found by email, to share with. The UI hands it back to share with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLookup {
    pub account_id: String,
    pub email: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    pub fingerprint: Fingerprint,
    /// The account's signed key record, which carries its ML-KEM key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
    /// What the key log says about these keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_log: Option<KeyCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMember {
    pub name: String,
    pub email: String,
    pub role: VaultRole,
    pub account_id: String,
    /// Computed here from the member's public keys, never taken from the server.
    pub fingerprint: Fingerprint,
    /// The user compared this fingerprint with the member, and the keys haven't changed since.
    pub verified: bool,
    /// What the key log says about this member's keys. Absent for the signed-in account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log: Option<KeyCheck>,
    pub is_you: bool,
    pub added_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyMember {
    #[serde(flatten)]
    pub member: octapass_api::FamilyMember,
    pub is_you: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Family {
    pub id: String,
    pub vault_id: String,
    pub organiser_id: String,
    pub is_organiser: bool,
    /// Members plus pending invites can't go over this.
    pub max_members: u32,
    pub members: Vec<FamilyMember>,
    /// Pending invites; only the organiser sees them.
    pub invites: Vec<FamilyInvite>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<Family>,
    /// Invitations this account received.
    pub invitations: Vec<FamilyInvite>,
}

/// A path segment, percent-encoded: ids come from the UI and the server.
pub(super) fn segment(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

pub(super) fn fingerprint_of(public_enc_key: &str, public_sign_key: &str) -> Result<Fingerprint> {
    let found = fingerprint(
        &b64_decode_array(public_enc_key)?,
        &b64_decode_array(public_sign_key)?,
    );
    Ok(Fingerprint {
        digits: found.digits,
        emoji: found
            .emoji
            .into_iter()
            .map(|e| FingerprintEmoji {
                emoji: e.emoji.into(),
                name: e.name.into(),
            })
            .collect(),
    })
}

/// The lookup's keys must be the ones whose fingerprint the user saw.
pub(super) fn check_fingerprint(account: &AccountLookup) -> Result<()> {
    let actual = fingerprint_of(&account.public_enc_key, &account.public_sign_key)?;
    require(
        actual.digits == account.fingerprint.digits,
        ErrorCode::UntrustedVault,
    )
}

fn core_role(role: VaultRole) -> Role {
    match role {
        VaultRole::Read => Role::Read,
        VaultRole::Write => Role::Write,
        VaultRole::Manage => Role::Manage,
        VaultRole::Owner => Role::Owner,
    }
}

/// Who gets a grant. The ML-KEM key comes only from a key record that checks out against the
/// offered keys, so the grant is hybrid exactly when that holds.
fn recipient(account: Offered<'_>, role: Role) -> Result<Recipient> {
    let offered = OfferedKeys {
        account_id: account.account_id,
        public_enc_key: account.public_enc_key,
        public_sign_key: account.public_sign_key,
    };
    Ok(Recipient {
        account_id: account.account_id.into(),
        public_enc_key: b64_decode_array(account.public_enc_key)?,
        public_pq_key: KeyRecord::pq_key_of(account.record, &offered)?,
        role,
    })
}

fn member_keys<'a>(member: &'a MemberRecord, record: Option<&'a KeyRecord>) -> Offered<'a> {
    Offered {
        account_id: &member.account_id,
        email: &member.email,
        public_enc_key: &member.public_enc_key,
        public_sign_key: &member.public_sign_key,
        record,
    }
}

pub(super) fn timestamp_ms() -> u64 {
    unix_ms(now())
}

impl Vault {
    /// The signed-in account's id, from its bundle.
    pub(super) fn account_id(&self) -> Result<String> {
        self.with_unlocked(|unlocked| {
            unlocked
                .session
                .bundle()
                .account_id
                .clone()
                .ok_or_else(|| VaultError::unexpected("the account has no id"))
        })
    }

    pub(super) fn sharing_changed(&self) {
        self.emit(Event::SharingChanged);
    }

    /// A call whose answer the caller doesn't need. The caller holds `io`.
    async fn send(
        &self,
        key: &AccountKey,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<()> {
        self.server::<Value>(key, method, path, body).await??;
        Ok(())
    }

    // ---------- Devices and the security log ----------

    pub async fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        Ok(self
            .server(&key, Method::GET, "/v1/devices", None)
            .await??)
    }

    /// Renames this device in the account's device list.
    pub async fn rename_device(&self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(VaultError::new(
                ErrorCode::ServerError,
                "A device name is 1 to 64 characters.",
            ));
        }
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let body = json!({ "name": name });
        self.send(&key, Method::PATCH, "/v1/devices/current", Some(body))
            .await
    }

    /// Signs another device out. Signing out this one is `sign_out`.
    pub async fn sign_out_device(&self, device_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!("/v1/devices/{}", segment(device_id));
        self.send(&key, Method::DELETE, &path, None).await
    }

    // ---------- Identity ----------

    pub fn my_fingerprint(&self) -> Result<Fingerprint> {
        let (enc, sign) = self.with_unlocked(|unlocked| {
            let bundle = unlocked.session.bundle();
            Ok((
                bundle.public_enc_key.clone(),
                bundle.public_sign_key.clone(),
            ))
        })?;
        fingerprint_of(&enc, &sign)
    }

    pub async fn lookup_account(&self, email: &str) -> Result<AccountLookup> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        self.lookup_locked(&key, email).await
    }

    async fn lookup_locked(&self, key: &AccountKey, email: &str) -> Result<AccountLookup> {
        let email = email.trim().to_lowercase();
        let path = format!("/v1/accounts/lookup?email={}", segment(&email));
        let found: ApiResult<AccountLookupResponse> =
            self.server(key, Method::GET, &path, None).await?;
        let record = match found {
            Err(error) if error.is(types::NOT_FOUND) => {
                return Err(ErrorCode::AccountNotFound.into());
            }
            other => other?,
        };
        let mut account = AccountLookup {
            fingerprint: fingerprint_of(&record.public_enc_key, &record.public_sign_key)?,
            key_record: core_record(record.key_record.as_ref()),
            account_id: record.account_id,
            email: record.email,
            public_enc_key: record.public_enc_key,
            public_sign_key: record.public_sign_key,
            key_log: None,
        };
        account.key_log = Some(self.check_account(key, (&account).into()).await?);
        Ok(account)
    }

    /// Remembers that the user compared this account's fingerprint with its owner.
    pub fn mark_verified(&self, account_id: &str, fingerprint: &Fingerprint) -> Result<()> {
        let key = self.account_key()?;
        self.store.update_notes(&key, |notes| {
            notes
                .verified
                .insert(account_id.into(), fingerprint.digits.clone());
        })?;
        self.sharing_changed();
        Ok(())
    }

    // ---------- Shared vaults ----------

    /// Creates a shared vault owned by this account, named by an encrypted record inside it.
    pub async fn create_vault(&self, name: &str) -> Result<VaultView> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let created = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .session
                .create_shared_vault(timestamp_ms(), &mut OsRng)?)
        })?;
        let body = serde_json::to_value(&created).expect("vaults serialize");
        let record: VaultRecord = self.create_once(&key, "/v1/vaults", body).await?;
        self.sync_locked().await?;
        let untrusted =
            self.with_unlocked(|unlocked| Ok(unlocked.untrusted.contains(&record.id)))?;
        require(!untrusted, ErrorCode::UntrustedVault)?;
        self.write_vault_name(&record.id, name).await?;
        self.sharing_changed();
        self.list_vaults()?
            .into_iter()
            .find(|vault| vault.id == record.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Creates under a client-chosen id, trying once more after a 500. Creating fails as a
    /// whole, so a retry can't make two; the SQLite server answers 500 when a concurrent write
    /// invalidates its snapshot mid-transaction (plan 15, History). The caller holds `io`.
    async fn create_once<T: serde::de::DeserializeOwned>(
        &self,
        key: &AccountKey,
        path: &str,
        body: Value,
    ) -> Result<T> {
        match self
            .server(key, Method::POST, path, Some(body.clone()))
            .await?
        {
            Err(error) if VaultError::from(error.clone()).code == ErrorCode::ServerError => {
                Ok(self.server(key, Method::POST, path, Some(body)).await??)
            }
            other => Ok(other?),
        }
    }

    pub async fn rename_vault(&self, vault_id: &str, name: &str) -> Result<()> {
        let _io = self.io.lock().await;
        self.write_vault_name(vault_id, name).await?;
        self.sharing_changed();
        Ok(())
    }

    /// The name lives in the vault as an encrypted record every member can read; the core keeps
    /// its unknown type as it is, so other clients round-trip it. The caller holds `io`.
    async fn write_vault_name(&self, vault_id: &str, name: &str) -> Result<()> {
        let title = match name.trim() {
            "" => default_vault_name(VaultType::Shared),
            name => name,
        };
        let existing = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .cache
                .items
                .iter()
                .filter(|record| record.vault_id == vault_id && record.deleted_at.is_none())
                .filter_map(|record| decrypt(&unlocked.session, record).ok())
                .filter(Item::is_vault_info)
                .max_by_key(|item| item.revision))
        })?;
        let draft = match existing {
            Some(item) => {
                let mut overview = item.overview;
                overview["title"] = Value::String(title.into());
                ItemDraft {
                    id: Some(item.id),
                    vault_id: vault_id.into(),
                    revision: Some(item.revision),
                    overview,
                    details: item.details,
                }
            }
            None => ItemDraft {
                id: None,
                vault_id: vault_id.into(),
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": VAULT_INFO_TYPE, "title": title }),
                details: json!({ "schemaVersion": 1 }),
            },
        };
        self.save_locked(draft).await?;
        Ok(())
    }

    /// The vault's members, with fingerprints computed here.
    pub async fn list_members(&self, vault_id: &str) -> Result<Vec<VaultMember>> {
        let key = self.account_key()?;
        let me = self.account_id()?;
        let _io = self.io.lock().await;
        let members = self.members(&key, vault_id).await?;
        let verified = self.store.load_notes(&key)?.verified;
        let mut listed = Vec::with_capacity(members.len());
        for member in members {
            let fingerprint = fingerprint_of(&member.public_enc_key, &member.public_sign_key)?;
            let is_you = member.account_id == me;
            let key_log = if is_you {
                None
            } else {
                let record = core_record(member.key_record.as_ref());
                Some(
                    self.check_account(&key, member_keys(&member, record.as_ref()))
                        .await?,
                )
            };
            listed.push(VaultMember {
                verified: is_you || verified.get(&member.account_id) == Some(&fingerprint.digits),
                key_log,
                is_you,
                fingerprint,
                name: member.email.clone(),
                email: member.email,
                role: member.role,
                account_id: member.account_id,
                added_at: member.added_at,
            });
        }
        Ok(listed)
    }

    /// The caller holds `io`.
    async fn members(&self, key: &AccountKey, vault_id: &str) -> Result<Vec<MemberRecord>> {
        let path = format!("/v1/vaults/{}/members", segment(vault_id));
        let response: MembersResponse = self.server(key, Method::GET, &path, None).await??;
        Ok(response.members)
    }

    /// Invites `account` (from `lookup_account`, after the user compared its fingerprint).
    pub async fn add_member(
        &self,
        vault_id: &str,
        account: &AccountLookup,
        role: VaultRole,
    ) -> Result<()> {
        check_fingerprint(account)?;
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        self.require_account(&key, account.into()).await?;
        let recipient = recipient(account.into(), core_role(role))?;
        let path = format!("/v1/vaults/{}/members", segment(vault_id));
        self.send_grant(&key, vault_id, &recipient, &path, &account.email)
            .await?;
        self.sharing_changed();
        Ok(())
    }

    /// A new grant with the new role replaces the old one.
    pub async fn change_role(
        &self,
        vault_id: &str,
        account_id: &str,
        role: VaultRole,
    ) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let member = self
            .members(&key, vault_id)
            .await?
            .into_iter()
            .find(|member| member.account_id == account_id)
            .ok_or(ErrorCode::NotFound)?;
        let record = core_record(member.key_record.as_ref());
        let offered = member_keys(&member, record.as_ref());
        if account_id != self.account_id()? {
            self.require_account(&key, offered).await?;
        }
        let recipient = recipient(offered, core_role(role))?;
        let path = format!("/v1/vaults/{}/members", segment(vault_id));
        self.send_grant(&key, vault_id, &recipient, &path, &member.email)
            .await?;
        self.sharing_changed();
        Ok(())
    }

    /// Removes the member, then gives the vault a new key so what they kept stops working.
    pub async fn remove_member(&self, vault_id: &str, account_id: &str) -> Result<()> {
        if account_id == self.account_id()? {
            return self.leave_vault(vault_id).await;
        }
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!(
            "/v1/vaults/{}/members/{}",
            segment(vault_id),
            segment(account_id)
        );
        self.send(&key, Method::DELETE, &path, None)
            .await
            .map_err(not_allowed)?;
        self.sharing_changed();
        self.rotate(&key, vault_id, Vec::new()).await
    }

    pub async fn leave_vault(&self, vault_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let me = self.account_id()?;
        let _io = self.io.lock().await;
        let path = format!("/v1/vaults/{}/members/{}", segment(vault_id), segment(&me));
        self.send(&key, Method::DELETE, &path, None)
            .await
            .map_err(not_allowed)?;
        self.sync_locked().await?;
        self.sharing_changed();
        Ok(())
    }

    /// A new key for a vault, on demand. A family vault's pending invites come along, as when a
    /// member leaves; a personal vault's key is wrapped by the account key, with no grants.
    pub async fn rotate_vault_key(&self, vault_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let vault_type = self.with_unlocked(|unlocked| {
            let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
            require(
                !unlocked.untrusted.contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            require(
                matches!(vault.role, VaultRole::Owner | VaultRole::Manage),
                ErrorCode::NotAllowed,
            )?;
            Ok(vault.vault_type)
        })?;
        match vault_type {
            VaultType::Personal => self.rotate_personal(&key, vault_id).await?,
            VaultType::Family => {
                let family = self.require_family(&key).await?;
                let invitees = self.invitees(&key, &family.invites).await?;
                self.rotate(&key, vault_id, invitees).await?;
            }
            VaultType::Shared => self.rotate(&key, vault_id, Vec::new()).await?,
        }
        self.sharing_changed();
        Ok(())
    }

    /// The caller holds `io`.
    async fn rotate_personal(&self, key: &AccountKey, vault_id: &str) -> Result<()> {
        for attempt in 1..=ROTATION_ATTEMPTS {
            self.sync_locked().await?;
            let (revision, rotation) = self.with_unlocked(|unlocked| {
                let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
                let items: Vec<ItemKey> = unlocked
                    .cache
                    .items
                    .iter()
                    .filter(|record| record.vault_id == vault_id)
                    .map(|record| ItemKey {
                        item_id: record.id.clone(),
                        encrypted_item_key: record.encrypted_item_key.clone(),
                    })
                    .collect();
                let rotation = unlocked
                    .session
                    .rotate_personal_vault_key(vault_id, &items, &mut OsRng)?;
                Ok((vault.revision, rotation))
            })?;
            let body = json!({
                "revision": revision,
                "keyId": rotation.key_id,
                "grants": [],
                "items": rotation.items,
                "wrappedVaultKey": rotation.wrapped_vault_key,
            });
            let path = format!("/v1/vaults/{}/rotate", segment(vault_id));
            match self
                .server::<Value>(key, Method::POST, &path, Some(body))
                .await?
            {
                Ok(_) => break,
                Err(error) if error.is(types::VAULT_CHANGED) && attempt < ROTATION_ATTEMPTS => {}
                Err(error) => return Err(not_allowed(error.into())),
            }
        }
        // The new wrapped key comes with the next sync, and with it the new key.
        self.sync_locked().await
    }

    /// The removed member still knows the old key, so everyone who stays gets a new one and
    /// every item key is re-wrapped under it; the item bodies don't change. `invitees` (a
    /// family's pending invites) get the new key in the same request; the server cancels any
    /// left out. The caller holds `io`.
    pub(super) async fn rotate(
        &self,
        key: &AccountKey,
        vault_id: &str,
        invitees: Vec<Recipient>,
    ) -> Result<()> {
        for attempt in 1..=ROTATION_ATTEMPTS {
            self.sync_locked().await?;
            let members = self.members(key, vault_id).await?;
            // A server too old to know them, or a failure here, leaves them with an old key
            // that no longer opens the vault: they fail closed, and the rotation goes on.
            let service = self
                .service_account_records(key, vault_id)
                .await
                .unwrap_or_default();
            let service = Self::service_recipients(&service)?;
            // A rotation seals to everyone again, so it's where a swapped key would do the most
            // harm.
            let me = self.account_id()?;
            let mut recipients = Vec::with_capacity(members.len() + invitees.len());
            for member in &members {
                let record = core_record(member.key_record.as_ref());
                let offered = member_keys(member, record.as_ref());
                if member.account_id != me {
                    self.require_account(key, offered).await?;
                }
                recipients.push(recipient(offered, core_role(member.role))?);
            }
            recipients.extend(invitees.iter().cloned());
            recipients.extend(service.iter().cloned());
            let (revision, rotation) = self.with_unlocked(|unlocked| {
                let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
                let items: Vec<ItemKey> = unlocked
                    .cache
                    .items
                    .iter()
                    .filter(|record| record.vault_id == vault_id)
                    .map(|record| ItemKey {
                        item_id: record.id.clone(),
                        encrypted_item_key: record.encrypted_item_key.clone(),
                    })
                    .collect();
                let rotation = unlocked.session.rotate_vault_key(
                    vault_id,
                    &recipients,
                    &items,
                    timestamp_ms(),
                    &mut OsRng,
                )?;
                Ok((vault.revision, rotation))
            })?;
            let mut grants = rotation.grants;
            let mut invites = grants.split_off(members.len());
            let service_grants = invites.split_off(invitees.len());
            let body = json!({
                "revision": revision,
                "keyId": rotation.key_id,
                "grants": grants,
                "items": rotation.items,
                "invites": invites,
                "serviceGrants": service_grants,
            });
            let path = format!("/v1/vaults/{}/rotate", segment(vault_id));
            match self
                .server::<Value>(key, Method::POST, &path, Some(body))
                .await?
            {
                Ok(_) => break,
                Err(error) if error.is(types::VAULT_CHANGED) && attempt < ROTATION_ATTEMPTS => {}
                Err(error) => return Err(not_allowed(error.into())),
            }
        }
        // The new grant comes with the next sync, and with it the new key.
        self.sync_locked().await
    }

    /// Seals the vault's current key to `recipient` and sends it to `path`: synced first, so a
    /// key rotated elsewhere isn't handed out. The request names the key's id, so a rotation
    /// that lands first refuses it with `vault-key-changed`; then it syncs and seals once more.
    /// The caller holds `io`.
    async fn send_grant(
        &self,
        key: &AccountKey,
        vault_id: &str,
        recipient: &Recipient,
        path: &str,
        email: &str,
    ) -> Result<()> {
        for attempt in 1..=GRANT_ATTEMPTS {
            self.sync_locked().await?;
            let (grant, key_id) = self.with_unlocked(|unlocked| {
                let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
                require(
                    !unlocked.untrusted.contains(vault_id),
                    ErrorCode::UntrustedVault,
                )?;
                require(
                    matches!(vault.role, VaultRole::Owner | VaultRole::Manage),
                    ErrorCode::NotAllowed,
                )?;
                require(
                    recipient.role != Role::Owner || vault.role == VaultRole::Owner,
                    ErrorCode::NotAllowed,
                )?;
                let grant = unlocked.session.grant_vault(
                    vault_id,
                    recipient,
                    timestamp_ms(),
                    &mut OsRng,
                )?;
                Ok((grant, vault.key_id.clone()))
            })?;
            let body = json!({ "email": email, "grant": grant, "keyId": key_id });
            match self
                .server::<Value>(key, Method::POST, path, Some(body))
                .await?
            {
                Ok(_) => return Ok(()),
                Err(error) if error.is(types::VAULT_KEY_CHANGED) && attempt < GRANT_ATTEMPTS => {}
                Err(error) => return Err(not_allowed(error.into())),
            }
        }
        unreachable!("the last attempt returns")
    }

    /// Moves an item to another vault: a copy there, the original to the trash.
    pub async fn move_item(&self, item_id: &str, to_vault_id: &str) -> Result<Item> {
        let copy = self.copy_item(item_id, to_vault_id).await?;
        self.delete_item(item_id).await?;
        Ok(copy)
    }

    /// Files are bound to their item and its key, so the copy gets its own copies of them.
    pub async fn copy_item(&self, item_id: &str, to_vault_id: &str) -> Result<Item> {
        let item = self.get_item(item_id)?;
        require(!item.is_vault_info(), ErrorCode::NotFound)?;
        let mut overview = item.overview.clone();
        if let Some(fields) = overview.as_object_mut() {
            fields.remove("favorite");
            fields.remove("pinned");
        }
        let mut copy = self
            .save_item(ItemDraft {
                id: None,
                vault_id: to_vault_id.into(),
                revision: None,
                overview,
                details: item.details.clone(),
            })
            .await?;
        let files = item
            .details
            .get("attachments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for file in files {
            let text = |field: &str| file.get(field).and_then(Value::as_str).unwrap_or_default();
            let bytes = self.get_attachment(item_id, text("id")).await?;
            copy = self
                .add_attachment(&copy.id, text("name"), text("type"), bytes)
                .await?;
        }
        Ok(copy)
    }

    /// Names of shared vaults this account alone owns: deleting the account deletes them for
    /// every member.
    pub(super) async fn shared_vaults_owned(&self, key: &AccountKey) -> Result<Vec<String>> {
        let me = self.account_id()?;
        let owned: Vec<VaultView> = self
            .list_vaults()?
            .into_iter()
            .filter(|vault| {
                vault.vault_type != VaultType::Personal && vault.role == VaultRole::Owner
            })
            .collect();
        let _io = self.io.lock().await;
        let mut alone = Vec::new();
        for vault in owned {
            let members = self.members(key, &vault.id).await?;
            let other_owner = members
                .iter()
                .any(|member| member.role == VaultRole::Owner && member.account_id != me);
            if !other_owner {
                alone.push(vault.name);
            }
        }
        Ok(alone)
    }

    // ---------- Families ----------

    pub async fn get_family(&self) -> Result<FamilyState> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        self.family_locked(&key).await
    }

    /// The caller holds `io`.
    async fn family_locked(&self, key: &AccountKey) -> Result<FamilyState> {
        let me = self.account_id()?;
        let response: FamiliesResponse = self
            .server(key, Method::GET, "/v1/families", None)
            .await??;
        Ok(FamilyState {
            invitations: response.invitations,
            family: response.family.map(|family| Family {
                is_organiser: family.organiser_id == me,
                members: family
                    .members
                    .into_iter()
                    .map(|member| FamilyMember {
                        is_you: member.account_id == me,
                        member,
                    })
                    .collect(),
                invites: family.invites,
                id: family.id,
                vault_id: family.vault_id,
                organiser_id: family.organiser_id,
                max_members: family.max_members,
                created_at: family.created_at,
            }),
        })
    }

    /// The caller holds `io`.
    pub(super) async fn require_family(&self, key: &AccountKey) -> Result<Family> {
        self.family_locked(key)
            .await?
            .family
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Creates a family and its shared Family vault, organised by this account.
    pub async fn create_family(&self) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let vault = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .session
                .create_shared_vault(timestamp_ms(), &mut OsRng)?)
        })?;
        let body = json!({ "id": new_id(timestamp_ms(), &mut OsRng), "vault": vault });
        self.create_once::<Value>(&key, "/v1/families", body)
            .await?;
        self.sync_locked().await?;
        self.sharing_changed();
        Ok(())
    }

    /// Invites carry a `write` grant for the Family vault, which turns into membership on
    /// accepting.
    pub async fn invite_to_family(&self, account: &AccountLookup) -> Result<()> {
        check_fingerprint(account)?;
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let family = self.require_family(&key).await?;
        self.require_account(&key, account.into()).await?;
        let recipient = recipient(account.into(), Role::Write)?;
        let path = format!("/v1/families/{}/invites", segment(&family.id));
        self.send_grant(&key, &family.vault_id, &recipient, &path, &account.email)
            .await?;
        self.sharing_changed();
        Ok(())
    }

    pub async fn accept_family_invite(&self, family_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!("/v1/families/{}/invites/accept", segment(family_id));
        self.send(&key, Method::POST, &path, Some(json!({})))
            .await?;
        self.sync_locked().await?;
        self.sharing_changed();
        Ok(())
    }

    pub async fn decline_family_invite(&self, family_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let me = self.account_id()?;
        let _io = self.io.lock().await;
        let path = format!(
            "/v1/families/{}/invites/{}",
            segment(family_id),
            segment(&me)
        );
        self.send(&key, Method::DELETE, &path, None).await?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: cancels a pending invite.
    pub async fn cancel_family_invite(&self, account_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let family = self.require_family(&key).await?;
        let path = format!(
            "/v1/families/{}/invites/{}",
            segment(&family.id),
            segment(account_id)
        );
        self.send(&key, Method::DELETE, &path, None)
            .await
            .map_err(not_allowed)?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: removes a member, then rotates the Family vault key.
    pub async fn remove_family_member(&self, account_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let family = self.require_family(&key).await?;
        let path = format!(
            "/v1/families/{}/members/{}",
            segment(&family.id),
            segment(account_id)
        );
        self.send(&key, Method::DELETE, &path, None)
            .await
            .map_err(not_allowed)?;
        self.sharing_changed();
        let invitees = self.invitees(&key, &family.invites).await?;
        self.rotate(&key, &family.vault_id, invitees).await
    }

    /// Pending invites hold the Family vault key from before a rotation, which would open
    /// nothing, so the rotation seals the new key to each invitee too. An invitee whose account
    /// is gone, or whose keys no longer match the fingerprint the user verified, is left out:
    /// the server cancels that invite. The caller holds `io`.
    async fn invitees(&self, key: &AccountKey, invites: &[FamilyInvite]) -> Result<Vec<Recipient>> {
        let verified = self.store.load_notes(key)?.verified;
        let mut recipients = Vec::new();
        for invite in invites {
            let account = match self.lookup_locked(key, &invite.email).await {
                Ok(account) => account,
                Err(error) if error.code == ErrorCode::AccountNotFound => continue,
                Err(error) => return Err(error),
            };
            if account.account_id != invite.account_id
                || verified
                    .get(&account.account_id)
                    .is_some_and(|digits| *digits != account.fingerprint.digits)
                || account.key_log == Some(KeyCheck::Failed)
            {
                continue;
            }
            recipients.push(recipient((&account).into(), Role::Write)?);
        }
        Ok(recipients)
    }

    pub async fn leave_family(&self) -> Result<()> {
        let key = self.account_key()?;
        let me = self.account_id()?;
        let _io = self.io.lock().await;
        let family = self.require_family(&key).await?;
        let path = format!(
            "/v1/families/{}/members/{}",
            segment(&family.id),
            segment(&me)
        );
        self.send(&key, Method::DELETE, &path, None).await?;
        self.sync_locked().await?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: deletes the family and its Family vault for everyone.
    pub async fn delete_family(&self) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let family = self.require_family(&key).await?;
        let path = format!("/v1/families/{}", segment(&family.id));
        self.send(&key, Method::DELETE, &path, None)
            .await
            .map_err(not_allowed)?;
        self.sync_locked().await?;
        self.sharing_changed();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(segment("0192-ab_c.d~"), "0192-ab_c.d~");
        assert_eq!(segment("a@b.c"), "a%40b.c");
        assert_eq!(segment("../x y"), "..%2Fx%20y");
    }

    #[test]
    fn fingerprints_come_from_the_keys() {
        let enc = octapass_core::encoding::b64_encode(&[1u8; 32]);
        let sign = octapass_core::encoding::b64_encode(&[2u8; 32]);
        let found = fingerprint_of(&enc, &sign).unwrap();
        assert_eq!(found.digits.split(' ').count(), 6);
        assert_eq!(found.emoji.len(), 8);
        assert!(fingerprint_of("short", &sign).is_err());

        let mut account = AccountLookup {
            account_id: "a".into(),
            email: "a@example.com".into(),
            public_enc_key: enc,
            public_sign_key: sign.clone(),
            fingerprint: found,
            key_record: None,
            key_log: None,
        };
        check_fingerprint(&account).unwrap();
        // The server swapped the keys after the user compared the fingerprint.
        account.public_enc_key = octapass_core::encoding::b64_encode(&[3u8; 32]);
        assert_eq!(
            check_fingerprint(&account).unwrap_err().code,
            ErrorCode::UntrustedVault
        );
    }
}
