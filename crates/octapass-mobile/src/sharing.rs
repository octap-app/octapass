//! Shared vaults, their members and keys, and families (plan 15), as the web vault does them in
//! `packages/vault-client/src/remote/sharing.ts`. Every vault key a member gets is sealed to
//! their public key and signed on this phone; the server only stores grants and checks who may
//! give them.
//!
//! Shared and family vaults open in `octapass-ffi`'s `Session` once their grant verifies against
//! the granter's signing key: a server that swapped the wrapped key or the role would otherwise go
//! unnoticed. A vault whose grant doesn't verify is `untrusted`, and its items stay hidden.

use std::collections::HashSet;

use octapass_api::{
    AccountLookupResponse, FamiliesResponse, Grant, MembersResponse, RotateVaultRequest,
    VaultRecord, VaultRole as ApiRole, VaultType as ApiType,
};
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::Role;
use octapass_core::sharing::fingerprint;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use octapass_core::sharing::vault::ItemKey;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use octapass_ffi::key_log::{Account, KeyCheck, core_record};
use octapass_mobile_vault::model::{Item as StoredItem, ItemDraft as StoredDraft, vault_names};
use octapass_mobile_vault::vault::Access;
use rand_core::OsRng;
use serde_json::{Value, json};

use crate::api::{Method, Refused, Server, segment};
use crate::error::{ErrorCode, Result, VaultError, not_allowed, require};
use crate::items::{VAULT_INFO_TYPE, is_vault_info, type_of};
use crate::local;
use crate::vault::{Ctx, now_ms};

/// A rotation races other members' writes; after this many `vault-changed` answers, give up.
const ROTATION_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultType {
    Personal,
    Shared,
    Family,
}

/// Each role includes the ones below it: `read` views, `write` edits items, `manage` adds and
/// removes members, `owner` also manages owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum VaultRole {
    Read,
    Write,
    Manage,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub vault_type: VaultType,
    pub role: VaultRole,
    /// Its grant didn't verify: the key isn't used, so it shows no items. Warn instead.
    pub untrusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FingerprintEmoji {
    pub emoji: String,
    /// The word to say for it, in English.
    pub name: String,
}

/// An account's public keys in a form people compare out of band: in person, or on a call.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Fingerprint {
    /// Six groups of four digits.
    pub digits: String,
    pub emoji: Vec<FingerprintEmoji>,
}

/// Someone found by email, to share with. The fingerprint is computed here from the keys.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountLookup {
    pub account_id: String,
    pub email: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultMember {
    pub account_id: String,
    pub email: String,
    pub role: VaultRole,
    /// Computed on this phone from the member's public keys, never taken from the server.
    pub fingerprint: Fingerprint,
    /// The user compared this fingerprint with the member, and the keys haven't changed since.
    pub verified: bool,
    pub is_you: bool,
    pub added_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FamilyRole {
    Organiser,
    Member,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FamilyMember {
    pub account_id: String,
    pub email: String,
    pub role: FamilyRole,
    pub joined_at: String,
    pub is_you: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FamilyInvite {
    pub family_id: String,
    pub account_id: String,
    pub email: String,
    pub organiser_email: String,
    pub invited_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FamilyState {
    pub family: Option<Family>,
    /// Invitations this account received.
    pub invitations: Vec<FamilyInvite>,
}

impl From<ApiRole> for VaultRole {
    fn from(role: ApiRole) -> Self {
        match role {
            ApiRole::Read => Self::Read,
            ApiRole::Write => Self::Write,
            ApiRole::Manage => Self::Manage,
            ApiRole::Owner => Self::Owner,
        }
    }
}

impl VaultRole {
    pub(crate) fn core(self) -> Role {
        match self {
            Self::Read => Role::Read,
            Self::Write => Role::Write,
            Self::Manage => Role::Manage,
            Self::Owner => Role::Owner,
        }
    }
}

impl From<ApiType> for VaultType {
    fn from(vault_type: ApiType) -> Self {
        match vault_type {
            ApiType::Personal => Self::Personal,
            ApiType::Shared => Self::Shared,
            ApiType::Family => Self::Family,
        }
    }
}

impl From<octapass_api::FamilyInvite> for FamilyInvite {
    fn from(invite: octapass_api::FamilyInvite) -> Self {
        Self {
            family_id: invite.family_id,
            account_id: invite.account_id,
            email: invite.email,
            organiser_email: invite.organiser_email,
            invited_at: invite.invited_at,
        }
    }
}

pub(crate) fn default_vault_name(vault_type: VaultType) -> &'static str {
    match vault_type {
        VaultType::Personal => "Personal",
        VaultType::Shared => "Shared vault",
        VaultType::Family => "Family",
    }
}

fn public_key(text: &str) -> Result<[u8; 32]> {
    Ok(b64_decode_array(text)?)
}

pub(crate) fn fingerprint_of(public_enc_key: &str, public_sign_key: &str) -> Result<Fingerprint> {
    let fingerprint =
        fingerprint::fingerprint(&public_key(public_enc_key)?, &public_key(public_sign_key)?);
    Ok(Fingerprint {
        digits: fingerprint.digits,
        emoji: fingerprint
            .emoji
            .into_iter()
            .map(|e| FingerprintEmoji {
                emoji: e.emoji.into(),
                name: e.name.into(),
            })
            .collect(),
    })
}

fn api_grant(grant: SignedGrant) -> Result<Grant> {
    serde_json::from_value(serde_json::to_value(grant).expect("grants serialize"))
        .map_err(|_| VaultError::unexpected("grant"))
}

/// The shared and family vaults whose grant didn't verify. `octapass-ffi`'s `Session` opens
/// every vault in the store as it changes (the same code the phone app and the autofill
/// extensions use); this asks it which ones it refused.
#[derive(Default)]
pub(crate) struct SharedVaults;

impl SharedVaults {
    /// Opens shared and family vaults whose grant is new or changed (after an unlock, a sync, a
    /// rotation). Returns the untrusted ones.
    pub fn open(&self, access: &Access) -> HashSet<String> {
        access
            .session()
            .untrusted_vaults(access.store())
            .map(|untrusted| untrusted.into_iter().collect())
            .unwrap_or_default()
    }
}

/// The vaults with their names, the personal one first, then family, then shared by name.
pub(crate) fn list_vaults(ctx: &Ctx, access: &Access, items: &[StoredItem]) -> Vec<Vault> {
    let untrusted = ctx.shared.open(access);
    let names = vault_names(items);
    let mut vaults: Vec<Vault> = access
        .store()
        .vaults()
        .into_iter()
        .map(|record| {
            let vault_type = VaultType::from(record.vault_type);
            Vault {
                name: names
                    .get(&record.id)
                    .cloned()
                    .unwrap_or_else(|| default_vault_name(vault_type).into()),
                untrusted: untrusted.contains(&record.id),
                id: record.id,
                vault_type,
                role: record.role.into(),
            }
        })
        .collect();
    let rank = |v: &Vault| match v.vault_type {
        VaultType::Personal => 0,
        VaultType::Family => 1,
        VaultType::Shared => 2,
    };
    vaults.sort_by(|a, b| {
        rank(a)
            .cmp(&rank(b))
            .then_with(|| crate::list::compare_names(&a.name, &b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    vaults
}

fn vault_record(access: &Access, vault_id: &str) -> Result<VaultRecord> {
    access
        .store()
        .vaults()
        .into_iter()
        .find(|vault| vault.id == vault_id)
        .ok_or_else(|| ErrorCode::NotFound.into())
}

fn account_id(access: &Access) -> Result<String> {
    access
        .store()
        .account_id()
        .ok_or_else(|| VaultError::unexpected("the store has no account id"))
}

impl Ctx<'_> {
    fn server<'a>(&'a self, access: &'a Access<'a>) -> Server<'a> {
        Server {
            api: self.api,
            access,
        }
    }

    /// Pushes and pulls, then opens what the sync brought.
    pub(crate) fn sync_and_open(&self) -> Result<()> {
        self.vault.sync()?;
        self.shared.open(&self.vault.access()?);
        Ok(())
    }

    // ---------- Identity ----------

    pub fn my_fingerprint(&self) -> Result<Fingerprint> {
        let access = self.vault.access()?;
        let (enc, sign) = access.session().with_keys(|core| {
            let bundle = core.bundle();
            Ok((
                bundle.public_enc_key.clone(),
                bundle.public_sign_key.clone(),
            ))
        })?;
        fingerprint_of(&enc, &sign)
    }

    pub fn lookup_account(&self, email: &str) -> Result<AccountLookup> {
        let access = self.vault.access()?;
        let email = email.trim().to_lowercase();
        let path = format!("v1/accounts/lookup?email={}", segment(&email));
        let record: AccountLookupResponse = self.server(&access).get(&path).map_err(|error| {
            if error.code() == ErrorCode::NotFound {
                ErrorCode::AccountNotFound.into()
            } else {
                error
            }
        })?;
        Ok(AccountLookup {
            fingerprint: fingerprint_of(&record.public_enc_key, &record.public_sign_key)?,
            account_id: record.account_id,
            email: record.email,
            public_enc_key: record.public_enc_key,
            public_sign_key: record.public_sign_key,
        })
    }

    /// Remembers that the user compared this account's fingerprint with its owner.
    pub fn mark_verified(&self, account_id: &str, fingerprint: &Fingerprint) -> Result<()> {
        let access = self.vault.access()?;
        local::update_notes(access.data_dir(), access.account_tag(), |notes| {
            notes
                .verified
                .insert(account_id.into(), fingerprint.digits.clone());
        })?;
        self.sharing_changed();
        Ok(())
    }

    /// The lookup's keys must be the ones whose fingerprint the user saw.
    fn check_fingerprint(account: &AccountLookup) -> Result<()> {
        let actual = fingerprint_of(&account.public_enc_key, &account.public_sign_key)?;
        require(
            actual.digits == account.fingerprint.digits,
            ErrorCode::UntrustedVault,
        )
    }

    // ---------- Shared vaults ----------

    pub fn create_vault(&self, name: &str) -> Result<Vault> {
        let access = self.vault.access()?;
        let created = access
            .session()
            .with_keys(|core| Ok(core.create_shared_vault(now_ms(), &mut OsRng)?))?;
        let body = json!({
            "id": created.id,
            "keyId": created.key_id,
            "grant": serde_json::to_value(&created.grant).expect("grants serialize"),
        });
        // Creating fails as a whole, so trying once more after a 500 (a SQLite server whose
        // snapshot a concurrent write invalidated) can't make two.
        let server = self.server(&access);
        let record: Result<VaultRecord> = server.post("v1/vaults", &body);
        let record = match record {
            Err(error) if error.code() == ErrorCode::ServerError => {
                server.post("v1/vaults", &body)?
            }
            other => other?,
        };
        drop(access);
        self.sync_and_open()?;
        let access = self.vault.access()?;
        require(
            !self.shared.open(&access).contains(&record.id),
            ErrorCode::UntrustedVault,
        )?;
        self.write_vault_name(&record.id, name)?;
        self.sharing_changed();
        let items = self.vault.all_items()?;
        list_vaults(self, &self.vault.access()?, &items)
            .into_iter()
            .find(|vault| vault.id == record.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    pub fn rename_vault(&self, vault_id: &str, name: &str) -> Result<()> {
        self.write_vault_name(vault_id, name)?;
        self.sharing_changed();
        Ok(())
    }

    /// The name lives in the vault as an encrypted record every member can read; the core keeps
    /// its unknown type as it is, so other clients round-trip it.
    fn write_vault_name(&self, vault_id: &str, name: &str) -> Result<()> {
        let title = match name.trim() {
            "" => default_vault_name(VaultType::Shared),
            name => name,
        };
        let existing = self
            .vault
            .all_items()?
            .into_iter()
            .filter(|item| {
                item.vault_id == vault_id && is_vault_info(item) && item.deleted_at.is_none()
            })
            .max_by_key(|item| item.revision);
        let draft = match existing {
            Some(item) => {
                let mut overview = item.overview.clone();
                overview["title"] = Value::String(title.into());
                StoredDraft {
                    id: Some(item.id),
                    vault_id: vault_id.into(),
                    revision: Some(item.revision),
                    overview,
                    details: item.details,
                }
            }
            None => StoredDraft {
                id: None,
                vault_id: vault_id.into(),
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": VAULT_INFO_TYPE, "title": title }),
                details: json!({ "schemaVersion": 1 }),
            },
        };
        self.vault.save_item(draft)?;
        Ok(())
    }

    pub fn list_members(&self, vault_id: &str) -> Result<Vec<VaultMember>> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        let response: MembersResponse = self
            .server(&access)
            .get(&format!("v1/vaults/{}/members", segment(vault_id)))?;
        let verified = local::load_notes(access.data_dir(), access.account_tag()).verified;
        response
            .members
            .into_iter()
            .map(|member| {
                let fingerprint = fingerprint_of(&member.public_enc_key, &member.public_sign_key)?;
                let is_you = member.account_id == me;
                Ok(VaultMember {
                    verified: is_you
                        || verified.get(&member.account_id) == Some(&fingerprint.digits),
                    is_you,
                    fingerprint,
                    account_id: member.account_id,
                    email: member.email,
                    role: member.role.into(),
                    added_at: member.added_at,
                })
            })
            .collect()
    }

    /// Invites `account` (from `lookupAccount`, after the user compared its fingerprint).
    pub fn add_member(
        &self,
        vault_id: &str,
        account: &AccountLookup,
        role: VaultRole,
    ) -> Result<()> {
        Self::check_fingerprint(account)?;
        let recipient = self.looked_up_recipient(account, role.core())?;
        let path = format!("v1/vaults/{}/members", segment(vault_id));
        self.send_grant(vault_id, &recipient, &path, &account.email)?;
        self.sharing_changed();
        Ok(())
    }

    /// A new grant with the new role replaces the old one.
    pub fn change_role(&self, vault_id: &str, account_id: &str, role: VaultRole) -> Result<()> {
        let member = self.member(vault_id, account_id)?;
        let recipient = self.checked_recipient(&self.vault.access()?, &member, role.core())?;
        let path = format!("v1/vaults/{}/members", segment(vault_id));
        self.send_grant(vault_id, &recipient, &path, &member.email)?;
        self.sharing_changed();
        Ok(())
    }

    /// Who gets a grant, after the key log has had its say. The hybrid box goes to accounts
    /// whose key record checks out against the offered keys.
    fn recipient_of(
        &self,
        access: &Access<'_>,
        keys: Account<'_>,
        role: Role,
    ) -> Result<Recipient> {
        if keys.account_id != account_id(access)? && access.check_account(keys)? == KeyCheck::Failed
        {
            return Err(ErrorCode::UntrustedVault.into());
        }
        let offered = OfferedKeys {
            account_id: keys.account_id,
            public_enc_key: keys.public_enc_key,
            public_sign_key: keys.public_sign_key,
        };
        Ok(Recipient {
            account_id: keys.account_id.to_owned(),
            public_enc_key: public_key(keys.public_enc_key)?,
            public_pq_key: KeyRecord::pq_key_of(keys.record, &offered)
                .map_err(|_| VaultError::from(ErrorCode::UntrustedVault))?,
            role,
        })
    }

    fn checked_recipient(
        &self,
        access: &Access<'_>,
        member: &octapass_api::MemberRecord,
        role: Role,
    ) -> Result<Recipient> {
        let record = core_record(member.key_record.as_ref());
        let keys = Account {
            account_id: &member.account_id,
            email: &member.email,
            public_enc_key: &member.public_enc_key,
            public_sign_key: &member.public_sign_key,
            record: record.as_ref(),
        };
        self.recipient_of(access, keys, role)
    }

    /// `AccountLookup` crosses to Swift and Kotlin and has no room for the key record, so it's
    /// fetched again here, and has to be about the keys the user saw.
    pub(crate) fn looked_up_recipient(
        &self,
        account: &AccountLookup,
        role: Role,
    ) -> Result<Recipient> {
        let access = self.vault.access()?;
        let path = format!("v1/accounts/lookup?email={}", segment(&account.email));
        let found: AccountLookupResponse = self.server(&access).get(&path)?;
        if found.account_id != account.account_id
            || found.public_enc_key != account.public_enc_key
            || found.public_sign_key != account.public_sign_key
        {
            return Err(ErrorCode::UntrustedVault.into());
        }
        let record = core_record(found.key_record.as_ref());
        let keys = Account {
            account_id: &found.account_id,
            email: &found.email,
            public_enc_key: &found.public_enc_key,
            public_sign_key: &found.public_sign_key,
            record: record.as_ref(),
        };
        self.recipient_of(&access, keys, role)
    }

    fn member(&self, vault_id: &str, account_id: &str) -> Result<octapass_api::MemberRecord> {
        let access = self.vault.access()?;
        let response: MembersResponse = self
            .server(&access)
            .get(&format!("v1/vaults/{}/members", segment(vault_id)))?;
        response
            .members
            .into_iter()
            .find(|member| member.account_id == account_id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Removes the member, then gives the vault a new key so what they kept stops working.
    pub fn remove_member(&self, vault_id: &str, account_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        if account_id == self::account_id(&access)? {
            drop(access);
            return self.leave_vault(vault_id);
        }
        self.server(&access)
            .delete(&format!(
                "v1/vaults/{}/members/{}",
                segment(vault_id),
                segment(account_id)
            ))
            .map_err(not_allowed)?;
        drop(access);
        self.sharing_changed();
        self.rotate(vault_id, Vec::new())
    }

    pub fn leave_vault(&self, vault_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        self.server(&access)
            .delete(&format!(
                "v1/vaults/{}/members/{}",
                segment(vault_id),
                segment(&me)
            ))
            .map_err(not_allowed)?;
        drop(access);
        self.sync_and_open()?;
        self.sharing_changed();
        Ok(())
    }

    /// A new key for a vault, on demand. A family vault's pending invites come along, as when a
    /// member leaves; a personal vault's key is wrapped by the account key, with no grants.
    pub fn rotate_vault_key(&self, vault_id: &str) -> Result<()> {
        let vault = {
            let access = self.vault.access()?;
            require(
                !self.shared.open(&access).contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            vault_record(&access, vault_id)?
        };
        require(
            matches!(
                vault.role,
                octapass_api::VaultRole::Owner | octapass_api::VaultRole::Manage
            ),
            ErrorCode::NotAllowed,
        )?;
        match vault.vault_type {
            octapass_api::VaultType::Personal => self.rotate_personal(vault_id)?,
            octapass_api::VaultType::Family => {
                let family = self.require_family()?;
                let invitees = self.invitees(&family.invites)?;
                self.rotate(vault_id, invitees)?;
            }
            octapass_api::VaultType::Shared => self.rotate(vault_id, Vec::new())?,
        }
        self.sharing_changed();
        Ok(())
    }

    fn rotate_personal(&self, vault_id: &str) -> Result<()> {
        for attempt in 1..=ROTATION_ATTEMPTS {
            self.sync_and_open()?;
            let access = self.vault.access()?;
            let vault = vault_record(&access, vault_id)?;
            let items: Vec<ItemKey> = access
                .store()
                .item_records()
                .into_iter()
                .filter(|record| record.vault_id == vault_id)
                .map(|record| ItemKey {
                    item_id: record.id,
                    encrypted_item_key: record.encrypted_item_key,
                })
                .collect();
            let rotation = access.session().with_keys(|core| {
                Ok(core.rotate_personal_vault_key(vault_id, &items, &mut OsRng)?)
            })?;
            let body = RotateVaultRequest {
                revision: vault.revision,
                key_id: rotation.key_id,
                grants: Vec::new(),
                service_grants: Vec::new(),
                items: rotation
                    .items
                    .into_iter()
                    .map(|item| octapass_api::ItemKeyUpdate {
                        item_id: item.item_id,
                        encrypted_item_key: item.encrypted_item_key,
                    })
                    .collect(),
                invites: Vec::new(),
                wrapped_vault_key: rotation.wrapped_vault_key,
            };
            let rotated: std::result::Result<Value, Refused> = self
                .server(&access)
                .call_unless(
                    Method::Post,
                    &format!("v1/vaults/{}/rotate", segment(vault_id)),
                    Some(&body),
                    "vault-changed",
                )
                .map_err(not_allowed)?;
            match rotated {
                Ok(_) => break,
                Err(Refused) if attempt < ROTATION_ATTEMPTS => continue,
                Err(Refused) => {
                    return Err(VaultError::new(
                        ErrorCode::ServerError,
                        "the vault kept changing during the key rotation",
                    ));
                }
            }
        }
        // The new wrapped key comes with the next sync, and with it the new key.
        self.sync_and_open()
    }

    /// The removed member still knows the old key, so everyone who stays gets a new one and every
    /// item key is re-wrapped under it; the item bodies don't change. `invitees` (a family's
    /// pending invites) get the new key in the same request; the server cancels any left out.
    fn rotate(&self, vault_id: &str, invitees: Vec<Recipient>) -> Result<()> {
        for attempt in 1..=ROTATION_ATTEMPTS {
            self.sync_and_open()?;
            let access = self.vault.access()?;
            let vault = vault_record(&access, vault_id)?;
            let server = self.server(&access);
            let members: MembersResponse =
                server.get(&format!("v1/vaults/{}/members", segment(vault_id)))?;
            // A rotation seals to everyone again, so it's where a swapped key would do the most
            // harm.
            let mut recipients = members
                .members
                .iter()
                .map(|member| {
                    self.checked_recipient(&access, member, VaultRole::from(member.role).core())
                })
                .collect::<Result<Vec<_>>>()?;
            recipients.extend(invitees.iter().cloned());
            let items: Vec<ItemKey> = access
                .store()
                .item_records()
                .into_iter()
                .filter(|record| record.vault_id == vault_id)
                .map(|record| ItemKey {
                    item_id: record.id,
                    encrypted_item_key: record.encrypted_item_key,
                })
                .collect();
            let rotation = access.session().with_keys(|core| {
                Ok(core.rotate_vault_key(vault_id, &recipients, &items, now_ms(), &mut OsRng)?)
            })?;
            let mut grants = rotation
                .grants
                .into_iter()
                .map(api_grant)
                .collect::<Result<Vec<_>>>()?;
            let invites = grants.split_off(members.members.len());
            let body = RotateVaultRequest {
                revision: vault.revision,
                key_id: rotation.key_id,
                grants,
                // The phone apps don't manage service accounts yet: any the vault has fail closed
                // (plan 03, "Service accounts") until the web vault or desktop app renews them.
                service_grants: Vec::new(),
                items: rotation
                    .items
                    .into_iter()
                    .map(|item| octapass_api::ItemKeyUpdate {
                        item_id: item.item_id,
                        encrypted_item_key: item.encrypted_item_key,
                    })
                    .collect(),
                invites,
                wrapped_vault_key: None,
            };
            let rotated: std::result::Result<Value, Refused> = server
                .call_unless(
                    Method::Post,
                    &format!("v1/vaults/{}/rotate", segment(vault_id)),
                    Some(&body),
                    "vault-changed",
                )
                .map_err(not_allowed)?;
            match rotated {
                Ok(_) => break,
                Err(Refused) if attempt < ROTATION_ATTEMPTS => continue,
                Err(Refused) => {
                    return Err(VaultError::new(
                        ErrorCode::ServerError,
                        "the vault kept changing during the key rotation",
                    ));
                }
            }
        }
        // The new grant comes with the next sync, and with it the new key.
        self.sync_and_open()
    }

    /// Seals the vault's current key to `recipient` and sends it to `path`: synced first, so a
    /// key rotated elsewhere isn't handed out. The request names the key's id, so a rotation
    /// that lands first refuses it with `vault-key-changed`; then it syncs and seals once more.
    fn send_grant(
        &self,
        vault_id: &str,
        recipient: &Recipient,
        path: &str,
        email: &str,
    ) -> Result<()> {
        for attempt in 1..=2 {
            self.sync_and_open()?;
            let access = self.vault.access()?;
            let vault = vault_record(&access, vault_id)?;
            require(
                !self.shared.open(&access).contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            require(
                matches!(vault.role, ApiRole::Owner | ApiRole::Manage),
                ErrorCode::NotAllowed,
            )?;
            require(
                recipient.role != Role::Owner || vault.role == ApiRole::Owner,
                ErrorCode::NotAllowed,
            )?;
            let grant = access.session().with_keys(|core| {
                Ok(core.grant_vault(vault_id, recipient, now_ms(), &mut OsRng)?)
            })?;
            let body = json!({
                "email": email,
                "grant": api_grant(grant)?,
                "keyId": vault.key_id,
            });
            let sent: std::result::Result<Value, Refused> = self
                .server(&access)
                .call_unless(Method::Post, path, Some(&body), "vault-key-changed")
                .map_err(not_allowed)?;
            match sent {
                Ok(_) => return Ok(()),
                Err(Refused) if attempt < 2 => continue,
                Err(Refused) => {
                    return Err(VaultError::new(
                        ErrorCode::ServerError,
                        "the vault key changed while sharing",
                    ));
                }
            }
        }
        unreachable!("the last attempt returns")
    }

    /// Moves an item to another vault: a copy there, the original to the trash.
    pub fn move_item(&self, item_id: &str, to_vault_id: &str) -> Result<StoredItem> {
        let copy = self.copy_item(item_id, to_vault_id)?;
        self.vault.delete_item(item_id)?;
        Ok(copy)
    }

    /// Files are bound to their item and its key, so the copy gets its own copies of them.
    pub fn copy_item(&self, item_id: &str, to_vault_id: &str) -> Result<StoredItem> {
        let item = self.vault.get_item(item_id)?;
        require(type_of(&item) != VAULT_INFO_TYPE, ErrorCode::NotFound)?;
        let mut overview = item.overview.clone();
        if let Some(fields) = overview.as_object_mut() {
            fields.remove("favorite");
            fields.remove("pinned");
        }
        let copy = self.vault.save_item(StoredDraft {
            id: None,
            vault_id: to_vault_id.into(),
            revision: None,
            overview,
            details: item.details.clone(),
        })?;
        let mut latest = copy;
        for file in crate::items::attachments(&item.details) {
            let bytes = zeroize::Zeroizing::new(self.vault.get_attachment(item_id, &file.id)?);
            latest = self
                .vault
                .add_attachment(&latest.id, &file.name, &file.media_type, &bytes)?;
        }
        Ok(latest)
    }

    // ---------- Families ----------

    pub fn get_family(&self) -> Result<FamilyState> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        let response: FamiliesResponse = self.server(&access).get("v1/families")?;
        Ok(FamilyState {
            invitations: response.invitations.into_iter().map(Into::into).collect(),
            family: response.family.map(|family| Family {
                is_organiser: family.organiser_id == me,
                members: family
                    .members
                    .into_iter()
                    .map(|member| FamilyMember {
                        is_you: member.account_id == me,
                        account_id: member.account_id,
                        email: member.email,
                        role: match member.role {
                            octapass_api::FamilyRole::Organiser => FamilyRole::Organiser,
                            octapass_api::FamilyRole::Member => FamilyRole::Member,
                        },
                        joined_at: member.joined_at,
                    })
                    .collect(),
                invites: family.invites.into_iter().map(Into::into).collect(),
                id: family.id,
                vault_id: family.vault_id,
                organiser_id: family.organiser_id,
                max_members: family.max_members,
                created_at: family.created_at,
            }),
        })
    }

    pub(crate) fn require_family(&self) -> Result<Family> {
        self.get_family()?
            .family
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Creates a family and its shared Family vault, organised by the user.
    pub fn create_family(&self) -> Result<()> {
        let access = self.vault.access()?;
        let id = octapass_core::account::new_id(now_ms(), &mut OsRng);
        let vault = access
            .session()
            .with_keys(|core| Ok(core.create_shared_vault(now_ms(), &mut OsRng)?))?;
        let body = json!({
            "id": id,
            "vault": {
                "id": vault.id,
                "keyId": vault.key_id,
                "grant": serde_json::to_value(&vault.grant).expect("grants serialize"),
            },
        });
        let server = self.server(&access);
        let created: Result<Value> = server.post("v1/families", &body);
        match created {
            Err(error) if error.code() == ErrorCode::ServerError => {
                server.post::<Value>("v1/families", &body)?;
            }
            other => {
                other?;
            }
        }
        drop(access);
        self.sync_and_open()?;
        self.sharing_changed();
        Ok(())
    }

    /// Invites carry a `write` grant for the Family vault, which turns into membership on
    /// accepting.
    pub fn invite_to_family(&self, account: &AccountLookup) -> Result<()> {
        Self::check_fingerprint(account)?;
        let family = self.require_family()?;
        let recipient = self.looked_up_recipient(account, Role::Write)?;
        let path = format!("v1/families/{}/invites", segment(&family.id));
        self.send_grant(&family.vault_id, &recipient, &path, &account.email)?;
        self.sharing_changed();
        Ok(())
    }

    pub fn accept_family_invite(&self, family_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        self.server(&access).post::<Value>(
            &format!("v1/families/{}/invites/accept", segment(family_id)),
            &json!({}),
        )?;
        drop(access);
        self.sync_and_open()?;
        self.sharing_changed();
        Ok(())
    }

    pub fn decline_family_invite(&self, family_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        self.server(&access).delete(&format!(
            "v1/families/{}/invites/{}",
            segment(family_id),
            segment(&me)
        ))?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: cancels a pending invite.
    pub fn cancel_family_invite(&self, account_id: &str) -> Result<()> {
        let family = self.require_family()?;
        let access = self.vault.access()?;
        self.server(&access)
            .delete(&format!(
                "v1/families/{}/invites/{}",
                segment(&family.id),
                segment(account_id)
            ))
            .map_err(not_allowed)?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: removes a member, then rotates the Family vault key.
    pub fn remove_family_member(&self, account_id: &str) -> Result<()> {
        let family = self.require_family()?;
        {
            let access = self.vault.access()?;
            self.server(&access)
                .delete(&format!(
                    "v1/families/{}/members/{}",
                    segment(&family.id),
                    segment(account_id)
                ))
                .map_err(not_allowed)?;
        }
        self.sharing_changed();
        let invitees = self.invitees(&family.invites)?;
        self.rotate(&family.vault_id, invitees)
    }

    /// Pending invites hold the Family vault key from before a rotation, which would open
    /// nothing, so the rotation seals the new key to each invitee too. An invitee whose account
    /// is gone, or whose keys no longer match the fingerprint this phone verified, is left out:
    /// the server cancels that invite.
    fn invitees(&self, invites: &[FamilyInvite]) -> Result<Vec<Recipient>> {
        let verified = {
            let access = self.vault.access()?;
            local::load_notes(access.data_dir(), access.account_tag()).verified
        };
        let mut recipients = Vec::new();
        for invite in invites {
            let account = match self.lookup_account(&invite.email) {
                Ok(account) => account,
                Err(error) if error.code() == ErrorCode::AccountNotFound => continue,
                Err(error) => return Err(error),
            };
            if account.account_id != invite.account_id {
                continue;
            }
            if verified
                .get(&account.account_id)
                .is_some_and(|digits| *digits != account.fingerprint.digits)
            {
                continue;
            }
            // A check that fails leaves the invitee out, which cancels the invite.
            if let Ok(recipient) = self.looked_up_recipient(&account, Role::Write) {
                recipients.push(recipient);
            }
        }
        Ok(recipients)
    }

    pub fn leave_family(&self) -> Result<()> {
        let family = self.require_family()?;
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        self.server(&access).delete(&format!(
            "v1/families/{}/members/{}",
            segment(&family.id),
            segment(&me)
        ))?;
        drop(access);
        self.sync_and_open()?;
        self.sharing_changed();
        Ok(())
    }

    /// Organiser: deletes the family and its Family vault for everyone.
    pub fn delete_family(&self) -> Result<()> {
        let family = self.require_family()?;
        let access = self.vault.access()?;
        self.server(&access)
            .delete(&format!("v1/families/{}", segment(&family.id)))
            .map_err(not_allowed)?;
        drop(access);
        self.sync_and_open()?;
        self.sharing_changed();
        Ok(())
    }

    /// Names of shared vaults this user alone owns: deleting the account deletes them for every
    /// member.
    pub fn shared_vaults_owned(&self, vaults: &[Vault]) -> Result<Vec<String>> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        let server = self.server(&access);
        let mut owned = Vec::new();
        for vault in vaults
            .iter()
            .filter(|v| v.vault_type != VaultType::Personal && v.role == VaultRole::Owner)
        {
            let members: MembersResponse =
                server.get(&format!("v1/vaults/{}/members", segment(&vault.id)))?;
            let other_owner = members
                .members
                .iter()
                .any(|m| m.role == ApiRole::Owner && m.account_id != me);
            if !other_owner {
                owned.push(vault.name.clone());
            }
        }
        Ok(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_newest_name_record_names_a_vault() {
        let item = |revision, vault: &str, title: &str, deleted: bool| StoredItem {
            id: format!("{vault}-{revision}"),
            vault_id: vault.into(),
            revision,
            created_at: String::new(),
            updated_at: String::new(),
            deleted_at: deleted.then(|| "t".into()),
            overview: json!({ "type": VAULT_INFO_TYPE, "title": title }),
            details: json!({}),
        };
        let names = vault_names(&[
            item(1, "a", "Old", false),
            item(3, "a", "New", false),
            item(5, "a", "Gone", true),
            item(1, "b", "", false),
        ]);
        assert_eq!(names.get("a").map(String::as_str), Some("New"));
        assert!(!names.contains_key("b"));
    }

    #[test]
    fn fingerprints_come_from_the_keys() {
        let enc = octapass_core::encoding::b64_encode(&[1u8; 32]);
        let sign = octapass_core::encoding::b64_encode(&[2u8; 32]);
        let fingerprint = fingerprint_of(&enc, &sign).unwrap();
        assert_eq!(fingerprint.digits.split(' ').count(), 6);
        assert_eq!(fingerprint.emoji.len(), 8);
        assert!(fingerprint_of("short", &sign).is_err());
    }
}
