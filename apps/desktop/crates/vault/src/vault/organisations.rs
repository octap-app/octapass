//! Organisations (plan 03, "Organisations and single sign-on"), as the web vault runs them in
//! `packages/vault-client/src/remote/organisations.ts`, for the desktop app and the CLI. Nothing
//! here is a key: roles, groups, policies, SSO and SCIM live on the server, and a vault key reaches
//! someone only through a grant sealed in this process, after a person reviewed it.
//!
//! Applying access is the one step that seals: the list of who should get a vault comes from the
//! server, so each person's fingerprint is computed here, shown, and checked again against what
//! the person confirmed before anything is sealed. Anyone the server added since isn't sealed to.

use octapass_api::problem::types;
use octapass_api::{
    CreatedScimToken, OrgAccessResponse, OrgEvent, OrgEventsResponse, OrgGroupRecord,
    OrgGroupsResponse, OrgInviteRecord, OrgMemberRecord, OrgMembersResponse, OrgPolicies,
    OrgRecord, OrgRole, OrgSamlRequest, OrgScimResponse, OrgSsoRecord, OrgSsoRequest,
    OrgSsoTestResponse, OrgVaultRecord, OrgVaultsResponse, OrgsResponse, ReauthPurpose,
    VaultRecord, VaultRole,
};
use octapass_core::account::new_id;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Vault;
use super::key_log::{Offered, core_record};
use super::sharing::{Fingerprint, core_role, fingerprint_of, recipient, segment, timestamp_ms};
use crate::api::Method;
use crate::error::{ErrorCode, Result, not_allowed};
use crate::model::{Vault as VaultView, require};
use crate::store::AccountKey;

/// A shared vault's name lives inside it, so an admin without the key sees part of its id.
const SHORT_ID: usize = 8;
/// Grants race key rotations; after this many `vault-key-changed` answers, give up.
const GRANT_ATTEMPTS: usize = 2;

/// A member as admins see them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgMember {
    #[serde(flatten)]
    pub record: OrgMemberRecord,
    pub is_you: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgMembers {
    pub members: Vec<OrgMember>,
    pub invites: Vec<OrgInviteRecord>,
}

/// An organisation vault, named if this account can open it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgVault {
    #[serde(flatten)]
    pub record: OrgVaultRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub short_id: String,
}

/// Someone a vault's key would be sealed to, with a fingerprint computed here.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgAccessGrant {
    pub account_id: String,
    pub email: String,
    pub role: VaultRole,
    /// Replaces a grant with a lower role.
    pub upgrade: bool,
    pub fingerprint: Fingerprint,
    /// The fingerprint matches one verified on this device.
    pub verified: bool,
    /// The fingerprint differs from one verified on this device: applying refuses it.
    pub key_changed: bool,
}

/// What a vault waits for from a key holder.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgAccessReview {
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_name: Option<String>,
    pub short_id: String,
    /// This account holds the key and may manage the vault.
    pub can_apply: bool,
    /// Someone lost access: the key should be rotated.
    pub rotate: bool,
    pub grants: Vec<OrgAccessGrant>,
}

/// A person the user confirmed, with the fingerprint that was on screen.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmedGrant {
    pub account_id: String,
    pub fingerprint: Fingerprint,
}

fn short_id(id: &str) -> String {
    let start = id.len().saturating_sub(SHORT_ID);
    id.get(start..).unwrap_or(id).to_owned()
}

impl Vault {
    /// A call whose answer is read. 403 means the role doesn't allow it. The caller holds `io`.
    async fn org_call<T: serde::de::DeserializeOwned>(
        &self,
        key: &AccountKey,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        self.server::<T>(key, method, path, body)
            .await?
            .map_err(|error| not_allowed(error.into()))
    }

    /// A call whose answer is empty (`204`). The caller holds `io`.
    async fn org_send(
        &self,
        key: &AccountKey,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<()> {
        match self.server::<Value>(key, method, path, body).await? {
            Ok(_) => Ok(()),
            Err(error) => Err(not_allowed(error.into())),
        }
    }

    /// The signed-in account's organisation id. The caller holds `io`.
    async fn org_id(&self, key: &AccountKey) -> Result<String> {
        let state: OrgsResponse = self.org_call(key, Method::GET, "/v1/orgs", None).await?;
        state
            .organisation
            .map(|org| org.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// `/v1/orgs/{id}` plus `rest`. The caller holds `io`.
    async fn org_path(&self, key: &AccountKey, rest: &str) -> Result<String> {
        Ok(format!(
            "/v1/orgs/{}{rest}",
            segment(&self.org_id(key).await?)
        ))
    }

    fn changed_orgs(&self) {
        self.sharing_changed();
    }

    // ---------- The organisation ----------

    pub async fn get_organisation(&self) -> Result<OrgsResponse> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        self.org_call(&key, Method::GET, "/v1/orgs", None).await
    }

    pub async fn create_organisation(&self, name: &str) -> Result<OrgRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let body = json!({ "id": new_id(timestamp_ms(), &mut OsRng), "name": name.trim() });
        let created = self
            .org_call(&key, Method::POST, "/v1/orgs", Some(body))
            .await?;
        self.changed_orgs();
        Ok(created)
    }

    pub async fn rename_organisation(&self, name: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "").await?;
        let body = json!({ "name": name.trim() });
        self.org_send(&key, Method::PATCH, &path, Some(body))
            .await?;
        self.changed_orgs();
        Ok(())
    }

    /// Deletes the organisation and all its vaults. Asks for the master password.
    pub async fn delete_organisation(
        &self,
        password: Zeroizing<String>,
        confirm_name: &str,
    ) -> Result<()> {
        let account = self.unlocked_account()?;
        let key = account.key.clone();
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "").await?;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::Organisation)
            .await?;
        self.reauthed(
            &key,
            Method::DELETE,
            &path,
            &reauth_token,
            Some(json!({ "confirmName": confirm_name })),
        )
        .await?;
        self.sync_locked().await?;
        self.changed_orgs();
        Ok(())
    }

    /// A call with a reauth token. The caller holds `io`.
    async fn reauthed(
        &self,
        key: &AccountKey,
        method: Method,
        path: &str,
        reauth_token: &str,
        body: Option<Value>,
    ) -> Result<()> {
        let result = self
            .authed(key, |api, token| {
                let (method, body, reauth) =
                    (method.clone(), body.clone(), reauth_token.to_owned());
                async move {
                    api.call_reauthed::<Value>(method, path, &token, &reauth, body.as_ref())
                        .await
                }
            })
            .await?;
        result
            .map(|_| ())
            .map_err(|error| not_allowed(error.into()))
    }

    pub async fn accept_org_invite(&self, org_id: &str, invite_id: &str) -> Result<OrgRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!(
            "/v1/orgs/{}/invites/{}/accept",
            segment(org_id),
            segment(invite_id)
        );
        let joined = self.org_call(&key, Method::POST, &path, None).await?;
        self.sync_locked().await?;
        self.changed_orgs();
        Ok(joined)
    }

    pub async fn decline_org_invite(&self, org_id: &str, invite_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!(
            "/v1/orgs/{}/invites/{}",
            segment(org_id),
            segment(invite_id)
        );
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Members and invites ----------

    pub async fn list_org_members(&self) -> Result<OrgMembers> {
        let key = self.account_key()?;
        let me = self.account_id()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/members").await?;
        let listed: OrgMembersResponse = self.org_call(&key, Method::GET, &path, None).await?;
        Ok(OrgMembers {
            members: listed
                .members
                .into_iter()
                .map(|record| OrgMember {
                    is_you: record.account_id == me,
                    record,
                })
                .collect(),
            invites: listed.invites,
        })
    }

    pub async fn invite_org_member(&self, email: &str, role: OrgRole) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/invites").await?;
        let body = json!({ "email": email.trim().to_lowercase(), "role": role });
        self.org_send(&key, Method::POST, &path, Some(body)).await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn cancel_org_invite(&self, invite_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/invites/{}", segment(invite_id)))
            .await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn set_org_member_role(&self, account_id: &str, role: OrgRole) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/members/{}", segment(account_id)))
            .await?;
        self.org_send(&key, Method::PATCH, &path, Some(json!({ "role": role })))
            .await?;
        self.changed_orgs();
        Ok(())
    }

    /// Fails with `orgVaultOrphaned` unless `orphan_vaults` says to go ahead.
    pub async fn remove_org_member(&self, account_id: &str, orphan_vaults: bool) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(
                &key,
                &format!(
                    "/members/{}?orphanVaults={orphan_vaults}",
                    segment(account_id)
                ),
            )
            .await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn leave_organisation(&self, orphan_vaults: bool) -> Result<()> {
        let me = self.account_id()?;
        self.remove_org_member(&me, orphan_vaults).await?;
        let _io = self.io.lock().await;
        self.sync_locked().await
    }

    // ---------- Groups ----------

    pub async fn list_org_groups(&self) -> Result<Vec<OrgGroupRecord>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/groups").await?;
        let listed: OrgGroupsResponse = self.org_call(&key, Method::GET, &path, None).await?;
        Ok(listed.groups)
    }

    pub async fn create_org_group(&self, name: &str) -> Result<OrgGroupRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/groups").await?;
        let body = json!({ "id": new_id(timestamp_ms(), &mut OsRng), "name": name.trim() });
        let group = self.org_call(&key, Method::POST, &path, Some(body)).await?;
        self.changed_orgs();
        Ok(group)
    }

    pub async fn rename_org_group(&self, group_id: &str, name: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/groups/{}", segment(group_id)))
            .await?;
        self.org_send(
            &key,
            Method::PATCH,
            &path,
            Some(json!({ "name": name.trim() })),
        )
        .await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn delete_org_group(&self, group_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/groups/{}", segment(group_id)))
            .await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn add_org_group_member(&self, group_id: &str, account_id: &str) -> Result<()> {
        self.group_member(Method::PUT, group_id, account_id).await
    }

    pub async fn remove_org_group_member(&self, group_id: &str, account_id: &str) -> Result<()> {
        self.group_member(Method::DELETE, group_id, account_id)
            .await
    }

    async fn group_member(&self, method: Method, group_id: &str, account_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let rest = format!(
            "/groups/{}/members/{}",
            segment(group_id),
            segment(account_id)
        );
        let path = self.org_path(&key, &rest).await?;
        self.org_send(&key, method, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Vaults ----------

    fn vault_names(&self) -> Result<std::collections::HashMap<String, String>> {
        Ok(self
            .list_vaults()?
            .into_iter()
            .map(|vault: VaultView| (vault.id, vault.name))
            .collect())
    }

    /// Vaults this account can open show their names; the rest show part of their id.
    pub async fn list_org_vaults(&self) -> Result<Vec<OrgVault>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/vaults").await?;
        let listed: OrgVaultsResponse = self.org_call(&key, Method::GET, &path, None).await?;
        let names = self.vault_names()?;
        Ok(listed
            .vaults
            .into_iter()
            .map(|record| OrgVault {
                name: names.get(&record.id).cloned(),
                short_id: short_id(&record.id),
                record,
            })
            .collect())
    }

    /// A shared vault of the organisation, owned by this account and named inside it.
    pub async fn create_org_vault(&self, name: &str) -> Result<VaultView> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/vaults").await?;
        let created = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .session
                .create_shared_vault(timestamp_ms(), &mut OsRng)?)
        })?;
        let body = serde_json::to_value(&created).expect("vaults serialize");
        let record: VaultRecord = self
            .create_once(&key, &path, body)
            .await
            .map_err(not_allowed)?;
        self.sync_locked().await?;
        let untrusted =
            self.with_unlocked(|unlocked| Ok(unlocked.untrusted.contains(&record.id)))?;
        require(!untrusted, ErrorCode::UntrustedVault)?;
        self.write_vault_name(&record.id, name).await?;
        self.changed_orgs();
        self.list_vaults()?
            .into_iter()
            .find(|vault| vault.id == record.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Needs no key: it's how an organisation clears a vault nobody can open. Asks for the
    /// master password.
    pub async fn delete_org_vault(
        &self,
        password: Zeroizing<String>,
        vault_id: &str,
    ) -> Result<()> {
        let account = self.unlocked_account()?;
        let key = account.key.clone();
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/vaults/{}", segment(vault_id)))
            .await?;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::Organisation)
            .await?;
        self.reauthed(&key, Method::DELETE, &path, &reauth_token, None)
            .await?;
        self.sync_locked().await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn link_org_vault_group(
        &self,
        vault_id: &str,
        group_id: &str,
        role: VaultRole,
    ) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let rest = format!("/vaults/{}/groups/{}", segment(vault_id), segment(group_id));
        let path = self.org_path(&key, &rest).await?;
        self.org_send(&key, Method::PUT, &path, Some(json!({ "role": role })))
            .await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn unlink_org_vault_group(&self, vault_id: &str, group_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let rest = format!("/vaults/{}/groups/{}", segment(vault_id), segment(group_id));
        let path = self.org_path(&key, &rest).await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Access: the reviewed step ----------

    fn reviewed(
        grant: &octapass_api::OrgPendingGrant,
        verified: &std::collections::BTreeMap<String, String>,
    ) -> Result<OrgAccessGrant> {
        let fingerprint = fingerprint_of(&grant.public_enc_key, &grant.public_sign_key)?;
        let known = verified.get(&grant.account_id);
        Ok(OrgAccessGrant {
            account_id: grant.account_id.clone(),
            email: grant.email.clone(),
            role: grant.role,
            upgrade: grant.upgrade,
            verified: known == Some(&fingerprint.digits),
            key_changed: known.is_some_and(|known| *known != fingerprint.digits),
            fingerprint,
        })
    }

    /// What vaults are waiting for from a key holder, for a person to review. The list comes
    /// from the server; the fingerprints don't.
    pub async fn org_access(&self) -> Result<Vec<OrgAccessReview>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        self.sync_locked().await?;
        let path = self.org_path(&key, "/access").await?;
        let access: OrgAccessResponse = self.org_call(&key, Method::GET, &path, None).await?;
        let verified = self.store.load_notes(&key)?.verified;
        let names = self.vault_names()?;
        access
            .vaults
            .into_iter()
            .map(|vault| {
                Ok(OrgAccessReview {
                    vault_name: names.get(&vault.vault_id).cloned(),
                    short_id: short_id(&vault.vault_id),
                    can_apply: vault.can_apply,
                    rotate: vault.rotate,
                    grants: vault
                        .grants
                        .iter()
                        .map(|grant| Self::reviewed(grant, &verified))
                        .collect::<Result<_>>()?,
                    vault_id: vault.vault_id,
                })
            })
            .collect()
    }

    /// Seals the vault to exactly the people a person confirmed. Each is checked against the plan
    /// as the server says it now: anyone whose keys differ from the fingerprint that was on
    /// screen, or from one verified earlier on this device, is refused rather than sealed to, and
    /// so is anyone the key log contradicts. Anyone the server added since isn't sealed to at all.
    /// Returns how many grants were stored.
    pub async fn apply_org_access(
        &self,
        vault_id: &str,
        confirmed: &[ConfirmedGrant],
    ) -> Result<usize> {
        if confirmed.is_empty() {
            return Ok(0);
        }
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let org_path = self.org_path(&key, "").await?;
        for attempt in 1..=GRANT_ATTEMPTS {
            self.sync_locked().await?;
            let key_id = self.with_unlocked(|unlocked| {
                let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
                require(
                    !unlocked.untrusted.contains(vault_id),
                    ErrorCode::UntrustedVault,
                )?;
                vault
                    .key_id
                    .clone()
                    .ok_or_else(|| ErrorCode::NotFound.into())
            })?;
            let access: OrgAccessResponse = self
                .org_call(&key, Method::GET, &format!("{org_path}/access"), None)
                .await?;
            let plan = access
                .vaults
                .into_iter()
                .find(|plan| plan.vault_id == vault_id)
                .filter(|plan| plan.can_apply)
                .ok_or(ErrorCode::NotAllowed)?;
            let verified = self.store.load_notes(&key)?.verified;
            let mut grants = Vec::new();
            for wanted in confirmed {
                let Some(pending) = plan
                    .grants
                    .iter()
                    .find(|grant| grant.account_id == wanted.account_id)
                else {
                    continue;
                };
                let actual = Self::reviewed(pending, &verified)?;
                require(
                    actual.fingerprint.digits == wanted.fingerprint.digits && !actual.key_changed,
                    ErrorCode::UntrustedVault,
                )?;
                // As for any share: the keys must not contradict the key log, and a valid record
                // makes the grant hybrid (plan 03).
                let record = core_record(pending.key_record.as_ref());
                let offered = Offered {
                    account_id: &pending.account_id,
                    email: &pending.email,
                    public_enc_key: &pending.public_enc_key,
                    public_sign_key: &pending.public_sign_key,
                    record: record.as_ref(),
                };
                self.require_account(&key, offered).await?;
                let recipient = recipient(offered, core_role(pending.role))?;
                let grant = self.with_unlocked(|unlocked| {
                    Ok(unlocked.session.grant_vault(
                        vault_id,
                        &recipient,
                        timestamp_ms(),
                        &mut OsRng,
                    )?)
                })?;
                grants.push(serde_json::to_value(grant).expect("grants serialize"));
            }
            if grants.is_empty() {
                return Ok(0);
            }
            let count = grants.len();
            let path = format!("{org_path}/vaults/{}/grants", segment(vault_id));
            let body = json!({ "keyId": key_id, "grants": grants });
            match self
                .server::<Value>(&key, Method::POST, &path, Some(body))
                .await?
            {
                Ok(_) => {
                    self.sync_locked().await?;
                    self.changed_orgs();
                    return Ok(count);
                }
                Err(error) if error.is(types::VAULT_KEY_CHANGED) && attempt < GRANT_ATTEMPTS => {}
                Err(error) => return Err(not_allowed(error.into())),
            }
        }
        unreachable!("the last attempt returns")
    }

    /// Rotates an organisation vault's key after someone lost access, as plan 15 describes.
    pub async fn rotate_org_vault(&self, vault_id: &str) -> Result<()> {
        self.rotate_vault_key(vault_id).await
    }

    // ---------- Policies, SSO, SCIM and the log ----------

    pub async fn set_org_policies(&self, policies: &OrgPolicies) -> Result<OrgPolicies> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/policies").await?;
        let body = serde_json::to_value(policies).expect("policies serialize");
        let saved = self.org_call(&key, Method::PUT, &path, Some(body)).await?;
        self.changed_orgs();
        Ok(saved)
    }

    pub async fn org_sso(&self) -> Result<OrgSsoRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/sso").await?;
        self.org_call(&key, Method::GET, &path, None).await
    }

    /// OpenID Connect settings. The server fetches the issuer's discovery document first.
    pub async fn save_org_sso(&self, request: &OrgSsoRequest) -> Result<OrgSsoRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/sso").await?;
        let body = serde_json::to_value(request).expect("requests serialize");
        let saved = self.org_call(&key, Method::PUT, &path, Some(body)).await?;
        self.changed_orgs();
        Ok(saved)
    }

    /// SAML settings: the provider's metadata, or its entity id, SSO URL and certificates.
    pub async fn save_org_saml(&self, request: &OrgSamlRequest) -> Result<OrgSsoRecord> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/sso/saml").await?;
        let body = serde_json::to_value(request).expect("requests serialize");
        let saved = self.org_call(&key, Method::PUT, &path, Some(body)).await?;
        self.changed_orgs();
        Ok(saved)
    }

    pub async fn remove_org_sso(&self) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/sso").await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    /// The URL of a test sign-in, to open in a browser.
    pub async fn test_org_sso(&self) -> Result<String> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/sso/test").await?;
        let started: OrgSsoTestResponse = self.org_call(&key, Method::POST, &path, None).await?;
        Ok(started.url)
    }

    pub async fn org_scim(&self) -> Result<OrgScimResponse> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/scim").await?;
        self.org_call(&key, Method::GET, &path, None).await
    }

    /// A new SCIM token. Its secret is in this answer only.
    pub async fn create_org_scim_token(&self, name: &str) -> Result<CreatedScimToken> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/scim/tokens").await?;
        let created = self
            .org_call(
                &key,
                Method::POST,
                &path,
                Some(json!({ "name": name.trim() })),
            )
            .await?;
        self.changed_orgs();
        Ok(created)
    }

    pub async fn revoke_org_scim_token(&self, token_id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self
            .org_path(&key, &format!("/scim/tokens/{}", segment(token_id)))
            .await?;
        self.org_send(&key, Method::DELETE, &path, None).await?;
        self.changed_orgs();
        Ok(())
    }

    pub async fn org_events(&self) -> Result<Vec<OrgEvent>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = self.org_path(&key, "/events").await?;
        let listed: OrgEventsResponse = self.org_call(&key, Method::GET, &path, None).await?;
        Ok(listed.events)
    }
}
