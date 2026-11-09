//! Organisations (plan 03, "Organisations and single sign-on"; plan 15), for the native iPhone,
//! iPad, Mac and Android apps. The calls are the desktop app's and the CLI's
//! (`apps/desktop/crates/vault/src/vault/organisations.rs`), which are the web vault's
//! (`packages/vault-client/src/remote/organisations.ts`), on this crate's blocking HTTP client and
//! the phone's store. The wire types are `octapass-api`'s; the keys and grants are
//! `octapass-core`'s, sealed in `octapass-ffi`'s `Session` as for any shared vault.
//!
//! Nothing here is a key: roles, groups, policies, SSO and SCIM live on the server, and a vault key
//! reaches someone only through a grant sealed on this device, after a person reviewed it.
//! Applying access is the one step that seals: the list of who should get a vault comes from the
//! server, so each person's fingerprint is computed here, shown, and checked again against what
//! the person confirmed before anything is sealed. Anyone the server added since isn't sealed to.
//!
//! Three policies are the apps' to apply (`ClientPolicies`): the longest auto-lock, the shortest
//! master password, and exports without organisation vaults. They're kept in the account's
//! device-local notes, so they hold offline and after a restart, and refreshed whenever the
//! organisation is read and after every sync.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use octapass_api::{
    OrgAccessResponse, OrgEventsResponse, OrgGroupsResponse, OrgMembersResponse,
    OrgScimResponse as ApiScim, OrgSsoRecord, OrgSsoTestResponse, OrgVaultsResponse, OrgsResponse,
    ReauthPurpose, VaultRecord, VaultRole as ApiRole,
};
use octapass_ffi::key_log::{Account, core_record};
use octapass_mobile_vault::model::vault_names;
use octapass_mobile_vault::vault::Access;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::api::{Method, Refused, segment};
use crate::error::{ErrorCode, Result, VaultError, not_allowed, require};
use crate::local;
use crate::sharing::{
    Fingerprint, Vault, VaultRole, account_id, api_grant, fingerprint_of, list_vaults, vault_record,
};
use crate::vault::{Ctx, OctaPassVault, now_ms};

/// A shared vault's name lives inside it, so an admin without the key sees part of its id.
const SHORT_ID: usize = 8;
/// Grants race key rotations; after this many `vault-key-changed` answers, give up.
const GRANT_ATTEMPTS: usize = 2;

// ---------- What crosses to Swift and Kotlin ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum OrgRole {
    Member,
    /// Manages members, invites, groups and vault links.
    Admin,
    /// Also manages policies, SSO and roles. Entitled to every organisation vault.
    Owner,
}

/// The organisation's rules. The first five are enforced by the server; the last three are the
/// apps' to apply (`ClientPolicies`), and a modified app can ignore them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct OrgPolicies {
    pub require_two_step: bool,
    pub require_sso: bool,
    /// How many hours a sign-in with SSO lasts, 1 to 8760; 0 checks only at sign-in.
    pub sso_max_age_hours: u32,
    pub disable_share_links: bool,
    pub disable_emergency_access: bool,
    pub disable_export: bool,
    pub max_auto_lock_minutes: Option<u32>,
    pub min_password_length: Option<u32>,
}

/// The policies this app applies itself, as the device last saw them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientPolicies {
    /// Exports leave out organisation vaults.
    pub disable_export: bool,
    /// The longest auto-lock, in minutes: "never" and longer choices aren't offered, and stay
    /// unlocked is off.
    pub max_auto_lock_minutes: Option<u32>,
    /// A new master password needs at least this many characters.
    pub min_password_length: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Organisation {
    pub id: String,
    pub name: String,
    /// The signed-in account's role.
    pub role: OrgRole,
    pub policies: OrgPolicies,
    pub member_count: u64,
    /// This member breaks a policy (two-step sign-in is off), so organisation vaults are withheld.
    pub access_withheld: bool,
    pub created_at: String,
}

/// An invitation this account received. `policies` are what joining agrees to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgInvitation {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub role: OrgRole,
    pub invited_by: Option<String>,
    pub policies: OrgPolicies,
    pub invited_at: String,
    pub expires_at: String,
}

/// `getOrganisation`: the organisation this account is in, if any, and its invitations. An
/// account is in one organisation at a time.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgState {
    pub organisation: Option<Organisation>,
    pub invitations: Vec<OrgInvitation>,
}

/// A member, as admins see them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgMember {
    pub account_id: String,
    pub email: String,
    pub role: OrgRole,
    pub two_step: bool,
    pub sso_linked: bool,
    pub joined_at: String,
    pub is_you: bool,
}

/// A pending invite, as admins see it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgInvite {
    pub id: String,
    pub email: String,
    pub role: OrgRole,
    pub invited_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgMembers {
    pub members: Vec<OrgMember>,
    pub invites: Vec<OrgInvite>,
}

/// A list of people; linked to a vault, it entitles them to it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgGroup {
    pub id: String,
    /// Plaintext: the server can read it.
    pub name: String,
    /// Account ids.
    pub members: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgVaultGroup {
    pub group_id: String,
    /// `read`, `write` or `manage`.
    pub role: VaultRole,
}

/// An organisation vault, named if this account can open it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgVault {
    pub id: String,
    /// The name inside the vault; none when this account can't open it.
    pub name: Option<String>,
    /// The end of its id, to tell vaults without a name apart.
    pub short_id: String,
    pub groups: Vec<OrgVaultGroup>,
    pub member_count: u64,
    /// Members who can grant access and rotate the key. At 0 nobody can, and it can only be
    /// deleted.
    pub manager_count: u64,
    /// This account's role, if it's a member.
    pub role: Option<VaultRole>,
    /// Someone lost access and the key hasn't been rotated yet.
    pub rotation_pending: bool,
    pub created_at: String,
}

/// Someone a vault's key would be sealed to, with a fingerprint computed on this device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgAccessReview {
    pub vault_id: String,
    pub vault_name: Option<String>,
    pub short_id: String,
    /// This account holds the key and may manage the vault.
    pub can_apply: bool,
    /// Someone lost access: the key should be rotated.
    pub rotate: bool,
    pub grants: Vec<OrgAccessGrant>,
}

/// A person the user confirmed, with the fingerprint digits that were on screen.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConfirmedGrant {
    pub account_id: String,
    pub fingerprint_digits: String,
}

/// One line of the organisation's activity log. `event_type` is a stable kebab-case name
/// (`member-removed`); the apps show `organisation.event<Name>`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgEvent {
    pub id: String,
    pub event_type: String,
    /// The email of who did it, unless that account is gone.
    pub actor: Option<String>,
    /// What it was done to: an email, a group's name or a vault id.
    pub subject: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SsoProtocol {
    Oidc,
    Saml,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SamlCertificate {
    /// SHA-256 of the DER, colon-separated hex.
    pub sha256: String,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SamlIdentityProvider {
    pub entity_id: String,
    pub sso_url: String,
    pub certificates: Vec<SamlCertificate>,
}

/// The organisation's single sign-on settings. The client secret never comes back.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgSso {
    /// Which protocol is saved; none when nothing is.
    pub protocol: Option<SsoProtocol>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub has_client_secret: bool,
    /// When a test sign-in last finished with these settings. `requireSso` needs one.
    pub tested_at: Option<String>,
    /// The OpenID Connect redirect URI to register at the provider.
    pub callback_url: String,
    pub saml: Option<SamlIdentityProvider>,
    /// What to register at a SAML provider: entity ID, ACS URL and metadata URL.
    pub saml_entity_id: String,
    pub saml_acs_url: String,
    pub saml_metadata_url: String,
}

/// OpenID Connect settings. The server fetches the issuer's discovery document first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OidcSettings {
    pub issuer: String,
    pub client_id: String,
    /// None for a public client, or to keep the saved one.
    pub client_secret: Option<String>,
}

/// SAML settings: the provider's metadata, or its entity id, SSO URL and certificates.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SamlSettings {
    pub metadata_xml: Option<String>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub certificates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScimToken {
    pub id: String,
    pub name: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgScim {
    /// The SCIM 2.0 base URL to give the identity provider.
    pub base_url: String,
    pub tokens: Vec<ScimToken>,
}

/// A new SCIM token. `secret` is in this answer only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedScimToken {
    pub token: ScimToken,
    pub secret: String,
}

// ---------- Between the wire and the bindings ----------

impl From<octapass_api::OrgRole> for OrgRole {
    fn from(role: octapass_api::OrgRole) -> Self {
        match role {
            octapass_api::OrgRole::Member => Self::Member,
            octapass_api::OrgRole::Admin => Self::Admin,
            octapass_api::OrgRole::Owner => Self::Owner,
        }
    }
}

impl From<OrgRole> for octapass_api::OrgRole {
    fn from(role: OrgRole) -> Self {
        match role {
            OrgRole::Member => Self::Member,
            OrgRole::Admin => Self::Admin,
            OrgRole::Owner => Self::Owner,
        }
    }
}

fn api_vault_role(role: VaultRole) -> ApiRole {
    match role {
        VaultRole::Read => ApiRole::Read,
        VaultRole::Write => ApiRole::Write,
        VaultRole::Manage => ApiRole::Manage,
        VaultRole::Owner => ApiRole::Owner,
    }
}

impl From<octapass_api::OrgPolicies> for OrgPolicies {
    fn from(p: octapass_api::OrgPolicies) -> Self {
        Self {
            require_two_step: p.require_two_step,
            require_sso: p.require_sso,
            sso_max_age_hours: p.sso_max_age_hours,
            disable_share_links: p.disable_share_links,
            disable_emergency_access: p.disable_emergency_access,
            disable_export: p.disable_export,
            max_auto_lock_minutes: p.max_auto_lock_minutes,
            min_password_length: p.min_password_length,
        }
    }
}

impl From<OrgPolicies> for octapass_api::OrgPolicies {
    fn from(p: OrgPolicies) -> Self {
        Self {
            require_two_step: p.require_two_step,
            require_sso: p.require_sso,
            sso_max_age_hours: p.sso_max_age_hours,
            disable_share_links: p.disable_share_links,
            disable_emergency_access: p.disable_emergency_access,
            disable_export: p.disable_export,
            max_auto_lock_minutes: p.max_auto_lock_minutes,
            min_password_length: p.min_password_length,
        }
    }
}

impl From<&OrgPolicies> for ClientPolicies {
    fn from(p: &OrgPolicies) -> Self {
        Self {
            disable_export: p.disable_export,
            max_auto_lock_minutes: p.max_auto_lock_minutes.filter(|minutes| *minutes > 0),
            min_password_length: p.min_password_length.filter(|length| *length > 0),
        }
    }
}

impl From<octapass_api::OrgRecord> for Organisation {
    fn from(org: octapass_api::OrgRecord) -> Self {
        Self {
            id: org.id,
            name: org.name,
            role: org.role.into(),
            policies: org.policies.into(),
            member_count: org.member_count,
            access_withheld: org.access_withheld,
            created_at: org.created_at,
        }
    }
}

impl From<octapass_api::OrgInvitation> for OrgInvitation {
    fn from(invite: octapass_api::OrgInvitation) -> Self {
        Self {
            id: invite.id,
            org_id: invite.org_id,
            org_name: invite.org_name,
            role: invite.role.into(),
            invited_by: invite.invited_by,
            policies: invite.policies.into(),
            invited_at: invite.invited_at,
            expires_at: invite.expires_at,
        }
    }
}

impl From<OrgsResponse> for OrgState {
    fn from(state: OrgsResponse) -> Self {
        Self {
            organisation: state.organisation.map(Into::into),
            invitations: state.invitations.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<octapass_api::OrgGroupRecord> for OrgGroup {
    fn from(group: octapass_api::OrgGroupRecord) -> Self {
        Self {
            id: group.id,
            name: group.name,
            members: group.members,
            created_at: group.created_at,
        }
    }
}

impl From<octapass_api::OrgEvent> for OrgEvent {
    fn from(event: octapass_api::OrgEvent) -> Self {
        Self {
            id: event.id,
            event_type: event.event_type,
            actor: event.actor,
            subject: event.subject,
            created_at: event.created_at,
        }
    }
}

impl From<OrgSsoRecord> for OrgSso {
    fn from(sso: OrgSsoRecord) -> Self {
        Self {
            protocol: sso.protocol.map(|protocol| match protocol {
                octapass_api::SsoProtocol::Oidc => SsoProtocol::Oidc,
                octapass_api::SsoProtocol::Saml => SsoProtocol::Saml,
            }),
            issuer: sso.issuer,
            client_id: sso.client_id,
            has_client_secret: sso.has_client_secret,
            tested_at: sso.tested_at,
            callback_url: sso.callback_url,
            saml: sso.saml.map(|saml| SamlIdentityProvider {
                entity_id: saml.entity_id,
                sso_url: saml.sso_url,
                certificates: saml
                    .certificates
                    .into_iter()
                    .map(|certificate| SamlCertificate {
                        sha256: certificate.sha256,
                        not_after: certificate.not_after,
                    })
                    .collect(),
            }),
            saml_entity_id: sso.saml_service_provider.entity_id,
            saml_acs_url: sso.saml_service_provider.acs_url,
            saml_metadata_url: sso.saml_service_provider.metadata_url,
        }
    }
}

impl From<octapass_api::OrgScimTokenRecord> for ScimToken {
    fn from(token: octapass_api::OrgScimTokenRecord) -> Self {
        Self {
            id: token.id,
            name: token.name,
            created_by: token.created_by,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// The catalog key of an activity log line (`organisation.eventMemberJoined`), as the web vault's
/// `ActivityPanel` names them; none for a type from a newer server, which the apps show as is.
#[uniffi::export]
pub fn org_event_message_key(event_type: String) -> Option<String> {
    let name = match event_type.as_str() {
        "org-created" => "OrgCreated",
        "org-renamed" => "OrgRenamed",
        "member-invited" => "MemberInvited",
        "invite-cancelled" => "InviteCancelled",
        "invite-declined" => "InviteDeclined",
        "member-joined" => "MemberJoined",
        "member-left" => "MemberLeft",
        "member-removed" => "MemberRemoved",
        "member-role-changed" => "RoleChanged",
        "group-created" => "GroupCreated",
        "group-renamed" => "GroupRenamed",
        "group-deleted" => "GroupDeleted",
        "group-member-added" => "GroupMemberAdded",
        "group-member-removed" => "GroupMemberRemoved",
        "vault-created" => "VaultCreated",
        "vault-deleted" => "VaultDeleted",
        "vault-group-linked" => "VaultLinked",
        "vault-group-unlinked" => "VaultUnlinked",
        "access-granted" => "AccessGranted",
        "policies-changed" => "PoliciesChanged",
        "sso-changed" => "SsoChanged",
        "sso-removed" => "SsoRemoved",
        "scim-token-created" => "ScimTokenCreated",
        "scim-token-revoked" => "ScimTokenRevoked",
        "scim-user-provisioned" => "ScimProvisioned",
        "scim-user-invited" => "ScimInvited",
        "scim-user-deprovisioned" => "ScimDeprovisioned",
        "scim-owner-kept" => "ScimOwnerKept",
        "scim-group-created" => "ScimGroupCreated",
        "scim-group-changed" => "ScimGroupChanged",
        "scim-group-deleted" => "ScimGroupDeleted",
        "scim-vault-orphaned" => "ScimVaultOrphaned",
        _ => return None,
    };
    Some(format!("organisation.event{name}"))
}

pub(crate) fn short_id(id: &str) -> String {
    let start = id.len().saturating_sub(SHORT_ID);
    id.get(start..).unwrap_or(id).to_owned()
}

/// The auto-lock time that applies: the user's choice, unless the organisation caps it.
/// "Never" (0) and anything longer than the cap become the cap.
pub(crate) fn capped_auto_lock(chosen: u32, max: Option<u32>) -> u32 {
    match max {
        Some(max) if max > 0 && (chosen == 0 || chosen > max) => max,
        _ => chosen,
    }
}

/// The client policies of the account last seen, in memory, so the auto-lock timer doesn't read
/// a file every tick. The notes file is the copy that outlives the app.
#[derive(Default)]
pub(crate) struct PolicyCache(Mutex<Option<(String, ClientPolicies)>>);

impl PolicyCache {
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<(String, ClientPolicies)>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The policies for the unlocked account, from memory or its notes.
    pub(crate) fn get(&self, access: &Access) -> ClientPolicies {
        let tag = access.account_tag();
        if let Some((cached, policies)) = &*self.guard()
            && cached == tag
        {
            return *policies;
        }
        let policies = local::load_notes(access.data_dir(), tag)
            .org_policies
            .unwrap_or_default();
        *self.guard() = Some((tag.to_owned(), policies));
        policies
    }

    fn set(&self, access: &Access, policies: ClientPolicies) -> Result<()> {
        let tag = access.account_tag();
        let saved = local::load_notes(access.data_dir(), tag)
            .org_policies
            .unwrap_or_default();
        if saved != policies {
            local::update_notes(access.data_dir(), tag, |notes| {
                notes.org_policies = (policies != ClientPolicies::default()).then_some(policies);
            })?;
        }
        *self.guard() = Some((tag.to_owned(), policies));
        Ok(())
    }
}

// ---------- The engine ----------

impl Ctx<'_> {
    /// A call whose answer is read. 403 means the role doesn't allow it.
    fn org_call<T: serde::de::DeserializeOwned>(
        &self,
        access: &Access,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T> {
        self.server(access)
            .call(method, path, body)
            .map_err(not_allowed)
    }

    /// A call whose answer is empty (`204`).
    fn org_send(
        &self,
        access: &Access,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<()> {
        self.org_call::<Value>(access, method, path, body)
            .map(|_| ())
    }

    fn orgs(&self, access: &Access) -> Result<OrgsResponse> {
        let state: OrgsResponse = self.org_call(access, Method::Get, "v1/orgs", None)?;
        let policies = state
            .organisation
            .as_ref()
            .map(|org| ClientPolicies::from(&OrgPolicies::from(org.policies)))
            .unwrap_or_default();
        self.policies.set(access, policies)?;
        Ok(state)
    }

    /// `v1/orgs/{id}` plus `rest`, for the signed-in account's organisation.
    fn org_path(&self, access: &Access, rest: &str) -> Result<String> {
        let id = self
            .orgs(access)?
            .organisation
            .map(|org| org.id)
            .ok_or(ErrorCode::NotFound)?;
        Ok(format!("v1/orgs/{}{rest}", segment(&id)))
    }

    /// The client policies as the server says them now, saved for when it can't be reached.
    /// Accounts on this device only have none.
    pub(crate) fn refresh_client_policies(&self) -> Result<ClientPolicies> {
        let access = self.vault.access()?;
        self.orgs(&access)?;
        Ok(self.policies.get(&access))
    }

    /// The client policies as last seen, without asking the server.
    pub(crate) fn client_policies(&self) -> ClientPolicies {
        self.vault
            .access()
            .map(|access| self.policies.get(&access))
            .unwrap_or_default()
    }

    /// The vaults an export leaves out under `disableExport`: the organisation's. The phone's
    /// store doesn't keep which vaults are an organisation's, so the server's sync answer says,
    /// asked with the store's revisions so it carries no items. Offline, the policy last seen
    /// applies, and every shared vault is left out, since any could be the organisation's.
    pub(crate) fn vaults_kept_from_export(&self) -> HashSet<String> {
        let policies = self
            .refresh_client_policies()
            .unwrap_or_else(|_| self.client_policies());
        if !policies.disable_export {
            return HashSet::new();
        }
        let Ok(access) = self.vault.access() else {
            return HashSet::new();
        };
        let vaults = access.store().vaults();
        let since = vaults
            .iter()
            .map(|vault| format!("{}:{}", vault.id, vault.revision))
            .collect::<Vec<_>>()
            .join(",");
        let path = format!("v1/sync?since={}", segment(&since));
        match self
            .server(&access)
            .get::<octapass_api::SyncResponse>(&path)
        {
            Ok(synced) => synced
                .vaults
                .into_iter()
                .filter(|vault| vault.org_id.is_some())
                .map(|vault| vault.id)
                .collect(),
            Err(_) => vaults
                .into_iter()
                .filter(|vault| vault.vault_type == octapass_api::VaultType::Shared)
                .map(|vault| vault.id)
                .collect(),
        }
    }

    /// Refuses a new master password shorter than the organisation asks for.
    pub(crate) fn check_password_policy(&self, password: &str) -> Result<()> {
        let policies = self
            .refresh_client_policies()
            .unwrap_or_else(|_| self.client_policies());
        match policies.min_password_length {
            Some(min) if (password.chars().count() as u64) < u64::from(min) => {
                Err(VaultError::new(
                    ErrorCode::OrgPolicy,
                    format!("the organisation asks for at least {min} characters"),
                ))
            }
            _ => Ok(()),
        }
    }

    fn changed_orgs(&self) {
        self.sharing_changed();
    }

    // ---------- The organisation ----------

    pub fn get_organisation(&self) -> Result<OrgState> {
        let access = self.vault.access()?;
        Ok(self.orgs(&access)?.into())
    }

    pub fn create_organisation(&self, name: &str) -> Result<Organisation> {
        let access = self.vault.access()?;
        let body = json!({
            "id": octapass_core::account::new_id(now_ms(), &mut OsRng),
            "name": name.trim(),
        });
        let created: octapass_api::OrgRecord =
            self.org_call(&access, Method::Post, "v1/orgs", Some(&body))?;
        self.orgs(&access)?;
        self.changed_orgs();
        Ok(created.into())
    }

    pub fn rename_organisation(&self, name: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "")?;
        self.org_send(
            &access,
            Method::Patch,
            &path,
            Some(&json!({ "name": name.trim() })),
        )?;
        self.changed_orgs();
        Ok(())
    }

    /// Deletes the organisation and all its vaults, for everyone. Asks for the master password,
    /// and the name typed to confirm.
    pub fn delete_organisation(&self, password: &str, confirm_name: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "")?;
        let reauth = access.reauth(password, ReauthPurpose::Organisation)?;
        self.server(&access)
            .call_reauthed::<Value>(
                Method::Delete,
                &path,
                &reauth,
                Some(&json!({ "confirmName": confirm_name })),
            )
            .map_err(not_allowed)?;
        self.orgs(&access)?;
        drop(access);
        self.sync_and_open()?;
        self.changed_orgs();
        Ok(())
    }

    /// Joins: the organisation's vaults come once a key holder reviews this account.
    pub fn accept_org_invite(&self, org_id: &str, invite_id: &str) -> Result<Organisation> {
        let access = self.vault.access()?;
        let path = format!(
            "v1/orgs/{}/invites/{}/accept",
            segment(org_id),
            segment(invite_id)
        );
        let joined: octapass_api::OrgRecord = self.org_call(&access, Method::Post, &path, None)?;
        self.orgs(&access)?;
        drop(access);
        self.sync_and_open()?;
        self.changed_orgs();
        Ok(joined.into())
    }

    pub fn decline_org_invite(&self, org_id: &str, invite_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = format!("v1/orgs/{}/invites/{}", segment(org_id), segment(invite_id));
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Members and invites ----------

    pub fn list_org_members(&self) -> Result<OrgMembers> {
        let access = self.vault.access()?;
        let me = account_id(&access)?;
        let path = self.org_path(&access, "/members")?;
        let listed: OrgMembersResponse = self.org_call(&access, Method::Get, &path, None)?;
        Ok(OrgMembers {
            members: listed
                .members
                .into_iter()
                .map(|member| OrgMember {
                    is_you: member.account_id == me,
                    account_id: member.account_id,
                    email: member.email,
                    role: member.role.into(),
                    two_step: member.two_step,
                    sso_linked: member.sso_linked,
                    joined_at: member.joined_at,
                })
                .collect(),
            invites: listed
                .invites
                .into_iter()
                .map(|invite| OrgInvite {
                    id: invite.id,
                    email: invite.email,
                    role: invite.role.into(),
                    invited_at: invite.invited_at,
                    expires_at: invite.expires_at,
                })
                .collect(),
        })
    }

    /// `member` or `admin`; owners are made from members. The answer is the same whether or not
    /// the email has an account.
    pub fn invite_org_member(&self, email: &str, role: OrgRole) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/invites")?;
        let body = json!({
            "email": email.trim().to_lowercase(),
            "role": octapass_api::OrgRole::from(role),
        });
        self.org_send(&access, Method::Post, &path, Some(&body))?;
        self.changed_orgs();
        Ok(())
    }

    pub fn cancel_org_invite(&self, invite_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/invites/{}", segment(invite_id)))?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    pub fn set_org_member_role(&self, account_id: &str, role: OrgRole) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/members/{}", segment(account_id)))?;
        let body = json!({ "role": octapass_api::OrgRole::from(role) });
        self.org_send(&access, Method::Patch, &path, Some(&body))?;
        self.changed_orgs();
        Ok(())
    }

    /// Fails with `orgVaultOrphaned` unless `orphan_vaults` says to go ahead.
    pub fn remove_org_member(&self, account_id: &str, orphan_vaults: bool) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(
            &access,
            &format!(
                "/members/{}?orphanVaults={orphan_vaults}",
                segment(account_id)
            ),
        )?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    /// The organisation's vaults go at once; the account and its personal vault stay.
    pub fn leave_organisation(&self, orphan_vaults: bool) -> Result<()> {
        let me = account_id(&self.vault.access()?)?;
        self.remove_org_member(&me, orphan_vaults)?;
        self.orgs(&self.vault.access()?)?;
        self.sync_and_open()?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Groups ----------

    pub fn list_org_groups(&self) -> Result<Vec<OrgGroup>> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/groups")?;
        let listed: OrgGroupsResponse = self.org_call(&access, Method::Get, &path, None)?;
        Ok(listed.groups.into_iter().map(Into::into).collect())
    }

    pub fn create_org_group(&self, name: &str) -> Result<OrgGroup> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/groups")?;
        let body = json!({
            "id": octapass_core::account::new_id(now_ms(), &mut OsRng),
            "name": name.trim(),
        });
        let group: octapass_api::OrgGroupRecord =
            self.org_call(&access, Method::Post, &path, Some(&body))?;
        self.changed_orgs();
        Ok(group.into())
    }

    pub fn rename_org_group(&self, group_id: &str, name: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/groups/{}", segment(group_id)))?;
        let body = json!({ "name": name.trim() });
        self.org_send(&access, Method::Patch, &path, Some(&body))?;
        self.changed_orgs();
        Ok(())
    }

    pub fn delete_org_group(&self, group_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/groups/{}", segment(group_id)))?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    /// Adding someone asks a vault manager to give them the key; it gives nothing itself.
    pub fn add_org_group_member(&self, group_id: &str, account_id: &str) -> Result<()> {
        self.group_member(Method::Put, group_id, account_id)
    }

    pub fn remove_org_group_member(&self, group_id: &str, account_id: &str) -> Result<()> {
        self.group_member(Method::Delete, group_id, account_id)
    }

    fn group_member(&self, method: Method, group_id: &str, account_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let rest = format!(
            "/groups/{}/members/{}",
            segment(group_id),
            segment(account_id)
        );
        let path = self.org_path(&access, &rest)?;
        self.org_send(&access, method, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Vaults ----------

    fn vault_names(&self) -> Result<HashMap<String, String>> {
        let items = self.vault.all_items()?;
        let access = self.vault.access()?;
        let names = vault_names(&items);
        Ok(access
            .store()
            .vaults()
            .into_iter()
            .filter_map(|vault| names.get(&vault.id).map(|name| (vault.id, name.clone())))
            .collect())
    }

    /// Vaults this account can open show their names; the rest show part of their id.
    pub fn list_org_vaults(&self) -> Result<Vec<OrgVault>> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/vaults")?;
        let listed: OrgVaultsResponse = self.org_call(&access, Method::Get, &path, None)?;
        drop(access);
        let names = self.vault_names()?;
        Ok(listed
            .vaults
            .into_iter()
            .map(|vault| OrgVault {
                name: names.get(&vault.id).cloned(),
                short_id: short_id(&vault.id),
                groups: vault
                    .groups
                    .into_iter()
                    .map(|group| OrgVaultGroup {
                        group_id: group.group_id,
                        role: group.role.into(),
                    })
                    .collect(),
                member_count: vault.member_count,
                manager_count: vault.manager_count,
                role: vault.role.map(Into::into),
                rotation_pending: vault.rotation_pending,
                created_at: vault.created_at,
                id: vault.id,
            })
            .collect())
    }

    /// A shared vault of the organisation, owned by this account and named inside it.
    pub fn create_org_vault(&self, name: &str) -> Result<Vault> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/vaults")?;
        let created = access
            .session()
            .with_keys(|core| Ok(core.create_shared_vault(now_ms(), &mut OsRng)?))?;
        let body = json!({
            "id": created.id,
            "keyId": created.key_id,
            "grant": serde_json::to_value(&created.grant).expect("grants serialize"),
        });
        // Creating fails as a whole, so trying once more after a 500 can't make two.
        let server = self.server(&access);
        let record: Result<VaultRecord> = server.post(&path, &body);
        let record = match record {
            Err(error) if error.code() == ErrorCode::ServerError => server.post(&path, &body),
            other => other,
        }
        .map_err(not_allowed)?;
        drop(access);
        self.sync_and_open()?;
        let access = self.vault.access()?;
        require(
            !self.shared.open(&access).contains(&record.id),
            ErrorCode::UntrustedVault,
        )?;
        drop(access);
        self.write_vault_name(&record.id, name)?;
        self.changed_orgs();
        let items = self.vault.all_items()?;
        list_vaults(self, &self.vault.access()?, &items)
            .into_iter()
            .find(|vault| vault.id == record.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    /// Needs no key: it's how an organisation clears a vault nobody can open. Asks for the
    /// master password.
    pub fn delete_org_vault(&self, password: &str, vault_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/vaults/{}", segment(vault_id)))?;
        let reauth = access.reauth(password, ReauthPurpose::Organisation)?;
        self.server(&access)
            .call_reauthed::<Value>(Method::Delete, &path, &reauth, None::<&Value>)
            .map_err(not_allowed)?;
        drop(access);
        self.sync_and_open()?;
        self.changed_orgs();
        Ok(())
    }

    /// Entitles a group's members to the vault with `role` (`read`, `write` or `manage`). The key
    /// follows only once a key holder applies access.
    pub fn link_org_vault_group(
        &self,
        vault_id: &str,
        group_id: &str,
        role: VaultRole,
    ) -> Result<()> {
        let access = self.vault.access()?;
        let rest = format!("/vaults/{}/groups/{}", segment(vault_id), segment(group_id));
        let path = self.org_path(&access, &rest)?;
        let body = json!({ "role": api_vault_role(role) });
        self.org_send(&access, Method::Put, &path, Some(&body))?;
        self.changed_orgs();
        Ok(())
    }

    pub fn unlink_org_vault_group(&self, vault_id: &str, group_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let rest = format!("/vaults/{}/groups/{}", segment(vault_id), segment(group_id));
        let path = self.org_path(&access, &rest)?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Access: the reviewed step ----------

    fn reviewed(
        grant: &octapass_api::OrgPendingGrant,
        verified: &BTreeMap<String, String>,
    ) -> Result<OrgAccessGrant> {
        let fingerprint = fingerprint_of(&grant.public_enc_key, &grant.public_sign_key)?;
        let known = verified.get(&grant.account_id);
        Ok(OrgAccessGrant {
            account_id: grant.account_id.clone(),
            email: grant.email.clone(),
            role: grant.role.into(),
            upgrade: grant.upgrade,
            verified: known == Some(&fingerprint.digits),
            key_changed: known.is_some_and(|known| *known != fingerprint.digits),
            fingerprint,
        })
    }

    /// What vaults are waiting for from a key holder, for a person to review. The list comes
    /// from the server; the fingerprints don't.
    pub fn org_access(&self) -> Result<Vec<OrgAccessReview>> {
        self.sync_and_open()?;
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/access")?;
        let plans: OrgAccessResponse = self.org_call(&access, Method::Get, &path, None)?;
        let verified = local::load_notes(access.data_dir(), access.account_tag()).verified;
        drop(access);
        let names = self.vault_names()?;
        plans
            .vaults
            .into_iter()
            .map(|plan| {
                Ok(OrgAccessReview {
                    vault_name: names.get(&plan.vault_id).cloned(),
                    short_id: short_id(&plan.vault_id),
                    can_apply: plan.can_apply,
                    rotate: plan.rotate,
                    grants: plan
                        .grants
                        .iter()
                        .map(|grant| Self::reviewed(grant, &verified))
                        .collect::<Result<_>>()?,
                    vault_id: plan.vault_id,
                })
            })
            .collect()
    }

    /// Seals the vault to exactly the people a person confirmed. Each is checked against the plan
    /// as the server says it now: anyone whose keys differ from the fingerprint that was on
    /// screen, or from one verified earlier on this device, is refused rather than sealed to, and
    /// so is anyone the key log contradicts. Anyone the server added since isn't sealed to at all.
    /// Returns how many grants were stored.
    pub fn apply_org_access(&self, vault_id: &str, confirmed: &[ConfirmedGrant]) -> Result<u32> {
        if confirmed.is_empty() {
            return Ok(0);
        }
        for attempt in 1..=GRANT_ATTEMPTS {
            self.sync_and_open()?;
            let access = self.vault.access()?;
            let org_path = self.org_path(&access, "")?;
            let vault = vault_record(&access, vault_id)?;
            require(
                !self.shared.open(&access).contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            let key_id = vault.key_id.clone().ok_or(ErrorCode::NotFound)?;
            let plans: OrgAccessResponse =
                self.org_call(&access, Method::Get, &format!("{org_path}/access"), None)?;
            let plan = plans
                .vaults
                .into_iter()
                .find(|plan| plan.vault_id == vault_id)
                .filter(|plan| plan.can_apply)
                .ok_or(ErrorCode::NotAllowed)?;
            let verified = local::load_notes(access.data_dir(), access.account_tag()).verified;
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
                    actual.fingerprint.digits == wanted.fingerprint_digits && !actual.key_changed,
                    ErrorCode::UntrustedVault,
                )?;
                // As for any share: the keys must not contradict the key log, and a valid record
                // makes the grant hybrid (plan 03).
                let record = core_record(pending.key_record.as_ref());
                let keys = Account {
                    account_id: &pending.account_id,
                    email: &pending.email,
                    public_enc_key: &pending.public_enc_key,
                    public_sign_key: &pending.public_sign_key,
                    record: record.as_ref(),
                };
                let role = VaultRole::from(pending.role).core();
                let recipient = self.recipient_of(&access, keys, role)?;
                let grant = access.session().with_keys(|core| {
                    Ok(core.grant_vault(vault_id, &recipient, now_ms(), &mut OsRng)?)
                })?;
                grants.push(api_grant(grant)?);
            }
            if grants.is_empty() {
                return Ok(0);
            }
            let count = grants.len() as u32;
            let path = format!("{org_path}/vaults/{}/grants", segment(vault_id));
            let body = json!({ "keyId": key_id, "grants": grants });
            let sent: std::result::Result<Value, Refused> = self
                .server(&access)
                .call_unless(Method::Post, &path, Some(&body), "vault-key-changed")
                .map_err(not_allowed)?;
            match sent {
                Ok(_) => {
                    drop(access);
                    self.sync_and_open()?;
                    self.changed_orgs();
                    return Ok(count);
                }
                Err(Refused) if attempt < GRANT_ATTEMPTS => continue,
                Err(Refused) => {
                    return Err(VaultError::new(
                        ErrorCode::ServerError,
                        "the vault key changed while giving access",
                    ));
                }
            }
        }
        unreachable!("the last attempt returns")
    }

    /// Rotates an organisation vault's key after someone lost access, as plan 15 describes.
    pub fn rotate_org_vault(&self, vault_id: &str) -> Result<()> {
        self.rotate_vault_key(vault_id)?;
        self.changed_orgs();
        Ok(())
    }

    // ---------- Policies, SSO, SCIM and the log ----------

    pub fn set_org_policies(&self, policies: OrgPolicies) -> Result<OrgPolicies> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/policies")?;
        let body = serde_json::to_value(octapass_api::OrgPolicies::from(policies))
            .expect("policies serialize");
        let saved: octapass_api::OrgPolicies =
            self.org_call(&access, Method::Put, &path, Some(&body))?;
        self.orgs(&access)?;
        self.changed_orgs();
        Ok(saved.into())
    }

    pub fn org_sso(&self) -> Result<OrgSso> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/sso")?;
        let sso: OrgSsoRecord = self.org_call(&access, Method::Get, &path, None)?;
        Ok(sso.into())
    }

    /// OpenID Connect settings. The server fetches the issuer's discovery document first.
    pub fn save_org_sso(&self, settings: &OidcSettings) -> Result<OrgSso> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/sso")?;
        let request = octapass_api::OrgSsoRequest {
            issuer: settings.issuer.trim().to_owned(),
            client_id: settings.client_id.trim().to_owned(),
            client_secret: settings
                .client_secret
                .clone()
                .filter(|secret| !secret.is_empty()),
        };
        let body = serde_json::to_value(&request).expect("requests serialize");
        let saved: OrgSsoRecord = self.org_call(&access, Method::Put, &path, Some(&body))?;
        self.changed_orgs();
        Ok(saved.into())
    }

    /// SAML settings: the provider's metadata, or its entity id, SSO URL and certificates.
    pub fn save_org_saml(&self, settings: &SamlSettings) -> Result<OrgSso> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/sso/saml")?;
        let given = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let request = octapass_api::OrgSamlRequest {
            metadata_xml: given(&settings.metadata_xml),
            entity_id: given(&settings.entity_id),
            sso_url: given(&settings.sso_url),
            certificates: settings
                .certificates
                .iter()
                .map(|certificate| certificate.trim().to_owned())
                .filter(|certificate| !certificate.is_empty())
                .collect(),
        };
        let body = serde_json::to_value(&request).expect("requests serialize");
        let saved: OrgSsoRecord = self.org_call(&access, Method::Put, &path, Some(&body))?;
        self.changed_orgs();
        Ok(saved.into())
    }

    pub fn remove_org_sso(&self) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/sso")?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    /// The URL of a test sign-in, to open in a browser.
    pub fn test_org_sso(&self) -> Result<String> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/sso/test")?;
        let started: OrgSsoTestResponse = self.org_call(&access, Method::Post, &path, None)?;
        Ok(started.url)
    }

    pub fn org_scim(&self) -> Result<OrgScim> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/scim")?;
        let scim: ApiScim = self.org_call(&access, Method::Get, &path, None)?;
        Ok(OrgScim {
            base_url: scim.base_url,
            tokens: scim.tokens.into_iter().map(Into::into).collect(),
        })
    }

    /// A new SCIM token. Its secret is in this answer only.
    pub fn create_org_scim_token(&self, name: &str) -> Result<CreatedScimToken> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/scim/tokens")?;
        let body = json!({ "name": name.trim() });
        let created: octapass_api::CreatedScimToken =
            self.org_call(&access, Method::Post, &path, Some(&body))?;
        self.changed_orgs();
        Ok(CreatedScimToken {
            token: created.token.into(),
            secret: created.secret,
        })
    }

    pub fn revoke_org_scim_token(&self, token_id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, &format!("/scim/tokens/{}", segment(token_id)))?;
        self.org_send(&access, Method::Delete, &path, None)?;
        self.changed_orgs();
        Ok(())
    }

    /// Newest first, kept a year. It never holds vault contents.
    pub fn org_events(&self) -> Result<Vec<OrgEvent>> {
        let access = self.vault.access()?;
        let path = self.org_path(&access, "/events")?;
        let listed: OrgEventsResponse = self.org_call(&access, Method::Get, &path, None)?;
        Ok(listed.events.into_iter().map(Into::into).collect())
    }
}

// ---------- The exported calls ----------

/// Organisations, as the apps call them. Everything here touches the network, so it's async
/// (Swift) / suspend (Kotlin), except `clientPolicies`.
#[uniffi::export]
impl OctaPassVault {
    /// The policies this app applies itself, as last seen (no network): cap the auto-lock
    /// choices, check a new master password's length, say exports leave out organisation vaults.
    pub fn client_policies(&self) -> ClientPolicies {
        self.ctx().client_policies()
    }

    /// The organisation this account is in, if any, and the invitations it received. Also
    /// refreshes the client policies.
    pub async fn get_organisation(self: Arc<Self>) -> Result<OrgState> {
        self.run(|this| this.ctx().get_organisation()).await
    }

    /// Creates an organisation with this account as its owner.
    pub async fn create_organisation(self: Arc<Self>, name: String) -> Result<Organisation> {
        self.run(move |this| this.ctx().create_organisation(&name))
            .await
    }

    pub async fn rename_organisation(self: Arc<Self>, name: String) -> Result<()> {
        self.run(move |this| this.ctx().rename_organisation(&name))
            .await
    }

    /// Owner: deletes the organisation and all its vaults, for everyone. `confirm_name` is the
    /// name as typed.
    pub async fn delete_organisation(
        self: Arc<Self>,
        password: String,
        confirm_name: String,
    ) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            this.ctx().delete_organisation(&password, &confirm_name)?;
            this.touch();
            Ok(())
        })
        .await
    }

    pub async fn accept_org_invite(
        self: Arc<Self>,
        org_id: String,
        invite_id: String,
    ) -> Result<Organisation> {
        self.run(move |this| this.ctx().accept_org_invite(&org_id, &invite_id))
            .await
    }

    pub async fn decline_org_invite(
        self: Arc<Self>,
        org_id: String,
        invite_id: String,
    ) -> Result<()> {
        self.run(move |this| this.ctx().decline_org_invite(&org_id, &invite_id))
            .await
    }

    pub async fn list_org_members(self: Arc<Self>) -> Result<OrgMembers> {
        self.run(|this| this.ctx().list_org_members()).await
    }

    pub async fn invite_org_member(self: Arc<Self>, email: String, role: OrgRole) -> Result<()> {
        self.run(move |this| this.ctx().invite_org_member(&email, role))
            .await
    }

    pub async fn cancel_org_invite(self: Arc<Self>, invite_id: String) -> Result<()> {
        self.run(move |this| this.ctx().cancel_org_invite(&invite_id))
            .await
    }

    pub async fn set_org_member_role(
        self: Arc<Self>,
        account_id: String,
        role: OrgRole,
    ) -> Result<()> {
        self.run(move |this| this.ctx().set_org_member_role(&account_id, role))
            .await
    }

    /// Fails with `orgVaultOrphaned` when nobody else could manage one of their vaults: ask, then
    /// call again with `orphan_vaults`.
    pub async fn remove_org_member(
        self: Arc<Self>,
        account_id: String,
        orphan_vaults: bool,
    ) -> Result<()> {
        self.run(move |this| this.ctx().remove_org_member(&account_id, orphan_vaults))
            .await
    }

    pub async fn leave_organisation(self: Arc<Self>, orphan_vaults: bool) -> Result<()> {
        self.run(move |this| this.ctx().leave_organisation(orphan_vaults))
            .await
    }

    pub async fn list_org_groups(self: Arc<Self>) -> Result<Vec<OrgGroup>> {
        self.run(|this| this.ctx().list_org_groups()).await
    }

    pub async fn create_org_group(self: Arc<Self>, name: String) -> Result<OrgGroup> {
        self.run(move |this| this.ctx().create_org_group(&name))
            .await
    }

    pub async fn rename_org_group(self: Arc<Self>, group_id: String, name: String) -> Result<()> {
        self.run(move |this| this.ctx().rename_org_group(&group_id, &name))
            .await
    }

    pub async fn delete_org_group(self: Arc<Self>, group_id: String) -> Result<()> {
        self.run(move |this| this.ctx().delete_org_group(&group_id))
            .await
    }

    pub async fn add_org_group_member(
        self: Arc<Self>,
        group_id: String,
        account_id: String,
    ) -> Result<()> {
        self.run(move |this| this.ctx().add_org_group_member(&group_id, &account_id))
            .await
    }

    pub async fn remove_org_group_member(
        self: Arc<Self>,
        group_id: String,
        account_id: String,
    ) -> Result<()> {
        self.run(move |this| this.ctx().remove_org_group_member(&group_id, &account_id))
            .await
    }

    pub async fn list_org_vaults(self: Arc<Self>) -> Result<Vec<OrgVault>> {
        self.run(|this| this.ctx().list_org_vaults()).await
    }

    /// A shared vault of the organisation, owned by this account.
    pub async fn create_org_vault(self: Arc<Self>, name: String) -> Result<Vault> {
        self.run(move |this| this.ctx().create_org_vault(&name))
            .await
    }

    /// Deletes an organisation vault and everything in it, for everyone. Asks for the master
    /// password.
    pub async fn delete_org_vault(
        self: Arc<Self>,
        password: String,
        vault_id: String,
    ) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| this.ctx().delete_org_vault(&password, &vault_id))
            .await
    }

    pub async fn link_org_vault_group(
        self: Arc<Self>,
        vault_id: String,
        group_id: String,
        role: VaultRole,
    ) -> Result<()> {
        self.run(move |this| this.ctx().link_org_vault_group(&vault_id, &group_id, role))
            .await
    }

    pub async fn unlink_org_vault_group(
        self: Arc<Self>,
        vault_id: String,
        group_id: String,
    ) -> Result<()> {
        self.run(move |this| this.ctx().unlink_org_vault_group(&vault_id, &group_id))
            .await
    }

    /// Who should get which vault, with fingerprints computed on this device, to review.
    pub async fn org_access(self: Arc<Self>) -> Result<Vec<OrgAccessReview>> {
        self.run(|this| this.ctx().org_access()).await
    }

    /// Seals the vault's key to the people confirmed on screen, checked again against the
    /// fingerprint each was shown with. Returns how many got access.
    pub async fn apply_org_access(
        self: Arc<Self>,
        vault_id: String,
        confirmed: Vec<ConfirmedGrant>,
    ) -> Result<u32> {
        self.run(move |this| this.ctx().apply_org_access(&vault_id, &confirmed))
            .await
    }

    pub async fn rotate_org_vault(self: Arc<Self>, vault_id: String) -> Result<()> {
        self.run(move |this| this.ctx().rotate_org_vault(&vault_id))
            .await
    }

    /// Owner: the organisation's policies.
    pub async fn set_org_policies(self: Arc<Self>, policies: OrgPolicies) -> Result<OrgPolicies> {
        self.run(move |this| this.ctx().set_org_policies(policies))
            .await
    }

    pub async fn org_sso(self: Arc<Self>) -> Result<OrgSso> {
        self.run(|this| this.ctx().org_sso()).await
    }

    pub async fn save_org_sso(self: Arc<Self>, settings: OidcSettings) -> Result<OrgSso> {
        self.run(move |this| this.ctx().save_org_sso(&settings))
            .await
    }

    pub async fn save_org_saml(self: Arc<Self>, settings: SamlSettings) -> Result<OrgSso> {
        self.run(move |this| this.ctx().save_org_saml(&settings))
            .await
    }

    pub async fn remove_org_sso(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.ctx().remove_org_sso()).await
    }

    /// The address of a test sign-in, to open in the browser.
    pub async fn test_org_sso(self: Arc<Self>) -> Result<String> {
        self.run(|this| this.ctx().test_org_sso()).await
    }

    pub async fn org_scim(self: Arc<Self>) -> Result<OrgScim> {
        self.run(|this| this.ctx().org_scim()).await
    }

    pub async fn create_org_scim_token(self: Arc<Self>, name: String) -> Result<CreatedScimToken> {
        self.run(move |this| this.ctx().create_org_scim_token(&name))
            .await
    }

    pub async fn revoke_org_scim_token(self: Arc<Self>, token_id: String) -> Result<()> {
        self.run(move |this| this.ctx().revoke_org_scim_token(&token_id))
            .await
    }

    pub async fn org_events(self: Arc<Self>) -> Result<Vec<OrgEvent>> {
        self.run(|this| this.ctx().org_events()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_organisation_caps_the_auto_lock() {
        assert_eq!(capped_auto_lock(0, None), 0);
        assert_eq!(capped_auto_lock(240, None), 240);
        assert_eq!(capped_auto_lock(0, Some(15)), 15);
        assert_eq!(capped_auto_lock(60, Some(15)), 15);
        assert_eq!(capped_auto_lock(5, Some(15)), 5);
        assert_eq!(capped_auto_lock(5, Some(0)), 5);
    }

    #[test]
    fn activity_lines_have_the_web_vault_messages() {
        let key = |event: &str| org_event_message_key(event.into());
        assert_eq!(
            key("member-joined").as_deref(),
            Some("organisation.eventMemberJoined")
        );
        assert_eq!(
            key("member-role-changed").as_deref(),
            Some("organisation.eventRoleChanged")
        );
        assert_eq!(
            key("scim-user-invited").as_deref(),
            Some("organisation.eventScimInvited")
        );
        assert_eq!(key("something-new"), None);
    }

    #[test]
    fn vaults_without_a_name_show_the_end_of_their_id() {
        assert_eq!(short_id("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"), "2e3f4a5b");
        assert_eq!(short_id("abc"), "abc");
    }

    #[test]
    fn client_policies_drop_zero_limits() {
        let policies = OrgPolicies {
            require_two_step: true,
            require_sso: false,
            sso_max_age_hours: 168,
            disable_share_links: false,
            disable_emergency_access: false,
            disable_export: true,
            max_auto_lock_minutes: Some(0),
            min_password_length: Some(14),
        };
        assert_eq!(
            ClientPolicies::from(&policies),
            ClientPolicies {
                disable_export: true,
                max_auto_lock_minutes: None,
                min_password_length: Some(14),
            }
        );
    }
}
