//! The organisation commands behind `TauriVaultService.organisations`: members, groups, vaults,
//! the reviewed access step, policies, SSO (OpenID Connect and SAML) and SCIM tokens. They run on
//! the vault's organisation engine (`octapass-desktop-vault`, `vault/organisations.rs`), which the
//! CLI shares; grants are sealed there, never here or in the UI.

use octapass_api::{
    CreatedScimToken, OrgEvent, OrgGroupRecord, OrgPolicies, OrgRole, OrgSamlRequest,
    OrgScimResponse, OrgSsoRecord, OrgSsoRequest, OrgsResponse, VaultRole,
};
use octapass_desktop_vault::VaultError;
use octapass_desktop_vault::model::Vault as VaultView;
use octapass_desktop_vault::vault::{ConfirmedGrant, OrgAccessReview, OrgMembers, OrgVault};
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::AppState;

type Result<T> = std::result::Result<T, VaultError>;

#[tauri::command]
pub async fn get_organisation(state: State<'_, AppState>) -> Result<OrgsResponse> {
    state.vault.get_organisation().await
}

#[tauri::command]
pub async fn create_organisation(state: State<'_, AppState>, name: String) -> Result<()> {
    state.vault.create_organisation(&name).await.map(|_| ())
}

#[tauri::command]
pub async fn rename_organisation(state: State<'_, AppState>, name: String) -> Result<()> {
    state.vault.rename_organisation(&name).await
}

#[tauri::command]
pub async fn delete_organisation(
    state: State<'_, AppState>,
    password: String,
    confirm_name: String,
) -> Result<()> {
    state
        .vault
        .delete_organisation(Zeroizing::new(password), &confirm_name)
        .await
}

#[tauri::command]
pub async fn accept_org_invite(
    state: State<'_, AppState>,
    org_id: String,
    invite_id: String,
) -> Result<()> {
    state
        .vault
        .accept_org_invite(&org_id, &invite_id)
        .await
        .map(|_| ())
}

#[tauri::command]
pub async fn decline_org_invite(
    state: State<'_, AppState>,
    org_id: String,
    invite_id: String,
) -> Result<()> {
    state.vault.decline_org_invite(&org_id, &invite_id).await
}

#[tauri::command]
pub async fn list_org_members(state: State<'_, AppState>) -> Result<OrgMembers> {
    state.vault.list_org_members().await
}

#[tauri::command]
pub async fn invite_org_member(
    state: State<'_, AppState>,
    email: String,
    role: OrgRole,
) -> Result<()> {
    state.vault.invite_org_member(&email, role).await
}

#[tauri::command]
pub async fn cancel_org_invite(state: State<'_, AppState>, invite_id: String) -> Result<()> {
    state.vault.cancel_org_invite(&invite_id).await
}

#[tauri::command]
pub async fn set_org_member_role(
    state: State<'_, AppState>,
    account_id: String,
    role: OrgRole,
) -> Result<()> {
    state.vault.set_org_member_role(&account_id, role).await
}

#[tauri::command]
pub async fn remove_org_member(
    state: State<'_, AppState>,
    account_id: String,
    orphan_vaults: bool,
) -> Result<()> {
    state
        .vault
        .remove_org_member(&account_id, orphan_vaults)
        .await
}

#[tauri::command]
pub async fn leave_organisation(state: State<'_, AppState>, orphan_vaults: bool) -> Result<()> {
    state.vault.leave_organisation(orphan_vaults).await
}

#[tauri::command]
pub async fn list_org_groups(state: State<'_, AppState>) -> Result<Vec<OrgGroupRecord>> {
    state.vault.list_org_groups().await
}

#[tauri::command]
pub async fn create_org_group(state: State<'_, AppState>, name: String) -> Result<OrgGroupRecord> {
    state.vault.create_org_group(&name).await
}

#[tauri::command]
pub async fn rename_org_group(
    state: State<'_, AppState>,
    group_id: String,
    name: String,
) -> Result<()> {
    state.vault.rename_org_group(&group_id, &name).await
}

#[tauri::command]
pub async fn delete_org_group(state: State<'_, AppState>, group_id: String) -> Result<()> {
    state.vault.delete_org_group(&group_id).await
}

#[tauri::command]
pub async fn add_org_group_member(
    state: State<'_, AppState>,
    group_id: String,
    account_id: String,
) -> Result<()> {
    state
        .vault
        .add_org_group_member(&group_id, &account_id)
        .await
}

#[tauri::command]
pub async fn remove_org_group_member(
    state: State<'_, AppState>,
    group_id: String,
    account_id: String,
) -> Result<()> {
    state
        .vault
        .remove_org_group_member(&group_id, &account_id)
        .await
}

#[tauri::command]
pub async fn list_org_vaults(state: State<'_, AppState>) -> Result<Vec<OrgVault>> {
    state.vault.list_org_vaults().await
}

#[tauri::command]
pub async fn create_org_vault(state: State<'_, AppState>, name: String) -> Result<VaultView> {
    state.vault.create_org_vault(&name).await
}

#[tauri::command]
pub async fn delete_org_vault(
    state: State<'_, AppState>,
    password: String,
    vault_id: String,
) -> Result<()> {
    state
        .vault
        .delete_org_vault(Zeroizing::new(password), &vault_id)
        .await
}

#[tauri::command]
pub async fn link_org_vault_group(
    state: State<'_, AppState>,
    vault_id: String,
    group_id: String,
    role: VaultRole,
) -> Result<()> {
    state
        .vault
        .link_org_vault_group(&vault_id, &group_id, role)
        .await
}

#[tauri::command]
pub async fn unlink_org_vault_group(
    state: State<'_, AppState>,
    vault_id: String,
    group_id: String,
) -> Result<()> {
    state
        .vault
        .unlink_org_vault_group(&vault_id, &group_id)
        .await
}

#[tauri::command]
pub async fn get_org_access(state: State<'_, AppState>) -> Result<Vec<OrgAccessReview>> {
    state.vault.org_access().await
}

/// Seals to exactly the people confirmed on screen, re-checked in the vault against the
/// fingerprint each was shown with.
#[tauri::command]
pub async fn apply_org_access(
    state: State<'_, AppState>,
    vault_id: String,
    confirmed: Vec<ConfirmedGrant>,
) -> Result<()> {
    state
        .vault
        .apply_org_access(&vault_id, &confirmed)
        .await
        .map(|_| ())
}

#[tauri::command]
pub async fn rotate_org_vault(state: State<'_, AppState>, vault_id: String) -> Result<()> {
    state.vault.rotate_org_vault(&vault_id).await
}

#[tauri::command]
pub async fn set_org_policies(state: State<'_, AppState>, policies: OrgPolicies) -> Result<()> {
    state.vault.set_org_policies(&policies).await.map(|_| ())
}

#[tauri::command]
pub async fn get_org_sso(state: State<'_, AppState>) -> Result<OrgSsoRecord> {
    state.vault.org_sso().await
}

#[tauri::command]
pub async fn save_org_sso(
    state: State<'_, AppState>,
    input: OrgSsoRequest,
) -> Result<OrgSsoRecord> {
    state.vault.save_org_sso(&input).await
}

#[tauri::command]
pub async fn save_org_saml(
    state: State<'_, AppState>,
    input: OrgSamlRequest,
) -> Result<OrgSsoRecord> {
    state.vault.save_org_saml(&input).await
}

#[tauri::command]
pub async fn remove_org_sso(state: State<'_, AppState>) -> Result<()> {
    state.vault.remove_org_sso().await
}

#[tauri::command]
pub async fn test_org_sso(state: State<'_, AppState>) -> Result<String> {
    state.vault.test_org_sso().await
}

#[tauri::command]
pub async fn list_org_events(state: State<'_, AppState>) -> Result<Vec<OrgEvent>> {
    state.vault.org_events().await
}

#[tauri::command]
pub async fn get_org_scim(state: State<'_, AppState>) -> Result<OrgScimResponse> {
    state.vault.org_scim().await
}

#[tauri::command]
pub async fn create_org_scim_token(
    state: State<'_, AppState>,
    name: String,
) -> Result<CreatedScimToken> {
    state.vault.create_org_scim_token(&name).await
}

#[tauri::command]
pub async fn revoke_org_scim_token(state: State<'_, AppState>, token_id: String) -> Result<()> {
    state.vault.revoke_org_scim_token(&token_id).await
}
