//! The sharing commands behind `TauriVaultService.sharing`: shared vaults, families, share
//! links, emergency access, devices and the security log. Keys are sealed, signed and opened
//! in the vault (`octapass-desktop-vault`); the UI gets fingerprints and decrypted fields.

use octapass_api::{
    DeviceRecord, EmergencyAccessLevel, EmergencyContactRecord, EmergencyContactsResponse,
    SecurityEvent, ShareLinkResponse, VaultRole,
};
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_desktop_vault::VaultError;
use octapass_desktop_vault::model::{Item, NewRecoveryKit, Vault as VaultView};
use octapass_desktop_vault::vault::{
    AccountLookup, CreatedShareLink, EmergencyVaultView, FamilyState, Fingerprint, KeyLogView,
    ServiceAccount, ShareLinkInfo, ShareLinkOptions, SharedItem, VaultMember,
};
use serde::Serialize;
use serde_json::Value;
use tauri::State;
use tauri::ipc::Response;
use zeroize::Zeroizing;

use crate::commands::AppState;

type Result<T> = std::result::Result<T, VaultError>;

// ---------- Devices and the security log ----------

#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<Vec<DeviceRecord>> {
    state.vault.list_devices().await
}

#[tauri::command]
pub async fn rename_device(state: State<'_, AppState>, name: String) -> Result<()> {
    state.vault.rename_device(&name).await
}

#[tauri::command]
pub async fn sign_out_device(state: State<'_, AppState>, device_id: String) -> Result<()> {
    state.vault.sign_out_device(&device_id).await
}

#[tauri::command]
pub async fn security_log(state: State<'_, AppState>) -> Result<Vec<Value>> {
    // The shared UI wants Connect's entries as `connect`, opened; the server's field is gone.
    let events = state.vault.security_log_opened().await?;
    Ok(events.into_iter().map(opened_event).collect())
}

fn opened_event(event: SecurityEvent) -> Value {
    let detail = event
        .sealed_detail
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let mut value = serde_json::to_value(&event).expect("events serialize");
    if let Value::Object(fields) = &mut value {
        fields.remove("sealedDetail");
        if let Some(detail) = detail {
            fields.insert("connect".into(), detail);
        }
    }
    value
}

// ---------- Service accounts ----------

#[tauri::command]
pub async fn list_service_accounts(
    state: State<'_, AppState>,
    vault_id: String,
) -> Result<Vec<ServiceAccount>> {
    state.vault.list_service_accounts(&vault_id).await
}

#[derive(Serialize)]
pub struct NewServiceAccount {
    account: ServiceAccount,
    token: String,
}

#[tauri::command]
pub async fn create_service_account(
    state: State<'_, AppState>,
    vault_id: String,
    name: String,
    role: VaultRole,
    expires_at: Option<String>,
) -> Result<NewServiceAccount> {
    let created = state
        .vault
        .create_service_account(&vault_id, &name, role, expires_at.as_deref())
        .await?;
    Ok(NewServiceAccount {
        account: created.account,
        token: created.token.to_string(),
    })
}

#[tauri::command]
pub async fn revoke_service_account(
    state: State<'_, AppState>,
    vault_id: String,
    id: String,
) -> Result<()> {
    state.vault.revoke_service_account(&vault_id, &id).await
}

// ---------- Identity ----------

#[tauri::command]
pub fn my_fingerprint(state: State<'_, AppState>) -> Result<Fingerprint> {
    state.vault.my_fingerprint()
}

#[tauri::command]
pub async fn lookup_account(state: State<'_, AppState>, email: String) -> Result<AccountLookup> {
    state.vault.lookup_account(&email).await
}

#[tauri::command]
pub fn mark_verified(
    state: State<'_, AppState>,
    account_id: String,
    fingerprint: Fingerprint,
) -> Result<()> {
    state.vault.mark_verified(&account_id, &fingerprint)
}

#[tauri::command]
pub fn key_log_state(state: State<'_, AppState>) -> Result<KeyLogView> {
    state.vault.key_log_state()
}

#[tauri::command]
pub async fn dismiss_key_log_alert(state: State<'_, AppState>) -> Result<()> {
    state.vault.dismiss_key_log_alert().await
}

// ---------- Shared vaults ----------

#[tauri::command]
pub async fn create_vault(state: State<'_, AppState>, name: String) -> Result<VaultView> {
    state.vault.create_vault(&name).await
}

#[tauri::command]
pub async fn rename_vault(
    state: State<'_, AppState>,
    vault_id: String,
    name: String,
) -> Result<()> {
    state.vault.rename_vault(&vault_id, &name).await
}

#[tauri::command]
pub async fn list_members(
    state: State<'_, AppState>,
    vault_id: String,
) -> Result<Vec<VaultMember>> {
    state.vault.list_members(&vault_id).await
}

#[tauri::command]
pub async fn add_member(
    state: State<'_, AppState>,
    vault_id: String,
    account: AccountLookup,
    role: VaultRole,
) -> Result<()> {
    state.vault.add_member(&vault_id, &account, role).await
}

#[tauri::command]
pub async fn change_role(
    state: State<'_, AppState>,
    vault_id: String,
    account_id: String,
    role: VaultRole,
) -> Result<()> {
    state.vault.change_role(&vault_id, &account_id, role).await
}

#[tauri::command]
pub async fn remove_member(
    state: State<'_, AppState>,
    vault_id: String,
    account_id: String,
) -> Result<()> {
    state.vault.remove_member(&vault_id, &account_id).await
}

#[tauri::command]
pub async fn leave_vault(state: State<'_, AppState>, vault_id: String) -> Result<()> {
    state.vault.leave_vault(&vault_id).await
}

#[tauri::command]
pub async fn move_item(
    state: State<'_, AppState>,
    item_id: String,
    to_vault_id: String,
) -> Result<Item> {
    state.vault.move_item(&item_id, &to_vault_id).await
}

#[tauri::command]
pub async fn copy_item(
    state: State<'_, AppState>,
    item_id: String,
    to_vault_id: String,
) -> Result<Item> {
    state.vault.copy_item(&item_id, &to_vault_id).await
}

// ---------- Families ----------

#[tauri::command]
pub async fn get_family(state: State<'_, AppState>) -> Result<FamilyState> {
    state.vault.get_family().await
}

#[tauri::command]
pub async fn create_family(state: State<'_, AppState>) -> Result<()> {
    state.vault.create_family().await
}

#[tauri::command]
pub async fn invite_to_family(state: State<'_, AppState>, account: AccountLookup) -> Result<()> {
    state.vault.invite_to_family(&account).await
}

#[tauri::command]
pub async fn accept_family_invite(state: State<'_, AppState>, family_id: String) -> Result<()> {
    state.vault.accept_family_invite(&family_id).await
}

#[tauri::command]
pub async fn decline_family_invite(state: State<'_, AppState>, family_id: String) -> Result<()> {
    state.vault.decline_family_invite(&family_id).await
}

#[tauri::command]
pub async fn cancel_family_invite(state: State<'_, AppState>, account_id: String) -> Result<()> {
    state.vault.cancel_family_invite(&account_id).await
}

#[tauri::command]
pub async fn remove_family_member(state: State<'_, AppState>, account_id: String) -> Result<()> {
    state.vault.remove_family_member(&account_id).await
}

#[tauri::command]
pub async fn leave_family(state: State<'_, AppState>) -> Result<()> {
    state.vault.leave_family().await
}

#[tauri::command]
pub async fn delete_family(state: State<'_, AppState>) -> Result<()> {
    state.vault.delete_family().await
}

// ---------- Share links ----------

#[tauri::command]
pub async fn create_share_link(
    state: State<'_, AppState>,
    item_id: String,
    options: ShareLinkOptions,
) -> Result<CreatedShareLink> {
    state.vault.create_share_link(&item_id, options).await
}

#[tauri::command]
pub async fn list_share_links(state: State<'_, AppState>) -> Result<Vec<ShareLinkInfo>> {
    state.vault.list_share_links().await
}

#[tauri::command]
pub async fn revoke_share_link(state: State<'_, AppState>, id: String) -> Result<()> {
    state.vault.revoke_share_link(&id).await
}

#[tauri::command]
pub async fn fetch_share_link(
    state: State<'_, AppState>,
    server_url: String,
    id: String,
) -> Result<ShareLinkResponse> {
    state.vault.fetch_share_link(&server_url, &id).await
}

#[tauri::command]
pub async fn open_share_link(
    state: State<'_, AppState>,
    ciphertext: String,
    key: String,
    passphrase: Option<String>,
) -> Result<SharedItem> {
    state
        .vault
        .open_share_link(ciphertext, key, passphrase.map(Zeroizing::new))
        .await
}

// ---------- Emergency access ----------

#[tauri::command]
pub async fn list_emergency_contacts(
    state: State<'_, AppState>,
) -> Result<EmergencyContactsResponse> {
    state.vault.list_emergency_contacts().await
}

#[tauri::command]
pub async fn add_emergency_contact(
    state: State<'_, AppState>,
    account: AccountLookup,
    wait_days: u32,
    access_level: EmergencyAccessLevel,
    scope: EmergencyScope,
) -> Result<EmergencyContactRecord> {
    state
        .vault
        .add_emergency_contact(&account, wait_days, access_level, scope)
        .await
}

#[tauri::command]
pub async fn remove_emergency_contact(state: State<'_, AppState>, id: String) -> Result<()> {
    state.vault.remove_emergency_contact(&id).await
}

/// `request`, `deny` or `approve`.
#[tauri::command]
pub async fn emergency_action(
    state: State<'_, AppState>,
    id: String,
    action: String,
) -> Result<()> {
    state.vault.emergency_action(&id, &action).await
}

#[tauri::command]
pub async fn rotate_vault_key(state: State<'_, AppState>, vault_id: String) -> Result<()> {
    state.vault.rotate_vault_key(&vault_id).await
}

#[tauri::command]
pub async fn renew_emergency_key(
    state: State<'_, AppState>,
    id: String,
    account: AccountLookup,
) -> Result<()> {
    state.vault.renew_emergency_key(&id, &account).await
}

#[tauri::command]
pub async fn take_over_account(
    state: State<'_, AppState>,
    id: String,
    contact_password: String,
    new_password: String,
) -> Result<NewRecoveryKit> {
    state
        .vault
        .take_over_account(
            &id,
            Zeroizing::new(contact_password),
            Zeroizing::new(new_password),
        )
        .await
}

#[tauri::command]
pub async fn enable_organiser_recovery(
    state: State<'_, AppState>,
    account: AccountLookup,
    wait_days: u32,
) -> Result<EmergencyContactRecord> {
    state
        .vault
        .enable_organiser_recovery(&account, wait_days)
        .await
}

#[tauri::command]
pub async fn open_emergency_access(
    state: State<'_, AppState>,
    id: String,
) -> Result<EmergencyVaultView> {
    state.vault.open_emergency_access(&id).await
}

#[tauri::command]
pub async fn emergency_attachment(
    state: State<'_, AppState>,
    id: String,
    item_id: String,
    attachment_id: String,
) -> Result<Response> {
    Ok(Response::new(
        state
            .vault
            .emergency_attachment(&id, &item_id, &attachment_id)
            .await?,
    ))
}
