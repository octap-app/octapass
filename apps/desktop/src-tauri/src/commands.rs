//! The Tauri commands behind `TauriVaultService` (`src/TauriVaultService.ts`). They mirror
//! `VaultService`; the UI gets decrypted fields to render, never keys.

use std::sync::Arc;

use octapass_api::{EmailBreach, ExportFormat, ServerInfo, TotpConfirmResponse};
use octapass_core::export::EXPORT_KDF;
use octapass_core::import::{CodeLink, ImportOptions, ImportSource};
use octapass_core::tools::generator::RandomOptions;
use octapass_core::tools::totp::HotpCode;
use octapass_desktop_vault::health::HealthInputs;
use octapass_desktop_vault::masked_email::{ProviderRequest, ProviderResponse};
use octapass_desktop_vault::model::{
    AccountSummary, Item, ItemDraft, ItemSummary, NewRecoveryKit, PasswordResetResult, RecoveryKit,
    ResetStarted, SignInResult, SignupStarted, TotpSetup, TwoStepProof, TwoStepStatus,
    UnlockMethods, Vault as VaultView,
};
use octapass_desktop_vault::site_icons::IconResponse;
use octapass_desktop_vault::tools::{CopyField, QrScan, TotpCode};
use octapass_desktop_vault::vault::{
    EquivalentDomains, EquivalentDomainsInput, FileExport, ImportReview, ImportSummary,
    ItemVersion, LocalCapabilities, LocalVaultInfo, RestoreSecret, StorageUsage,
};
use octapass_desktop_vault::{ErrorCode, SessionSnapshot, Vault, VaultError};
use serde::Serialize;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::{clipboard, menu, quick};

pub struct AppState {
    pub vault: Arc<Vault>,
}

type Result<T> = std::result::Result<T, VaultError>;

#[tauri::command]
pub fn session_snapshot(state: State<'_, AppState>) -> SessionSnapshot {
    state.vault.snapshot()
}

#[tauri::command]
pub async fn server_info(state: State<'_, AppState>, server_url: String) -> Result<ServerInfo> {
    state.vault.server_info(&server_url).await
}

#[tauri::command]
pub async fn start_signup(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<SignupStarted> {
    state
        .vault
        .start_signup(&server_url, &email, Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn finish_signup(
    state: State<'_, AppState>,
    signup_id: String,
    verification_code: String,
) -> Result<RecoveryKit> {
    state
        .vault
        .finish_signup(&signup_id, &verification_code)
        .await
}

#[tauri::command]
pub async fn sign_in(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
    secret_key: Option<String>,
) -> Result<SignInResult> {
    state
        .vault
        .sign_in(
            &server_url,
            &email,
            Zeroizing::new(password),
            secret_key.map(Zeroizing::new),
        )
        .await
}

#[tauri::command]
pub async fn finish_two_step(state: State<'_, AppState>, proof: TwoStepProof) -> Result<()> {
    state.vault.finish_two_step(proof).await
}

/// Plan 03's autofill gate on this computer.
#[tauri::command]
pub fn fill_gate(state: State<'_, AppState>) -> bool {
    state.vault.fill_gate()
}

#[tauri::command]
pub fn set_fill_gate(state: State<'_, AppState>, on: bool) -> Result<()> {
    state.vault.set_fill_gate(on)
}

// ---------- Vaults on this computer only ----------

#[tauri::command]
pub async fn local_capabilities(state: State<'_, AppState>) -> Result<LocalCapabilities> {
    Ok(state.vault.local_capabilities().await)
}

#[tauri::command]
pub fn local_vaults(state: State<'_, AppState>) -> Vec<LocalVaultInfo> {
    state.vault.local_vaults()
}

#[tauri::command]
pub async fn create_local_vault(
    state: State<'_, AppState>,
    name: String,
    password: String,
) -> Result<String> {
    let code = state
        .vault
        .create_local_vault(&name, Zeroizing::new(password))
        .await?;
    Ok(code.to_string())
}

/// The file comes as the raw request body. What opens it comes in percent-encoded
/// `x-backup-password`, or `x-backup-code` and `x-backup-new-password`.
#[tauri::command]
pub async fn restore_local_vault(state: State<'_, AppState>, request: Request<'_>) -> Result<()> {
    let InvokeBody::Raw(file) = request.body() else {
        return Err(VaultError::new(
            ErrorCode::Unexpected,
            "expected the file as raw bytes",
        ));
    };
    let header = |name: &str| {
        let value = request.headers().get(name)?.to_str().ok()?;
        let decoded = percent_encoding::percent_decode_str(value).decode_utf8_lossy();
        (!decoded.is_empty()).then(|| Zeroizing::new(decoded.into_owned()))
    };
    let secret = match (
        header("x-backup-password"),
        header("x-backup-code"),
        header("x-backup-new-password"),
    ) {
        (Some(password), _, _) => RestoreSecret::Password(password),
        (None, Some(code), Some(new_password)) => {
            RestoreSecret::RecoveryCode { code, new_password }
        }
        _ => return Err(ErrorCode::InvalidBackup.into()),
    };
    state.vault.restore_local_vault(file.clone(), secret).await
}

#[tauri::command]
pub fn switch_local_vault(state: State<'_, AppState>, id: String) -> Result<()> {
    state.vault.switch_local_vault(&id)
}

#[tauri::command]
pub fn leave_local_vault(state: State<'_, AppState>) -> Result<()> {
    state.vault.leave_local_vault()
}

#[tauri::command]
pub fn rename_local_vault(state: State<'_, AppState>, name: String) -> Result<()> {
    state.vault.rename_local_vault(&name)
}

#[tauri::command]
pub async fn delete_local_vault(state: State<'_, AppState>, password: String) -> Result<()> {
    state
        .vault
        .delete_local_vault(Zeroizing::new(password))
        .await
}

/// Asks where to save a backup of the open vault, and writes it there: the file never passes
/// through the web view. `None`: cancelled.
#[tauri::command]
pub async fn save_local_backup(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(state.vault.local_backup_file_name()?)
        .add_filter("Octa Pass backup", &["octapass-backup"])
        .save_file(move |path| {
            let _ = sender.send(path);
        });
    let Some(path) = receiver
        .await
        .ok()
        .flatten()
        .and_then(|path| path.into_path().ok())
    else {
        return Ok(None);
    };
    let bytes = state.vault.create_local_backup()?;
    std::fs::write(&path, bytes)
        .map_err(|error| VaultError::unexpected(format!("backup: {error}")))?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
pub fn local_recovery_code(state: State<'_, AppState>) -> Result<String> {
    Ok(state.vault.local_recovery_code()?.to_string())
}

/// Shows the system's folder chooser and turns automatic backups on there. `None`: cancelled.
#[tauri::command]
pub async fn choose_backup_folder(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_folder(move |folder| {
        let _ = sender.send(folder);
    });
    let folder = receiver
        .await
        .ok()
        .flatten()
        .and_then(|folder| folder.into_path().ok())
        .map(|folder| folder.to_string_lossy().into_owned());
    if folder.is_some() {
        state.vault.set_backup_folder(folder.clone())?;
    }
    Ok(folder)
}

#[tauri::command]
pub fn clear_backup_folder(state: State<'_, AppState>) -> Result<()> {
    state.vault.set_backup_folder(None)
}

#[tauri::command]
pub async fn start_turn_on_sync(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<SignupStarted> {
    state
        .vault
        .start_turn_on_sync(&server_url, &email, Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn finish_turn_on_sync(
    state: State<'_, AppState>,
    signup_id: String,
    verification_code: String,
) -> Result<RecoveryKit> {
    state
        .vault
        .finish_turn_on_sync(&signup_id, &verification_code)
        .await
}

#[tauri::command]
pub async fn finish_sso(state: State<'_, AppState>, code: String) -> Result<SignInResult> {
    state.vault.finish_sso(&code).await
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) {
    state.vault.lock();
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<()> {
    state.vault.unlock(Zeroizing::new(password)).await
}

#[tauri::command]
pub async fn sign_out(state: State<'_, AppState>) -> Result<()> {
    state.vault.sign_out().await
}

#[tauri::command]
pub fn secret_key(state: State<'_, AppState>) -> Result<String> {
    state.vault.secret_key()
}

#[tauri::command]
pub async fn account_summary(state: State<'_, AppState>) -> Result<AccountSummary> {
    state.vault.account_summary().await
}

#[tauri::command]
pub async fn delete_account(
    state: State<'_, AppState>,
    confirm_email: String,
    password: String,
) -> Result<()> {
    state
        .vault
        .delete_account(&confirm_email, Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<()> {
    state
        .vault
        .change_master_password(
            Zeroizing::new(current_password),
            Zeroizing::new(new_password),
        )
        .await
}

#[tauri::command]
pub async fn rotate_secret_key(
    state: State<'_, AppState>,
    password: String,
    new_recovery_code: bool,
) -> Result<NewRecoveryKit> {
    state
        .vault
        .rotate_secret_key(Zeroizing::new(password), new_recovery_code)
        .await
}

#[tauri::command]
pub async fn start_password_reset(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
) -> Result<ResetStarted> {
    state.vault.start_password_reset(&server_url, &email).await
}

#[tauri::command]
pub async fn verify_password_reset(
    state: State<'_, AppState>,
    reset_id: String,
    verification_code: String,
) -> Result<()> {
    state
        .vault
        .verify_password_reset(&reset_id, &verification_code)
        .await
}

#[tauri::command]
pub async fn finish_password_reset(
    state: State<'_, AppState>,
    reset_id: String,
    recovery_code: String,
    password: String,
) -> Result<PasswordResetResult> {
    state
        .vault
        .finish_password_reset(&reset_id, &recovery_code, Zeroizing::new(password))
        .await
}

#[tauri::command]
pub fn cancel_password_reset(state: State<'_, AppState>, reset_id: String) {
    state.vault.cancel_password_reset(&reset_id);
}

#[tauri::command]
pub async fn two_step_status(state: State<'_, AppState>) -> Result<TwoStepStatus> {
    state.vault.two_step_status().await
}

#[tauri::command]
pub async fn start_totp_setup(state: State<'_, AppState>, password: String) -> Result<TotpSetup> {
    state.vault.start_totp_setup(Zeroizing::new(password)).await
}

#[tauri::command]
pub async fn confirm_totp_setup(
    state: State<'_, AppState>,
    code: String,
) -> Result<TotpConfirmResponse> {
    state.vault.confirm_totp_setup(&code).await
}

#[tauri::command]
pub async fn renew_recovery_codes(
    state: State<'_, AppState>,
    password: String,
) -> Result<Vec<String>> {
    state
        .vault
        .renew_recovery_codes(Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn disable_two_step(state: State<'_, AppState>, password: String) -> Result<()> {
    state.vault.disable_two_step(Zeroizing::new(password)).await
}

#[tauri::command]
pub async fn remove_security_key(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> Result<()> {
    state
        .vault
        .remove_security_key(&id, Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn unlock_methods(state: State<'_, AppState>) -> Result<UnlockMethods> {
    Ok(state.vault.unlock_methods().await)
}

#[tauri::command]
pub async fn enable_device_unlock(state: State<'_, AppState>) -> Result<()> {
    state.vault.enable_device_unlock().await
}

#[tauri::command]
pub fn disable_device_unlock(state: State<'_, AppState>) -> Result<()> {
    state.vault.disable_device_unlock()
}

#[tauri::command]
pub async fn unlock_with_device(state: State<'_, AppState>) -> Result<()> {
    state.vault.unlock_with_device().await
}

/// Stay unlocked while logged in to this computer (plan 18).
#[tauri::command]
pub async fn stay_unlocked_status(
    state: State<'_, AppState>,
) -> Result<octapass_desktop_vault::vault::StayUnlockedStatus> {
    Ok(state.vault.stay_unlocked_status().await)
}

#[tauri::command]
pub async fn set_stay_unlocked(
    state: State<'_, AppState>,
    on: bool,
) -> Result<octapass_desktop_vault::vault::StayUnlockedStatus> {
    state.vault.set_stay_unlocked(on).await
}

/// Opens the vault without a prompt when stay unlocked can; false means ask as before.
#[tauri::command]
pub async fn unlock_stay_unlocked(state: State<'_, AppState>) -> Result<bool> {
    state.vault.unlock_stay_unlocked().await
}

#[tauri::command]
pub async fn confirm_master_password(state: State<'_, AppState>, password: String) -> Result<()> {
    state
        .vault
        .confirm_master_password(Zeroizing::new(password))
        .await
}

#[tauri::command]
pub async fn confirm_with_device(state: State<'_, AppState>) -> Result<()> {
    state.vault.confirm_with_device().await
}

#[tauri::command]
pub fn list_vaults(state: State<'_, AppState>) -> Result<Vec<VaultView>> {
    state.vault.list_vaults()
}

#[tauri::command]
pub fn list_items(state: State<'_, AppState>) -> Result<Vec<ItemSummary>> {
    state.vault.list_items()
}

#[tauri::command]
pub fn get_item(state: State<'_, AppState>, id: String) -> Result<Item> {
    state.vault.get_item(&id)
}

#[tauri::command]
pub async fn save_item(state: State<'_, AppState>, draft: ItemDraft) -> Result<Item> {
    state.vault.save_item(draft).await
}

#[tauri::command]
pub async fn delete_item(state: State<'_, AppState>, id: String) -> Result<()> {
    state.vault.delete_item(&id).await
}

#[tauri::command]
pub async fn restore_item(state: State<'_, AppState>, id: String) -> Result<()> {
    state.vault.restore_item(&id).await
}

/// The file comes as the raw request body, so it isn't copied into JSON; the item id, file name
/// and media type come in percent-encoded `x-attachment-*` headers.
#[tauri::command]
pub async fn add_attachment(state: State<'_, AppState>, request: Request<'_>) -> Result<Item> {
    let InvokeBody::Raw(file) = request.body() else {
        return Err(VaultError::new(
            ErrorCode::Unexpected,
            "expected the file as raw bytes",
        ));
    };
    let header = |name: &str| {
        let value = request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok());
        let decoded =
            percent_encoding::percent_decode_str(value.unwrap_or_default()).decode_utf8_lossy();
        decoded.into_owned()
    };
    let (item_id, name, media_type) = (
        header("x-attachment-item"),
        header("x-attachment-name"),
        header("x-attachment-type"),
    );
    state
        .vault
        .add_attachment(&item_id, &name, &media_type, file.clone())
        .await
}

/// The decrypted file as raw bytes (an `ArrayBuffer` on the other side).
#[tauri::command]
pub async fn get_attachment(
    state: State<'_, AppState>,
    item_id: String,
    attachment_id: String,
) -> Result<Response> {
    Ok(Response::new(
        state.vault.get_attachment(&item_id, &attachment_id).await?,
    ))
}

#[tauri::command]
pub async fn remove_attachment(
    state: State<'_, AppState>,
    item_id: String,
    attachment_id: String,
) -> Result<Item> {
    state
        .vault
        .remove_attachment(&item_id, &attachment_id)
        .await
}

#[tauri::command]
pub async fn storage_usage(state: State<'_, AppState>) -> Result<StorageUsage> {
    state.vault.storage_usage().await
}

#[tauri::command]
pub async fn sync(state: State<'_, AppState>) -> Result<()> {
    state.vault.sync().await
}

#[tauri::command]
pub async fn import_items(state: State<'_, AppState>, drafts: Vec<ItemDraft>) -> Result<usize> {
    state.vault.import_items(drafts).await
}

/// The CXF or encrypted export, as raw bytes. The master password is checked first (plan 07).
#[tauri::command]
pub async fn export_file(
    state: State<'_, AppState>,
    format: FileExport,
    password: Option<String>,
    master_password: Option<String>,
) -> Result<Response> {
    let password = password.map(Zeroizing::new);
    if let Some(master) = master_password {
        state.vault.unlock(Zeroizing::new(master)).await?;
    }
    let file = state
        .vault
        .export_file(format, password.as_deref().map(String::as_str), EXPORT_KDF)
        .await?;
    Ok(Response::new(file.to_vec()))
}

/// "Vault exported" in the security log, once the web view has the file (any format).
#[tauri::command]
pub async fn record_export(state: State<'_, AppState>, format: ExportFormat) -> Result<()> {
    state.vault.record_export(format).await
}

/// Imports a file into the Personal vault. The file is the raw request body; the source, the
/// file's password and a KeePass key file (base64url) come in percent-encoded `x-import-*` headers.
#[tauri::command]
pub async fn import_file(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<ImportSummary> {
    let (file, source, options) = import_request(&request)?;
    let personal = personal_vault(&state)?;
    state
        .vault
        .import_file(source, file, options, &personal)
        .await
}

/// Parses a file for the import review, like `import_file`; nothing is saved yet.
#[tauri::command]
pub async fn review_import(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<ImportReview> {
    let (file, source, options) = import_request(&request)?;
    let personal = personal_vault(&state)?;
    state.vault.review_import(source, file, options, &personal)
}

#[tauri::command]
pub async fn finish_import(
    state: State<'_, AppState>,
    review_id: String,
    links: Vec<CodeLink>,
) -> Result<ImportSummary> {
    state.vault.finish_import(&review_id, &links).await
}

#[tauri::command]
pub fn cancel_import(state: State<'_, AppState>, review_id: String) {
    state.vault.cancel_import(&review_id);
}

/// The file and what the `x-import-*` headers say about it.
fn import_request<'a>(request: &'a Request<'_>) -> Result<(&'a [u8], ImportSource, ImportOptions)> {
    let InvokeBody::Raw(file) = request.body() else {
        return Err(VaultError::new(
            ErrorCode::Unexpected,
            "expected the file as raw bytes",
        ));
    };
    let header = |name: &str| {
        let value = request.headers().get(name)?.to_str().ok()?;
        let decoded = percent_encoding::percent_decode_str(value).decode_utf8_lossy();
        (!decoded.is_empty()).then(|| Zeroizing::new(decoded.into_owned()))
    };
    let source: ImportSource = header("x-import-source")
        .and_then(|source| {
            serde_json::from_value(serde_json::Value::String(source.to_string())).ok()
        })
        .ok_or_else(|| VaultError::new(ErrorCode::InvalidImportFile, "unknown import source"))?;
    let options: ImportOptions = serde_json::from_value(serde_json::json!({
        "password": header("x-import-password").as_deref().map(String::as_str),
        "keyFile": header("x-import-key-file").as_deref().map(String::as_str),
    }))
    .map_err(|_| VaultError::new(ErrorCode::InvalidImportFile, "the key file isn't base64url"))?;
    Ok((file, source, options))
}

/// Where imports go.
fn personal_vault(state: &AppState) -> Result<String> {
    state
        .vault
        .list_vaults()?
        .into_iter()
        .find(|vault| vault.vault_type == octapass_api::VaultType::Personal)
        .map(|vault| vault.id)
        .ok_or_else(|| ErrorCode::NotFound.into())
}

/// The text of every QR code in an image (the raw request body), read here on the device.
#[tauri::command]
pub async fn read_qr_codes(request: Request<'_>) -> Result<Vec<String>> {
    let InvokeBody::Raw(image) = request.body() else {
        return Err(VaultError::new(
            ErrorCode::Unexpected,
            "expected the image as raw bytes",
        ));
    };
    octapass_desktop_vault::tools::read_qr_codes(image)
}

#[tauri::command]
pub fn summarize_qr_scans(texts: Vec<String>) -> QrScan {
    octapass_desktop_vault::tools::summarize_qr_scans(&texts)
}

/// Plaintext for an export the user asked for; it becomes a file they save.
#[tauri::command]
pub fn export_items(state: State<'_, AppState>) -> Result<Vec<Item>> {
    state.vault.live_items()
}

#[tauri::command]
pub async fn health_inputs(state: State<'_, AppState>) -> Result<HealthInputs> {
    state.vault.health_inputs().await
}

/// The health report's site lists: bundled, or a newer signed file from the server.
#[tauri::command]
pub async fn health_data(
    state: State<'_, AppState>,
) -> Result<octapass_desktop_vault::HealthDataLists> {
    state.vault.health_data().await
}

#[tauri::command]
pub async fn lookup_email_breaches(
    state: State<'_, AppState>,
    address: String,
) -> Result<Vec<EmailBreach>> {
    state.vault.lookup_email_breaches(&address).await
}

/// A masked email provider call the web view can't make (no CORS). Provider API hosts only.
#[tauri::command]
pub async fn masked_email_request(
    state: State<'_, AppState>,
    request: ProviderRequest,
) -> Result<ProviderResponse> {
    state.vault.masked_email_request(request).await
}

/// A website icon from the server, which the web view can't call itself.
#[tauri::command]
pub async fn site_icon(
    state: State<'_, AppState>,
    server_url: String,
    domain: String,
) -> Result<IconResponse> {
    state.vault.site_icon(&server_url, &domain).await
}

#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, totp: String, at: Option<u64>) -> Result<TotpCode> {
    state.vault.totp(&totp, at)
}

#[tauri::command]
pub async fn item_versions(state: State<'_, AppState>, id: String) -> Result<Vec<ItemVersion>> {
    state.vault.item_versions(&id).await
}

#[tauri::command]
pub async fn restore_item_version(
    state: State<'_, AppState>,
    id: String,
    revision: u64,
) -> Result<Item> {
    state.vault.restore_item_version(&id, revision).await
}

#[tauri::command]
pub async fn next_hotp_code(state: State<'_, AppState>, id: String) -> Result<HotpCode> {
    state.vault.next_hotp_code(&id).await
}

#[tauri::command]
pub async fn set_hotp_counter(
    state: State<'_, AppState>,
    id: String,
    counter: u64,
) -> Result<Item> {
    state.vault.set_hotp_counter(&id, counter).await
}

/// Nearby: every place with its items, the place this computer is at first. `here` (the Wi-Fi
/// network it's on, a location reading) stays on this computer.
#[tauri::command]
pub fn nearby(
    state: State<'_, AppState>,
    here: octapass_core::places::Here,
) -> Result<Vec<octapass_core::places::NearbyPlace>> {
    state.vault.nearby(&here)
}

#[tauri::command]
pub fn suggest_place(
    state: State<'_, AppState>,
    item_id: String,
    here: octapass_core::places::Here,
) -> Result<Option<String>> {
    state.vault.suggest_place(&item_id, &here)
}

#[tauri::command]
pub fn equivalent_domains(state: State<'_, AppState>) -> Result<EquivalentDomains> {
    state.vault.equivalent_domains()
}

#[tauri::command]
pub async fn save_equivalent_domains(
    state: State<'_, AppState>,
    input: EquivalentDomainsInput,
) -> Result<EquivalentDomains> {
    state.vault.save_equivalent_domains(input).await
}

#[tauri::command]
pub fn generate_password_for_site(
    state: State<'_, AppState>,
    url: String,
    options: RandomOptions,
) -> Result<String> {
    Ok(state
        .vault
        .generate_password_for_site(&url, &options)?
        .to_string())
}

#[tauri::command]
pub async fn check_breached(state: State<'_, AppState>, password: String) -> Result<u64> {
    state.vault.check_breached(&Zeroizing::new(password)).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Copied {
    /// Seconds until the clipboard is cleared.
    pub clears_in: u64,
}

/// Copies an item's username, password or current code natively, so the value never passes
/// through the web view, and clears it again after a while.
#[tauri::command]
pub fn copy_field(state: State<'_, AppState>, id: String, field: CopyField) -> Result<Copied> {
    let value = state.vault.copy_value(&id, field)?;
    clipboard::copy_and_clear(value).map_err(VaultError::unexpected)?;
    Ok(Copied {
        clears_in: clipboard::CLEAR_AFTER.as_secs(),
    })
}

/// The language the vault window shows (`en`, `ar`), for the app's own menus.
#[tauri::command]
pub fn set_language(app: AppHandle, language: String) {
    let _ = menu::set_language(&app, menu::Language::from_tag(&language));
}

#[tauri::command]
pub fn hide_quick_access(app: AppHandle) {
    quick::hide(&app);
}

#[tauri::command]
pub fn show_main_window(app: AppHandle) {
    quick::hide(&app);
    crate::show_main(&app);
}
