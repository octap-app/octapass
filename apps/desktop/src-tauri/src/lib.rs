//! The Octa Pass desktop app for Windows and Linux: the web vault's UI in a Tauri window, backed by
//! the native vault (`octapass-desktop-vault`), with device unlock, a quick-access window on a global
//! shortcut, a tray icon and opening at login for running in the background, auto-type, the native
//! messaging bridge for the browser extension and the computer's Wi-Fi. On a Mac, Octa Pass is the
//! native app in `apps/macos` (plan 19).

// The Mac app is the native one now (plan 19); this one stopped building for macOS when its Mac
// parts (AutoFill, Safes in Finder, Credential Exchange, links) were removed.
#[cfg(target_os = "macos")]
compile_error!(
    "The Tauri desktop app is for Windows and Linux only. On a Mac, build the native app in apps/macos: pnpm build:macos (plan 19)."
);

mod autotype;
mod background;
mod bridge;
mod clipboard;
mod commands;
mod connect;
mod files;
mod integration;
mod menu;
mod organisations;
mod quick;
mod sharing;
mod ssh;
mod toolkit;
mod tray;
mod wifi;
mod windows_passkey;

use std::sync::Arc;
use std::time::Duration;

use octapass_api::DeviceInfo;
use octapass_desktop_vault::cli_session::{self, CliGrants};
use octapass_desktop_vault::model::SessionStatus;
use octapass_desktop_vault::{Config, Event, Vault};
use octapass_login_item::HIDDEN_ARG;
use octapass_native_host::ipc;
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

use crate::commands::AppState;

pub(crate) const MAIN: &str = "main";
const PWNED_PASSWORDS_URL: &str = "https://api.pwnedpasswords.com";
const SYNC_EVERY: Duration = Duration::from_secs(120);
const BACKUP_CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

pub fn run() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = integration::run_cli(&args) {
        std::process::exit(code);
    }
    if let Some(code) = files::run_cli(&args) {
        std::process::exit(code);
    }
    // Opened at login: stay in the tray, without the vault window.
    let hidden = args.iter().any(|arg| arg == HIDDEN_ARG);

    let app = tauri::Builder::default()
        // First, so a second copy hands over and exits before anything else starts: opening the app
        // again shows the running one's window.
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if !args.iter().any(|arg| arg == HIDDEN_ARG) {
                show_main(app);
            }
        }))
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_shortcuts([quick::SHORTCUT, autotype::SHORTCUT])
                .expect("the global shortcuts parse")
                .with_handler(quick::on_shortcut)
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .menu(menu::build)
        .on_menu_event(menu::on_event)
        .setup(move |app| {
            let handle = app.handle().clone();
            let data_dir = ipc::data_dir().ok_or("no data folder for this user")?;
            let vault = Vault::new(
                Config {
                    data_dir: data_dir.clone(),
                    device: device_info(),
                    pwned_passwords_url: PWNED_PASSWORDS_URL.into(),
                },
                Arc::from(octapass_device_unlock::platform()),
                Box::new(move |event| forward(&handle, event)),
            )?;
            app.manage(AppState {
                vault: Arc::clone(&vault),
            });
            watch_screen_lock(Arc::clone(&vault));
            app.manage(connect::ConnectState::default());
            connect::start_if_enabled(app.handle());
            app.manage(menu::MenuLanguage::default());
            app.manage(files::FilesState::default());
            files::watch_requests(app.handle().clone());
            app.manage(toolkit::Hashing::default());
            app.manage(autotype::AutoTypeState::new());
            let wifi = wifi::WifiState::new();
            wifi::watch_joins(app.handle().clone(), Arc::clone(&wifi.wifi));
            app.manage(wifi);

            app.manage(ssh::SshState::new(
                app.handle().clone(),
                Arc::clone(&vault),
                data_dir.clone(),
            ));
            ssh::start_if_enabled(app.handle());
            start_in_background(app.handle(), &data_dir);

            let cli = Arc::clone(&vault);
            let cli_endpoint = cli_session::endpoint(&data_dir);
            tauri::async_runtime::spawn(async move {
                let grants = Arc::new(CliGrants::default());
                if let Err(error) =
                    cli_session::serve(cli, grants, cli_endpoint, bridge::cli_peer).await
                {
                    eprintln!("CLI bridge stopped: {error}");
                }
            });
            let bridge = Arc::clone(&vault);
            tauri::async_runtime::spawn(async move {
                if let Err(error) =
                    bridge::serve(bridge, ipc::endpoint(&data_dir), bridge::host_check()).await
                {
                    eprintln!("browser bridge stopped: {error}");
                }
            });
            #[cfg(windows)]
            windows_passkey::start(app.handle(), Arc::clone(&vault), &args);
            tauri::async_runtime::spawn(back_up_periodically(Arc::clone(&vault)));
            tauri::async_runtime::spawn(sync_periodically(app.handle().clone(), vault));
            quick::setup(app.handle());
            if !hidden {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the vault window keeps the app running for quick access, the browser and the
            // agents. The tray's Quit (and the menu's) ends it.
            if window.label() == MAIN
                && let WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
                let _ = window.hide();
            }
            // Files dropped on the window: the Files screen may use these paths from now on.
            if window.label() == MAIN
                && let WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event
            {
                window.state::<files::FilesState>().grant(paths);
                let _ = window.emit("files://dropped", paths);
            }
        })
        .invoke_handler(tauri::generate_handler![
            toolkit::toolkit_run,
            toolkit::toolkit_hash_begin,
            toolkit::toolkit_hash_update,
            toolkit::toolkit_hash_finish,
            toolkit::toolkit_fetch_jwks,
            toolkit::toolkit_fetch_host,
            toolkit::toolkit_set_ca_trust,
            commands::session_snapshot,
            commands::server_info,
            commands::start_signup,
            commands::finish_signup,
            commands::sign_in,
            commands::finish_two_step,
            commands::finish_sso,
            commands::lock,
            commands::unlock,
            commands::sign_out,
            commands::fill_gate,
            commands::set_fill_gate,
            commands::local_capabilities,
            commands::local_vaults,
            commands::create_local_vault,
            commands::restore_local_vault,
            commands::switch_local_vault,
            commands::leave_local_vault,
            commands::rename_local_vault,
            commands::delete_local_vault,
            commands::save_local_backup,
            commands::local_recovery_code,
            commands::choose_backup_folder,
            commands::clear_backup_folder,
            commands::start_turn_on_sync,
            commands::finish_turn_on_sync,
            commands::secret_key,
            commands::account_summary,
            commands::delete_account,
            commands::change_master_password,
            commands::rotate_secret_key,
            commands::start_password_reset,
            commands::verify_password_reset,
            commands::finish_password_reset,
            commands::cancel_password_reset,
            commands::two_step_status,
            commands::start_totp_setup,
            commands::confirm_totp_setup,
            commands::renew_recovery_codes,
            commands::disable_two_step,
            commands::remove_security_key,
            commands::unlock_methods,
            commands::enable_device_unlock,
            commands::disable_device_unlock,
            commands::unlock_with_device,
            commands::stay_unlocked_status,
            commands::set_stay_unlocked,
            commands::unlock_stay_unlocked,
            commands::confirm_master_password,
            commands::confirm_with_device,
            commands::list_vaults,
            commands::list_items,
            commands::get_item,
            commands::save_item,
            commands::delete_item,
            commands::restore_item,
            commands::add_attachment,
            commands::get_attachment,
            commands::remove_attachment,
            commands::storage_usage,
            organisations::get_organisation,
            organisations::create_organisation,
            organisations::rename_organisation,
            organisations::delete_organisation,
            organisations::accept_org_invite,
            organisations::decline_org_invite,
            organisations::list_org_members,
            organisations::invite_org_member,
            organisations::cancel_org_invite,
            organisations::set_org_member_role,
            organisations::remove_org_member,
            organisations::leave_organisation,
            organisations::list_org_groups,
            organisations::create_org_group,
            organisations::rename_org_group,
            organisations::delete_org_group,
            organisations::add_org_group_member,
            organisations::remove_org_group_member,
            organisations::list_org_vaults,
            organisations::create_org_vault,
            organisations::delete_org_vault,
            organisations::link_org_vault_group,
            organisations::unlink_org_vault_group,
            organisations::get_org_access,
            organisations::apply_org_access,
            organisations::rotate_org_vault,
            organisations::set_org_policies,
            organisations::get_org_sso,
            organisations::save_org_sso,
            organisations::save_org_saml,
            organisations::remove_org_sso,
            organisations::test_org_sso,
            organisations::list_org_events,
            organisations::get_org_scim,
            organisations::create_org_scim_token,
            organisations::revoke_org_scim_token,
            sharing::list_devices,
            sharing::rename_device,
            sharing::sign_out_device,
            sharing::security_log,
            sharing::list_service_accounts,
            sharing::create_service_account,
            sharing::revoke_service_account,
            connect::connect_state,
            connect::set_connect_enabled,
            connect::connect_revoke_client,
            sharing::my_fingerprint,
            sharing::lookup_account,
            sharing::mark_verified,
            sharing::key_log_state,
            sharing::dismiss_key_log_alert,
            sharing::create_vault,
            sharing::rename_vault,
            sharing::list_members,
            sharing::add_member,
            sharing::change_role,
            sharing::remove_member,
            sharing::leave_vault,
            sharing::move_item,
            sharing::copy_item,
            sharing::get_family,
            sharing::create_family,
            sharing::invite_to_family,
            sharing::accept_family_invite,
            sharing::decline_family_invite,
            sharing::cancel_family_invite,
            sharing::remove_family_member,
            sharing::leave_family,
            sharing::delete_family,
            sharing::create_share_link,
            sharing::list_share_links,
            sharing::revoke_share_link,
            sharing::fetch_share_link,
            sharing::open_share_link,
            sharing::list_emergency_contacts,
            sharing::add_emergency_contact,
            sharing::remove_emergency_contact,
            sharing::emergency_action,
            sharing::open_emergency_access,
            sharing::emergency_attachment,
            sharing::renew_emergency_key,
            sharing::take_over_account,
            sharing::enable_organiser_recovery,
            sharing::rotate_vault_key,
            commands::sync,
            commands::import_items,
            commands::export_items,
            commands::export_file,
            commands::record_export,
            commands::import_file,
            commands::review_import,
            commands::finish_import,
            commands::cancel_import,
            commands::read_qr_codes,
            commands::summarize_qr_scans,
            commands::health_inputs,
            commands::lookup_email_breaches,
            commands::health_data,
            commands::masked_email_request,
            commands::site_icon,
            commands::totp_code,
            commands::item_versions,
            commands::restore_item_version,
            commands::next_hotp_code,
            commands::set_hotp_counter,
            commands::equivalent_domains,
            commands::save_equivalent_domains,
            commands::generate_password_for_site,
            commands::check_breached,
            commands::copy_field,
            commands::set_language,
            commands::hide_quick_access,
            commands::show_main_window,
            background::background_status,
            background::background_set_tray,
            background::background_set_open_at_login,
            autotype::auto_type,
            autotype::auto_type_status,
            autotype::open_accessibility_settings,
            wifi::wifi_features,
            wifi::wifi_permission,
            wifi::wifi_request_permission,
            wifi::wifi_current,
            wifi::wifi_nearby,
            wifi::wifi_saved,
            wifi::wifi_read_passwords,
            files::describe_files,
            files::choose_files,
            files::encrypt_files,
            files::decrypt_files,
            files::find_file_recipient,
            files::own_file_recipient,
            files::context_menu_status,
            files::install_context_menu,
            files::remove_context_menu,
            files::list_safes,
            files::create_safe,
            files::set_safe_sync,
            files::sync_safe,
            files::safe_entries,
            files::safe_add_files,
            files::safe_create_folder,
            files::safe_rename,
            files::safe_delete,
            files::safe_save_file,
            files::safe_mount,
            files::safe_lock,
            files::safe_lock_problems,
            files::delete_safe,
            windows_passkey::windows_passkey_status,
            windows_passkey::windows_passkey_set,
            windows_passkey::windows_passkey_open_settings,
            ssh::ssh_generate,
            ssh::ssh_read,
            ssh::ssh_write,
            ssh::ssh_agent_status,
            ssh::ssh_agent_set_enabled,
            ssh::ssh_config_connect,
            ssh::ssh_config_disconnect,
            ssh::ssh_home_scan,
            ssh::ssh_home_read,
            ssh::ssh_home_write,
        ])
        .build(tauri::generate_context!())
        .expect("Octa Pass failed to start");

    app.run(|_, _| {});
}

/// The tray icon and opening at login (`background.rs`). The tray library can panic where the
/// system has no AppIndicator library (Linux); the app runs on without the icon, and Settings says
/// why.
fn start_in_background(app: &AppHandle, data_dir: &std::path::Path) {
    let background = background::BackgroundState::load(data_dir);
    background.at_startup();
    let visible = background.tray();
    app.manage(background);
    app.manage(tray::TrayState::default());
    let created =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tray::create(app, visible)));
    let error = match created {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error.to_string(),
        Err(panic) => panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_else(|| "the tray icon couldn't be made".into()),
    };
    eprintln!("no tray icon: {error}");
    app.state::<background::BackgroundState>()
        .set_tray_error(error);
}

pub(crate) fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Session, item and sharing changes go to every window: the vault and quick access stay in step.
fn forward(app: &AppHandle, event: Event) {
    #[cfg(windows)]
    windows_passkey::on_event(app, &event);
    match event {
        Event::Session(snapshot) => {
            // A Safe locks with the vault, before anything else hears of it.
            if snapshot.session.status != SessionStatus::Unlocked
                && let Some(files) = app.try_state::<files::FilesState>()
            {
                files.lock_all();
            }
            tray::session_changed(
                app,
                matches!(snapshot.session.status, SessionStatus::Unlocked),
            );
            let _ = app.emit("vault://session", snapshot);
        }
        Event::ItemsChanged => {
            let _ = app.emit("vault://items-changed", ());
        }
        Event::SharingChanged => {
            let _ = app.emit("vault://sharing-changed", ());
        }
        Event::SyncFailed { message } => eprintln!("sync failed: {message}"),
        // The vault is safe here; the reminder in the app takes over if this goes on.
        Event::BackupFailed { message } => eprintln!("automatic backup failed: {message}"),
    }
}

/// Automatic backups of a local vault wait for a quiet minute; this looks for one.
async fn back_up_periodically(vault: Arc<Vault>) {
    let mut interval = tokio::time::interval(BACKUP_CHECK_EVERY);
    loop {
        interval.tick().await;
        vault.auto_backup(false);
    }
}

async fn sync_periodically(app: AppHandle, vault: Arc<Vault>) {
    let mut interval = tokio::time::interval(SYNC_EVERY);
    interval.tick().await;
    loop {
        interval.tick().await;
        if let Err(error) = vault.sync().await {
            eprintln!("sync failed: {}", error.message);
        }
        if let Some(files) = app.try_state::<files::FilesState>() {
            files::sync_open_safes(&vault, &files).await;
        }
    }
}

fn device_info() -> DeviceInfo {
    let platform = if cfg!(windows) { "windows" } else { "linux" };
    DeviceInfo {
        name: format!("Octa Pass desktop ({platform})"),
        platform: platform.into(),
    }
}

/// Stay unlocked (plan 18): when the screen locks or the computer sleeps, revealing and copying
/// ask again. Polls the system's own lock state, and notices sleep as a gap between polls (the
/// thread doesn't run while the computer sleeps).
fn watch_screen_lock(vault: Arc<Vault>) {
    const POLL: std::time::Duration = std::time::Duration::from_secs(2);
    const SLEPT: std::time::Duration = std::time::Duration::from_secs(30);
    let _ = std::thread::Builder::new()
        .name("octapass-screen-lock".into())
        .spawn(move || {
            let mut was_locked = false;
            let mut last = std::time::SystemTime::now();
            loop {
                std::thread::sleep(POLL);
                let now = std::time::SystemTime::now();
                let slept = now.duration_since(last).is_ok_and(|gap| gap > SLEPT);
                last = now;
                let locked = octapass_device_unlock::screen_locked().unwrap_or(false);
                if (locked && !was_locked) || slept {
                    vault.device_locked();
                }
                was_locked = locked;
            }
        });
}
