//! The Windows 11 passkey provider in the app: the Settings switch, the words Windows shows, and
//! on Windows the COM server and keeping Windows' list of passkeys current. The logic is in
//! `octapass-windows-passkey`, and `octapass_desktop_vault::windows_passkey` joins it to the vault.
//!
//! The state lives in Windows (a provider is registered or isn't, and the user enables it in
//! Settings), so there's nothing to store: it's per device and never synced. Off by default,
//! because nothing is registered until the user turns it on.

use octapass_windows_passkey::Purpose;
use serde::Serialize;

use crate::menu::Language;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    /// This Windows has the API and the app is installed from its package.
    pub available: bool,
    /// Turned on here: Windows knows Octa Pass as a provider.
    pub registered: bool,
    /// Also turned on in Windows Settings, the last step only Windows can ask for.
    pub enabled: bool,
}

/// The line Windows Hello shows under the user name.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn hint(language: Language, purpose: Purpose, site: &str) -> String {
    match (language, purpose) {
        (Language::English, Purpose::Create) => format!("Save a passkey for {site}"),
        (Language::English, Purpose::SignIn) => format!("Sign in to {site}"),
        (Language::Arabic, Purpose::Create) => format!("حفظ مفتاح مرور لـ {site}"),
        (Language::Arabic, Purpose::SignIn) => format!("تسجيل الدخول إلى {site}"),
    }
}

/// The heading of the account chooser.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn choose_account(language: Language, site: &str) -> String {
    match language {
        Language::English => format!("Choose an account for {site}"),
        Language::Arabic => format!("اختر حسابًا لـ {site}"),
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ProviderStatus;

    pub fn status() -> ProviderStatus {
        ProviderStatus::default()
    }

    pub fn set(_enabled: bool, _vault: &octapass_desktop_vault::Vault) -> Result<(), String> {
        Err("The passkey provider is only on Windows 11.".into())
    }

    pub fn open_settings() {}
}

#[cfg(windows)]
mod platform {
    use std::sync::Arc;

    use octapass_desktop_vault::model::SessionStatus;
    use octapass_desktop_vault::windows_passkey::{PluginVault, credential_metadata};
    use octapass_desktop_vault::{Event, Vault};
    use octapass_windows_passkey::windows::{self as provider, Words};
    use octapass_windows_passkey::{ACTIVATION_ARGUMENT, Purpose, ctap};
    use tauri::{AppHandle, Manager};

    use super::ProviderStatus;
    use crate::commands::AppState;
    use crate::menu::{Language, MenuLanguage};

    pub fn status() -> ProviderStatus {
        let status = provider::status();
        ProviderStatus {
            available: status.available,
            registered: status.registered,
            enabled: status.enabled,
        }
    }

    pub fn set(enabled: bool, vault: &Vault) -> Result<(), String> {
        if enabled {
            let info = ctap::authenticator_info(&octapass_core::passkey::AAGUID, &[-7, -8]);
            provider::register(&info).map_err(|error| error.to_string())?;
            refresh(vault);
            Ok(())
        } else {
            provider::unregister().map_err(|error| error.to_string())
        }
    }

    pub fn open_settings() {
        provider::open_settings();
    }

    /// Windows lists the account's passkeys in its autofill. A locked vault keeps the list it
    /// has; it's names, like macOS's identity store.
    fn refresh(vault: &Vault) {
        if let Ok(credentials) = credential_metadata(vault)
            && let Err(error) = provider::replace_credentials(&credentials)
        {
            eprintln!("passkey provider: {error}");
        }
    }

    struct AppWords(AppHandle);

    impl AppWords {
        fn language(&self) -> Language {
            self.0.state::<MenuLanguage>().get()
        }
    }

    impl Words for AppWords {
        fn hint(&self, purpose: Purpose, site: &str) -> String {
            super::hint(self.language(), purpose, site)
        }
        fn choose_account(&self, site: &str) -> String {
            super::choose_account(self.language(), site)
        }
        fn right_to_left(&self) -> bool {
            self.language() == Language::Arabic
        }
    }

    /// Serves Windows' calls. When Windows started the app for one, the window stays hidden
    /// unless the vault needs its lock screen.
    pub fn start(app: &AppHandle, vault: Arc<Vault>, args: &[String]) {
        if !provider::status().available {
            return;
        }
        if args.iter().any(|arg| arg == ACTIVATION_ARGUMENT)
            && let Some(window) = app.get_webview_window(crate::MAIN)
        {
            let _ = window.hide();
        }
        let handle = app.clone();
        let show_lock_screen = Box::new(move || crate::show_main(&handle));
        let runtime = tauri::async_runtime::handle().inner().clone();
        provider::serve(
            Box::new(PluginVault::new(vault, runtime, show_lock_screen)),
            Box::new(AppWords(app.clone())),
        );
    }

    /// Keeps Windows' list in step with the vault; signing out empties it. Off this call's stack,
    /// which may hold the vault, and it decrypts the vault's items.
    pub fn on_event(app: &AppHandle, event: &Event) {
        let signed_out = match event {
            Event::Session(snapshot) => snapshot.session.status == SessionStatus::SignedOut,
            Event::ItemsChanged => false,
            _ => return,
        };
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            if !provider::status().registered {
                return;
            }
            if signed_out {
                let _ = provider::replace_credentials(&[]);
            } else if let Some(state) = app.try_state::<AppState>() {
                refresh(&state.vault);
            }
        });
    }
}

#[cfg(windows)]
pub use platform::{on_event, start};

#[tauri::command]
pub fn windows_passkey_status() -> ProviderStatus {
    platform::status()
}

#[tauri::command]
pub async fn windows_passkey_set(
    state: tauri::State<'_, crate::commands::AppState>,
    enabled: bool,
) -> Result<ProviderStatus, String> {
    platform::set(enabled, &state.vault)?;
    Ok(platform::status())
}

#[tauri::command]
pub fn windows_passkey_open_settings() {
    platform::open_settings();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_what_is_happening_in_each_language() {
        assert_eq!(
            hint(Language::English, Purpose::SignIn, "example.com"),
            "Sign in to example.com"
        );
        assert_eq!(
            hint(Language::English, Purpose::Create, "example.com"),
            "Save a passkey for example.com"
        );
        for purpose in [Purpose::Create, Purpose::SignIn] {
            let arabic = hint(Language::Arabic, purpose, "example.com");
            assert!(arabic.contains("example.com") && !arabic.is_ascii());
        }
        assert!(choose_account(Language::Arabic, "example.com").contains("example.com"));
        assert_eq!(
            choose_account(Language::English, "example.com"),
            "Choose an account for example.com"
        );
    }

    #[test]
    fn elsewhere_the_switch_stays_hidden() {
        #[cfg(not(windows))]
        assert_eq!(windows_passkey_status(), ProviderStatus::default());
    }
}
