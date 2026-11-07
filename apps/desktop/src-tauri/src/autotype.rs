//! Auto-type (plan 05): from the quick-access window (⌘↵ / Ctrl+Enter on a login), or with the
//! global shortcut, which types the login that belongs to the focused window, or opens quick
//! access to pick one when none or several do. The checks and the typing are
//! `octapass-autotype`'s; this decides what to type and where, with values that come straight
//! from the vault and never pass through a web view.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use octapass_autotype::{
    Backend, DEFAULT_SEQUENCE, Field, FocusedWindow, ItemRules, PASSWORD_SEQUENCE, Permission,
    Platform, Refusal, Request, Sequence, SequenceError,
};
use octapass_core::matching::MatchOptions;
use octapass_desktop_vault::tools::{AutoTypeItem, CopyField};
use octapass_desktop_vault::{ErrorCode, Vault, VaultError};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::commands::AppState;
use crate::{clipboard, quick};

pub const SHORTCUT: &str = "CommandOrControl+Shift+Backslash";

pub struct AutoTypeState {
    platform: Arc<dyn Platform>,
    /// The window quick access was opened over: typing goes back there.
    target: Mutex<Option<FocusedWindow>>,
}

impl AutoTypeState {
    pub fn new() -> Self {
        Self {
            platform: Arc::from(octapass_autotype::platform()),
            target: Mutex::new(None),
        }
    }

    fn target(&self) -> Option<FocusedWindow> {
        self.target
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_target(&self, window: Option<FocusedWindow>) {
        *self.target.lock().unwrap_or_else(|p| p.into_inner()) = window;
    }

    /// The focused window, unless it's Octa Pass's own.
    fn focused(&self) -> Option<FocusedWindow> {
        self.platform
            .focused_window()
            .ok()
            .flatten()
            .filter(|window| window.pid != std::process::id())
    }

    /// Called just before quick access opens.
    pub fn remember_target(&self) {
        self.set_target(self.focused());
    }
}

/// How the quick-access window was opened, sent with `quick://opened`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opened {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_type: Option<Picker>,
}

/// Opened by the auto-type shortcut: pick the login to type.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Picker {
    pub window: Option<String>,
    /// The logins that belong to the window, best first.
    pub matches: Vec<String>,
    /// Typing the only match was refused, and that login's title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AutoTyped {
    Typed {
        window: Option<String>,
    },
    /// Nothing can type here (Wayland without the portal): the password was copied instead.
    Copied {
        clears_in: u64,
    },
}

/// Everything that stops auto-type, each with a `code` for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Failure {
    Refused(Refusal),
    Vault { code: ErrorCode, message: String },
    InvalidSequence { code: &'static str, message: String },
}

impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Self {
        Failure::Refused(refusal)
    }
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        Failure::Vault {
            code: error.code,
            message: error.message,
        }
    }
}

impl From<SequenceError> for Failure {
    fn from(error: SequenceError) -> Self {
        Failure::InvalidSequence {
            code: "invalidSequence",
            message: error.to_string(),
        }
    }
}

fn rules(item: &AutoTypeItem, options: &MatchOptions) -> ItemRules {
    ItemRules {
        id: item.id.clone(),
        title: item.title.clone(),
        urls: item.urls.clone(),
        url_match: item.url_match.clone(),
        window_titles: item.window_titles.clone(),
        equivalent_domains: options.equivalent_domains.clone(),
        excluded_defaults: options.excluded_defaults.clone(),
    }
}

/// The keystrokes for `item`, with only the fields its sequence uses read from the vault.
fn actions(vault: &Vault, item: &AutoTypeItem) -> Result<Vec<octapass_autotype::Action>, Failure> {
    let default = match item.item_type.as_str() {
        "password" => PASSWORD_SEQUENCE,
        _ => DEFAULT_SEQUENCE,
    };
    let sequence = Sequence::for_item(item.sequence.as_deref(), default)?;
    let mut values: HashMap<Field, Zeroizing<String>> = HashMap::new();
    for field in sequence.fields() {
        if values.contains_key(&field) {
            continue;
        }
        let copy = match field {
            Field::Username => CopyField::Username,
            Field::Password => CopyField::Password,
            Field::Totp => CopyField::Code,
        };
        match vault.copy_value(&item.id, copy) {
            Ok(value) => values.insert(field, value),
            Err(error) if error.code == ErrorCode::NotFound => {
                return Err(Refusal::MissingField { field }.into());
            }
            Err(error) => return Err(error.into()),
        };
    }
    sequence
        .actions(&|field| values.get(&field).cloned())
        .map_err(|field| Refusal::MissingField { field }.into())
}

/// Types `id` into `target` (or whatever has focus). Blocks while typing.
fn type_item(
    app: &AppHandle,
    id: &str,
    target: Option<FocusedWindow>,
    picked: bool,
) -> Result<AutoTyped, Failure> {
    let vault = Arc::clone(&app.state::<AppState>().vault);
    let platform = Arc::clone(&app.state::<AutoTypeState>().platform);
    // Plan 03's autofill gate, before anything leaves the vault.
    vault.confirm_fill("type this login")?;
    if platform.backend() == Backend::Clipboard {
        let password = vault.copy_value(id, CopyField::Password)?;
        clipboard::copy_and_clear(password).map_err(VaultError::unexpected)?;
        return Ok(AutoTyped::Copied {
            clears_in: clipboard::CLEAR_AFTER.as_secs(),
        });
    }
    if let Permission::Missing { settings_url } = platform.permission() {
        return Err(Refusal::PermissionRequired { settings_url }.into());
    }
    let item = vault.auto_type_item(id)?;
    let rules = rules(&item, &vault.match_options().unwrap_or_default());
    // Refuse a mismatch while quick access is still up, rather than after it hid.
    if let Some(target) = &target
        && rules.matches(target).is_none()
    {
        return Err(Refusal::NoMatch {
            window: target.describe(),
        }
        .into());
    }
    let actions = actions(&vault, &item)?;
    quick::hide(app);
    let typed = octapass_autotype::run(
        &*platform,
        &Request {
            own_pid: std::process::id(),
            item: &rules,
            actions: &actions,
            target: target.as_ref(),
            picked,
        },
    )?;
    Ok(AutoTyped::Typed {
        window: typed.window,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub backend: Backend,
    pub permission: Permission,
    pub shortcut: &'static str,
}

#[tauri::command]
pub fn auto_type_status(auto: State<'_, AutoTypeState>) -> Status {
    Status {
        backend: auto.platform.backend(),
        permission: auto.platform.permission(),
        shortcut: SHORTCUT,
    }
}

/// From the quick-access window: types the login into the window quick access was opened over.
/// When that's refused, quick access comes back with the reason.
#[tauri::command]
pub async fn auto_type(app: AppHandle, id: String) -> Result<AutoTyped, Failure> {
    let target = app.state::<AutoTypeState>().target();
    let worker = app.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || type_item(&worker, &id, target, true))
            .await
            .unwrap_or_else(|error| Err(VaultError::unexpected(error.to_string()).into()));
    if result.is_err() {
        quick::reveal(&app);
    }
    result
}

/// Opened the Mac's Accessibility settings, which auto-type needed there. Windows and Linux ask
/// for no such permission, so there's nothing to open; the web UI's call stays harmless.
#[tauri::command]
pub fn open_accessibility_settings(auto: State<'_, AutoTypeState>) {
    if let Permission::Missing { settings_url } = auto.platform.permission() {
        let _ = settings_url;
    }
}

/// The global shortcut. Reading windows can take a moment, so this runs off the main thread.
pub fn on_shortcut(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || shortcut(&app));
}

fn shortcut(app: &AppHandle) {
    let auto = app.state::<AutoTypeState>();
    if quick::is_visible(app) {
        return;
    }
    let window = auto.focused();
    auto.set_target(window.clone());
    let failure = match auto.platform.permission() {
        Permission::Missing { settings_url } => {
            Some(Refusal::PermissionRequired { settings_url }.into())
        }
        Permission::Granted => None,
    };
    let matches: Vec<AutoTypeItem> = match (&window, &failure) {
        (Some(window), None) => {
            let vault = &app.state::<AppState>().vault;
            let options = vault.match_options().unwrap_or_default();
            vault
                .auto_type_items()
                .unwrap_or_default()
                .into_iter()
                .filter(|item| rules(item, &options).matches(window).is_some())
                .collect()
        }
        _ => Vec::new(),
    };
    let (failure, title) = match (&window, matches.as_slice(), failure) {
        (_, _, Some(failure)) => (Some(failure), None),
        (Some(window), [only], None) => {
            match type_item(app, &only.id, Some(window.clone()), false) {
                Ok(_) => return,
                Err(failure) => (Some(failure), Some(only.title.clone())),
            }
        }
        _ => (None, None),
    };
    quick::open(
        app,
        Opened {
            auto_type: Some(Picker {
                window: window.as_ref().map(FocusedWindow::describe),
                matches: matches.into_iter().map(|item| item.id).collect(),
                failure,
                title,
            }),
        },
    );
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn failures_carry_a_code() {
        let refused = Failure::from(Refusal::NoMatch { window: "w".into() });
        assert_eq!(
            serde_json::to_value(refused).unwrap(),
            json!({ "code": "noMatch", "window": "w" })
        );
        let vault = Failure::from(VaultError::new(ErrorCode::Locked, "locked"));
        assert_eq!(serde_json::to_value(vault).unwrap()["code"], "locked");
        let sequence = Failure::from(SequenceError::Unknown { name: "X".into() });
        assert_eq!(
            serde_json::to_value(sequence).unwrap(),
            json!({ "code": "invalidSequence", "message": "{X} isn't a placeholder" })
        );
        assert_eq!(
            serde_json::to_value(AutoTyped::Copied { clears_in: 30 }).unwrap(),
            json!({ "status": "copied", "clearsIn": 30 })
        );
    }

    #[test]
    fn the_picker_names_the_window_and_its_logins() {
        let opened = Opened {
            auto_type: Some(Picker {
                window: Some("GitHub — Safari".into()),
                matches: vec!["a".into()],
                failure: None,
                title: None,
            }),
        };
        assert_eq!(
            serde_json::to_value(opened).unwrap(),
            json!({ "autoType": { "window": "GitHub — Safari", "matches": ["a"] } })
        );
        assert_eq!(serde_json::to_value(Opened::default()).unwrap(), json!({}));
    }
}
