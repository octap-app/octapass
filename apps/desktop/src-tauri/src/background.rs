//! Running in the background: the tray icon and opening at login, both on by default and both for
//! this computer only (Settings → Running in the background). Closing the vault window never quits
//! the app (`lib.rs`), so quick access, the browser extension and the agents keep working; the
//! tray's Quit does.
//!
//! The tray switch is kept in `background.json` in the app's data folder. Whether the app opens at
//! login is read from the system each time ([`octapass_login_item`]), so turning it off in System
//! Settings, Task Manager or the desktop's startup settings shows here too. The first start of an
//! installed release build turns it on; after that only the person changes it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use octapass_desktop_vault::VaultError;
use octapass_login_item::{self as login_item, LoginItem};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::tray;

type Result<T> = std::result::Result<T, VaultError>;

const FILE: &str = "background.json";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    /// Show the tray icon.
    tray: bool,
    /// Opening at login has had its default (on). Until then each start of an installed app tries.
    login_item_set_up: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tray: true,
            login_item_set_up: false,
        }
    }
}

pub struct BackgroundState {
    path: PathBuf,
    settings: Mutex<Settings>,
    login_item: Option<Box<dyn LoginItem + Send + Sync>>,
    /// Why the tray icon couldn't be made, for Settings.
    tray_error: Mutex<Option<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundStatus {
    tray: bool,
    open_at_login: bool,
    /// `false` while the app runs from a disk image or from Downloads before it was moved, where
    /// opening it at login would point at a copy that goes away.
    installed: bool,
    /// `windows` or `linux`: the words differ.
    platform: &'static str,
    /// Why the tray icon or opening at login doesn't work.
    error: Option<String>,
}

impl BackgroundState {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(FILE);
        Self {
            settings: Mutex::new(read(&path)),
            path,
            login_item: login_item::system(),
            tray_error: Mutex::new(None),
        }
    }

    pub fn tray(&self) -> bool {
        self.settings.lock().unwrap().tray
    }

    pub fn set_tray_error(&self, error: String) {
        *self.tray_error.lock().unwrap() = Some(error);
    }

    /// Turns opening at login on the first time, and follows the app when it moved. Release builds
    /// only: a development build would point the login item at `target/debug`.
    pub fn at_startup(&self) {
        if cfg!(debug_assertions) {
            return;
        }
        let Some(item) = self.login_item.as_deref() else {
            return;
        };
        let Ok(program) = login_item::current_program() else {
            return;
        };
        if !login_item::is_installed(&program) {
            return;
        }
        let mut settings = self.settings.lock().unwrap();
        let first_time = !settings.login_item_set_up;
        match login_item::at_startup(item, &program, first_time) {
            Ok(_) if first_time => {
                settings.login_item_set_up = true;
                if let Err(error) = write(&self.path, &settings) {
                    eprintln!("couldn't save the background settings: {error}");
                }
            }
            Ok(_) => {}
            Err(error) => eprintln!("couldn't set up opening at login: {error}"),
        }
    }

    fn status(&self) -> BackgroundStatus {
        let tray = self.tray();
        let mut error = self.tray_error.lock().unwrap().clone().filter(|_| tray);
        let open_at_login = match self
            .login_item
            .as_deref()
            .map(|item| login_item::is_on(item))
        {
            Some(Ok(on)) => on,
            Some(Err(failure)) => {
                error.get_or_insert_with(|| failure.to_string());
                false
            }
            None => {
                error.get_or_insert_with(|| "This user has no home folder.".into());
                false
            }
        };
        BackgroundStatus {
            tray,
            open_at_login,
            installed: login_item::current_program().is_ok_and(|p| login_item::is_installed(&p)),
            platform: platform(),
            error,
        }
    }

    fn update(&self, change: impl FnOnce(&mut Settings)) -> Result<()> {
        let mut settings = self.settings.lock().unwrap();
        change(&mut settings);
        write(&self.path, &settings).map_err(failed)
    }
}

fn platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "linux" }
}

fn failed(error: impl ToString) -> VaultError {
    VaultError::unexpected(error.to_string())
}

/// The saved settings; anything unreadable is the defaults.
fn read(path: &Path) -> Settings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write(path: &Path, settings: &Settings) -> std::io::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(settings)?)
}

#[tauri::command]
pub fn background_status(state: State<'_, BackgroundState>) -> BackgroundStatus {
    state.status()
}

#[tauri::command]
pub fn background_set_tray(
    app: AppHandle,
    state: State<'_, BackgroundState>,
    visible: bool,
) -> Result<BackgroundStatus> {
    state.update(|settings| settings.tray = visible)?;
    tray::set_visible(&app, visible);
    Ok(state.status())
}

/// A change the system refuses comes back in the status's `error`, with the system's reason.
#[tauri::command]
pub fn background_set_open_at_login(
    state: State<'_, BackgroundState>,
    enabled: bool,
) -> Result<BackgroundStatus> {
    let item = state
        .login_item
        .as_deref()
        .ok_or_else(|| failed("This user has no home folder."))?;
    let changed = if enabled {
        login_item::current_program().and_then(|program| {
            if login_item::is_installed(&program) {
                item.register(&program)
            } else {
                Err(std::io::Error::other(
                    "Move Octa Pass to your Applications folder and open it from there first.",
                ))
            }
        })
    } else {
        item.unregister()
    };
    // The person chose: the default no longer applies.
    state.update(|settings| settings.login_item_set_up = true)?;
    let mut status = state.status();
    if let Err(error) = changed {
        status.error = Some(error.to_string());
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_are_on_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let settings = read(&dir.path().join(FILE));
        assert!(settings.tray);
        assert!(!settings.login_item_set_up);
        // Older or partial files keep the defaults for what they don't say.
        std::fs::write(dir.path().join(FILE), br#"{"loginItemSetUp":true}"#).unwrap();
        assert_eq!(
            read(&dir.path().join(FILE)),
            Settings {
                tray: true,
                login_item_set_up: true
            }
        );
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        assert_eq!(read(&dir.path().join(FILE)), Settings::default());
    }

    #[test]
    fn the_status_has_the_names_the_settings_read() {
        let status = BackgroundStatus {
            tray: true,
            open_at_login: false,
            installed: true,
            platform: "linux",
            error: None,
        };
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::json!({
                "tray": true,
                "openAtLogin": false,
                "installed": true,
                "platform": "linux",
                "error": null,
            })
        );
    }

    #[test]
    fn the_tray_switch_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let state = BackgroundState::load(dir.path());
        assert!(state.tray());
        state.update(|settings| settings.tray = false).unwrap();
        assert!(!BackgroundState::load(dir.path()).tray());
    }

    #[test]
    fn a_tray_error_only_matters_while_the_tray_is_on() {
        let dir = tempfile::tempdir().unwrap();
        let state = BackgroundState::load(dir.path());
        state.set_tray_error("no AppIndicator library".into());
        assert_eq!(
            state.status().error.as_deref(),
            Some("no AppIndicator library")
        );
        state.update(|settings| settings.tray = false).unwrap();
        assert_ne!(
            state.status().error.as_deref(),
            Some("no AppIndicator library")
        );
    }
}
