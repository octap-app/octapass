//! Settings → Browser extension, and the vault window's offer of the extension: which supported
//! browsers this computer has, which are connected (have the native messaging manifest), and
//! which the extension has reached the app from (`octapass_native_host::seen`, noted by the
//! bridge). Connecting and disconnecting are the Browser menu's (`integration`). Getting the
//! extension opens its page for that browser (`octapass_native_host::stores`).

use std::process::Command;

use octapass_desktop_vault::VaultError;
use octapass_native_host::manifests::{self, Browser, Locations};
use octapass_native_host::{ipc, seen};
use serde::Serialize;

use crate::integration;

type Result<T> = std::result::Result<T, VaultError>;

/// A supported browser on this computer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentBrowser {
    /// "Chrome", "Edge", "Brave", "Chromium", "Firefox".
    name: &'static str,
    /// Where it gets the extension: `chrome`, `edge` or `firefox`.
    store: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserExtensionStatus {
    browsers: Vec<PresentBrowser>,
    /// Those with the manifest, by the same names.
    connected: Vec<&'static str>,
    /// The browsers the extension has reached this app from, as the bridge names them ("Google
    /// Chrome"). None means it most likely isn't installed.
    seen: Vec<String>,
}

fn failed(error: impl ToString) -> VaultError {
    VaultError::unexpected(error.to_string())
}

fn status() -> BrowserExtensionStatus {
    let locations = Locations::for_user();
    let present = locations
        .as_ref()
        .map(manifests::present)
        .unwrap_or_default();
    let connected = locations
        .as_ref()
        .map(manifests::installed)
        .unwrap_or_default();
    BrowserExtensionStatus {
        browsers: present
            .into_iter()
            .map(|browser| PresentBrowser {
                name: browser.name(),
                store: browser.store().id(),
            })
            .collect(),
        connected: connected.into_iter().map(Browser::name).collect(),
        seen: ipc::data_dir()
            .map(|dir| seen::read(&dir))
            .unwrap_or_default()
            .into_iter()
            .map(|one| one.browser)
            .collect(),
    }
}

#[tauri::command]
pub fn browser_extension_status() -> BrowserExtensionStatus {
    status()
}

/// The Browser menu's Connect: a manifest for each browser on this computer.
#[tauri::command]
pub fn browser_extension_connect() -> Result<BrowserExtensionStatus> {
    integration::install().map_err(failed)?;
    Ok(status())
}

#[tauri::command]
pub fn browser_extension_disconnect() -> Result<BrowserExtensionStatus> {
    integration::uninstall().map_err(failed)?;
    Ok(status())
}

/// Opens where `browser` gets the extension. The address is the app's own, never the page's.
#[tauri::command]
pub fn browser_extension_get(browser: String) -> Result<()> {
    let browser = Browser::from_name(&browser)
        .ok_or_else(|| failed(format!("{browser} isn't a supported browser")))?;
    open(browser, browser.store().page()).map_err(failed)
}

/// In that browser where it can be started by name (Linux), otherwise in the default browser.
fn open(browser: Browser, url: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let _ = browser;
        // The default browser, without a console window.
        Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
            .map(reap)
    }
    #[cfg(not(windows))]
    {
        let programs: &[&str] = match browser {
            Browser::Chrome => &["google-chrome", "google-chrome-stable"],
            Browser::Chromium => &["chromium", "chromium-browser"],
            Browser::Edge => &["microsoft-edge", "microsoft-edge-stable"],
            Browser::Brave => &["brave-browser", "brave"],
            Browser::Firefox => &["firefox"],
        };
        for program in programs {
            if let Ok(child) = Command::new(program).arg(url).spawn() {
                reap(child);
                return Ok(());
            }
        }
        Command::new("xdg-open").arg(url).spawn().map(reap)
    }
}

/// Waits for it on a thread of its own, so it doesn't linger as a zombie once it exits.
fn reap(mut child: std::process::Child) {
    std::thread::spawn(move || child.wait());
}
