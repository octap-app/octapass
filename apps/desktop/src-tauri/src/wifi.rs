//! The computer's Wi-Fi for the vault window (`src/wifi.ts`): the connected and in-range marks,
//! importing saved networks, and `wifi://joined` when the computer joins a network, for "Save
//! this network?". Calls block (scans, the system's password prompts), so they run off the UI
//! thread.

use std::sync::Arc;
use std::time::Duration;

use octapass_wifi::{Error, Features, Permission, SavedNetwork, Sighting, WifiSystem};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

/// How often the current network is checked for joins. Only its name is read; nothing is stored.
const JOIN_CHECK_EVERY: Duration = Duration::from_secs(10);
/// How long a location prompt waits for the user's answer.
const PERMISSION_WAIT: Duration = Duration::from_secs(60);

pub struct WifiState {
    pub wifi: Arc<dyn WifiSystem>,
}

impl WifiState {
    pub fn new() -> Self {
        Self {
            wifi: Arc::from(octapass_wifi::platform()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Failure {
    code: &'static str,
    message: String,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = match error {
            Error::NoWifi => "unsupported",
            Error::Denied => "denied",
            Error::Failed(_) => "failed",
        };
        Failure {
            code,
            message: error.to_string(),
        }
    }
}

async fn blocking<T: Send + 'static>(
    wifi: &Arc<dyn WifiSystem>,
    call: impl FnOnce(&dyn WifiSystem) -> octapass_wifi::Result<T> + Send + 'static,
) -> Result<T, Failure> {
    let wifi = Arc::clone(wifi);
    tauri::async_runtime::spawn_blocking(move || call(wifi.as_ref()))
        .await
        .map_err(|error| Failure {
            code: "failed",
            message: error.to_string(),
        })?
        .map_err(Failure::from)
}

#[tauri::command]
pub fn wifi_features(state: State<'_, WifiState>) -> Features {
    state.wifi.features()
}

#[tauri::command]
pub fn wifi_permission(state: State<'_, WifiState>) -> Permission {
    state.wifi.permission()
}

/// Shows the system's location prompt (on macOS, from the main thread) and waits for the answer.
#[tauri::command]
pub async fn wifi_request_permission(
    app: AppHandle,
    state: State<'_, WifiState>,
) -> Result<Permission, Failure> {
    let wifi = Arc::clone(&state.wifi);
    if wifi.permission() != Permission::Prompt {
        wifi.request_permission();
        return Ok(wifi.permission());
    }
    let asker = Arc::clone(&wifi);
    app.run_on_main_thread(move || asker.request_permission())
        .map_err(|error| Failure {
            code: "failed",
            message: error.to_string(),
        })?;
    let started = std::time::Instant::now();
    while wifi.permission() == Permission::Prompt && started.elapsed() < PERMISSION_WAIT {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(wifi.permission())
}

#[tauri::command]
pub async fn wifi_current(state: State<'_, WifiState>) -> Result<Option<String>, Failure> {
    blocking(&state.wifi, |wifi| wifi.current()).await
}

#[tauri::command]
pub async fn wifi_nearby(
    state: State<'_, WifiState>,
    rescan: bool,
) -> Result<Vec<Sighting>, Failure> {
    blocking(&state.wifi, move |wifi| wifi.nearby(rescan)).await
}

#[tauri::command]
pub async fn wifi_saved(state: State<'_, WifiState>) -> Result<Vec<SavedNetwork>, Failure> {
    blocking(&state.wifi, |wifi| wifi.saved()).await
}

/// The chosen networks with their passwords: the system may ask first, once per network.
#[tauri::command]
pub async fn wifi_read_passwords(
    state: State<'_, WifiState>,
    ssids: Vec<String>,
) -> Result<Vec<SavedNetwork>, Failure> {
    blocking(&state.wifi, move |wifi| wifi.read_passwords(&ssids)).await
}

/// Emits `wifi://joined` with the network's name each time the computer moves to a new network.
/// The first check only notes where it is: being on a network when the app starts isn't a join.
pub fn watch_joins(app: AppHandle, wifi: Arc<dyn WifiSystem>) {
    tauri::async_runtime::spawn(async move {
        let mut last = None;
        let mut first = true;
        loop {
            let current = {
                let wifi = Arc::clone(&wifi);
                tauri::async_runtime::spawn_blocking(move || wifi.current().ok().flatten())
                    .await
                    .ok()
                    .flatten()
            };
            let joined = joined(&mut last, current, first);
            first = false;
            if let Some(ssid) = joined {
                let _ = app.emit("wifi://joined", ssid);
            }
            tokio::time::sleep(JOIN_CHECK_EVERY).await;
        }
    });
}

/// The network just joined, if `current` is a different one from `last`.
fn joined(last: &mut Option<String>, current: Option<String>, first: bool) -> Option<String> {
    let changed = current.is_some() && *last != current;
    *last = current.clone();
    if changed && !first { current } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_are_moves_to_a_new_network() {
        let mut last = None;
        let home = || Some("Home".to_owned());
        assert_eq!(
            joined(&mut last, home(), true),
            None,
            "already on it at start"
        );
        assert_eq!(joined(&mut last, home(), false), None);
        assert_eq!(joined(&mut last, None, false), None, "left");
        assert_eq!(joined(&mut last, home(), false), home(), "came back");
        assert_eq!(
            joined(&mut last, Some("Cafe".into()), false).as_deref(),
            Some("Cafe")
        );
    }

    #[test]
    fn failures_carry_a_code() {
        let failure = Failure::from(Error::Denied);
        assert_eq!(serde_json::to_value(failure).unwrap()["code"], "denied");
    }
}
