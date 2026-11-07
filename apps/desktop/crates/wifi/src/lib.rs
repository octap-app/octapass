//! The device's Wi-Fi for the desktop app (plan 01, Wi-Fi): the network it's on, the networks in
//! range, and the networks it has saved, with their passwords where the system gives them.
//!
//! - **macOS:** CoreWLAN for the current network and scans (macOS gives apps network names only
//!   with location access), `networksetup` for the saved networks, and the System keychain for
//!   their passwords through `security`, which shows macOS's own administrator prompt.
//! - **Windows:** the Native Wi-Fi API (`wlanapi`): the current connection, the available network
//!   list, and the WLAN profiles with their keys (Windows gives the key only to administrators).
//! - **Linux:** NetworkManager over D-Bus, with the secrets through its agent (polkit may ask).
//!
//! What the systems print or return is parsed by plain functions in each module, compiled and
//! tested everywhere; only the calls into the OS are behind `cfg`. Nothing here stores anything.

use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod linux;
pub mod macos;
pub mod windows;

/// How a network is secured, as the vault's `WifiSecurity` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Security {
    Open,
    Wep,
    Wpa,
    WpaWpa2,
    Wpa2,
    Wpa2Wpa3,
    Wpa3,
    Wpa2Enterprise,
    Wpa3Enterprise,
}

/// The system's location permission, which macOS (and Windows 11 24H2) need before telling apps
/// network names. `Unsupported`: the system doesn't ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    Granted,
    Denied,
    Prompt,
    Unsupported,
}

/// What this computer can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    pub current: bool,
    pub nearby: bool,
    pub saved_networks: bool,
    pub joins: bool,
}

/// A network in range. `signal` is 0–100.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sighting {
    pub ssid: String,
    pub signal: u8,
}

/// A network saved on this computer. The password is there only after [`WifiSystem::read_passwords`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SavedNetwork {
    pub ssid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Zeroizing<String>>,
}

impl SavedNetwork {
    pub fn named(ssid: impl Into<String>) -> Self {
        Self {
            ssid: ssid.into(),
            security: None,
            hidden: false,
            password: None,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// No Wi-Fi hardware, or the Wi-Fi service isn't running.
    #[error("this computer has no Wi-Fi")]
    NoWifi,
    /// Location access (or the Wi-Fi service's own check) refused.
    #[error("the system didn't allow it")]
    Denied,
    #[error("{0}")]
    Failed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The computer's Wi-Fi. Calls block (a scan takes seconds, a password waits for the user's
/// answer to the system's prompt), so callers run them off the UI thread.
pub trait WifiSystem: Send + Sync {
    fn features(&self) -> Features;
    fn permission(&self) -> Permission;
    /// Shows the system's location prompt if it hasn't been answered. On macOS, call it on the
    /// main thread; the answer comes later, through [`WifiSystem::permission`].
    fn request_permission(&self);
    /// The network the computer is on; `None` when it's on none, or the system won't say.
    fn current(&self) -> Result<Option<String>>;
    /// Networks in range, strongest first, one per name. `rescan` scans again first.
    fn nearby(&self, rescan: bool) -> Result<Vec<Sighting>>;
    /// The saved networks, without passwords.
    fn saved(&self) -> Result<Vec<SavedNetwork>>;
    /// The chosen saved networks with their passwords, one prompt at a time where the system asks.
    /// A password the system won't give is left out; the network is still returned.
    fn read_passwords(&self, ssids: &[String]) -> Result<Vec<SavedNetwork>>;
}

/// This computer's Wi-Fi.
pub fn platform() -> Box<dyn WifiSystem> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::Mac::new());
    #[cfg(windows)]
    return Box::new(windows::Windows);
    #[cfg(target_os = "linux")]
    return Box::new(linux::NetworkManager);
    #[allow(unreachable_code)]
    Box::new(Unsupported)
}

/// A system Octa Pass can't read Wi-Fi on.
pub struct Unsupported;

impl WifiSystem for Unsupported {
    fn features(&self) -> Features {
        Features {
            current: false,
            nearby: false,
            saved_networks: false,
            joins: false,
        }
    }
    fn permission(&self) -> Permission {
        Permission::Unsupported
    }
    fn request_permission(&self) {}
    fn current(&self) -> Result<Option<String>> {
        Ok(None)
    }
    fn nearby(&self, _rescan: bool) -> Result<Vec<Sighting>> {
        Ok(Vec::new())
    }
    fn saved(&self) -> Result<Vec<SavedNetwork>> {
        Ok(Vec::new())
    }
    fn read_passwords(&self, _ssids: &[String]) -> Result<Vec<SavedNetwork>> {
        Ok(Vec::new())
    }
}

/// Signal from dBm (-100 is nothing, -50 or stronger is full) to 0–100.
pub fn signal_from_dbm(dbm: i64) -> u8 {
    ((dbm + 100) * 2).clamp(0, 100) as u8
}

/// One sighting per name, the strongest, strongest first. Hidden networks (no name) are left out.
pub fn strongest_first(sightings: impl IntoIterator<Item = Sighting>) -> Vec<Sighting> {
    let mut best: Vec<Sighting> = Vec::new();
    for sighting in sightings {
        if sighting.ssid.is_empty() {
            continue;
        }
        match best.iter_mut().find(|s| s.ssid == sighting.ssid) {
            Some(existing) if existing.signal < sighting.signal => *existing = sighting,
            Some(_) => {}
            None => best.push(sighting),
        }
    }
    best.sort_by(|a, b| b.signal.cmp(&a.signal).then_with(|| a.ssid.cmp(&b.ssid)));
    best
}

/// A network name from its raw bytes: SSIDs are up to 32 bytes, usually UTF-8.
pub fn ssid_from_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_owned();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_follows_dbm() {
        assert_eq!(signal_from_dbm(-100), 0);
        assert_eq!(signal_from_dbm(-120), 0);
        assert_eq!(signal_from_dbm(-75), 50);
        assert_eq!(signal_from_dbm(-50), 100);
        assert_eq!(signal_from_dbm(-30), 100);
    }

    #[test]
    fn sightings_keep_the_strongest_of_each_name() {
        let s = |ssid: &str, signal| Sighting {
            ssid: ssid.into(),
            signal,
        };
        assert_eq!(
            strongest_first([s("Cafe", 30), s("", 90), s("Home", 70), s("Cafe", 55)]),
            [s("Home", 70), s("Cafe", 55)]
        );
    }

    #[test]
    fn names_come_from_bytes() {
        assert_eq!(ssid_from_bytes(b"Home\0\0").as_deref(), Some("Home"));
        assert_eq!(ssid_from_bytes("مقهى".as_bytes()).as_deref(), Some("مقهى"));
        assert_eq!(ssid_from_bytes(b""), None);
    }

    #[test]
    fn saved_networks_serialize_like_the_vault_types() {
        let mut network = SavedNetwork::named("Home");
        network.security = Some(Security::Wpa2Wpa3);
        network.password = Some(Zeroizing::new("pw".into()));
        assert_eq!(
            serde_json::to_value(&network).unwrap(),
            serde_json::json!({ "ssid": "Home", "security": "wpa2Wpa3", "password": "pw" })
        );
        assert_eq!(serde_json::to_value(Permission::Prompt).unwrap(), "prompt");
    }
}
