//! macOS: CoreWLAN, `networksetup` and the System keychain.
//!
//! Since macOS 14, CoreWLAN gives apps network names only with location access (an unbundled
//! binary can't get it, so in development the names are empty). The saved networks come from
//! `networksetup -listpreferredwirelessnetworks`, which needs no permission. Their passwords are
//! "AirPort network password" items in the System keychain: `security find-generic-password` shows
//! macOS's own prompt for an administrator's name and password, once per network, and Octa Pass
//! only ever sees the password it returns.

use crate::Security;

/// The Wi-Fi device (`en0`) in `networksetup -listallhardwareports`.
pub fn parse_wifi_device(ports: &str) -> Option<String> {
    let mut lines = ports.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(port) = line.strip_prefix("Hardware Port:") else {
            continue;
        };
        if !matches!(port.trim(), "Wi-Fi" | "AirPort") {
            continue;
        }
        for line in lines.by_ref() {
            if let Some(device) = line.strip_prefix("Device:") {
                return Some(device.trim().to_owned()).filter(|d| !d.is_empty());
            }
            if line.starts_with("Hardware Port:") {
                break;
            }
        }
    }
    None
}

/// The names in `networksetup -listpreferredwirelessnetworks en0`: a heading, then one tab-indented
/// name per line (names can have spaces of their own at either end, so only the tab goes).
pub fn parse_preferred_networks(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix('\t'))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// CoreWLAN's `CWSecurity` values.
pub fn security_from_cw(value: isize) -> Option<Security> {
    Some(match value {
        0 | 14 | 15 => Security::Open,
        1 | 6 => Security::Wep,
        2 => Security::Wpa,
        3 => Security::WpaWpa2,
        4 | 5 => Security::Wpa2,
        11 => Security::Wpa3,
        13 => Security::Wpa2Wpa3,
        7..=10 => Security::Wpa2Enterprise,
        12 => Security::Wpa3Enterprise,
        _ => return None,
    })
}

/// What `security find-generic-password -w` printed: the password and a newline.
pub fn parse_keychain_password(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8(stdout.to_vec()).ok()?;
    let password = text.strip_suffix('\n').unwrap_or(&text);
    (!password.is_empty()).then(|| password.to_owned())
}

#[cfg(target_os = "macos")]
pub use system::Mac;

#[cfg(target_os = "macos")]
mod system {
    use std::process::Command;

    use objc2::rc::Retained;
    use objc2_core_location::{CLAuthorizationStatus, CLLocationManager};
    use objc2_core_wlan::{CWInterface, CWNetwork, CWWiFiClient};
    use objc2_foundation::NSSet;
    use zeroize::Zeroizing;

    use super::{
        parse_keychain_password, parse_preferred_networks, parse_wifi_device, security_from_cw,
    };
    use crate::{
        Error, Features, Permission, Result, SavedNetwork, Sighting, WifiSystem, signal_from_dbm,
        strongest_first,
    };

    const NETWORKSETUP: &str = "/usr/sbin/networksetup";
    const SECURITY: &str = "/usr/bin/security";
    const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

    pub struct Mac;

    impl Mac {
        pub fn new() -> Self {
            Mac
        }

        fn interface(&self) -> Result<Retained<CWInterface>> {
            // SAFETY: CoreWLAN's client and interface are safe to use from any thread.
            unsafe { CWWiFiClient::sharedWiFiClient().interface() }.ok_or(Error::NoWifi)
        }

        fn device(&self) -> Result<String> {
            if let Ok(iface) = self.interface()
                && let Some(name) = unsafe { iface.interfaceName() }
            {
                return Ok(name.to_string());
            }
            let ports = run(NETWORKSETUP, &["-listallhardwareports"])?;
            parse_wifi_device(&ports).ok_or(Error::NoWifi)
        }
    }

    impl Default for Mac {
        fn default() -> Self {
            Self::new()
        }
    }

    fn run(program: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| Error::Failed(e.to_string()))?;
        if !output.status.success() {
            return Err(Error::Failed(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn sightings(networks: &NSSet<CWNetwork>) -> Vec<Sighting> {
        strongest_first(networks.iter().filter_map(|network| {
            // SAFETY: plain property reads on a CWNetwork CoreWLAN returned.
            let ssid = unsafe { network.ssid() }?.to_string();
            let signal = signal_from_dbm(unsafe { network.rssiValue() } as i64);
            Some(Sighting { ssid, signal })
        }))
    }

    impl WifiSystem for Mac {
        fn features(&self) -> Features {
            Features {
                current: true,
                nearby: true,
                saved_networks: true,
                joins: true,
            }
        }

        fn permission(&self) -> Permission {
            // SAFETY: reading the authorization status has no requirements.
            let (enabled, status) = unsafe {
                let manager = CLLocationManager::new();
                (
                    CLLocationManager::locationServicesEnabled_class(),
                    manager.authorizationStatus(),
                )
            };
            if !enabled {
                return Permission::Denied;
            }
            match status {
                CLAuthorizationStatus::NotDetermined => Permission::Prompt,
                CLAuthorizationStatus::Denied | CLAuthorizationStatus::Restricted => {
                    Permission::Denied
                }
                _ => Permission::Granted,
            }
        }

        fn request_permission(&self) {
            // The manager has to outlive the prompt, and lives on the main thread that asked.
            thread_local! {
                static MANAGER: std::cell::OnceCell<Retained<CLLocationManager>> = const { std::cell::OnceCell::new() };
            }
            MANAGER.with(|cell| {
                // SAFETY: called on the main thread, as `WifiSystem::request_permission` requires.
                let manager = cell.get_or_init(|| unsafe { CLLocationManager::new() });
                unsafe { manager.requestWhenInUseAuthorization() };
            });
        }

        fn current(&self) -> Result<Option<String>> {
            let iface = self.interface()?;
            // SAFETY: a property read; nil without location access or when not associated.
            Ok(unsafe { iface.ssid() }
                .map(|ssid| ssid.to_string())
                .filter(|s| !s.is_empty()))
        }

        fn nearby(&self, rescan: bool) -> Result<Vec<Sighting>> {
            let iface = self.interface()?;
            if rescan {
                // SAFETY: a blocking scan of a few seconds, off the UI thread.
                if let Ok(networks) = unsafe { iface.scanForNetworksWithName_error(None) } {
                    return Ok(sightings(&networks));
                }
            }
            // SAFETY: the results of the system's last scan.
            Ok(unsafe { iface.cachedScanResults() }
                .map(|networks| sightings(&networks))
                .unwrap_or_default())
        }

        fn saved(&self) -> Result<Vec<SavedNetwork>> {
            let device = self.device()?;
            let names = parse_preferred_networks(&run(
                NETWORKSETUP,
                &["-listpreferredwirelessnetworks", &device],
            )?);
            // With location access, CoreWLAN's profiles also say how each network is secured.
            let mut profiles = Vec::new();
            if let Ok(iface) = self.interface()
                && let Some(configuration) = unsafe { iface.configuration() }
            {
                let set = unsafe { configuration.networkProfiles() };
                for i in 0..set.count() {
                    let profile = set.objectAtIndex(i);
                    if let Some(ssid) = unsafe { profile.ssid() } {
                        profiles.push((
                            ssid.to_string(),
                            security_from_cw(unsafe { profile.security() }.0),
                        ));
                    }
                }
            }
            Ok(names
                .into_iter()
                .map(|ssid| {
                    let security = profiles
                        .iter()
                        .find(|(name, _)| *name == ssid)
                        .and_then(|(_, security)| *security);
                    SavedNetwork {
                        security,
                        ..SavedNetwork::named(ssid)
                    }
                })
                .collect())
        }

        fn read_passwords(&self, ssids: &[String]) -> Result<Vec<SavedNetwork>> {
            let saved = self.saved()?;
            let mut out = Vec::new();
            for ssid in ssids {
                let mut network = saved
                    .iter()
                    .find(|n| &n.ssid == ssid)
                    .cloned()
                    .unwrap_or_else(|| SavedNetwork::named(ssid));
                // macOS asks for an administrator's name and password in its own window. A
                // refusal, or no such item (an open network), leaves the password out.
                let output = Command::new(SECURITY)
                    .args([
                        "find-generic-password",
                        "-D",
                        "AirPort network password",
                        "-a",
                        ssid,
                        "-w",
                        SYSTEM_KEYCHAIN,
                    ])
                    .output()
                    .map_err(|e| Error::Failed(e.to_string()))?;
                if output.status.success() {
                    let stdout = Zeroizing::new(output.stdout);
                    network.password = parse_keychain_password(&stdout).map(Zeroizing::new);
                }
                out.push(network);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_wifi_device() {
        let ports = "\nHardware Port: Ethernet\nDevice: en1\nEthernet Address: aa\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 5c:52\n\nVLAN Configurations\n===================\n";
        assert_eq!(parse_wifi_device(ports).as_deref(), Some("en0"));
        assert_eq!(
            parse_wifi_device("Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n"),
            None
        );
    }

    #[test]
    fn lists_preferred_networks_as_they_are_named() {
        let output = "Preferred networks on en0:\n\tlilas5\n\tHomeNet_5G\n\tCafé Lumen \n\tOffice-wifi\n";
        assert_eq!(
            parse_preferred_networks(output),
            ["lilas5", "HomeNet_5G", "Café Lumen ", "Office-wifi"]
        );
        assert!(parse_preferred_networks("Error: en1 is not a Wi-Fi interface.\n").is_empty());
    }

    #[test]
    fn reads_corewlan_security() {
        assert_eq!(security_from_cw(0), Some(Security::Open));
        assert_eq!(security_from_cw(3), Some(Security::WpaWpa2));
        assert_eq!(security_from_cw(4), Some(Security::Wpa2));
        assert_eq!(security_from_cw(13), Some(Security::Wpa2Wpa3));
        assert_eq!(security_from_cw(9), Some(Security::Wpa2Enterprise));
        assert_eq!(security_from_cw(12), Some(Security::Wpa3Enterprise));
        assert_eq!(security_from_cw(isize::MAX), None);
    }

    #[test]
    fn keychain_passwords_keep_their_spaces() {
        assert_eq!(
            parse_keychain_password(b" pass word \n").as_deref(),
            Some(" pass word ")
        );
        assert_eq!(parse_keychain_password(b"\n"), None);
        assert_eq!(parse_keychain_password(&[0xff, 0xfe]), None);
    }
}
