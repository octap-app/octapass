//! Linux: NetworkManager over the system D-Bus.
//!
//! The current network is the Wi-Fi device's `ActiveAccessPoint`, networks in range its access
//! points (`RequestScan` asks for a new scan), and saved networks the `802-11-wireless`
//! connections. Their keys come from `GetSecrets`, which NetworkManager answers for the user's own
//! connections and, through polkit, may ask the user's password for system-wide ones.

use crate::Security;

/// A connection's `802-11-wireless-security.key-mgmt` (and `auth-alg`), as NetworkManager writes them.
pub fn security_from_key_mgmt(key_mgmt: Option<&str>, auth_alg: Option<&str>) -> Option<Security> {
    Some(match key_mgmt {
        // No security section at all: an open network.
        None | Some("owe") => Security::Open,
        Some("none")
            if auth_alg == Some("open") || auth_alg == Some("shared") || auth_alg.is_none() =>
        {
            Security::Wep
        }
        Some("ieee8021x") => Security::Wep,
        Some("wpa-psk") => Security::Wpa2,
        Some("sae") => Security::Wpa3,
        Some("wpa-eap") => Security::Wpa2Enterprise,
        Some("wpa-eap-suite-b-192") => Security::Wpa3Enterprise,
        _ => return None,
    })
}

#[cfg(target_os = "linux")]
pub use system::NetworkManager;

#[cfg(target_os = "linux")]
mod system {
    use std::collections::HashMap;

    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};
    use zeroize::Zeroizing;

    use super::security_from_key_mgmt;
    use crate::{
        Error, Features, Permission, Result, SavedNetwork, Sighting, WifiSystem, ssid_from_bytes,
        strongest_first,
    };

    const NM: &str = "org.freedesktop.NetworkManager";
    const WIFI_DEVICE: u32 = 2;
    const WIRELESS: &str = "802-11-wireless";
    const SECURITY: &str = "802-11-wireless-security";

    type Settings = HashMap<String, HashMap<String, OwnedValue>>;

    pub struct NetworkManager;

    fn failed(error: zbus::Error) -> Error {
        match &error {
            zbus::Error::MethodError(name, _, _)
                if name.as_str().ends_with("PermissionDenied")
                    || name.as_str().ends_with("AccessDenied") =>
            {
                Error::Denied
            }
            _ => Error::Failed(error.to_string()),
        }
    }

    fn proxy<'a>(bus: &Connection, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(bus, NM, path, interface).map_err(failed)
    }

    fn bus() -> Result<Connection> {
        Connection::system().map_err(|_| Error::NoWifi)
    }

    fn wifi_devices(bus: &Connection) -> Result<Vec<OwnedObjectPath>> {
        let nm = proxy(bus, "/org/freedesktop/NetworkManager", NM)?;
        let devices: Vec<OwnedObjectPath> =
            nm.call("GetDevices", &()).map_err(|_| Error::NoWifi)?;
        let wifi: Vec<_> = devices
            .into_iter()
            .filter(|path| {
                proxy(bus, path.as_str(), "org.freedesktop.NetworkManager.Device")
                    .and_then(|device| device.get_property::<u32>("DeviceType").map_err(failed))
                    .is_ok_and(|kind| kind == WIFI_DEVICE)
            })
            .collect();
        if wifi.is_empty() {
            Err(Error::NoWifi)
        } else {
            Ok(wifi)
        }
    }

    fn access_point(bus: &Connection, path: &OwnedObjectPath) -> Option<Sighting> {
        let ap = proxy(
            bus,
            path.as_str(),
            "org.freedesktop.NetworkManager.AccessPoint",
        )
        .ok()?;
        let ssid = ssid_from_bytes(&ap.get_property::<Vec<u8>>("Ssid").ok()?)?;
        let signal = ap.get_property::<u8>("Strength").ok()?.min(100);
        Some(Sighting { ssid, signal })
    }

    fn text(section: Option<&HashMap<String, OwnedValue>>, key: &str) -> Option<String> {
        String::try_from(section?.get(key)?.try_clone().ok()?).ok()
    }

    fn network(settings: &Settings) -> Option<SavedNetwork> {
        let wireless = settings.get(WIRELESS)?;
        let ssid =
            ssid_from_bytes(&Vec::<u8>::try_from(wireless.get("ssid")?.try_clone().ok()?).ok()?)?;
        let hidden = wireless
            .get("hidden")
            .and_then(|v| bool::try_from(v.try_clone().ok()?).ok())
            .unwrap_or(false);
        let security_section = settings.get(SECURITY);
        let security = security_from_key_mgmt(
            text(security_section, "key-mgmt").as_deref(),
            text(security_section, "auth-alg").as_deref(),
        );
        Some(SavedNetwork {
            ssid,
            security,
            hidden,
            password: None,
        })
    }

    /// The Wi-Fi connections NetworkManager has saved, with their D-Bus paths.
    fn connections(bus: &Connection) -> Result<Vec<(OwnedObjectPath, SavedNetwork)>> {
        let settings = proxy(
            bus,
            "/org/freedesktop/NetworkManager/Settings",
            "org.freedesktop.NetworkManager.Settings",
        )?;
        let paths: Vec<OwnedObjectPath> = settings.call("ListConnections", &()).map_err(failed)?;
        let mut out: Vec<(OwnedObjectPath, SavedNetwork)> = Vec::new();
        for path in paths {
            let Ok(connection) = proxy(
                bus,
                path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            ) else {
                continue;
            };
            let Ok(settings) = connection.call::<_, _, Settings>("GetSettings", &()) else {
                continue;
            };
            drop(connection);
            if let Some(network) = network(&settings)
                && !out.iter().any(|(_, n)| n.ssid == network.ssid)
            {
                out.push((path, network));
            }
        }
        Ok(out)
    }

    impl WifiSystem for NetworkManager {
        fn features(&self) -> Features {
            Features {
                current: true,
                nearby: true,
                saved_networks: true,
                joins: true,
            }
        }

        fn permission(&self) -> Permission {
            // NetworkManager doesn't ask for location access.
            Permission::Unsupported
        }

        fn request_permission(&self) {}

        fn current(&self) -> Result<Option<String>> {
            let bus = bus()?;
            for device in wifi_devices(&bus)? {
                let wireless = proxy(
                    &bus,
                    device.as_str(),
                    "org.freedesktop.NetworkManager.Device.Wireless",
                )?;
                let active: OwnedObjectPath =
                    wireless.get_property("ActiveAccessPoint").map_err(failed)?;
                if active.as_str() != "/"
                    && let Some(sighting) = access_point(&bus, &active)
                {
                    return Ok(Some(sighting.ssid));
                }
            }
            Ok(None)
        }

        fn nearby(&self, rescan: bool) -> Result<Vec<Sighting>> {
            let bus = bus()?;
            let mut all = Vec::new();
            for device in wifi_devices(&bus)? {
                let wireless = proxy(
                    &bus,
                    device.as_str(),
                    "org.freedesktop.NetworkManager.Device.Wireless",
                )?;
                if rescan {
                    // Refused when the last scan was moments ago: the current list is fine then.
                    let _ = wireless.call::<_, _, ()>(
                        "RequestScan",
                        &(HashMap::<&str, zbus::zvariant::Value>::new(),),
                    );
                }
                let points: Vec<OwnedObjectPath> =
                    wireless.call("GetAllAccessPoints", &()).map_err(failed)?;
                all.extend(points.iter().filter_map(|path| access_point(&bus, path)));
            }
            Ok(strongest_first(all))
        }

        fn saved(&self) -> Result<Vec<SavedNetwork>> {
            Ok(connections(&bus()?)?
                .into_iter()
                .map(|(_, network)| network)
                .collect())
        }

        fn read_passwords(&self, ssids: &[String]) -> Result<Vec<SavedNetwork>> {
            let bus = bus()?;
            let saved = connections(&bus)?;
            let mut out = Vec::new();
            for ssid in ssids {
                let Some((path, network)) = saved.iter().find(|(_, n)| &n.ssid == ssid) else {
                    out.push(SavedNetwork::named(ssid));
                    continue;
                };
                let mut network = network.clone();
                let secrets = proxy(
                    &bus,
                    path.as_str(),
                    "org.freedesktop.NetworkManager.Settings.Connection",
                )
                .and_then(|connection| {
                    connection
                        .call::<_, _, Settings>("GetSecrets", &(SECURITY,))
                        .map_err(failed)
                });
                if let Ok(secrets) = secrets {
                    let section = secrets.get(SECURITY);
                    network.password = text(section, "psk")
                        .or_else(|| text(section, "wep-key0"))
                        .filter(|p| !p.is_empty())
                        .map(Zeroizing::new);
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
    fn reads_networkmanager_security() {
        assert_eq!(security_from_key_mgmt(None, None), Some(Security::Open));
        assert_eq!(
            security_from_key_mgmt(Some("none"), Some("open")),
            Some(Security::Wep)
        );
        assert_eq!(
            security_from_key_mgmt(Some("wpa-psk"), None),
            Some(Security::Wpa2)
        );
        assert_eq!(
            security_from_key_mgmt(Some("sae"), None),
            Some(Security::Wpa3)
        );
        assert_eq!(
            security_from_key_mgmt(Some("wpa-eap"), None),
            Some(Security::Wpa2Enterprise)
        );
        assert_eq!(
            security_from_key_mgmt(Some("wpa-eap-suite-b-192"), None),
            Some(Security::Wpa3Enterprise)
        );
        assert_eq!(security_from_key_mgmt(Some("something-new"), None), None);
    }
}
