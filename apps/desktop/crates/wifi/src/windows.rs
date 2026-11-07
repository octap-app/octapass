//! Windows: the Native Wi-Fi API (`wlanapi`).
//!
//! Saved networks are WLAN profiles. `WlanGetProfile` with `WLAN_PROFILE_GET_PLAINTEXT_KEY` gives
//! the key in plain text only to administrators; for everyone else it stays `protected` and the
//! network comes in without its password. Since Windows 11 24H2 the Wi-Fi calls also need location
//! access for Octa Pass (Settings → Privacy & security → Location).

use zeroize::Zeroizing;

use crate::{SavedNetwork, Security};

/// The text of the first `<tag>…</tag>` in `xml` (namespaces aside), unescaped.
fn tag(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    loop {
        let start = rest.find(&format!("<{name}"))?;
        let after = &rest[start + name.len() + 1..];
        // `<name>` or `<name xmlns="…">`, not `<nameOther>`.
        if after.starts_with('>') || after.starts_with(' ') {
            let open_end = after.find('>')?;
            let body = &after[open_end + 1..];
            let close = body.find(&format!("</{name}>"))?;
            return Some(unescape(&body[..close]));
        }
        rest = after;
    }
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// A profile's `authentication` and `encryption`, as Windows writes them.
pub fn security_from_profile(
    authentication: &str,
    encryption: &str,
    transition: bool,
) -> Option<Security> {
    Some(match authentication.to_ascii_lowercase().as_str() {
        "open" if encryption.eq_ignore_ascii_case("wep") => Security::Wep,
        "open" | "owe" => Security::Open,
        "shared" => Security::Wep,
        "wpapsk" => Security::Wpa,
        "wpa2psk" => Security::Wpa2,
        "wpa3sae" if transition => Security::Wpa2Wpa3,
        "wpa3sae" => Security::Wpa3,
        "wpa" | "wpa2" => Security::Wpa2Enterprise,
        "wpa3" | "wpa3ent" | "wpa3ent192" => Security::Wpa3Enterprise,
        _ => return None,
    })
}

/// A WLAN profile's XML: the network, how it's secured, and its key when Windows gave it in plain text.
pub fn parse_profile(xml: &str) -> Option<SavedNetwork> {
    let ssid_config = tag(xml, "SSIDConfig")?;
    let ssid = tag(&ssid_config, "hex")
        .and_then(|hex| hex_bytes(&hex))
        .and_then(|bytes| crate::ssid_from_bytes(&bytes))
        .or_else(|| tag(&ssid_config, "name"))?;
    let hidden = tag(&ssid_config, "nonBroadcast").is_some_and(|v| v.trim() == "true");
    let security = tag(xml, "authentication").and_then(|auth| {
        let encryption = tag(xml, "encryption").unwrap_or_default();
        let transition = tag(xml, "transitionMode").is_some_and(|v| v.trim() == "true");
        security_from_profile(auth.trim(), encryption.trim(), transition)
    });
    let protected = tag(xml, "protected").is_some_and(|v| v.trim() == "true");
    let password = (!protected)
        .then(|| tag(xml, "keyMaterial"))
        .flatten()
        .filter(|k| !k.is_empty())
        .map(Zeroizing::new);
    Some(SavedNetwork {
        ssid,
        security,
        hidden,
        password,
    })
}

#[cfg(windows)]
pub use system::Windows;

#[cfg(windows)]
mod system {
    use std::ptr::null_mut;

    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS, HANDLE};
    use windows::Win32::NetworkManagement::WiFi::*;
    use windows::core::{GUID, PCWSTR, PWSTR};
    use zeroize::Zeroizing;

    use super::parse_profile;
    use crate::{
        Error, Features, Permission, Result, SavedNetwork, Sighting, WifiSystem, ssid_from_bytes,
        strongest_first,
    };

    pub struct Windows;

    /// An open WLAN client handle, closed when dropped.
    struct Client(HANDLE);

    impl Drop for Client {
        fn drop(&mut self) {
            // SAFETY: the handle came from WlanOpenHandle and is closed once.
            unsafe { WlanCloseHandle(self.0, None) };
        }
    }

    fn check(code: u32) -> Result<()> {
        match code {
            c if c == ERROR_SUCCESS.0 => Ok(()),
            c if c == ERROR_ACCESS_DENIED.0 => Err(Error::Denied),
            c => Err(Error::Failed(format!("wlanapi error {c}"))),
        }
    }

    fn wide(text: &[u16]) -> String {
        let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        String::from_utf16_lossy(&text[..end])
    }

    fn ssid(raw: &DOT11_SSID) -> Option<String> {
        ssid_from_bytes(&raw.ucSSID[..(raw.uSSIDLength as usize).min(32)])
    }

    impl Client {
        fn open() -> Result<Self> {
            let mut version = 0;
            let mut handle = HANDLE::default();
            // SAFETY: out-pointers to locals.
            check(unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) })
                .map_err(|_| Error::NoWifi)?;
            Ok(Client(handle))
        }

        fn interfaces(&self) -> Result<Vec<GUID>> {
            let mut list: *mut WLAN_INTERFACE_INFO_LIST = null_mut();
            // SAFETY: the list is read within its item count, then freed.
            unsafe {
                check(WlanEnumInterfaces(self.0, None, &mut list))?;
                let items = std::slice::from_raw_parts(
                    (*list).InterfaceInfo.as_ptr(),
                    (*list).dwNumberOfItems as usize,
                );
                let guids = items.iter().map(|i| i.InterfaceGuid).collect();
                WlanFreeMemory(list as _);
                if items.is_empty() {
                    Err(Error::NoWifi)
                } else {
                    Ok(guids)
                }
            }
        }

        fn current(&self, guid: &GUID) -> Result<Option<String>> {
            let mut size = 0;
            let mut data: *mut core::ffi::c_void = null_mut();
            // SAFETY: Windows allocates a WLAN_CONNECTION_ATTRIBUTES, freed after reading.
            unsafe {
                let code = WlanQueryInterface(
                    self.0,
                    guid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut size,
                    &mut data,
                    None,
                );
                if code != ERROR_SUCCESS.0 {
                    // Not connected is an error too.
                    return if code == ERROR_ACCESS_DENIED.0 {
                        Err(Error::Denied)
                    } else {
                        Ok(None)
                    };
                }
                let attributes = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
                let name = ssid(&attributes.wlanAssociationAttributes.dot11Ssid);
                WlanFreeMemory(data);
                Ok(name)
            }
        }

        fn available(&self, guid: &GUID) -> Result<Vec<Sighting>> {
            let mut list: *mut WLAN_AVAILABLE_NETWORK_LIST = null_mut();
            // SAFETY: the list is read within its item count, then freed.
            unsafe {
                check(WlanGetAvailableNetworkList(
                    self.0, guid, 0, None, &mut list,
                ))?;
                let items = std::slice::from_raw_parts(
                    (*list).Network.as_ptr(),
                    (*list).dwNumberOfItems as usize,
                );
                let sightings = items
                    .iter()
                    .filter_map(|n| {
                        Some(Sighting {
                            ssid: ssid(&n.dot11Ssid)?,
                            signal: n.wlanSignalQuality.min(100) as u8,
                        })
                    })
                    .collect::<Vec<_>>();
                WlanFreeMemory(list as _);
                Ok(sightings)
            }
        }

        fn profiles(&self, guid: &GUID, keys: bool) -> Result<Vec<SavedNetwork>> {
            let mut list: *mut WLAN_PROFILE_INFO_LIST = null_mut();
            let mut out = Vec::new();
            // SAFETY: lists and XML strings Windows allocates are read within bounds, then freed.
            unsafe {
                check(WlanGetProfileList(self.0, guid, None, &mut list))?;
                let items = std::slice::from_raw_parts(
                    (*list).ProfileInfo.as_ptr(),
                    (*list).dwNumberOfItems as usize,
                );
                for profile in items {
                    let name = profile.strProfileName;
                    let mut xml = PWSTR::null();
                    let mut flags = if keys {
                        WLAN_PROFILE_GET_PLAINTEXT_KEY
                    } else {
                        0
                    };
                    if WlanGetProfile(
                        self.0,
                        guid,
                        PCWSTR(name.as_ptr()),
                        None,
                        &mut xml,
                        Some(&mut flags),
                        None,
                    ) != ERROR_SUCCESS.0
                    {
                        continue;
                    }
                    let text = Zeroizing::new(xml.to_string().unwrap_or_default());
                    WlanFreeMemory(xml.0 as _);
                    if let Some(mut network) = parse_profile(&text) {
                        if !keys {
                            network.password = None;
                        }
                        if !out.iter().any(|n: &SavedNetwork| n.ssid == network.ssid) {
                            out.push(network);
                        }
                    } else if !wide(&name).is_empty() {
                        out.push(SavedNetwork::named(wide(&name)));
                    }
                }
                WlanFreeMemory(list as _);
            }
            Ok(out)
        }
    }

    impl WifiSystem for Windows {
        fn features(&self) -> Features {
            Features {
                current: true,
                nearby: true,
                saved_networks: true,
                joins: true,
            }
        }

        fn permission(&self) -> Permission {
            let Ok(client) = Client::open() else {
                return Permission::Unsupported;
            };
            let Ok(guids) = client.interfaces() else {
                return Permission::Unsupported;
            };
            // Windows 11 24H2 refuses network names without location access.
            match guids.first().map(|guid| client.available(guid)) {
                Some(Err(Error::Denied)) => Permission::Denied,
                _ => Permission::Granted,
            }
        }

        fn request_permission(&self) {
            // There's no prompt to show: the location settings are where it's turned on.
            let _ = std::process::Command::new("explorer")
                .arg("ms-settings:privacy-location")
                .spawn();
        }

        fn current(&self) -> Result<Option<String>> {
            let client = Client::open()?;
            for guid in client.interfaces()? {
                if let Some(name) = client.current(&guid)? {
                    return Ok(Some(name));
                }
            }
            Ok(None)
        }

        fn nearby(&self, rescan: bool) -> Result<Vec<Sighting>> {
            let client = Client::open()?;
            let guids = client.interfaces()?;
            if rescan {
                for guid in &guids {
                    // SAFETY: a request; the list refreshes within about four seconds.
                    unsafe { WlanScan(client.0, guid, None, None, None) };
                }
                std::thread::sleep(std::time::Duration::from_secs(4));
            }
            let mut all = Vec::new();
            for guid in &guids {
                all.extend(client.available(guid)?);
            }
            Ok(strongest_first(all))
        }

        fn saved(&self) -> Result<Vec<SavedNetwork>> {
            let client = Client::open()?;
            let mut all: Vec<SavedNetwork> = Vec::new();
            for guid in client.interfaces()? {
                for network in client.profiles(&guid, false)? {
                    if !all.iter().any(|n| n.ssid == network.ssid) {
                        all.push(network);
                    }
                }
            }
            Ok(all)
        }

        fn read_passwords(&self, ssids: &[String]) -> Result<Vec<SavedNetwork>> {
            let client = Client::open()?;
            let mut all: Vec<SavedNetwork> = Vec::new();
            for guid in client.interfaces()? {
                all.extend(client.profiles(&guid, true)?);
            }
            Ok(ssids
                .iter()
                .map(|ssid| {
                    all.iter()
                        .find(|n| &n.ssid == ssid)
                        .cloned()
                        .unwrap_or_else(|| SavedNetwork::named(ssid))
                })
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>Home &amp; Garden</name>
	<SSIDConfig>
		<SSID>
			<hex>486F6D6520262047617264656E</hex>
			<name>Home &amp; Garden</name>
		</SSID>
		<nonBroadcast>true</nonBroadcast>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA3SAE</authentication>
				<encryption>AES</encryption>
				<useOneX>false</useOneX>
				<transitionMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v4">true</transitionMode>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>p&lt;ss word</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>"#;

    #[test]
    fn profiles_give_the_network_and_its_key() {
        let network = parse_profile(PROFILE).unwrap();
        assert_eq!(network.ssid, "Home & Garden");
        assert!(network.hidden);
        assert_eq!(network.security, Some(Security::Wpa2Wpa3));
        assert_eq!(
            network.password.as_deref().map(String::as_str),
            Some("p<ss word")
        );
    }

    #[test]
    fn protected_keys_stay_out() {
        let protected = PROFILE
            .replace(
                "<protected>false</protected>",
                "<protected>true</protected>",
            )
            .replace("p&lt;ss word", "01000000D08C9DDF0115D1118C7A00C04FC297EB");
        assert_eq!(parse_profile(&protected).unwrap().password, None);
        let open = r#"<WLANProfile><SSIDConfig><SSID><name>Cafe</name></SSID></SSIDConfig><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption></authEncryption></security></MSM></WLANProfile>"#;
        let cafe = parse_profile(open).unwrap();
        assert_eq!(
            (
                cafe.ssid.as_str(),
                cafe.security,
                cafe.hidden,
                cafe.password
            ),
            ("Cafe", Some(Security::Open), false, None)
        );
        assert!(parse_profile("<WLANProfile><name>x</name></WLANProfile>").is_none());
    }

    #[test]
    fn reads_windows_security_names() {
        assert_eq!(
            security_from_profile("open", "WEP", false),
            Some(Security::Wep)
        );
        assert_eq!(
            security_from_profile("WPAPSK", "TKIP", false),
            Some(Security::Wpa)
        );
        assert_eq!(
            security_from_profile("WPA2PSK", "AES", false),
            Some(Security::Wpa2)
        );
        assert_eq!(
            security_from_profile("WPA3SAE", "AES", false),
            Some(Security::Wpa3)
        );
        assert_eq!(
            security_from_profile("WPA2", "AES", false),
            Some(Security::Wpa2Enterprise)
        );
        assert_eq!(
            security_from_profile("WPA3ENT192", "GCMP256", false),
            Some(Security::Wpa3Enterprise)
        );
        assert_eq!(security_from_profile("future", "x", false), None);
    }
}
