//! Writing a Wi-Fi network to an NFC tag (plan 01): the `application/vnd.wfa.wsc` payload, the Wi-Fi
//! Alliance's Wi-Fi Simple Configuration credential that Android's NFC service reads, so a guest
//! taps the tag and joins.
//!
//! A tag is not encrypted: anyone who taps it can read the password, so the apps say so first.

use serde::Deserialize;
use zeroize::Zeroizing;

/// The MIME type of the NDEF record holding [`wsc_credential`]'s bytes.
pub const WSC_MIME_TYPE: &str = "application/vnd.wfa.wsc";

const CREDENTIAL: u16 = 0x100e;
const NETWORK_INDEX: u16 = 0x1026;
const SSID: u16 = 0x1045;
const AUTH_TYPE: u16 = 0x1003;
const ENCRYPTION_TYPE: u16 = 0x100f;
const NETWORK_KEY: u16 = 0x1027;
const MAC_ADDRESS: u16 = 0x1020;

const AUTH_OPEN: u16 = 0x0001;
const AUTH_WPA_PSK: u16 = 0x0002;
const AUTH_WPA2_PSK: u16 = 0x0020;
const ENCRYPTION_NONE: u16 = 0x0001;
const ENCRYPTION_TKIP: u16 = 0x0004;
const ENCRYPTION_AES: u16 = 0x0008;

/// The longest network name 802.11 allows, in bytes.
const MAX_SSID: usize = 32;
/// The longest WPA key: 63 characters, or 64 hex digits.
const MAX_KEY: usize = 64;

/// The security types of a Wi-Fi item, as far as a tag can carry them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TagSecurity {
    Open,
    Wpa,
    WpaWpa2,
    Wpa2,
    /// The WPA2 half of a transition network: a phone that only reads WPA2 still joins.
    Wpa2Wpa3,
}

impl TagSecurity {
    /// `None` for what a tag can't carry: WPA3-only and Enterprise have no WSC value that Android
    /// reads, and WEP isn't joined any more.
    pub fn parse(security: &str) -> Option<Self> {
        Some(match security {
            "open" => Self::Open,
            "wpa" => Self::Wpa,
            "wpaWpa2" => Self::WpaWpa2,
            "wpa2" => Self::Wpa2,
            "wpa2Wpa3" => Self::Wpa2Wpa3,
            _ => return None,
        })
    }

    fn types(self) -> (u16, u16) {
        match self {
            Self::Open => (AUTH_OPEN, ENCRYPTION_NONE),
            Self::Wpa => (AUTH_WPA_PSK, ENCRYPTION_TKIP),
            Self::WpaWpa2 => (
                AUTH_WPA_PSK | AUTH_WPA2_PSK,
                ENCRYPTION_TKIP | ENCRYPTION_AES,
            ),
            Self::Wpa2 | Self::Wpa2Wpa3 => (AUTH_WPA2_PSK, ENCRYPTION_AES),
        }
    }
}

fn attribute(out: &mut Vec<u8>, id: u16, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("attributes are far below 64 KiB");
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
}

/// The record's payload, or `None` when the network can't go on a tag: an empty or over-long name,
/// a key too long for WPA, or a secured network with no password.
pub fn wsc_credential(
    ssid: &str,
    security: TagSecurity,
    password: Option<&str>,
) -> Option<Zeroizing<Vec<u8>>> {
    if ssid.is_empty() || ssid.len() > MAX_SSID {
        return None;
    }
    let key = match security {
        TagSecurity::Open => "",
        _ => password.filter(|key| !key.is_empty() && key.len() <= MAX_KEY)?,
    };
    let (auth, encryption) = security.types();
    let mut inner = Zeroizing::new(Vec::with_capacity(64 + ssid.len() + key.len()));
    attribute(&mut inner, NETWORK_INDEX, &[1]);
    attribute(&mut inner, SSID, ssid.as_bytes());
    attribute(&mut inner, AUTH_TYPE, &auth.to_be_bytes());
    attribute(&mut inner, ENCRYPTION_TYPE, &encryption.to_be_bytes());
    attribute(&mut inner, NETWORK_KEY, key.as_bytes());
    // The broadcast address: any access point with this name.
    attribute(&mut inner, MAC_ADDRESS, &[0xff; 6]);
    let mut payload = Zeroizing::new(Vec::with_capacity(inner.len() + 4));
    attribute(&mut payload, CREDENTIAL, &inner);
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attributes of a credential, read the way Android's `NfcWifiProtectedSetup` reads them.
    fn attributes(mut bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut found = Vec::new();
        while !bytes.is_empty() {
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            found.push((id, bytes[4..4 + length].to_vec()));
            bytes = &bytes[4 + length..];
        }
        found
    }

    /// A worked example, byte by byte, from the WSC attribute table.
    #[test]
    fn wpa2_credential_vector() {
        let payload = wsc_credential("Home", TagSecurity::Wpa2, Some("secret12")).unwrap();
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x10, 0x0e, 0x00, 0x2f,
            0x10, 0x26, 0x00, 0x01, 0x01,
            0x10, 0x45, 0x00, 0x04, b'H', b'o', b'm', b'e',
            0x10, 0x03, 0x00, 0x02, 0x00, 0x20,
            0x10, 0x0f, 0x00, 0x02, 0x00, 0x08,
            0x10, 0x27, 0x00, 0x08, b's', b'e', b'c', b'r', b'e', b't', b'1', b'2',
            0x10, 0x20, 0x00, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert_eq!(payload.as_slice(), expected);
    }

    #[test]
    fn open_networks_have_an_empty_key() {
        let payload = wsc_credential("Cafe", TagSecurity::Open, Some("ignored")).unwrap();
        let outer = attributes(&payload);
        assert_eq!(outer[0].0, CREDENTIAL);
        let inner = attributes(&outer[0].1);
        let get = |id| inner.iter().find(|(a, _)| *a == id).map(|(_, v)| v.clone());
        assert_eq!(get(AUTH_TYPE).unwrap(), [0, 1]);
        assert_eq!(get(ENCRYPTION_TYPE).unwrap(), [0, 1]);
        assert_eq!(get(NETWORK_KEY).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn transition_networks_join_as_wpa2() {
        let payload = wsc_credential("Home", TagSecurity::Wpa2Wpa3, Some("secret12")).unwrap();
        let inner = attributes(&attributes(&payload)[0].1);
        assert_eq!(inner[2], (AUTH_TYPE, vec![0, 0x20]));
        let mixed = wsc_credential("Home", TagSecurity::WpaWpa2, Some("secret12")).unwrap();
        let inner = attributes(&attributes(&mixed)[0].1);
        assert_eq!(inner[2], (AUTH_TYPE, vec![0, 0x22]));
    }

    #[test]
    fn what_a_tag_cant_carry_is_refused() {
        for security in ["wep", "wpa3", "wpa2Enterprise", "wpa3Enterprise", "new"] {
            assert_eq!(TagSecurity::parse(security), None, "{security}");
        }
        assert!(wsc_credential("", TagSecurity::Open, None).is_none());
        assert!(wsc_credential(&"x".repeat(33), TagSecurity::Open, None).is_none());
        assert!(wsc_credential("Home", TagSecurity::Wpa2, None).is_none());
        assert!(wsc_credential("Home", TagSecurity::Wpa2, Some("")).is_none());
        assert!(wsc_credential("Home", TagSecurity::Wpa2, Some(&"k".repeat(65))).is_none());
        assert!(wsc_credential("Home", TagSecurity::Wpa2, Some(&"k".repeat(64))).is_some());
    }
}
