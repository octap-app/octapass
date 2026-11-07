//! A stored passkey: one entry of a login's `details.passkeys`.

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::PrivateKey;
use crate::encoding::b64_decode;
use crate::error::{Error, Result};
use crate::item;

/// Everything needed to sign in with a passkey. It lives only inside an item's encrypted details.
///
/// The first three fields are the display fields every client already shows; entries without the
/// rest (passkeys a client only knows about, such as imported display data) can't sign.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRecord {
    pub rp_id: String,
    pub user_name: String,
    /// RFC 3339, e.g. `2026-10-24T09:30:00.000Z`.
    pub created_at: String,
    /// base64url, 16 random bytes for passkeys created here.
    pub credential_id: String,
    /// base64url, chosen by the relying party.
    pub user_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    /// base64url of the unencrypted PKCS#8 DER private key.
    pub private_key: String,
    /// Always 0: synced passkeys can't keep a counter consistent across devices.
    pub sign_count: u32,
    /// base64url, 32 random bytes: the key behind the PRF extension (plan 05, *PRF on Octa Pass's
    /// own passkeys*). Passkeys made before it have none and answer without PRF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_secret: Option<String>,
    #[serde(flatten)]
    #[zeroize(skip)]
    pub extra: Map<String, Value>,
}

impl PasskeyRecord {
    /// Reads a full record from an item's passkey entry, or `None` for a display-only entry.
    pub fn from_item(passkey: &item::Passkey) -> Option<Self> {
        serde_json::to_value(passkey)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
    }

    pub fn to_item(&self) -> item::Passkey {
        serde_json::to_value(self)
            .and_then(serde_json::from_value)
            .expect("a record is a valid item passkey")
    }

    pub fn credential_id_bytes(&self) -> Result<Vec<u8>> {
        b64_decode(&self.credential_id).map_err(|_| Error::InvalidItem)
    }

    /// The PRF extension's output for `input`: `HMAC-SHA-256(secret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖
    /// input))`, WebAuthn's salt over CTAP's `hmac-secret` (Octa Pass always verifies the user, so
    /// one secret). `None` for a passkey with no PRF secret.
    pub fn prf(&self, input: &[u8]) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let Some(secret) = &self.prf_secret else {
            return Ok(None);
        };
        let secret = zeroize::Zeroizing::new(b64_decode(secret).map_err(|_| Error::InvalidItem)?);
        let mut salt = Sha256::new();
        salt.update(b"WebAuthn PRF\x00");
        salt.update(input);
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).map_err(|_| Error::InvalidItem)?;
        mac.update(&salt.finalize());
        Ok(Some(zeroize::Zeroizing::new(
            mac.finalize().into_bytes().into(),
        )))
    }

    pub(crate) fn private_key(&self) -> Result<PrivateKey> {
        let der = zeroize::Zeroizing::new(b64_decode(&self.private_key)?);
        PrivateKey::from_pkcs8(&der)
    }
}

impl fmt::Debug for PasskeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyRecord")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// Formats Unix milliseconds as RFC 3339 in UTC, the way JavaScript's `toISOString` does.
pub(crate) fn iso_timestamp(unix_ms: u64) -> String {
    let (days, ms_of_day) = (unix_ms / 86_400_000, unix_ms % 86_400_000);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01 (never negative here).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let seconds = ms_of_day / 1000;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        ms_of_day % 1000
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn timestamps_match_to_iso_string() {
        assert_eq!(iso_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_792_800_000_123), "2026-10-24T00:00:00.123Z");
        assert_eq!(iso_timestamp(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn item_round_trip_keeps_unknown_fields() {
        let entry = json!({
            "rpId": "example.com", "userName": "a", "createdAt": "2026-10-24T00:00:00.000Z",
            "credentialId": "AQID", "userHandle": "BA", "privateKey": "c2VjcmV0", "signCount": 0,
            "fromTheFuture": true,
        });
        let passkey: item::Passkey = serde_json::from_value(entry.clone()).unwrap();
        let record = PasskeyRecord::from_item(&passkey).unwrap();
        assert_eq!(record.credential_id_bytes().unwrap(), [1, 2, 3]);
        assert_eq!(serde_json::to_value(record.to_item()).unwrap(), entry);
        assert!(!format!("{record:?}").contains("c2VjcmV0"));
    }

    #[test]
    fn display_only_entries_are_not_records() {
        let passkey: item::Passkey = serde_json::from_value(json!({
            "rpId": "example.com", "userName": "a", "createdAt": "2026-10-24T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(PasskeyRecord::from_item(&passkey), None);
    }
}
