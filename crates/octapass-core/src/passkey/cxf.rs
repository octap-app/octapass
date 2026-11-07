//! Passkeys in the FIDO Credential Exchange Format (CXF): the `passkey` credential of an item.
//!
//! The rest of a CXF file (header, accounts, items, other credential types) belongs to the
//! importers and exporters; they call these two conversions for each passkey.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key::PrivateKey;
use super::record::PasskeyRecord;
use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};

const PASSKEY: &str = "passkey";
/// Where a CXF passkey's `fido2Extensions` are kept in the record, so an export gives them back.
const EXTENSIONS_FIELD: &str = "fido2Extensions";
/// CXF's `Fido2HmacCredentials`, in `fido2Extensions`: the record's PRF secret (plan 05). Octa Pass
/// always verifies the user, so one secret is both `credWithUV` and `credWithoutUV`; an import
/// keeps `credWithUV`.
const HMAC_FIELD: &str = "hmacCredentials";
const HMAC_ALGORITHM: &str = "hmac-sha256";

/// A CXF `PasskeyCredential`. Binary fields are base64url.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct CxfPasskey {
    #[serde(rename = "type")]
    pub kind: String,
    pub credential_id: String,
    pub rp_id: String,
    pub username: String,
    pub user_display_name: String,
    pub user_handle: String,
    /// PKCS#8 DER private key.
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub fido2_extensions: Option<Value>,
}

impl core::fmt::Debug for CxfPasskey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CxfPasskey")
            .field("rp_id", &self.rp_id)
            .field("username", &self.username)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

impl PasskeyRecord {
    pub fn to_cxf(&self) -> CxfPasskey {
        CxfPasskey {
            kind: PASSKEY.into(),
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            username: self.user_name.clone(),
            user_display_name: self.user_display_name.clone().unwrap_or_default(),
            user_handle: self.user_handle.clone(),
            key: self.private_key.clone(),
            fido2_extensions: self.cxf_extensions(),
        }
    }

    /// The `fido2Extensions` an import kept, with the PRF secret as `hmacCredentials`.
    fn cxf_extensions(&self) -> Option<Value> {
        let mut extensions = self.extra.get(EXTENSIONS_FIELD).cloned();
        if let Some(secret) = &self.prf_secret {
            let hmac = serde_json::json!({
                "algorithm": HMAC_ALGORITHM,
                "credWithUV": secret,
                "credWithoutUV": secret,
            });
            match extensions.get_or_insert_with(|| Value::Object(Map::new())) {
                Value::Object(map) => {
                    map.insert(HMAC_FIELD.into(), hmac);
                }
                other => *other = serde_json::json!({ HMAC_FIELD: hmac }),
            }
        }
        extensions
    }

    /// Imports a CXF passkey. `created_at` (RFC 3339) comes from the CXF item's `creationAt`.
    /// Refuses keys this authenticator can't sign with (only ES256 and EdDSA are supported).
    pub fn from_cxf(passkey: &CxfPasskey, created_at: String) -> Result<Self> {
        let decode = |text: &str| b64_decode(text).map_err(|_| Error::InvalidItem);
        let credential_id = decode(&passkey.credential_id)?;
        let user_handle = decode(&passkey.user_handle)?;
        let key = zeroize::Zeroizing::new(decode(&passkey.key)?);
        if passkey.kind != PASSKEY || credential_id.is_empty() || passkey.rp_id.is_empty() {
            return Err(Error::InvalidItem);
        }
        if PrivateKey::from_pkcs8(&key).is_err() {
            return Err(Error::PasskeyUnsupportedAlgorithm);
        }
        let mut extra = Map::new();
        let mut prf_secret = None;
        if let Some(extensions) = &passkey.fido2_extensions {
            let mut extensions = extensions.clone();
            // A 32-byte `credWithUV` is the PRF secret; anything else stays as it came.
            if let Some(map) = extensions.as_object_mut()
                && let Some(secret) = map
                    .get(HMAC_FIELD)
                    .filter(|hmac| hmac["algorithm"] == HMAC_ALGORITHM)
                    .and_then(|hmac| hmac["credWithUV"].as_str())
                    .and_then(|secret| b64_decode(secret).ok())
                    .filter(|secret| secret.len() == 32)
            {
                prf_secret = Some(b64_encode(&secret));
                map.remove(HMAC_FIELD);
            }
            if extensions.as_object().is_none_or(|map| !map.is_empty()) {
                extra.insert(EXTENSIONS_FIELD.into(), extensions);
            }
        }
        let display_name = &passkey.user_display_name;
        Ok(Self {
            rp_id: passkey.rp_id.to_ascii_lowercase(),
            user_name: passkey.username.clone(),
            created_at,
            credential_id: b64_encode(&credential_id),
            user_handle: b64_encode(&user_handle),
            user_display_name: (!display_name.is_empty()).then(|| display_name.clone()),
            private_key: b64_encode(&key),
            sign_count: 0,
            prf_secret,
            extra,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::json;

    use super::*;
    use crate::passkey::{Caller, ClientData, CreationOptions, RequestOptions, create, get};

    fn record() -> PasskeyRecord {
        let options: CreationOptions = serde_json::from_value(json!({
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": "dXNlcg", "name": "alice", "displayName": "Alice" },
            "challenge": "AAAA",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -8 }],
        }))
        .unwrap();
        let caller: ClientData = ClientData::Web(
            serde_json::from_value::<Caller>(json!({ "origin": "https://example.com" })).unwrap(),
        );
        create(&options, &caller, 0, &mut ChaCha20Rng::seed_from_u64(1))
            .unwrap()
            .record
    }

    #[test]
    fn export_import_round_trip_still_signs() {
        let original = record();
        let cxf = original.to_cxf();
        let exported = serde_json::to_value(&cxf).unwrap();
        assert_eq!(exported["type"], "passkey");
        assert_eq!(exported["username"], "alice");
        assert_eq!(exported["userDisplayName"], "Alice");
        assert_eq!(exported["key"], original.private_key.as_str());
        let secret = original.prf_secret.as_deref().unwrap();
        assert_eq!(
            exported["fido2Extensions"],
            json!({ "hmacCredentials": { "algorithm": "hmac-sha256", "credWithUV": secret, "credWithoutUV": secret } })
        );

        let imported = PasskeyRecord::from_cxf(
            &serde_json::from_value(exported).unwrap(),
            original.created_at.clone(),
        )
        .unwrap();
        assert_eq!(imported, original);
        let request: RequestOptions =
            serde_json::from_value(json!({ "challenge": "AAAA" })).unwrap();
        let caller: ClientData = ClientData::Web(
            serde_json::from_value::<Caller>(json!({ "origin": "https://example.com" })).unwrap(),
        );
        assert!(get(&request, &caller, &imported).is_ok());
    }

    #[test]
    fn extensions_round_trip() {
        let mut cxf = record().to_cxf();
        let hmac = cxf.fido2_extensions.as_ref().unwrap()["hmacCredentials"].clone();
        cxf.fido2_extensions = Some(json!({ "credBlob": "AQID", "hmacCredentials": hmac }));
        let imported = PasskeyRecord::from_cxf(&cxf, "2026-10-24T00:00:00Z".into()).unwrap();
        assert_eq!(imported.to_cxf().fido2_extensions, cxf.fido2_extensions);

        // From a manager without PRF, or with another algorithm: no secret, the rest kept.
        cxf.fido2_extensions =
            Some(json!({ "hmacCredentials": { "algorithm": "other", "credWithUV": "AQID" } }));
        let imported = PasskeyRecord::from_cxf(&cxf, String::new()).unwrap();
        assert_eq!(imported.prf_secret, None);
        assert_eq!(imported.to_cxf().fido2_extensions, cxf.fido2_extensions);
    }

    #[test]
    fn refuses_what_it_cant_use() {
        let good = record().to_cxf();
        let with = |change: fn(&mut CxfPasskey)| {
            let mut cxf = good.clone();
            change(&mut cxf);
            PasskeyRecord::from_cxf(&cxf, String::new()).unwrap_err()
        };
        assert_eq!(with(|c| c.kind = "totp".into()), Error::InvalidItem);
        assert_eq!(
            with(|c| c.credential_id = String::new()),
            Error::InvalidItem
        );
        assert_eq!(with(|c| c.user_handle = "!".into()), Error::InvalidItem);
        assert_eq!(
            with(|c| c.key = b64_encode(b"an RSA key, say")),
            Error::PasskeyUnsupportedAlgorithm
        );
        assert!(!format!("{good:?}").contains(&good.key));
    }
}
