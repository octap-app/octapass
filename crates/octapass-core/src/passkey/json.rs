//! The WebAuthn Level 3 JSON forms: `PublicKeyCredentialCreationOptionsJSON` and
//! `PublicKeyCredentialRequestOptionsJSON` in, `RegistrationResponseJSON` and
//! `AuthenticationResponseJSON` (what `PublicKeyCredential.toJSON()` returns) out.
//!
//! Binary fields are base64url strings, as in the spec. Option members this authenticator
//! doesn't act on (`timeout`, `hints`, `attestation`, `authenticatorSelection`, …) are accepted
//! and ignored.

use serde::{Deserialize, Serialize};

use super::key::Algorithm;
use crate::encoding::b64_decode;
use crate::error::{Error, Result};

pub(crate) const PUBLIC_KEY: &str = "public-key";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationOptions {
    pub rp: RelyingPartyEntity,
    pub user: UserEntity,
    pub challenge: String,
    #[serde(default)]
    pub pub_key_cred_params: Vec<CredentialParameters>,
    #[serde(default)]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(default)]
    pub extensions: ExtensionInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    pub challenge: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(default)]
    pub extensions: ExtensionInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RelyingPartyEntity {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    /// The user handle, base64url (1 to 64 bytes).
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CredentialParameters {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionInputs {
    #[serde(default)]
    pub cred_props: bool,
    /// The PRF extension (plan 05, *PRF on Octa Pass's own passkeys*).
    #[serde(default)]
    pub prf: Option<PrfInputs>,
}

/// `AuthenticationExtensionsPRFInputs`: `evalByCredential` only in a request, keyed by base64url
/// credential ID.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrfInputs {
    #[serde(default)]
    pub eval: Option<PrfValues>,
    #[serde(default)]
    pub eval_by_credential: std::collections::BTreeMap<String, PrfValues>,
}

/// `AuthenticationExtensionsPRFValues`, base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfValues {
    pub first: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

impl PrfInputs {
    /// The inputs for `credential_id`: its own in `evalByCredential`, else `eval`.
    pub fn for_credential(&self, credential_id: &[u8]) -> Option<&PrfValues> {
        self.eval_by_credential
            .iter()
            .find(|(id, _)| b64_decode(id).is_ok_and(|id| id == credential_id))
            .map(|(_, values)| values)
            .or(self.eval.as_ref())
    }
}

impl CreationOptions {
    /// The first algorithm in the RP's preference order that this authenticator supports. An
    /// empty list means ES256 or RS256 (WebAuthn §5.1.3 step 10).
    pub fn algorithm(&self) -> Result<Algorithm> {
        if self.pub_key_cred_params.is_empty() {
            return Ok(Algorithm::Es256);
        }
        self.pub_key_cred_params
            .iter()
            .filter(|param| param.kind == PUBLIC_KEY)
            .find_map(|param| Algorithm::from_cose(param.alg))
            .ok_or(Error::PasskeyUnsupportedAlgorithm)
    }

    /// Whether a credential the user already has is in `excludeCredentials`.
    pub fn excludes(&self, credential_id: &[u8]) -> bool {
        contains(&self.exclude_credentials, credential_id)
    }
}

impl RequestOptions {
    /// Whether `allowCredentials` permits this credential (an empty list permits any).
    pub fn allows(&self, credential_id: &[u8]) -> bool {
        self.allow_credentials.is_empty() || contains(&self.allow_credentials, credential_id)
    }
}

/// Compares decoded bytes, so differently padded or invalid ids never match by accident.
fn contains(list: &[CredentialDescriptor], credential_id: &[u8]) -> bool {
    list.iter().any(|descriptor| {
        descriptor.kind == PUBLIC_KEY
            && b64_decode(&descriptor.id).is_ok_and(|id| id == credential_id)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AttestationResponse,
    pub authenticator_attachment: &'static str,
    pub client_extension_results: ExtensionOutputs,
    #[serde(rename = "type")]
    pub kind: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub transports: Vec<&'static str>,
    /// DER `SubjectPublicKeyInfo`.
    pub public_key: String,
    pub public_key_algorithm: i64,
    pub attestation_object: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AssertionResponse,
    pub authenticator_attachment: &'static str,
    pub client_extension_results: ExtensionOutputs,
    #[serde(rename = "type")]
    pub kind: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionOutputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfOutputs>,
}

/// `AuthenticationExtensionsPRFOutputs`: `enabled` on creation only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PrfOutputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfValues>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialProperties {
    /// Every Octa Pass passkey is discoverable.
    pub rk: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn creation(params: serde_json::Value) -> CreationOptions {
        serde_json::from_value(json!({
            "rp": { "name": "Example" },
            "user": { "id": "AQ", "name": "a", "displayName": "A" },
            "challenge": "AAAA",
            "pubKeyCredParams": params,
            "timeout": 60000,
            "authenticatorSelection": { "residentKey": "required" },
        }))
        .unwrap()
    }

    #[test]
    fn algorithm_follows_the_rp_preference() {
        let es = json!({ "type": "public-key", "alg": -7 });
        let ed = json!({ "type": "public-key", "alg": -8 });
        let rs = json!({ "type": "public-key", "alg": -257 });
        assert_eq!(creation(json!([es, ed])).algorithm(), Ok(Algorithm::Es256));
        assert_eq!(creation(json!([ed, es])).algorithm(), Ok(Algorithm::EdDsa));
        assert_eq!(creation(json!([rs, ed])).algorithm(), Ok(Algorithm::EdDsa));
        assert_eq!(creation(json!([])).algorithm(), Ok(Algorithm::Es256));
        assert_eq!(
            creation(json!([rs, { "type": "other", "alg": -7 }])).algorithm(),
            Err(Error::PasskeyUnsupportedAlgorithm)
        );
    }

    #[test]
    fn credential_lists_compare_bytes() {
        let options: RequestOptions = serde_json::from_value(json!({
            "challenge": "AAAA",
            "allowCredentials": [
                { "type": "public-key", "id": "AQID", "transports": ["internal"] },
                { "type": "future", "id": "BAUG" },
                { "type": "public-key", "id": "!!" },
            ],
        }))
        .unwrap();
        assert!(options.allows(&[1, 2, 3]));
        assert!(!options.allows(&[4, 5, 6]), "unknown types are ignored");
        assert!(!options.allows(&[]));

        let any: RequestOptions = serde_json::from_value(json!({ "challenge": "AAAA" })).unwrap();
        assert!(any.allows(&[9]));
    }
}
