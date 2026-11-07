//! The relying party half of WebAuthn, for security keys as a second step:
//! registration with `none` attestation and assertions, ES256 and Ed25519.
//!
//! Attestation statements are not checked (we ask for `none`): any
//! authenticator the user holds is fine. What is checked is what binds a
//! ceremony to this server: the challenge, the origin, the relying party id
//! hash, user presence and the signature.

use ciborium::Value;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::crypto::constant_time_eq;

/// COSE algorithm ids.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;
/// Credential ids are at most 1023 bytes (WebAuthn level 3).
const MAX_CREDENTIAL_ID: usize = 1023;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("clientDataJSON doesn't match this ceremony")]
    ClientData,
    #[error("authenticator data is malformed or for another site")]
    AuthenticatorData,
    #[error("the authenticator didn't confirm the user was present")]
    UserNotPresent,
    #[error("the attestation object is malformed")]
    Attestation,
    #[error("only ES256 and Ed25519 security keys are supported")]
    UnsupportedKey,
    #[error("the signature doesn't verify")]
    Signature,
    #[error("the signature counter went backwards: the key may have been cloned")]
    Counter,
}

/// What a ceremony must be bound to.
pub struct Ceremony<'a> {
    pub rp_id: &'a str,
    pub origins: &'a [String],
    pub challenge: &'a [u8],
}

/// A credential, as stored after registration.
pub struct Credential {
    pub id: Vec<u8>,
    pub algorithm: i64,
    /// An uncompressed SEC1 point for ES256, 32 bytes for Ed25519.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

impl Ceremony<'_> {
    fn check_client_data(&self, json: &[u8], kind: &str) -> Result<(), WebAuthnError> {
        let data: ClientData =
            serde_json::from_slice(json).map_err(|_| WebAuthnError::ClientData)?;
        let challenge = crate::validate::base64url("challenge", &data.challenge, 1024)
            .map_err(|_| WebAuthnError::ClientData)?;
        let origin = data.origin.trim_end_matches('/');
        if data.kind != kind
            || data.cross_origin
            || !constant_time_eq(&challenge, self.challenge)
            || !self.origins.iter().any(|allowed| allowed == origin)
        {
            return Err(WebAuthnError::ClientData);
        }
        Ok(())
    }

    /// Checks the fixed 37-byte head of authenticator data; returns the flags and counter.
    fn check_authenticator_data(&self, data: &[u8]) -> Result<(u8, u32), WebAuthnError> {
        if data.len() < 37 {
            return Err(WebAuthnError::AuthenticatorData);
        }
        if !constant_time_eq(&data[..32], &Sha256::digest(self.rp_id.as_bytes())) {
            return Err(WebAuthnError::AuthenticatorData);
        }
        let flags = data[32];
        if flags & FLAG_USER_PRESENT == 0 {
            return Err(WebAuthnError::UserNotPresent);
        }
        let counter = u32::from_be_bytes(data[33..37].try_into().expect("4 bytes"));
        Ok((flags, counter))
    }

    /// Checks a `navigator.credentials.create()` answer and returns the new credential.
    pub fn register(
        &self,
        client_data_json: &[u8],
        attestation_object: &[u8],
    ) -> Result<Credential, WebAuthnError> {
        self.check_client_data(client_data_json, "webauthn.create")?;
        let attestation: Value = ciborium::de::from_reader(attestation_object)
            .map_err(|_| WebAuthnError::Attestation)?;
        let auth_data = map_get(&attestation, &Value::Text("authData".into()))
            .and_then(Value::as_bytes)
            .ok_or(WebAuthnError::Attestation)?;
        let (flags, sign_count) = self.check_authenticator_data(auth_data)?;
        if flags & FLAG_ATTESTED_CREDENTIAL == 0 || auth_data.len() < 37 + 18 {
            return Err(WebAuthnError::AuthenticatorData);
        }
        // AAGUID (16 bytes), then the credential id's length and the id.
        let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
        let rest = &auth_data[55..];
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID || rest.len() < id_len {
            return Err(WebAuthnError::AuthenticatorData);
        }
        let (id, mut cose) = rest.split_at(id_len);
        let key: Value =
            ciborium::de::from_reader(&mut cose).map_err(|_| WebAuthnError::AuthenticatorData)?;
        let (algorithm, public_key) = cose_key(&key)?;
        Ok(Credential {
            id: id.to_vec(),
            algorithm,
            public_key,
            sign_count,
        })
    }

    /// Checks a `navigator.credentials.get()` answer from `credential`.
    /// Returns the authenticator's new signature counter.
    pub fn assert(
        &self,
        credential: &Credential,
        client_data_json: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
    ) -> Result<u32, WebAuthnError> {
        self.check_client_data(client_data_json, "webauthn.get")?;
        let (_, counter) = self.check_authenticator_data(authenticator_data)?;
        let mut signed = authenticator_data.to_vec();
        signed.extend_from_slice(&Sha256::digest(client_data_json));
        verify_signature(
            credential.algorithm,
            &credential.public_key,
            &signed,
            signature,
        )?;
        // Authenticators without a counter always send 0.
        if (counter != 0 || credential.sign_count != 0) && counter <= credential.sign_count {
            return Err(WebAuthnError::Counter);
        }
        Ok(counter)
    }
}

fn map_get<'a>(map: &'a Value, key: &Value) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
}

fn int_key(map: &Value, key: i64) -> Option<&Value> {
    map_get(map, &Value::Integer(key.into()))
}

fn as_i64(value: Option<&Value>) -> Option<i64> {
    value?.as_integer().and_then(|i| i64::try_from(i).ok())
}

/// A COSE_Key (RFC 9053) for ES256 or Ed25519, as (algorithm, raw public key).
fn cose_key(key: &Value) -> Result<(i64, Vec<u8>), WebAuthnError> {
    let kty = as_i64(int_key(key, 1));
    let alg = as_i64(int_key(key, 3));
    let crv = as_i64(int_key(key, -1));
    let x = int_key(key, -2).and_then(Value::as_bytes);
    match (kty, alg, crv, x) {
        // EC2, P-256
        (Some(2), Some(ES256), Some(1), Some(x)) => {
            let y = int_key(key, -3)
                .and_then(Value::as_bytes)
                .ok_or(WebAuthnError::UnsupportedKey)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(WebAuthnError::UnsupportedKey);
            }
            let mut point = vec![0x04];
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            p256::PublicKey::from_sec1_bytes(&point).map_err(|_| WebAuthnError::UnsupportedKey)?;
            Ok((ES256, point))
        }
        // OKP, Ed25519
        (Some(1), Some(EDDSA), Some(6), Some(x)) => {
            let bytes: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| WebAuthnError::UnsupportedKey)?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|_| WebAuthnError::UnsupportedKey)?;
            Ok((EDDSA, bytes.to_vec()))
        }
        _ => Err(WebAuthnError::UnsupportedKey),
    }
}

fn verify_signature(
    algorithm: i64,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), WebAuthnError> {
    match algorithm {
        ES256 => {
            use p256::ecdsa::signature::Verifier;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| WebAuthnError::Signature)?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| WebAuthnError::Signature)?;
            key.verify(message, &signature)
                .map_err(|_| WebAuthnError::Signature)
        }
        EDDSA => {
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| WebAuthnError::Signature)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| WebAuthnError::Signature)?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| WebAuthnError::Signature)?;
            key.verify_strict(message, &signature)
                .map_err(|_| WebAuthnError::Signature)
        }
        _ => Err(WebAuthnError::UnsupportedKey),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::base64url;
    use p256::ecdsa::signature::Signer;
    use rand_core::OsRng;

    const ORIGIN: &str = "https://vault.example.com";

    /// A software security key, as a browser and authenticator together.
    pub struct SoftKey {
        key: p256::ecdsa::SigningKey,
        pub id: Vec<u8>,
        pub counter: u32,
    }

    impl SoftKey {
        pub fn new() -> Self {
            Self {
                key: p256::ecdsa::SigningKey::random(&mut OsRng),
                id: vec![7; 16],
                counter: 0,
            }
        }

        fn auth_data(&self, rp_id: &str, flags: u8, attested: Option<Vec<u8>>) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&self.counter.to_be_bytes());
            if let Some(cose) = attested {
                data.extend_from_slice(&[0; 16]);
                data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.id);
                data.extend_from_slice(&cose);
            }
            data
        }

        pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::json!({ "type": kind, "challenge": base64url(challenge), "origin": origin })
                .to_string()
                .into_bytes()
        }

        /// (clientDataJSON, attestationObject)
        pub fn create(&self, rp_id: &str, origin: &str, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let point = self.key.verifying_key().to_encoded_point(false);
            let cose = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(3.into()), Value::Integer(ES256.into())),
                (Value::Integer((-1).into()), Value::Integer(1.into())),
                (
                    Value::Integer((-2).into()),
                    Value::Bytes(point.x().unwrap().to_vec()),
                ),
                (
                    Value::Integer((-3).into()),
                    Value::Bytes(point.y().unwrap().to_vec()),
                ),
            ]);
            let mut cose_bytes = Vec::new();
            ciborium::ser::into_writer(&cose, &mut cose_bytes).unwrap();
            let auth_data = self.auth_data(rp_id, 0x41, Some(cose_bytes));
            let attestation = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (Value::Text("authData".into()), Value::Bytes(auth_data)),
            ]);
            let mut attestation_bytes = Vec::new();
            ciborium::ser::into_writer(&attestation, &mut attestation_bytes).unwrap();
            (
                Self::client_data("webauthn.create", challenge, origin),
                attestation_bytes,
            )
        }

        /// (clientDataJSON, authenticatorData, signature)
        pub fn get(
            &mut self,
            rp_id: &str,
            origin: &str,
            challenge: &[u8],
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.counter += 1;
            let client_data = Self::client_data("webauthn.get", challenge, origin);
            let auth_data = self.auth_data(rp_id, 0x01, None);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data));
            let signature: p256::ecdsa::Signature = self.key.sign(&signed);
            (
                client_data,
                auth_data,
                signature.to_der().as_bytes().to_vec(),
            )
        }
    }

    fn ceremony<'a>(origins: &'a [String], challenge: &'a [u8]) -> Ceremony<'a> {
        Ceremony {
            rp_id: "vault.example.com",
            origins,
            challenge,
        }
    }

    #[test]
    fn registers_and_asserts_an_es256_key() {
        let origins = vec![ORIGIN.to_owned()];
        let mut key = SoftKey::new();
        let (client_data, attestation) = key.create("vault.example.com", ORIGIN, b"challenge-1");
        let mut credential = ceremony(&origins, b"challenge-1")
            .register(&client_data, &attestation)
            .unwrap();
        assert_eq!(credential.id, key.id);
        assert_eq!(credential.algorithm, ES256);
        assert_eq!(credential.public_key.len(), 65);

        let (client_data, auth_data, signature) = key.get("vault.example.com", ORIGIN, b"c2");
        let counter = ceremony(&origins, b"c2")
            .assert(&credential, &client_data, &auth_data, &signature)
            .unwrap();
        assert_eq!(counter, 1);
        credential.sign_count = counter;

        // Replaying the same assertion fails on the counter, another challenge on the client data.
        assert_eq!(
            ceremony(&origins, b"c2").assert(&credential, &client_data, &auth_data, &signature),
            Err(WebAuthnError::Counter)
        );
        assert_eq!(
            ceremony(&origins, b"c3").assert(&credential, &client_data, &auth_data, &signature),
            Err(WebAuthnError::ClientData)
        );
    }

    #[test]
    fn refuses_other_sites_challenges_and_tampering() {
        let origins = vec![ORIGIN.to_owned()];
        let mut key = SoftKey::new();
        let (client_data, attestation) = key.create("vault.example.com", ORIGIN, b"c");
        let credential = ceremony(&origins, b"c")
            .register(&client_data, &attestation)
            .unwrap();
        assert!(matches!(
            ceremony(&origins, b"other").register(&client_data, &attestation),
            Err(WebAuthnError::ClientData)
        ));
        let (client_data, attestation) =
            key.create("vault.example.com", "https://evil.example", b"c");
        assert!(matches!(
            ceremony(&origins, b"c").register(&client_data, &attestation),
            Err(WebAuthnError::ClientData)
        ));
        let (client_data, attestation) = key.create("evil.example", ORIGIN, b"c");
        assert!(matches!(
            ceremony(&origins, b"c").register(&client_data, &attestation),
            Err(WebAuthnError::AuthenticatorData)
        ));
        let (client_data, _) = key.create("vault.example.com", ORIGIN, b"c");
        assert!(matches!(
            ceremony(&origins, b"c").register(&client_data, b"\xa0"),
            Err(WebAuthnError::Attestation)
        ));

        // A create answer can't stand in for a get, and signatures must match.
        let (client_data, auth_data, mut signature) = key.get("vault.example.com", ORIGIN, b"g");
        let create = SoftKey::client_data("webauthn.create", b"g", ORIGIN);
        assert_eq!(
            ceremony(&origins, b"g").assert(&credential, &create, &auth_data, &signature),
            Err(WebAuthnError::ClientData)
        );
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert_eq!(
            ceremony(&origins, b"g").assert(&credential, &client_data, &auth_data, &signature),
            Err(WebAuthnError::Signature)
        );
        let mut absent = auth_data.clone();
        absent[32] = 0;
        assert_eq!(
            ceremony(&origins, b"g").assert(&credential, &client_data, &absent, &signature),
            Err(WebAuthnError::UserNotPresent)
        );
    }

    #[test]
    fn accepts_ed25519_and_refuses_other_keys() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let okp = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Integer(EDDSA.into())),
            (Value::Integer((-1).into()), Value::Integer(6.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(signing.verifying_key().to_bytes().to_vec()),
            ),
        ]);
        let (alg, key) = cose_key(&okp).unwrap();
        assert_eq!(alg, EDDSA);
        use ed25519_dalek::Signer as _;
        let signature = signing.sign(b"message").to_bytes();
        assert!(verify_signature(alg, &key, b"message", &signature).is_ok());
        assert!(verify_signature(alg, &key, b"other", &signature).is_err());

        let rsa = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(3.into())),
            (Value::Integer(3.into()), Value::Integer((-257).into())),
        ]);
        assert_eq!(cose_key(&rsa), Err(WebAuthnError::UnsupportedKey));
    }
}
