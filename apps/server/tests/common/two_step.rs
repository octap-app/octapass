//! Two-step sign-in helpers: authenticator codes, recovery codes and a
//! software security key, as a real client and authenticator would make them.

use axum::http::{Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value as Cbor;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Device, PASSWORD, Response, TestServer, b64, unb64};

pub const ORIGIN: &str = "http://localhost:5173";
pub const RP_ID: &str = "localhost";

/// RFC 6238 with SHA-1, 6 digits, 30 seconds, at Unix milliseconds `now`.
pub fn totp(secret_base32: &str, now: i64) -> String {
    let secret = base32_decode(secret_base32);
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&secret).unwrap();
    mac.update(&now.div_euclid(30_000).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let value = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!("{:06}", value % 1_000_000)
}

fn base32_decode(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = alphabet.iter().position(|&a| a == c).unwrap() as u64;
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

/// A fresh reauth token for `purpose`.
pub async fn reauth(server: &TestServer, device: &Device, purpose: &str) -> String {
    use opaque_ke::ClientLogin;
    let start = ClientLogin::<super::Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let started = server
        .call(
            Method::POST,
            "/v1/auth/reauth/start",
            Some(&device.access_token),
            &[],
            Some(json!({ "credentialRequest": b64(start.message.serialize()) })),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let finalization =
        super::client_finish(start.state, PASSWORD, &started.body["credentialResponse"]);
    let finished = server
        .call(
            Method::POST,
            "/v1/auth/reauth/finish",
            Some(&device.access_token),
            &[],
            Some(json!({
                "reauthId": started.body["reauthId"],
                "credentialFinalization": finalization,
                "purpose": purpose
            })),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    finished.body["reauthToken"].as_str().unwrap().to_owned()
}

/// Turns two-step sign-in on with an authenticator. Returns its base32
/// secret and the recovery codes.
pub async fn enable(server: &TestServer, device: &Device) -> (String, Vec<String>) {
    let token = reauth(server, device, "two-step").await;
    let setup = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&device.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{:?}", setup.body);
    let secret = setup.body["secret"].as_str().unwrap().to_owned();
    let code = totp(&secret, server.state_now());
    let confirmed = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp/confirm",
            Some(&device.access_token),
            &[],
            Some(json!({ "setupId": setup.body["setupId"], "code": code })),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body);
    let codes = confirmed.body["recoveryCodes"]
        .as_array()
        .expect("recovery codes when turning on")
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    (secret, codes)
}

/// `login/second-factor` with `proof` merged into the body.
pub async fn second_factor(server: &TestServer, challenge_id: &Value, proof: Value) -> Response {
    let mut body = json!({ "challengeId": challenge_id });
    body.as_object_mut()
        .unwrap()
        .extend(proof.as_object().unwrap().clone());
    server.post("/v1/auth/login/second-factor", body).await
}

/// A software security key and browser together.
pub struct SoftKey {
    key: p256::ecdsa::SigningKey,
    pub id: Vec<u8>,
    counter: u32,
}

impl SoftKey {
    pub fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::random(&mut OsRng),
            id: super::random_bytes(32),
            counter: 0,
        }
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": challenge, "origin": origin })
            .to_string()
            .into_bytes()
    }

    /// The body for `POST /v1/account/two-step/security-keys` answering `options`.
    pub fn create(&self, options: &Value, name: &str) -> Value {
        let public_key = &options["publicKey"];
        assert_eq!(public_key["rp"]["id"], RP_ID);
        let point = self.key.verifying_key().to_encoded_point(false);
        let cose = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
            (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
            (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
            (
                Cbor::Integer((-2).into()),
                Cbor::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Cbor::Integer((-3).into()),
                Cbor::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(0x41);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.id);
        ciborium::ser::into_writer(&cose, &mut auth_data).unwrap();
        let attestation = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut attestation_object).unwrap();
        let challenge = public_key["challenge"].as_str().unwrap();
        json!({
            "setupId": options["setupId"],
            "name": name,
            "credentialId": b64(&self.id),
            "clientDataJson": b64(Self::client_data("webauthn.create", challenge, ORIGIN)),
            "attestationObject": b64(attestation_object),
        })
    }

    /// The `webauthn` member answering a `second-factor-required` challenge.
    pub fn get(&mut self, challenge: &Value) -> Value {
        let options = &challenge["webauthn"];
        assert_eq!(options["rpId"], RP_ID);
        let id = b64(&self.id);
        assert!(
            options["allowCredentials"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == &Value::String(id.clone()))
        );
        self.counter += 1;
        let client_data = Self::client_data(
            "webauthn.get",
            options["challenge"].as_str().unwrap(),
            ORIGIN,
        );
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(0x01);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: p256::ecdsa::Signature = self.key.sign(&signed);
        json!({
            "credentialId": id,
            "clientDataJson": b64(client_data),
            "authenticatorData": b64(auth_data),
            "signature": b64(signature.to_der().as_bytes()),
        })
    }
}

/// The decoded challenge id, to check it's opaque.
pub fn challenge_bytes(challenge: &Value) -> Vec<u8> {
    unb64(&challenge["challengeId"])
}

pub fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).unwrap()
}
