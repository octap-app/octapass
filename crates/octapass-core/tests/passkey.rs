//! The passkey authenticator, checked by a relying-party verifier written from WebAuthn §7.1 and
//! §7.2 with independent parsers (`ciborium`, `coset`), plus the passkey test vectors in
//! `tests/vectors/passkey.json` (regenerate with `OCTAPASS_UPDATE_VECTORS=1`). Both kinds of
//! client data go through the same verifier: client data the core writes for a page, and client
//! data the platform wrote and only passed the hash of (iOS, Android).

use std::sync::OnceLock;

use ciborium::Value as Cbor;
use coset::{CborSerializable, CoseKey, iana};
use octapass_core::Error;
use octapass_core::account::NewAccount;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::item::{Item, ItemDetails};
use octapass_core::kdf::KdfParams;
use octapass_core::passkey::{
    self, AAGUID, AuthenticationResponse, Caller, Candidate, ClientData, CreationOptions,
    PasskeyRecord, RegistrationResponse, RequestOptions, Target,
};
use octapass_core::session::{EncryptedItem, Session};
use p256::ecdsa::signature::Verifier as _;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NOW_MS: u64 = 1_792_800_000_000;
const CHALLENGE: &str = "3q2-7_7erb7-_t6tvv7-rQ";

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn caller(origin: &str) -> ClientData {
    ClientData::Web(serde_json::from_value(json!({ "origin": origin })).unwrap())
}

fn creation(algs: &[i64], extra: Value) -> CreationOptions {
    let mut options = json!({
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": "dXNlci0xMjM", "name": "alice@example.com", "displayName": "Alice" },
        "challenge": CHALLENGE,
        "pubKeyCredParams": algs.iter().map(|alg| json!({ "type": "public-key", "alg": alg })).collect::<Vec<_>>(),
        "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
        "attestation": "none",
    });
    options
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(options).unwrap()
}

fn request(extra: Value) -> RequestOptions {
    let mut options =
        json!({ "challenge": CHALLENGE, "rpId": "example.com", "userVerification": "required" });
    options
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(options).unwrap()
}

/// What a relying party keeps after registration.
struct StoredCredential {
    id: Vec<u8>,
    alg: i64,
    key: CoseKey,
}

/// WebAuthn §7.1, the steps that apply to attestation `none`.
fn verify_registration(
    credential: &Value,
    rp_id: &str,
    origin: &str,
    challenge: &str,
) -> StoredCredential {
    assert_eq!(credential["type"], "public-key");
    assert_eq!(credential["id"], credential["rawId"]);
    let response = &credential["response"];
    verify_client_data(response, "webauthn.create", origin, challenge);

    let attestation: Cbor =
        ciborium::from_reader(bytes(&response["attestationObject"]).as_slice()).unwrap();
    let entries = attestation.as_map().unwrap();
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_text() == Some(name))
            .map(|(_, value)| value.clone())
            .unwrap()
    };
    assert_eq!(entries.len(), 3);
    assert_eq!(field("fmt"), Cbor::from("none"));
    assert_eq!(field("attStmt"), Cbor::Map(vec![]));
    let auth_data = field("authData").into_bytes().unwrap();
    assert_eq!(auth_data, bytes(&response["authenticatorData"]));

    assert_eq!(auth_data[..32], Sha256::digest(rp_id.as_bytes())[..]);
    assert_eq!(auth_data[32], 0x5d, "UP | UV | BE | BS | AT");
    assert_eq!(auth_data[33..37], [0, 0, 0, 0], "signCount");
    assert_eq!(auth_data[37..53], AAGUID);
    let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let id = auth_data[55..55 + id_len].to_vec();
    assert_eq!(id, bytes(&credential["rawId"]));
    assert_eq!(id.len(), 16);
    let key = CoseKey::from_slice(&auth_data[55 + id_len..]).unwrap();
    let alg = match key.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => -7,
        Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)) => -8,
        ref other => panic!("unexpected algorithm {other:?}"),
    };
    assert_eq!(response["publicKeyAlgorithm"], alg);
    assert_eq!(response["transports"], json!(["internal"]));
    assert_eq!(credential["authenticatorAttachment"], "platform");
    let stored = StoredCredential { id, alg, key };
    assert_eq!(spki_of(&stored), bytes(&response["publicKey"]));
    stored
}

/// WebAuthn §7.2.
fn verify_assertion(
    assertion: &Value,
    stored: &StoredCredential,
    rp_id: &str,
    origin: &str,
    challenge: &str,
) {
    assert_eq!(assertion["type"], "public-key");
    assert_eq!(bytes(&assertion["rawId"]), stored.id);
    let response = &assertion["response"];
    let client_data = verify_client_data(response, "webauthn.get", origin, challenge);
    let auth_data = bytes(&response["authenticatorData"]);
    assert_eq!(auth_data.len(), 37, "no attested credential data");
    assert_eq!(auth_data[..32], Sha256::digest(rp_id.as_bytes())[..]);
    assert_eq!(auth_data[32], 0x1d, "UP | UV | BE | BS");
    assert_eq!(auth_data[33..37], [0, 0, 0, 0]);

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature = bytes(&response["signature"]);
    let x = cose_param(&stored.key, -2);
    match stored.alg {
        -7 => {
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                cose_param(&stored.key, -3).as_slice().into(),
                false,
            );
            let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap();
            let signature = p256::ecdsa::Signature::from_der(&signature).unwrap();
            key.verify(&signed, &signature).unwrap();
        }
        -8 => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
            key.verify_strict(&signed, &signature).unwrap();
        }
        _ => unreachable!(),
    }
}

fn verify_client_data(response: &Value, kind: &str, origin: &str, challenge: &str) -> Vec<u8> {
    let raw = bytes(&response["clientDataJSON"]);
    let client_data: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(client_data["type"], kind);
    assert_eq!(client_data["challenge"], challenge);
    assert_eq!(client_data["origin"], origin);
    assert_eq!(client_data["crossOrigin"], false);
    // The limited verification algorithm (§5.8.1.2) matches this exact prefix.
    let prefix = format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false"#
    );
    assert!(String::from_utf8(raw.clone()).unwrap().starts_with(&prefix));
    raw
}

fn spki_of(stored: &StoredCredential) -> Vec<u8> {
    use p256::pkcs8::EncodePublicKey as _;
    let x = cose_param(&stored.key, -2);
    match stored.alg {
        -7 => {
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                cose_param(&stored.key, -3).as_slice().into(),
                false,
            );
            p256::PublicKey::from_sec1_bytes(point.as_bytes())
                .unwrap()
                .to_public_key_der()
                .unwrap()
                .into_vec()
        }
        _ => ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap())
            .unwrap()
            .to_public_key_der()
            .unwrap()
            .into_vec(),
    }
}

fn cose_param(key: &CoseKey, label: i64) -> Vec<u8> {
    key.params
        .iter()
        .find(|(l, _)| *l == coset::Label::Int(label))
        .and_then(|(_, value)| value.as_bytes().cloned())
        .unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    b64_decode(value.as_str().unwrap()).unwrap()
}

fn to_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn es256_and_eddsa_register_and_sign_in() {
    for (algs, expected) in [(&[-7, -8][..], -7), (&[-8, -7][..], -8), (&[][..], -7)] {
        let options = creation(algs, json!({}));
        let origin = "https://login.example.com";
        let new = passkey::create(&options, &caller(origin), NOW_MS, &mut rng(1)).unwrap();
        let stored =
            verify_registration(&to_json(&new.credential), "example.com", origin, CHALLENGE);
        assert_eq!(stored.alg, expected);

        let record = &new.record;
        assert_eq!(record.rp_id, "example.com");
        assert_eq!(record.user_handle, "dXNlci0xMjM");
        assert_eq!(record.user_name, "alice@example.com");
        assert_eq!(record.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(record.created_at, "2026-10-24T00:00:00.000Z");
        assert_eq!(record.sign_count, 0);

        let assertion = passkey::get(&request(json!({})), &caller(origin), record).unwrap();
        let assertion = to_json(&assertion);
        verify_assertion(&assertion, &stored, "example.com", origin, CHALLENGE);
        assert_eq!(assertion["response"]["userHandle"], "dXNlci0xMjM");
        assert_eq!(assertion["clientExtensionResults"], json!({}));
    }
}

#[test]
fn every_passkey_is_new() {
    let options = creation(&[-7], json!({}));
    let first = passkey::create(
        &options,
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(1),
    )
    .unwrap();
    let second = passkey::create(
        &options,
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(2),
    )
    .unwrap();
    assert_ne!(first.record.credential_id, second.record.credential_id);
    assert_ne!(first.record.private_key, second.record.private_key);
}

#[test]
fn requests_for_another_site_are_refused() {
    let options = creation(&[-7], json!({}));
    let new = passkey::create(
        &options,
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(1),
    )
    .unwrap();

    for origin in [
        "https://example.com.evil.net",
        "https://examp1e.com",
        "http://example.com",
    ] {
        assert_eq!(
            passkey::create(&options, &caller(origin), NOW_MS, &mut rng(1)).unwrap_err(),
            Error::PasskeyRpMismatch,
            "{origin}"
        );
        assert_eq!(
            passkey::get(&request(json!({})), &caller(origin), &new.record).unwrap_err(),
            Error::PasskeyRpMismatch,
            "{origin}"
        );
    }
    // A phishing page asking for its own rpId gets nothing from example.com's passkey.
    assert_eq!(
        passkey::get(
            &request(json!({ "rpId": null })),
            &caller("https://evil.net"),
            &new.record
        )
        .unwrap_err(),
        Error::PasskeyNotFound
    );
}

#[test]
fn allow_credentials_restricts_the_passkey() {
    let new = passkey::create(
        &creation(&[-7], json!({})),
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(1),
    )
    .unwrap();
    let other =
        json!({ "allowCredentials": [{ "type": "public-key", "id": "AAAAAAAAAAAAAAAAAAAAAA" }] });
    assert_eq!(
        passkey::get(&request(other), &caller("https://example.com"), &new.record).unwrap_err(),
        Error::PasskeyNotFound
    );
    let this =
        json!({ "allowCredentials": [{ "type": "public-key", "id": new.record.credential_id }] });
    assert!(passkey::get(&request(this), &caller("https://example.com"), &new.record).is_ok());
}

#[test]
fn malformed_requests() {
    let caller = caller("https://example.com");
    let create = |extra| passkey::create(&creation(&[-7], extra), &caller, NOW_MS, &mut rng(1));
    assert_eq!(
        create(json!({ "challenge": "not base64!" })).unwrap_err(),
        Error::InvalidPasskeyRequest
    );
    assert_eq!(
        create(json!({ "user": { "id": "", "name": "a", "displayName": "" } })).unwrap_err(),
        Error::InvalidPasskeyRequest
    );
    assert_eq!(
        create(json!({ "user": { "id": b64_encode(&[1; 65]), "name": "a", "displayName": "" } }))
            .unwrap_err(),
        Error::InvalidPasskeyRequest
    );
    assert_eq!(
        passkey::create(&creation(&[-257], json!({})), &caller, NOW_MS, &mut rng(1)).unwrap_err(),
        Error::PasskeyUnsupportedAlgorithm
    );
}

#[test]
fn cred_props_and_cross_origin_frames() {
    let options = creation(&[-7], json!({ "extensions": { "credProps": true } }));
    let frame: Caller = serde_json::from_value(json!({
        "origin": "https://example.com", "topOrigin": "https://shop.example", "frameAllowed": true,
    }))
    .unwrap();
    let new = passkey::create(&options, &ClientData::Web(frame), NOW_MS, &mut rng(1)).unwrap();
    let credential = to_json(&new.credential);
    assert_eq!(
        credential["clientExtensionResults"],
        json!({ "credProps": { "rk": true } })
    );
    let client_data = String::from_utf8(bytes(&credential["response"]["clientDataJSON"])).unwrap();
    assert!(client_data.ends_with(r#""crossOrigin":true,"topOrigin":"https://shop.example"}"#));

    let refused: Caller = serde_json::from_value(json!({
        "origin": "https://example.com", "topOrigin": "https://shop.example",
    }))
    .unwrap();
    assert_eq!(
        passkey::get(&request(json!({})), &refused.into(), &new.record).unwrap_err(),
        Error::PasskeyFrameNotAllowed
    );
}

/// WebAuthn PRF over CTAP `hmac-secret`, written out here from the spec.
fn expected_prf(record: &PasskeyRecord, input: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let secret = b64_decode(record.prf_secret.as_deref().unwrap()).unwrap();
    let salt = Sha256::digest([b"WebAuthn PRF".as_slice(), &[0], input].concat());
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&salt);
    b64_encode(&mac.finalize().into_bytes())
}

#[test]
fn prf_on_creation_and_sign_in() {
    let (first, second) = (b"first salt".as_slice(), b"second salt".as_slice());
    let options = creation(
        &[-7],
        json!({ "extensions": { "prf": { "eval": { "first": b64_encode(first), "second": b64_encode(second) } } } }),
    );
    let new = passkey::create(
        &options,
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(1),
    )
    .unwrap();
    assert_eq!(
        b64_decode(new.record.prf_secret.as_deref().unwrap())
            .unwrap()
            .len(),
        32
    );
    let prf = &to_json(&new.credential)["clientExtensionResults"]["prf"];
    assert_eq!(prf["enabled"], true);
    assert_eq!(prf["results"]["first"], expected_prf(&new.record, first));
    assert_eq!(prf["results"]["second"], expected_prf(&new.record, second));

    // Asked for support only: enabled, no results.
    let support = creation(&[-7], json!({ "extensions": { "prf": {} } }));
    let checked = passkey::create(
        &support,
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(2),
    )
    .unwrap();
    assert_eq!(
        to_json(&checked.credential)["clientExtensionResults"],
        json!({ "prf": { "enabled": true } })
    );

    // Sign-in: `eval`, or the passkey's own entry in `evalByCredential` over it.
    let get = |extensions: Value| {
        let response = passkey::get(
            &request(json!({ "extensions": extensions })),
            &caller("https://example.com"),
            &new.record,
        )
        .unwrap();
        to_json(&response)["clientExtensionResults"].clone()
    };
    assert_eq!(
        get(json!({ "prf": { "eval": { "first": b64_encode(first) } } })),
        json!({ "prf": { "results": { "first": expected_prf(&new.record, first) } } })
    );
    let other = b"just for this passkey".as_slice();
    assert_eq!(
        get(json!({ "prf": {
            "eval": { "first": b64_encode(first) },
            "evalByCredential": { new.record.credential_id.clone(): { "first": b64_encode(other) } },
        } }))["prf"]["results"]["first"],
        expected_prf(&new.record, other)
    );
    assert_eq!(get(json!({})), json!({}), "nothing asked, nothing answered");
    assert_ne!(
        expected_prf(&new.record, first),
        expected_prf(&checked.record, first),
        "a secret per passkey"
    );

    // A passkey from before PRF has no secret: it signs in without PRF.
    let mut old = new.record.clone();
    old.prf_secret = None;
    let response = passkey::get(
        &request(json!({ "extensions": { "prf": { "eval": { "first": b64_encode(first) } } } })),
        &caller("https://example.com"),
        &old,
    )
    .unwrap();
    assert_eq!(to_json(&response)["clientExtensionResults"], json!({}));
}

#[test]
fn prf_from_the_platform_for_an_extensions_own_passkey() {
    let id = "oojckfebkmiogiahdggohbdnndbfcjnm";
    let mut options = creation(
        &[-7],
        json!({ "extensions": { "prf": { "eval": { "first": "AQID" } } } }),
    );
    options.rp.id = Some(id.into());
    let client = ClientData::Hash([7; 32]);
    let new = passkey::create(&options, &client, NOW_MS, &mut rng(3)).unwrap();
    assert_eq!(new.record.rp_id, id);
    let created =
        to_json(&new.credential)["clientExtensionResults"]["prf"]["results"]["first"].clone();
    let mut sign_in = request(json!({ "extensions": { "prf": { "eval": { "first": "AQID" } } } }));
    sign_in.rp_id = Some(id.into());
    let response = passkey::get(&sign_in, &client, &new.record).unwrap();
    assert_eq!(
        to_json(&response)["clientExtensionResults"]["prf"]["results"]["first"],
        created
    );
}

// --- Client data the platform wrote (iOS, Android) ------------------------------------------

/// `clientDataJSON` as the platform writes it for an app or browser it verified.
fn platform_client_data(kind: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{CHALLENGE}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

fn platform(client_data: &[u8]) -> ClientData {
    ClientData::Hash(Sha256::digest(client_data).into())
}

/// What the platform does with a response: puts in the `clientDataJSON` it wrote.
fn with_client_data(response: &impl serde::Serialize, client_data: &[u8]) -> Value {
    let mut value = to_json(response);
    assert_eq!(
        value["response"]["clientDataJSON"], "",
        "left for the platform"
    );
    value["response"]["clientDataJSON"] = b64_encode(client_data).into();
    value
}

#[test]
fn platform_client_data_registers_and_signs_in() {
    for (alg, origin) in [
        (-7, "https://login.example.com"),
        (-8, "android:apk-key-hash:3q2-7w"),
    ] {
        // The challenge is in the platform's client data, so the options' one isn't read.
        let unread = json!({ "challenge": "not base64!" });
        let create = platform_client_data("webauthn.create", origin);
        let new = passkey::create(
            &creation(&[alg], unread.clone()),
            &platform(&create),
            NOW_MS,
            &mut rng(1),
        )
        .unwrap();
        let credential = with_client_data(&new.credential, &create);
        let stored = verify_registration(&credential, "example.com", origin, CHALLENGE);
        assert_eq!(stored.alg, alg);
        assert_eq!(new.record.rp_id, "example.com");
        assert_eq!(new.record.sign_count, 0);

        let get = platform_client_data("webauthn.get", origin);
        let assertion = passkey::get(&request(unread), &platform(&get), &new.record).unwrap();
        let assertion = with_client_data(&assertion, &get);
        verify_assertion(&assertion, &stored, "example.com", origin, CHALLENGE);
        assert_eq!(assertion["response"]["userHandle"], "dXNlci0xMjM");
    }
}

#[test]
fn platform_hash_signs_like_written_client_data() {
    // ES256 (RFC 6979) and Ed25519 signatures are deterministic, so signing the hash of the
    // client data the core writes for a page must give that page's assertion byte for byte.
    for alg in [-7, -8] {
        let page = caller("https://login.example.com");
        let options = creation(&[alg], json!({}));
        let web = passkey::create(&options, &page, NOW_MS, &mut rng(1)).unwrap();
        let written = bytes(&to_json(&web.credential)["response"]["clientDataJSON"]);
        let hashed = passkey::create(&options, &platform(&written), NOW_MS, &mut rng(1)).unwrap();
        assert_eq!(hashed.record, web.record);
        assert_eq!(
            with_client_data(&hashed.credential, &written),
            to_json(&web.credential)
        );

        let web = passkey::get(&request(json!({})), &page, &web.record).unwrap();
        let written = bytes(&to_json(&web)["response"]["clientDataJSON"]);
        let hashed =
            passkey::get(&request(json!({})), &platform(&written), &hashed.record).unwrap();
        assert_eq!(with_client_data(&hashed, &written), to_json(&web));
    }
}

#[test]
fn platform_requests_keep_the_rp_checks() {
    let new = passkey::create(
        &creation(&[-7], json!({})),
        &caller("https://example.com"),
        NOW_MS,
        &mut rng(1),
    )
    .unwrap();
    let hash = platform(b"{}");
    let create = |extra| passkey::create(&creation(&[-7], extra), &hash, NOW_MS, &mut rng(1));
    let get = |extra| passkey::get(&request(extra), &hash, &new.record);

    // There's no origin to default the rpId to.
    let no_rp_id = json!({ "rp": { "name": "Example" } });
    assert_eq!(create(no_rp_id).unwrap_err(), Error::InvalidPasskeyRequest);
    assert_eq!(
        get(json!({ "rpId": null })).unwrap_err(),
        Error::InvalidPasskeyRequest
    );
    for rp_id in ["com", "co.uk", "github.io", "127.0.0.1", ""] {
        let rp = json!({ "rp": { "id": rp_id, "name": "x" } });
        assert_eq!(create(rp).unwrap_err(), Error::PasskeyRpMismatch, "{rp_id}");
        assert_eq!(
            get(json!({ "rpId": rp_id })).unwrap_err(),
            Error::PasskeyRpMismatch,
            "{rp_id}"
        );
    }
    for rp_id in ["login.example.com", "example.org"] {
        assert_eq!(
            get(json!({ "rpId": rp_id })).unwrap_err(),
            Error::PasskeyNotFound,
            "{rp_id}"
        );
    }
    let other =
        json!({ "allowCredentials": [{ "type": "public-key", "id": "AAAAAAAAAAAAAAAAAAAAAA" }] });
    assert_eq!(get(other).unwrap_err(), Error::PasskeyNotFound);
    let this =
        json!({ "allowCredentials": [{ "type": "public-key", "id": new.record.credential_id }] });
    assert!(get(this).is_ok());
    assert_eq!(
        get(json!({ "rpId": "EXAMPLE.com" })).unwrap().id,
        new.record.credential_id
    );

    assert_eq!(
        create(json!({ "user": { "id": "", "name": "a", "displayName": "" } })).unwrap_err(),
        Error::InvalidPasskeyRequest
    );
    assert_eq!(
        passkey::create(&creation(&[-257], json!({})), &hash, NOW_MS, &mut rng(1)).unwrap_err(),
        Error::PasskeyUnsupportedAlgorithm
    );
}

// --- Passkeys inside encrypted items -------------------------------------------------------

fn session() -> (Session, String) {
    static ACCOUNT: OnceLock<NewAccount> = OnceLock::new();
    let account = ACCOUNT.get_or_init(|| {
        NewAccount::create(
            "a@example.com",
            "pw",
            KdfParams::DEFAULT,
            NOW_MS,
            &mut rng(9),
        )
        .unwrap()
    });
    let session = Session::from_new_account(account).unwrap();
    (session, account.personal_vault.id.clone())
}

fn item_id(n: u8) -> String {
    format!("0192f0c8-1c2d-7a00-8000-0000000000{n:02x}")
}

fn candidate(vault_id: &str, item_id: &str, item: &EncryptedItem) -> Candidate {
    Candidate {
        vault_id: vault_id.into(),
        item_id: item_id.into(),
        item: item.clone(),
    }
}

fn new_target(vault_id: &str, item_id: &str) -> Target {
    Target {
        vault_id: vault_id.into(),
        item_id: item_id.into(),
        item: None,
    }
}

#[test]
fn session_creates_a_login_and_signs_in_with_it() {
    let (session, vault) = session();
    let origin = caller("https://login.example.com");
    let id = item_id(1);
    let (credential, encrypted) = session
        .create_passkey(
            &creation(&[-7], json!({})),
            &origin,
            &new_target(&vault, &id),
            &[],
            NOW_MS,
            &mut rng(1),
        )
        .unwrap();
    let stored = verify_registration(
        &to_json(&credential),
        "example.com",
        "https://login.example.com",
        CHALLENGE,
    );

    let item = to_json(&session.decrypt_item(&vault, &id, &encrypted).unwrap());
    assert_eq!(item["overview"]["title"], "Example");
    assert_eq!(item["overview"]["type"], "login");
    assert_eq!(
        item["overview"]["urls"],
        json!(["https://login.example.com"])
    );
    assert_eq!(item["details"]["username"], "alice@example.com");
    let entry = &item["details"]["passkeys"][0];
    assert_eq!(entry["rpId"], "example.com");
    assert_eq!(entry["credentialId"], credential.id);
    assert_eq!(entry["signCount"], 0);
    assert!(entry["privateKey"].as_str().unwrap().len() > 100);

    let candidates = [candidate(&vault, &id, &encrypted)];
    let found = session
        .find_passkeys(&request(json!({})), &origin, &candidates)
        .unwrap();
    assert_eq!(
        to_json(&found),
        json!([{
            "vaultId": vault, "itemId": id, "credentialId": credential.id, "rpId": "example.com",
            "userName": "alice@example.com", "userDisplayName": "Alice", "createdAt": "2026-10-24T00:00:00.000Z",
        }])
    );
    let assertion = session
        .get_assertion(&request(json!({})), &origin, &candidates[0], &credential.id)
        .unwrap();
    verify_assertion(
        &to_json(&assertion),
        &stored,
        "example.com",
        "https://login.example.com",
        CHALLENGE,
    );

    assert_eq!(
        session
            .get_assertion(&request(json!({})), &origin, &candidates[0], "AAAA")
            .unwrap_err(),
        Error::PasskeyNotFound
    );
    assert_eq!(
        session
            .find_passkeys(
                &request(json!({ "rpId": null })),
                &caller("https://evil.net"),
                &candidates
            )
            .unwrap(),
        vec![]
    );
    assert_eq!(
        session
            .find_passkeys(
                &request(json!({})),
                &caller("https://evil.net"),
                &candidates
            )
            .unwrap_err(),
        Error::PasskeyRpMismatch
    );
}

#[test]
fn session_adds_to_an_existing_login_and_replaces_the_same_user() {
    let (session, vault) = session();
    let id = item_id(2);
    let login = Item::from_json(&json!({
        "overview": { "title": "Example", "type": "login", "urls": ["https://example.com"] },
        "details": {
            "username": "alice", "password": "hunter2",
            "passkeys": [{ "rpId": "example.com", "userName": "old display-only entry", "createdAt": "2025-01-01T00:00:00Z" }],
        },
    }).to_string())
    .unwrap();
    let existing = session
        .encrypt_item(&vault, &id, &login, None, &mut rng(3))
        .unwrap();
    let origin = caller("https://example.com");
    let target = Target {
        item: Some(existing.clone()),
        ..new_target(&vault, &id)
    };

    let (first, updated) = session
        .create_passkey(
            &creation(&[-8], json!({})),
            &origin,
            &target,
            &[],
            NOW_MS,
            &mut rng(4),
        )
        .unwrap();
    let with_old_key = EncryptedItem {
        encrypted_item_key: existing.encrypted_item_key.clone(),
        ..updated.clone()
    };
    assert!(
        session.decrypt_item(&vault, &id, &with_old_key).is_ok(),
        "the item keeps its key"
    );
    let item = to_json(&session.decrypt_item(&vault, &id, &updated).unwrap());
    assert_eq!(item["details"]["password"], "hunter2");
    assert_eq!(item["details"]["passkeys"].as_array().unwrap().len(), 2);

    // Registering the same user handle again replaces that passkey, as an authenticator does.
    let target = Target {
        item: Some(updated),
        ..target
    };
    let (second, updated) = session
        .create_passkey(
            &creation(&[-7], json!({})),
            &origin,
            &target,
            &[],
            NOW_MS,
            &mut rng(5),
        )
        .unwrap();
    let item = to_json(&session.decrypt_item(&vault, &id, &updated).unwrap());
    let passkeys = item["details"]["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 2);
    assert_eq!(passkeys[0]["userName"], "old display-only entry");
    assert_eq!(passkeys[1]["credentialId"], second.id);
    assert_ne!(first.id, second.id);
}

#[test]
fn session_honours_exclude_credentials() {
    let (session, vault) = session();
    let origin = caller("https://example.com");
    let (existing, encrypted) = session
        .create_passkey(
            &creation(&[-7], json!({})),
            &origin,
            &new_target(&vault, &item_id(3)),
            &[],
            NOW_MS,
            &mut rng(6),
        )
        .unwrap();
    let exclude = json!({ "excludeCredentials": [{ "type": "public-key", "id": existing.id }] });
    let others = [candidate(&vault, &item_id(3), &encrypted)];

    let refused = session.create_passkey(
        &creation(&[-7], exclude.clone()),
        &origin,
        &new_target(&vault, &item_id(4)),
        &others,
        NOW_MS,
        &mut rng(7),
    );
    assert_eq!(refused.unwrap_err(), Error::PasskeyExcluded);
    let into_same = Target {
        item: Some(encrypted.clone()),
        ..new_target(&vault, &item_id(3))
    };
    let refused = session.create_passkey(
        &creation(&[-7], exclude),
        &origin,
        &into_same,
        &[],
        NOW_MS,
        &mut rng(7),
    );
    assert_eq!(refused.unwrap_err(), Error::PasskeyExcluded);

    let other_excluded =
        json!({ "excludeCredentials": [{ "type": "public-key", "id": "AAAAAAAAAAAAAAAAAAAAAA" }] });
    assert!(
        session
            .create_passkey(
                &creation(&[-7], other_excluded),
                &origin,
                &new_target(&vault, &item_id(4)),
                &others,
                NOW_MS,
                &mut rng(7)
            )
            .is_ok()
    );
}

#[test]
fn session_refuses_non_login_targets() {
    let (session, vault) = session();
    let id = item_id(5);
    let note = Item::from_json(
        r#"{"overview":{"title":"n","type":"secureNote"},"details":{"notes":"hi"}}"#,
    )
    .unwrap();
    let encrypted = session
        .encrypt_item(&vault, &id, &note, None, &mut rng(8))
        .unwrap();
    let target = Target {
        item: Some(encrypted),
        ..new_target(&vault, &id)
    };
    let result = session.create_passkey(
        &creation(&[-7], json!({})),
        &caller("https://example.com"),
        &target,
        &[],
        NOW_MS,
        &mut rng(8),
    );
    assert_eq!(result.unwrap_err(), Error::InvalidItem);
    assert!(matches!(note.details, ItemDetails::SecureNote(_)));
}

#[test]
fn session_signs_platform_client_data() {
    let (session, vault) = session();
    let id = item_id(6);
    let create = platform_client_data("webauthn.create", "https://example.com");
    let (credential, encrypted) = session
        .create_passkey(
            &creation(&[-7], json!({})),
            &platform(&create),
            &new_target(&vault, &id),
            &[],
            NOW_MS,
            &mut rng(10),
        )
        .unwrap();
    let stored = verify_registration(
        &with_client_data(&credential, &create),
        "example.com",
        "https://example.com",
        CHALLENGE,
    );
    let item = to_json(&session.decrypt_item(&vault, &id, &encrypted).unwrap());
    assert_eq!(item["overview"]["title"], "Example");
    assert_eq!(item["overview"]["urls"], json!(["https://example.com"]));
    assert_eq!(
        item["details"]["passkeys"][0]["credentialId"],
        credential.id
    );

    let candidates = [candidate(&vault, &id, &encrypted)];
    let get = platform_client_data("webauthn.get", "https://example.com");
    let found = session
        .find_passkeys(&request(json!({})), &platform(&get), &candidates)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].credential_id, credential.id);
    let assertion = session
        .get_assertion(
            &request(json!({})),
            &platform(&get),
            &candidates[0],
            &credential.id,
        )
        .unwrap();
    verify_assertion(
        &with_client_data(&assertion, &get),
        &stored,
        "example.com",
        "https://example.com",
        CHALLENGE,
    );

    assert_eq!(
        session
            .find_passkeys(
                &request(json!({ "rpId": "other.example" })),
                &platform(&get),
                &candidates
            )
            .unwrap(),
        vec![]
    );
    let exclude = json!({ "excludeCredentials": [{ "type": "public-key", "id": credential.id }] });
    assert_eq!(
        session
            .create_passkey(
                &creation(&[-7], exclude),
                &platform(&create),
                &new_target(&vault, &item_id(7)),
                &candidates,
                NOW_MS,
                &mut rng(11),
            )
            .unwrap_err(),
        Error::PasskeyExcluded
    );
}

// --- Test vectors ------------------------------------------------------------------------------

#[test]
fn vectors() {
    let cases: Vec<Value> = [(-7, 1u8), (-8, 2u8)]
        .into_iter()
        .map(|(alg, seed)| {
            let options = creation(&[alg], json!({}));
            let origin = caller("https://login.example.com");
            let new = passkey::create(&options, &origin, NOW_MS, &mut rng(seed)).unwrap();
            let assertion = passkey::get(&request(json!({})), &origin, &new.record).unwrap();
            let stored = verify_registration(
                &to_json(&new.credential),
                "example.com",
                "https://login.example.com",
                CHALLENGE,
            );
            verify_assertion(
                &to_json(&assertion),
                &stored,
                "example.com",
                "https://login.example.com",
                CHALLENGE,
            );
            vector_case(&options, &new.credential, &new.record, &assertion)
        })
        .collect();
    check(json!({
        "description": "Passkeys from the Octa Pass authenticator for origin https://login.example.com and rpId example.com. ES256 signatures are deterministic (RFC 6979) and Ed25519 signatures always are, so an implementation given `record.privateKey` must reproduce `registration` byte for byte (with the same credential id) and `assertion` exactly. Binary values are base64url without padding.",
        "aaguid": "c9a07734-1d0b-4c72-8ff5-45e0daa2064f",
        "cases": cases,
    }));
}

fn vector_case(
    options: &CreationOptions,
    credential: &RegistrationResponse,
    record: &PasskeyRecord,
    assertion: &AuthenticationResponse,
) -> Value {
    json!({
        "algorithm": options.pub_key_cred_params[0].alg,
        "registration": to_json(credential),
        "record": to_json(record),
        "assertionRequest": { "challenge": CHALLENGE, "rpId": "example.com" },
        "assertion": to_json(assertion),
    })
}

fn check(vectors: Value) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/passkey.json");
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    }
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        vectors, committed,
        "passkey.json changed; regenerate only if the format change is intended"
    );
}
