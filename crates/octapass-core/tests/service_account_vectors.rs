//! Test vectors for service account tokens in `tests/vectors/service-account.json`: from a fixed
//! root, the derived keys, the token text and the sign-in signature, so other implementations can
//! reproduce each one. Regenerate after an intended format change with
//! `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test service_account_vectors`.

use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::service_account::{ServiceAccountToken, auth_message};
use serde_json::{Value, json};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/service-account.json"
);
const ID: &str = "0192f0c8-1c2d-7a00-8000-0000000000c1";
const VAULT: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
const SERVER: &str = "https://octap.app";
const CHALLENGE: &str = "c2lnbiBtZSBvbmNl";

fn bytes(seed: u8) -> [u8; 32] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn compute(root: [u8; 32], creator: [u8; 32]) -> Value {
    let token = ServiceAccountToken::new(ID, VAULT, root, creator, SERVER).unwrap();
    let keys = token.keys();
    json!({
        "id": ID,
        "vaultId": VAULT,
        "serverUrl": SERVER,
        "root": b64_encode(&root),
        "creatorPublicSignKey": b64_encode(&creator),
        "publicEncKey": b64_encode(&keys.public_enc_key()),
        "publicSignKey": b64_encode(&keys.public_sign_key()),
        "token": token.encode().as_str(),
        "challenge": CHALLENGE,
        "authMessage": b64_encode(&auth_message(ID, CHALLENGE)),
        "signature": keys.sign_challenge(ID, CHALLENGE).unwrap(),
    })
}

#[test]
fn vectors() {
    let computed = compute(bytes(0x10), bytes(0x60));
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        let text = serde_json::to_string_pretty(&computed).unwrap() + "\n";
        std::fs::write(PATH, text).unwrap();
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(stored, computed);

    // The stored token parses back to the same parts, and derives the same keys.
    let token = ServiceAccountToken::parse(stored["token"].as_str().unwrap()).unwrap();
    assert_eq!(token.id(), ID);
    assert_eq!(token.vault_id(), VAULT);
    assert_eq!(token.server_url(), SERVER);
    let creator: [u8; 32] =
        b64_decode_array(stored["creatorPublicSignKey"].as_str().unwrap()).unwrap();
    assert_eq!(token.creator_public_sign_key(), &creator);
    assert_eq!(
        b64_encode(&token.keys().public_enc_key()),
        stored["publicEncKey"].as_str().unwrap()
    );
}
