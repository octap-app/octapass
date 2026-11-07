//! Deterministic vectors for Octa Pass Safe and the account's age keys, in
//! `tests/vectors/safe.json`, for other implementations to check against. Regenerate after an
//! intended format change with `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test
//! safe_vectors`.

use std::path::PathBuf;

use octapass_core::account::AccountKeyPairs;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::keys::SymmetricKey;
use octapass_core::safe::{
    BlobKind, ObjectKind, ObjectRecord, ROOT, SafeKeys, encode_file_key, new_blob_id,
    open_content_blob,
};
use octapass_core::tools::age::{AccountFileKeys, recipient_of};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

const SAFE_ID: &str = "11111111-1111-4111-8111-111111111111";
const OBJECT: &str = "22222222-2222-4222-8222-222222222222";

fn path() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "vectors", "safe.json"]
        .iter()
        .collect()
}

fn vectors() -> Value {
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let safe_key = SymmetricKey::from_bytes([0x5a; 32]);
    let keys = SafeKeys::derive(&safe_key, SAFE_ID).unwrap();

    let plaintext: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let content_id = new_blob_id(BlobKind::Content, &mut rng);
    let (file_key, mut encryptor) = keys.new_content(OBJECT, &content_id, &mut rng).unwrap();
    let mut content = encryptor.push(&plaintext).unwrap();
    content.extend_from_slice(&encryptor.finish().unwrap());

    let record = ObjectRecord {
        object: OBJECT.into(),
        rev: 3,
        prev: Some(new_blob_id(BlobKind::Record, &mut rng)),
        parent: ROOT.into(),
        name: "الميزانية 2026.pdf".into(),
        kind: ObjectKind::File,
        size: plaintext.len() as u64,
        modified: 1_793_577_600_000,
        content: Some(content_id.clone()),
        file_key: Some(encode_file_key(&file_key)),
    };
    let record_id = new_blob_id(BlobKind::Record, &mut rng);
    let sealed = keys.seal_record(&record_id, &record, &mut rng).unwrap();

    let pairs = AccountKeyPairs::generate(&mut ChaCha20Rng::from_seed([22; 32]));
    let file_keys = AccountFileKeys::derive(&pairs).unwrap();

    json!({
        "safe": {
            "safeKey": b64_encode(safe_key.as_bytes()),
            "safeId": SAFE_ID,
            "object": OBJECT,
            "record": serde_json::to_value(&record).unwrap(),
            "recordBlobId": record_id,
            "recordBlob": b64_encode(&sealed),
            "contentBlobId": content_id,
            "contentBlob": b64_encode(&content),
            "plaintextLength": plaintext.len(),
            "plaintextRule": "byte i is i mod 251",
        },
        "fileIdentity": {
            "accountEncryptionPrivateKey": b64_encode(pairs.encryption_key().as_bytes()),
            "fileIdentity": file_keys.file_identity.as_str(),
            "fileRecipient": file_keys.file_recipient,
            "accountRecipient": file_keys.account_recipient,
            "derivation": "HKDF-SHA256(ikm = private key, salt = empty, info = \"octapass/v1/age-identity\"), then age bech32",
        },
    })
}

#[test]
fn matches_the_committed_vectors() {
    let made = vectors();
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        std::fs::write(path(), serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
        return;
    }
    let committed: Value = serde_json::from_slice(&std::fs::read(path()).unwrap()).unwrap();
    assert_eq!(made, committed);
}

#[test]
fn the_committed_vectors_open() {
    let vectors: Value = serde_json::from_slice(&std::fs::read(path()).unwrap()).unwrap();
    let safe = &vectors["safe"];
    let text = |value: &Value| value.as_str().unwrap().to_owned();
    let key = SymmetricKey::from_slice(&b64_decode(&text(&safe["safeKey"])).unwrap()).unwrap();
    let keys = SafeKeys::derive(&key, &text(&safe["safeId"])).unwrap();
    let record = keys
        .open_record(
            &text(&safe["recordBlobId"]),
            &b64_decode(&text(&safe["recordBlob"])).unwrap(),
        )
        .unwrap();
    assert_eq!(record.name, "الميزانية 2026.pdf");
    let plain = open_content_blob(
        &keys,
        &record,
        &b64_decode(&text(&safe["contentBlob"])).unwrap(),
    )
    .unwrap();
    assert_eq!(
        plain.len() as u64,
        safe["plaintextLength"].as_u64().unwrap()
    );
    assert!(
        plain
            .iter()
            .enumerate()
            .all(|(i, byte)| *byte == (i % 251) as u8)
    );

    let identity = &vectors["fileIdentity"];
    assert_eq!(
        recipient_of(&text(&identity["fileIdentity"])).unwrap(),
        text(&identity["fileRecipient"])
    );
}
