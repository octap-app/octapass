//! Test vectors for the sharing and key log constructions in `tests/vectors/sharing.json`. Randomness comes
//! from a fixed byte tape, and every random value the construction draws is listed in the
//! vector, so other implementations can reproduce each output exactly. Regenerate after an
//! intended format change with
//! `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test sharing_vectors`.

use ed25519_dalek::SigningKey;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::item::Item;
use octapass_core::keys::SymmetricKey;
use octapass_core::sharing::Role;
use octapass_core::sharing::fingerprint::fingerprint;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use octapass_core::sharing::pq::PqKeyPair;
use octapass_core::sharing::seal::{Opener, SealContext, open_key, seal_key, seal_key_hybrid};
use octapass_core::sharing::share_link;
use octapass_core::transparency::head::{LogIdentity, SignedHead};
use octapass_core::transparency::label::LabelKey;
use octapass_core::transparency::merkle::{
    Frontier, consistency_ranges, fold_nodes, inclusion_ranges, leaf_hash, range_nodes,
};
use octapass_core::transparency::record::KeyRecord;
use rand_core::{CryptoRng, RngCore};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

const VAULT: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
const OWNER: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";
const MEMBER: &str = "0192f0c8-1c2d-7a00-8000-0000000000b1";

/// Hands out exactly the bytes it was given, then panics: proves which random values a
/// construction draws, and in what order.
struct Tape(Vec<u8>);

impl Tape {
    fn new(parts: &[&[u8]]) -> Self {
        Self(parts.concat())
    }

    fn assert_used(&self) {
        assert!(self.0.is_empty(), "{} tape bytes left over", self.0.len());
    }
}

impl RngCore for Tape {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("constructions only fill bytes")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("constructions only fill bytes")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(dest.len() <= self.0.len(), "tape ran out");
        dest.copy_from_slice(&self.0[..dest.len()]);
        self.0.drain(..dest.len());
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Tape {}

fn bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn key32(seed: u8) -> [u8; 32] {
    bytes(seed, 32).try_into().unwrap()
}

fn check(vectors: Value) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/sharing.json");
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    }
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        vectors, committed,
        "sharing.json changed; regenerate only if the format change is intended"
    );
}

fn sealed_box() -> Value {
    let recipient = StaticSecret::from(key32(0x10));
    let recipient_public = PublicKey::from(&recipient).to_bytes();
    let key = SymmetricKey::from_bytes(key32(0x40));
    let (ephemeral, nonce) = (key32(0x70), bytes(0xa0, 24));
    let contexts = [
        SealContext::VaultKey {
            vault_id: VAULT,
            recipient_account_id: MEMBER,
        },
        SealContext::EmergencyAccount {
            grantor_account_id: OWNER,
            contact_account_id: MEMBER,
        },
        SealContext::EmergencyVault {
            grantor_account_id: OWNER,
            contact_account_id: MEMBER,
            vault_id: VAULT,
        },
    ];
    let cases: Vec<Value> = contexts
        .iter()
        .map(|context| {
            let mut tape = Tape::new(&[&ephemeral, &nonce]);
            let sealed = seal_key(&recipient_public, context, &key, &mut tape).unwrap();
            tape.assert_used();
            assert_eq!(open_key(&recipient, context, &sealed).unwrap(), key);
            json!({
                "context": context.to_string(),
                "associatedData": String::from_utf8(context.associated_data()).unwrap(),
                "sealed": sealed,
            })
        })
        .collect();
    json!({
        "description": "X25519 sealed box. The ephemeral secret is drawn first, then the nonce. sealed = 0x01 ‖ ephemeral public ‖ nonce ‖ XChaCha20-Poly1305 ciphertext and tag.",
        "recipientPrivateKey": b64_encode(recipient.as_bytes()),
        "recipientPublicKey": b64_encode(&recipient_public),
        "key": b64_encode(key.as_bytes()),
        "ephemeralSecret": b64_encode(&ephemeral),
        "ephemeralPublicKey": b64_encode(PublicKey::from(&StaticSecret::from(ephemeral)).as_bytes()),
        "nonce": b64_encode(&nonce),
        "cases": cases,
    })
}

fn hybrid_sealed_box() -> Value {
    let recipient = StaticSecret::from(key32(0x10));
    let recipient_public = PublicKey::from(&recipient).to_bytes();
    let seed = bytes(0x90, 64);
    let pq = PqKeyPair::from_seed(&seed).unwrap();
    let key = SymmetricKey::from_bytes(key32(0x40));
    let (ephemeral, encapsulation, nonce) = (key32(0x70), key32(0xe0), bytes(0xa0, 24));
    let context = SealContext::VaultKey {
        vault_id: VAULT,
        recipient_account_id: MEMBER,
    };
    let mut tape = Tape::new(&[&ephemeral, &encapsulation, &nonce]);
    let sealed = seal_key_hybrid(
        &recipient_public,
        pq.public_key(),
        &context,
        &key,
        &mut tape,
    )
    .unwrap();
    tape.assert_used();
    let opener = Opener {
        x25519: &recipient,
        pq: Some(&pq),
    };
    assert_eq!(open_key(opener, &context, &sealed).unwrap(), key);
    json!({
        "description": "Hybrid X25519 + ML-KEM-768 sealed box. The X25519 ephemeral secret is drawn first, then FIPS 203's 32-byte m, then the nonce. sealed = 0x02 ‖ ephemeral public ‖ ML-KEM ciphertext ‖ nonce ‖ XChaCha20-Poly1305 ciphertext and tag.",
        "recipientPrivateKey": b64_encode(recipient.as_bytes()),
        "recipientPublicKey": b64_encode(&recipient_public),
        "recipientPqSeed": b64_encode(&seed),
        "recipientPqPublicKey": pq.public_key().to_b64(),
        "key": b64_encode(key.as_bytes()),
        "ephemeralSecret": b64_encode(&ephemeral),
        "encapsulationRandomness": b64_encode(&encapsulation),
        "nonce": b64_encode(&nonce),
        "context": context.to_string(),
        "sealed": sealed,
    })
}

fn key_log() -> Value {
    let log_key = SigningKey::from_bytes(&key32(0x21));
    let label_key = LabelKey::from_seed(&key32(0x22)).unwrap();
    let identity = LogIdentity {
        sign_key: b64_encode(log_key.verifying_key().as_bytes()),
        oprf_key: label_key.public_key(),
    };
    let log_id = identity.log_id().unwrap();
    let email = "member@example.com";
    let label = label_key.label(email).unwrap();

    let account = SigningKey::from_bytes(&key32(0x23));
    let pq = PqKeyPair::from_seed(&bytes(0x91, 64)).unwrap();
    let record = KeyRecord {
        log_id: b64_encode(&log_id),
        account_id: MEMBER.into(),
        label: b64_encode(&label),
        public_enc_key: b64_encode(PublicKey::from(&StaticSecret::from(key32(0x24))).as_bytes()),
        public_sign_key: b64_encode(account.verifying_key().as_bytes()),
        public_pq_key: pq.public_key().to_b64(),
        created_at: 1_761_177_600_000,
        signature: String::new(),
    }
    .signed(&account);
    record.verify().unwrap();

    // A five-leaf tree with the record as leaf 2.
    let leaves: Vec<Vec<u8>> = (0..5u8)
        .map(|i| match i {
            2 => record.leaf().unwrap().to_vec(),
            _ => bytes(i.wrapping_mul(16), 64),
        })
        .collect();
    let hash = |range: core::ops::Range<u64>| {
        let nodes: Vec<_> = range_nodes(range)
            .into_iter()
            .map(|node| {
                let start = node.index << node.level;
                let mut tree = Frontier::default();
                for leaf in &leaves[start as usize..(start + (1 << node.level)) as usize] {
                    tree.push(leaf_hash(leaf));
                }
                tree.root()
            })
            .collect();
        fold_nodes(&nodes).unwrap()
    };
    let root = hash(0..5);
    let head = SignedHead::sign(&log_key, &log_id, 5, &root, 1_761_177_600_000);
    head.verify(&identity).unwrap();
    let proof = |ranges: Vec<core::ops::Range<u64>>| -> Vec<String> {
        ranges.into_iter().map(|r| b64_encode(&hash(r))).collect()
    };
    json!({
        "description": "The key log. Head and record signatures are Ed25519. Leaves are label ‖ record hash; the tree is RFC 9162. The label comes from the VOPRF seed below (RFC 9497, ristretto255-SHA512, info octapass/v1/key-log-oprf).",
        "logSigningSeed": b64_encode(log_key.as_bytes()),
        "oprfSeed": b64_encode(&key32(0x22)),
        "log": identity,
        "logId": b64_encode(&log_id),
        "email": email,
        "label": b64_encode(&label),
        "accountSigningSeed": b64_encode(account.as_bytes()),
        "record": record,
        "message": b64_encode(&record.message()),
        "recordHash": b64_encode(&record.record_hash()),
        "leaves": leaves.iter().map(|leaf| b64_encode(leaf)).collect::<Vec<_>>(),
        "head": head,
        "inclusionOfLeaf2": proof(inclusion_ranges(2, 5)),
        "consistencyFrom3": { "rootAt3": b64_encode(&hash(0..3)), "proof": proof(consistency_ranges(3, 5)) },
    })
}

fn grant() -> Value {
    let granter = SigningKey::from_bytes(&key32(0x20));
    let member = StaticSecret::from(key32(0x30));
    let vault_key = SymmetricKey::from_bytes(key32(0x50));
    let (ephemeral, nonce) = (key32(0x80), bytes(0xb0, 24));
    let recipient = Recipient {
        account_id: MEMBER.into(),
        public_enc_key: PublicKey::from(&member).to_bytes(),
        public_pq_key: None,
        role: Role::Write,
    };
    let mut tape = Tape::new(&[&ephemeral, &nonce]);
    let grant = SignedGrant::create(
        VAULT,
        &vault_key,
        &recipient,
        OWNER,
        &granter,
        1_761_177_600_000,
        &mut tape,
    )
    .unwrap();
    tape.assert_used();
    let granter_public = granter.verifying_key().to_bytes();
    assert_eq!(
        grant.open(VAULT, MEMBER, &member, &granter_public).unwrap(),
        vault_key
    );
    json!({
        "description": "A signed grant. The vault key is sealed to the member (as in sealedBox, context vaultkey:<vaultId>:<recipientAccountId>), then the message is signed with Ed25519.",
        "granterSigningSeed": b64_encode(granter.as_bytes()),
        "granterPublicSignKey": b64_encode(&granter_public),
        "memberPrivateKey": b64_encode(member.as_bytes()),
        "vaultKey": b64_encode(vault_key.as_bytes()),
        "ephemeralSecret": b64_encode(&ephemeral),
        "nonce": b64_encode(&nonce),
        "message": b64_encode(&grant.message()),
        "grant": serde_json::to_value(&grant).unwrap(),
    })
}

fn fingerprints() -> Value {
    let cases: Vec<Value> = [(0x01, 0x02), (0x11, 0x22)]
        .iter()
        .map(|&(enc, sign)| {
            let print = fingerprint(&key32(enc), &key32(sign));
            json!({
                "publicEncKey": b64_encode(&key32(enc)),
                "publicSignKey": b64_encode(&key32(sign)),
                "fingerprint": serde_json::to_value(print).unwrap(),
            })
        })
        .collect();
    json!({
        "description": "Fingerprints: SHA-256 of a label and both public keys, shown as 6 groups of 4 digits and 8 emoji.",
        "cases": cases,
    })
}

fn share_links() -> Value {
    let item = Item::from_json(
        r#"{"overview":{"title":"Router","type":"login"},"details":{"username":"admin","password":"hunter2"}}"#,
    )
    .unwrap();
    let (link_key, salt, nonce) = (key32(0x60), bytes(0xc0, 16), bytes(0xd0, 24));

    let mut tape = Tape::new(&[&link_key, &nonce]);
    let plain = share_link::create(&item, None, &mut tape).unwrap();
    tape.assert_used();
    assert_eq!(
        share_link::open(&plain.ciphertext, &plain.key, None).unwrap(),
        item
    );

    let passphrase = "correct horse battery";
    let mut tape = Tape::new(&[&link_key, &salt, &nonce]);
    let protected = share_link::create(&item, Some(passphrase), &mut tape).unwrap();
    tape.assert_used();
    assert_eq!(
        share_link::open(&protected.ciphertext, &protected.key, Some(passphrase)).unwrap(),
        item
    );
    // The fragment is the link key, whatever the passphrase.
    assert_eq!(b64_decode(&protected.key).unwrap(), link_key);

    json!({
        "description": "Share links. The link key is drawn first, then the Argon2id salt (passphrase only), then the nonce. The key is the URL fragment.",
        "item": item.to_json(),
        "linkKey": b64_encode(&link_key),
        "salt": b64_encode(&salt),
        "nonce": b64_encode(&nonce),
        "withoutPassphrase": { "ciphertext": plain.ciphertext },
        "withPassphrase": {
            "passphrase": passphrase,
            "kdf": { "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1 },
            "ciphertext": protected.ciphertext,
        },
    })
}

#[test]
fn sharing() {
    check(json!({
        "sealedBox": sealed_box(),
        "hybridSealedBox": hybrid_sealed_box(),
        "keyLog": key_log(),
        "grant": grant(),
        "fingerprint": fingerprints(),
        "shareLink": share_links(),
    }));
}
