//! Test vectors for key rotation and emergency takeover, in `tests/vectors/key-rotation.json`.
//! Randomness comes from a fixed byte tape, and every random value a construction draws is listed
//! in the vector, so other implementations can reproduce each output exactly. Regenerate after an
//! intended format change with
//! `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test key_rotation_vectors`.

use octapass_core::account::{AccountBundle, AccountKeyPairs};
use octapass_core::credentials::{CredentialsUpdate, takeover_message};
use octapass_core::encoding::b64_encode;
use octapass_core::envelope::{Context, seal_b64, wrap_key};
use octapass_core::kdf::{AccountKeys, KdfParams};
use octapass_core::keys::SymmetricKey;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session;
use octapass_core::sharing::Role;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_core::sharing::vault::{ItemKey, SyncedVault};
use rand_core::{CryptoRng, RngCore};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

const ACCOUNT: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";
const CONTACT: &str = "0192f0c8-1c2d-7a00-8000-0000000000b1";
const RECORD: &str = "0192f0c8-1c2d-7a00-8000-0000000000c1";
const VAULT: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
const ITEM: &str = "0192f0c8-1c2d-7a00-8000-0000000000d1";

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

fn key(seed: u8) -> SymmetricKey {
    let bytes: [u8; 32] = bytes(seed, 32).try_into().unwrap();
    SymmetricKey::from_bytes(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check(vectors: Value) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/key-rotation.json"
    );
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    }
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        vectors, committed,
        "key-rotation.json changed; regenerate only if the format change is intended"
    );
}

/// An unlocked account built from fixed keys.
struct Fixture {
    auk: SymmetricKey,
    ask: SymmetricKey,
    session: Session,
}

fn fixture() -> Fixture {
    let (auk, ask) = (key(0x10), key(0x30));
    let mut tape = Tape::new(&[
        &bytes(0x50, 32), // the Ed25519 seed
        &bytes(0x70, 32), // the X25519 secret
        &bytes(0x90, 24), // the wrapped ASK's nonce
        &bytes(0xa0, 24), // the wrapped private keys' nonce
    ]);
    let pairs = AccountKeyPairs::generate(&mut tape);
    let wrapped_ask = wrap_key(&auk, &Context::Ask, &ask, &mut tape).unwrap();
    let private_keys = {
        let mut both = bytes(0x70, 32);
        both.extend(bytes(0x50, 32));
        both
    };
    let bundle = AccountBundle {
        account_id: Some(ACCOUNT.into()),
        email: "grantor@example.com".into(),
        kdf: KdfParams::DEFAULT,
        account_salt: b64_encode(&bytes(0xb0, 16)),
        wrapped_ask,
        public_enc_key: b64_encode(&pairs.public_enc_key()),
        public_sign_key: b64_encode(&pairs.public_sign_key()),
        wrapped_private_keys: seal_b64(&ask, &Context::PrivateKeys, &private_keys, &mut tape)
            .unwrap(),
        recovery_wrapped_ask: String::new(),
        wrapped_pq_private_key: None,
        key_record: None,
    };
    tape.assert_used();
    let session = Session::unlock(bundle, &auk).unwrap();
    Fixture { auk, ask, session }
}

/// The personal vault of the fixture, its open key and one item.
fn personal_vault(fixture: &mut Fixture) -> (SymmetricKey, String, String) {
    let vault_key = key(0x31);
    let item_key = key(0x32);
    let mut tape = Tape::new(&[&bytes(0x11, 24), &bytes(0x12, 24)]);
    let wrapped_vault_key = wrap_key(
        &fixture.ask,
        &Context::VaultKey { vault_id: VAULT },
        &vault_key,
        &mut tape,
    )
    .unwrap();
    let wrapped_item_key = wrap_key(
        &vault_key,
        &Context::ItemKey {
            vault_id: VAULT,
            item_id: ITEM,
        },
        &item_key,
        &mut tape,
    )
    .unwrap();
    tape.assert_used();
    fixture
        .session
        .open_vault(VAULT, &wrapped_vault_key)
        .unwrap();
    (vault_key, wrapped_vault_key, wrapped_item_key)
}

fn secret_key_rotation(fixture: &Fixture) -> Value {
    // Rotating keeps the password, so the only randomness is the Secret Key, the salt and a nonce.
    let (secret_key, salt, nonce) = (bytes(0x21, 16), bytes(0x22, 16), bytes(0x23, 24));
    let mut tape = Tape::new(&[&secret_key, &salt, &nonce]);
    let new = fixture
        .session
        .new_credentials(
            "correct horse battery staple",
            None,
            false,
            KdfParams::DEFAULT,
            &mut tape,
        )
        .unwrap();
    tape.assert_used();
    let derived = AccountKeys::derive(
        "correct horse battery staple",
        &new.secret_key,
        "grantor@example.com",
        &salt,
        &KdfParams::DEFAULT,
    )
    .unwrap();
    assert_eq!(derived.auk, new.keys.auk);
    let bundle = new.apply(fixture.session.bundle());
    let reopened = Session::unlock(bundle, &new.keys.auk).unwrap();
    assert_eq!(
        reopened.key_pairs().public_sign_key(),
        fixture.session.key_pairs().public_sign_key()
    );
    json!({
        "email": "grantor@example.com",
        "password": "correct horse battery staple",
        "ask": b64_encode(fixture.ask.as_bytes()),
        "kdf": KdfParams::DEFAULT,
        "tape": { "secretKey": hex(&secret_key), "accountSalt": hex(&salt), "wrappedAskNonce": hex(&nonce) },
        "newSecretKey": new.secret_key.to_text().as_str(),
        "newAuk": b64_encode(new.keys.auk.as_bytes()),
        "newAuthSecret": b64_encode(new.keys.auth_secret.as_bytes()),
        "update": new.update,
    })
}

fn personal_rotation(fixture: &mut Fixture) -> Value {
    let (vault_key, wrapped_vault_key, wrapped_item_key) = personal_vault(fixture);
    let (new_key, item_nonce, vault_nonce) = (key(0x33), bytes(0x13, 24), bytes(0x14, 24));
    let mut tape = Tape::new(&[new_key.as_bytes(), &item_nonce, &vault_nonce]);
    let items = [ItemKey {
        item_id: ITEM.into(),
        encrypted_item_key: wrapped_item_key.clone(),
    }];
    let rotation = fixture
        .session
        .rotate_personal_vault_key(VAULT, &items, &mut tape)
        .unwrap();
    tape.assert_used();
    assert_eq!(rotation.key_id, b64_encode(&new_key.key_id()));
    json!({
        "accountKey": b64_encode(fixture.ask.as_bytes()),
        "vaultId": VAULT,
        "itemId": ITEM,
        "vaultKey": b64_encode(vault_key.as_bytes()),
        "wrappedVaultKey": wrapped_vault_key,
        "encryptedItemKey": wrapped_item_key,
        "tape": { "newVaultKey": b64_encode(new_key.as_bytes()), "itemKeyNonce": hex(&item_nonce), "vaultKeyNonce": hex(&vault_nonce) },
        "rotation": rotation,
    })
}

fn pending_change(fixture: &mut Fixture) -> Value {
    let (_, _, wrapped_item_key) = personal_vault(fixture);
    let new_key = key(0x34);
    let mut wrap = Tape::new(&[&bytes(0x15, 24)]);
    let new_wrapped = wrap_key(
        &fixture.ask,
        &Context::VaultKey { vault_id: VAULT },
        &new_key,
        &mut wrap,
    )
    .unwrap();
    wrap.assert_used();
    let item_nonce = bytes(0x16, 24);
    let mut tape = Tape::new(&[&item_nonce]);
    let pending = [ItemKey {
        item_id: ITEM.into(),
        encrypted_item_key: wrapped_item_key.clone(),
    }];
    let moved = fixture
        .session
        .rekey_synced_vault(
            &SyncedVault {
                id: VAULT,
                personal: true,
                role: Role::Owner,
                wrapped_vault_key: &new_wrapped,
                grant: None,
            },
            &pending,
            &mut tape,
        )
        .unwrap();
    tape.assert_used();
    json!({
        "newWrappedVaultKey": new_wrapped,
        "encryptedItemKey": wrapped_item_key,
        "itemKeyNonce": hex(&item_nonce),
        "moved": moved,
    })
}

fn takeover(fixture: &Fixture) -> Value {
    let update = CredentialsUpdate {
        kdf: KdfParams::DEFAULT,
        account_salt: b64_encode(&bytes(0x41, 16)),
        wrapped_ask: "new-wrapped-ask".into(),
        recovery_wrapped_ask: Some("new-recovery-wrapped-ask".into()),
    };
    let session = &fixture.session;
    let salt = session.bundle().account_salt.clone();
    let message = takeover_message(RECORD, ACCOUNT, CONTACT, &salt, "upload", &update).unwrap();
    let signature = session
        .sign_takeover(RECORD, CONTACT, "upload", &update)
        .unwrap();
    json!({
        "recordId": RECORD,
        "grantorId": ACCOUNT,
        "contactId": CONTACT,
        "currentAccountSalt": salt,
        "registrationUpload": "upload",
        "update": update,
        "publicSignKey": b64_encode(&session.key_pairs().public_sign_key()),
        "message": hex(&message),
        "signature": signature,
    })
}

fn renewed_emergency_key(fixture: &mut Fixture) -> Value {
    personal_vault(fixture);
    let contact = StaticSecret::from(<[u8; 32]>::try_from(bytes(0xc0, 32)).unwrap());
    let contact_public = PublicKey::from(&contact).to_bytes();
    let (ephemeral, nonce) = (bytes(0xd0, 32), bytes(0xf0, 24));
    let mut tape = Tape::new(&[&ephemeral, &nonce]);
    let sealed = fixture
        .session
        .seal_for_emergency_contact(
            CONTACT,
            &contact_public,
            None,
            &EmergencyScope::Vault {
                vault_id: VAULT.into(),
            },
            &mut tape,
        )
        .unwrap();
    tape.assert_used();
    json!({
        "grantorId": ACCOUNT,
        "contactId": CONTACT,
        "vaultId": VAULT,
        "contactPublicKey": b64_encode(&contact_public),
        "tape": { "ephemeralSecret": hex(&ephemeral), "nonce": hex(&nonce) },
        "context": format!("emergency:{ACCOUNT}:{CONTACT}:vault:{VAULT}"),
        "sealedKey": sealed,
    })
}

#[test]
fn key_rotation_vectors() {
    let mut fixture = fixture();
    assert_eq!(fixture.auk, key(0x10));
    check(json!({
        "secretKeyRotation": secret_key_rotation(&fixture),
        "personalVaultRotation": personal_rotation(&mut fixture),
        "pendingChange": pending_change(&mut fixture),
        "emergencyTakeover": takeover(&fixture),
        "renewedEmergencyKey": renewed_emergency_key(&mut fixture),
    }));
}

#[test]
fn a_secret_key_from_the_vector_parses() {
    let mut tape = Tape::new(&[&bytes(0x21, 16)]);
    let key = SecretKey::generate(&mut tape);
    tape.assert_used();
    assert_eq!(SecretKey::parse(key.to_text().as_str()).unwrap(), key);
}
