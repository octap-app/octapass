//! Deterministic test vectors in `tests/vectors/*.json`, for other implementations to check
//! against. Every vector is regenerated from fixed inputs and fixed-seed randomness and compared
//! with the committed file. After an intended format change, regenerate with
//! `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test vectors`.

use std::path::PathBuf;

use octapass_core::account::{AccountBundle, NewAccount, new_id};
use octapass_core::attachment::{self, Encryptor};
use octapass_core::backup::BACKUP_KDF;
use octapass_core::device;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::envelope::{Context, open_b64, seal_b64, unwrap_key, wrap_key};
use octapass_core::item::Item;
use octapass_core::kdf::{self, AccountKeys, KdfParams};
use octapass_core::keys::SymmetricKey;
use octapass_core::local::{DeviceProtection, LocalVault, keys};
use octapass_core::opaque::server::OpaqueServer;
use octapass_core::opaque::{LoginClient, RegistrationClient};
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::{EncryptedItem, Session};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn vector_path(name: &str) -> PathBuf {
    [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "vectors",
        &format!("{name}.json"),
    ]
    .iter()
    .collect()
}

fn check(name: &str, vectors: Value) {
    let path = vector_path(name);
    if std::env::var_os("OCTAPASS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vectors).unwrap() + "\n",
        )
        .unwrap();
    }
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        vectors, committed,
        "{name}.json changed; regenerate only if the format change is intended"
    );
}

#[test]
fn kdf() {
    let password = "P\u{e4}ssw\u{f6}rd \u{fb01} \u{1f511}";
    let email = "  Alice@Example.COM ";
    let account_salt: Vec<u8> = (0..16).collect();
    let secret_key = SecretKey::from_bytes(core::array::from_fn(|i| 0x10 + i as u8));
    let params = KdfParams::DEFAULT;

    let pw_key = kdf::password_key(password, email, &account_salt, &params).unwrap();
    let sk_key = kdf::secret_key_key(&secret_key, &account_salt);
    let keys = AccountKeys::combine(&pw_key, &sk_key);
    let derived = AccountKeys::derive(
        password,
        &SecretKey::parse(&secret_key.to_text()).unwrap(),
        email,
        &account_salt,
        &params,
    )
    .unwrap();
    assert_eq!(derived.auk, keys.auk);

    check(
        "kdf",
        json!({
            "description": "Master password + Secret Key -> AUK and auth_secret. Binary values are base64url without padding.",
            "input": {
                "password": password,
                "email": email,
                "accountSalt": b64_encode(&account_salt),
                "secretKey": secret_key.to_text().as_str(),
                "kdf": params,
            },
            "normalizedEmail": kdf::normalize_email(email),
            "normalizedPasswordUtf8": b64_encode(kdf::normalize_password(password).as_bytes()),
            "argon2Salt": b64_encode(&kdf::argon2_salt(&account_salt, email)),
            "pwKey": b64_encode(pw_key.as_bytes()),
            "skKey": b64_encode(sk_key.as_bytes()),
            "auk": b64_encode(keys.auk.as_bytes()),
            "authSecret": b64_encode(keys.auth_secret.as_bytes()),
        }),
    );
}

#[test]
fn secret_key_and_recovery_code() {
    let mut random = rng(1);
    let secret_keys: Vec<Value> = [
        [0u8; 16],
        [0xff; 16],
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|_| random.next_u32() as u8),
    ]
    .into_iter()
    .map(|bytes| {
        let key = SecretKey::from_bytes(bytes);
        assert_eq!(SecretKey::parse(&key.to_text()).unwrap(), key);
        json!({ "bytes": b64_encode(&bytes), "text": key.to_text().as_str() })
    })
    .collect();
    check(
        "secret-key",
        json!({ "description": "Secret Key bytes and their text form.", "cases": secret_keys }),
    );

    let codes: Vec<Value> = [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)]
        .into_iter()
        .map(|bytes| {
            let code = RecoveryCode::from_bytes(bytes);
            assert_eq!(RecoveryCode::parse(&code.to_text()).unwrap(), code);
            json!({ "bytes": b64_encode(&bytes), "text": code.to_text().as_str(), "wrappingKey": b64_encode(code.wrapping_key().as_bytes()) })
        })
        .collect();
    check(
        "recovery-code",
        json!({ "description": "Recovery code bytes, text form (with checksum) and the key that wraps the ASK.", "cases": codes }),
    );
}

#[test]
fn envelope() {
    let mut random = rng(2);
    let key = SymmetricKey::from_bytes(core::array::from_fn(|i| 0x80 + i as u8));
    let (vault_id, item_id) = (
        "0192f0c8-1c2d-7a00-8000-0000000000aa",
        "0192f0c8-1c2d-7a00-8000-0000000000bb",
    );
    let cases: Vec<Value> = [
        (Context::Ask, b"".as_slice()),
        (Context::VaultKey { vault_id }, &[0x42; 32]),
        (Context::ItemKey { vault_id, item_id }, &[0x43; 32]),
        (
            Context::ItemOverview { vault_id, item_id },
            br#"{"schemaVersion":1,"title":"GitHub","type":"login"}"#,
        ),
        (
            Context::ItemDetails { vault_id, item_id },
            br#"{"schemaVersion":1,"password":"hunter2"}"#,
        ),
    ]
    .into_iter()
    .map(|(context, plaintext)| {
        let envelope = seal_b64(&key, &context, plaintext, &mut random).unwrap();
        assert_eq!(
            open_b64(&key, &context, &envelope).unwrap().as_slice(),
            plaintext
        );
        let bytes = b64_decode(&envelope).unwrap();
        json!({
            "context": context.to_string(),
            "associatedData": String::from_utf8(context.associated_data()).unwrap(),
            "plaintext": b64_encode(plaintext),
            "nonce": b64_encode(&bytes[17..41]),
            "envelope": envelope,
        })
    })
    .collect();
    check(
        "envelope",
        json!({
            "description": "XChaCha20-Poly1305 envelopes: version (0x01) || keyId (16) || nonce (24) || ciphertext || tag (16).",
            "key": b64_encode(key.as_bytes()),
            "keyId": b64_encode(&key.key_id()),
            "cases": cases,
        }),
    );
}

#[test]
fn attachment() {
    let mut random = rng(9);
    let key = SymmetricKey::from_bytes(core::array::from_fn(|i| 0x40 + i as u8));
    let (vault_id, item_id, attachment_id) = (
        "0192f0c8-1c2d-7a00-8000-0000000000aa",
        "0192f0c8-1c2d-7a00-8000-0000000000bb",
        "0192f0c8-1c2d-7a00-8000-0000000000cc",
    );
    let cases: Vec<Value> = [
        0usize,
        100,
        attachment::CHUNK_LEN,
        attachment::CHUNK_LEN + 1,
    ]
    .into_iter()
    .map(|len| {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut encryptor =
            Encryptor::new(&key, vault_id, item_id, attachment_id, &mut random).unwrap();
        let mut file = encryptor.push(&plaintext).unwrap();
        file.extend(encryptor.finish().unwrap());
        assert_eq!(file.len() as u64, attachment::encrypted_len(len as u64));
        let sha256: String = Sha256::digest(&file)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut case = json!({
            "plaintextLength": len,
            "header": b64_encode(&file[..attachment::HEADER_LEN]),
            "encryptedLength": file.len(),
            "encryptedSha256": sha256,
        });
        if len <= 100 {
            case["encrypted"] = json!(b64_encode(&file));
        }
        case
    })
    .collect();
    check(
        "attachment",
        json!({
            "description": "Attachment files: header (version 0x01 || keyId (16) || noncePrefix (19)) then 64 KiB chunks, each XChaCha20-Poly1305 with nonce noncePrefix || index (u32 big-endian) || last (0x00 or 0x01). The plaintext of each case is byte i = i mod 251.",
            "fileKey": b64_encode(key.as_bytes()),
            "associatedData": String::from_utf8(Context::Attachment { vault_id, item_id, attachment_id }.associated_data()).unwrap(),
            "chunkLength": attachment::CHUNK_LEN,
            "cases": cases,
        }),
    );
}

#[test]
fn opaque() {
    let mut random = rng(3);
    let server = OpaqueServer::generate(&mut random);
    let auth_secret = SymmetricKey::from_bytes([0x11; 32]);
    let email = "alice@example.com";

    let (registration, registration_request) =
        RegistrationClient::start(&auth_secret, &mut random).unwrap();
    let registration_response = server
        .registration_start(email, &registration_request)
        .unwrap();
    let registration_upload = registration
        .finish(&auth_secret, &registration_response, &mut random)
        .unwrap();
    let password_file = OpaqueServer::registration_finish(&registration_upload).unwrap();

    let (login, credential_request) = LoginClient::start(&auth_secret, &mut random).unwrap();
    let (state, credential_response) = server
        .login_start(
            email,
            Some(&password_file),
            &credential_request,
            &mut random,
        )
        .unwrap();
    let credential_finalization = login
        .finish(&auth_secret, &credential_response, &mut random)
        .unwrap();
    state.finish(&credential_finalization).unwrap();

    check(
        "opaque",
        json!({
            "description": "One OPAQUE registration and login (ristretto255, TripleDh<Ristretto255, Sha512>, identity KSF). Messages are the HTTP API fields.",
            "serverSetup": b64_encode(&server.to_bytes()),
            "credentialIdentifier": email,
            "authSecret": b64_encode(auth_secret.as_bytes()),
            "registrationRequest": registration_request,
            "registrationResponse": registration_response,
            "registrationUpload": registration_upload,
            "passwordFile": password_file,
            "credentialRequest": credential_request,
            "credentialResponse": credential_response,
            "credentialFinalization": credential_finalization,
        }),
    );
}

#[test]
fn account() {
    let mut random = rng(4);
    let (email, password, now_ms) = (
        "alice@example.com",
        "correct horse battery staple",
        1_761_177_600_000,
    );
    let account =
        NewAccount::create(email, password, KdfParams::DEFAULT, now_ms, &mut random).unwrap();
    let vault_id = account.personal_vault.id.clone();
    let item_id = new_id(now_ms, &mut random);
    let plaintext = json!({
        "overview": { "schemaVersion": 1, "title": "GitHub", "type": "login", "urls": ["https://github.com"] },
        "details": { "schemaVersion": 1, "username": "alice", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP" }
    });
    let item = Item::from_json(&plaintext.to_string()).unwrap();
    let encrypted = Session::from_new_account(&account)
        .unwrap()
        .encrypt_item(&vault_id, &item_id, &item, None, &mut random)
        .unwrap();

    // Opening it the way a client on a new device does: from the bundle and the two secrets.
    let secret_key = SecretKey::parse(&account.secret_key.to_text()).unwrap();
    let keys = AccountKeys::derive(
        password,
        &secret_key,
        email,
        &b64_decode(&account.bundle.account_salt).unwrap(),
        &account.bundle.kdf,
    )
    .unwrap();
    let mut session = Session::unlock(account.bundle.clone(), &keys.auk).unwrap();
    session
        .open_vault(&vault_id, &account.personal_vault.wrapped_vault_key)
        .unwrap();
    assert_eq!(
        session
            .decrypt_item(&vault_id, &item_id, &encrypted)
            .unwrap(),
        item
    );

    check(
        "account",
        json!({
            "description": "A complete account as created at sign-up, plus one encrypted item. Unlock with password + secretKey, or with recoveryCode.",
            "input": { "email": email, "password": password, "nowMs": now_ms },
            "secretKey": account.secret_key.to_text().as_str(),
            "recoveryCode": account.recovery_code.to_text().as_str(),
            "auk": b64_encode(account.keys.auk.as_bytes()),
            "authSecret": b64_encode(account.keys.auth_secret.as_bytes()),
            "ask": b64_encode(account.ask.as_bytes()),
            "personalVaultKey": b64_encode(account.personal_vault_key.as_bytes()),
            "account": account.bundle,
            "personalVault": account.personal_vault,
            "item": {
                "vaultId": vault_id,
                "itemId": item_id,
                "plaintext": plaintext,
                "encrypted": encrypted,
            },
        }),
    );
}

#[test]
fn committed_account_vector_opens_with_the_recovery_code() {
    let vector: Value =
        serde_json::from_str(&std::fs::read_to_string(vector_path("account")).unwrap()).unwrap();
    let code = RecoveryCode::parse(vector["recoveryCode"].as_str().unwrap()).unwrap();
    let mut session = Session::recover(
        serde_json::from_value(vector["account"].clone()).unwrap(),
        &code,
    )
    .unwrap();
    let item = &vector["item"];
    let vault_id = item["vaultId"].as_str().unwrap();
    session
        .open_vault(
            vault_id,
            vector["personalVault"]["wrappedVaultKey"].as_str().unwrap(),
        )
        .unwrap();
    let encrypted: EncryptedItem = serde_json::from_value(item["encrypted"].clone()).unwrap();
    let decrypted = session
        .decrypt_item(vault_id, item["itemId"].as_str().unwrap(), &encrypted)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&decrypted.to_json()).unwrap(),
        item["plaintext"]
    );
}

/// Device unlock for the account in `account.json`.
#[test]
fn device_unlock() {
    let account: Value =
        serde_json::from_str(&std::fs::read_to_string(vector_path("account")).unwrap()).unwrap();
    let bundle: AccountBundle = serde_json::from_value(account["account"].clone()).unwrap();
    let ask =
        SymmetricKey::from_slice(&b64_decode(account["ask"].as_str().unwrap()).unwrap()).unwrap();

    let mut random = rng(5);
    let prf_output: [u8; 32] = core::array::from_fn(|i| 0xa0 + i as u8);
    let device_salt = device::generate_device_salt(&mut random);
    let device_key = device::device_key(&prf_output, &device_salt).unwrap();
    let wrapped_ask = wrap_key(&device_key, &Context::DeviceUnlock, &ask, &mut random).unwrap();

    assert_eq!(
        unwrap_key(&device_key, &Context::DeviceUnlock, &wrapped_ask).unwrap(),
        ask
    );
    let session =
        Session::unlock_with_device_key(bundle, &prf_output, &device_salt, &wrapped_ask).unwrap();
    assert_eq!(session.bundle().email, "alice@example.com");

    check(
        "device-unlock",
        json!({
            "description": "Device unlock (passkey PRF) for the account in account.json: device_key = HKDF-SHA256(prfOutput, salt = deviceSalt, info = \"openpass/v1/device-unlock\"), wrappedAsk = AEAD(device_key, ASK, \"device-unlock\").",
            "prfInput": b64_encode(&device::prf_input()),
            "prfOutput": b64_encode(&prf_output),
            "deviceSalt": b64_encode(&device_salt),
            "deviceKey": b64_encode(device_key.as_bytes()),
            "ask": account["ask"],
            "wrappedAsk": wrapped_ask,
        }),
    );
}

#[test]
fn chip_secret_for_the_extension() {
    let key = SymmetricKey::from_slice(&[0x31; 32]).unwrap();
    let secret: [u8; 32] = core::array::from_fn(|i| 0x70 + i as u8);
    let sealed = keys::seal_chip_secret(&key, &secret, &mut rng(11)).unwrap();
    assert_eq!(
        keys::open_chip_secret(&key, &sealed).unwrap().as_slice(),
        &secret
    );
    check(
        "chip-secret",
        json!({
            "description": "A device chip's secret sealed by the desktop app for the browser extension. key = HKDF-SHA256(X25519 shared secret, salt = app public key || extension public key, info = \"openpass/v1/native-messaging-chip\"); sealed = envelope(key, secret, context \"chip-secret\"). hardwareSecret itself is SHA-256(\"openpass/v1/chip-secret|\" || what the chip returned). Binary values are base64url without padding.",
            "key": b64_encode(key.as_bytes()),
            "secret": b64_encode(&secret),
            "sealed": sealed,
        }),
    );
}

#[test]
fn local_vault_and_backup() {
    let password = "vexed-kiwi-trumpet-galaxy-oboe";
    let chip: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
    let now_ms = 1_792_713_600_000;
    let protection = DeviceProtection {
        kdf: KdfParams::DEFAULT,
        hardware_secret: Some(&chip),
    };
    let item = Item::from_json(
        &json!({
            "overview": { "schemaVersion": 1, "title": "Example", "type": "login", "urls": ["https://example.com"] },
            "details": { "schemaVersion": 1, "username": "alice", "password": "hunter2" }
        })
        .to_string(),
    )
    .unwrap();
    let mut random = rng(9);
    let mut vault = LocalVault::create(password, protection, now_ms, &mut random).unwrap();
    let item_id = vault.add_item(&item, now_ms + 1, &mut random).unwrap();
    let blob = vault.to_bytes(&mut random).unwrap();
    let backup = vault.create_backup(&mut random).unwrap();

    let file: Value = serde_json::from_slice(&blob).unwrap();
    let salt = b64_decode(file["salt"].as_str().unwrap()).unwrap();
    let pw_key = keys::password_key(password, &salt, &KdfParams::DEFAULT).unwrap();
    let luk = keys::local_unlock_key(password, &salt, &KdfParams::DEFAULT, Some(&chip)).unwrap();
    let backup_key = keys::password_key(password, &backup[17..33], &BACKUP_KDF).unwrap();
    let unlocked = LocalVault::unlock(&blob, password, Some(&chip)).unwrap();
    assert_eq!(unlocked.get_item(&item_id).unwrap(), item);

    check(
        "local-vault",
        json!({
            "description": "A local vault bound to a device chip, with one item, and a backup of it. pwKey = Argon2id(NFKD(password), salt); luk = HKDF-SHA256(pwKey || hardwareSecret, salt = \"\", info = \"openpass/v1/local-unlock\"); wrappedAsk = AEAD(luk, ASK, \"local-ask\"); body = AEAD(ASK, JSON, \"local-vault\"). backupKey = Argon2id(NFKD(password), backup salt, m = 256 MiB, t = 4, p = 1). The backup layout is in crates/octapass-core/src/backup/mod.rs. Binary values are base64url without padding.",
            "input": {
                "password": password,
                "hardwareSecret": b64_encode(&chip),
                "kdf": KdfParams::DEFAULT,
                "nowMs": now_ms,
                "item": serde_json::from_str::<Value>(&item.to_json()).unwrap(),
            },
            "pwKey": b64_encode(pw_key.as_bytes()),
            "luk": b64_encode(luk.as_bytes()),
            "vault": file,
            "itemId": item_id,
            "backupRecoveryCode": vault.backup_recovery_code().as_str(),
            "backupKey": b64_encode(backup_key.as_bytes()),
            "backup": b64_encode(&backup),
        }),
    );
}
