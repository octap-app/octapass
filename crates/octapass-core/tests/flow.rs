//! The whole client lifecycle against an in-process OPAQUE server:
//! sign-up → login on a new device → encrypt → decrypt → reauth → recovery.

use octapass_core::Error;
use octapass_core::account::{AccountBundle, NewAccount, new_id};
use octapass_core::item::Item;
use octapass_core::kdf::{AccountKeys, KdfParams};
use octapass_core::opaque::server::OpaqueServer;
use octapass_core::opaque::{LoginClient, ReauthClient, RegistrationClient};
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

const EMAIL: &str = "Alice@Example.com";
const PASSWORD: &str = "correct horse battery staple";
const NOW_MS: u64 = 1_761_177_600_000;

/// What the server keeps for the account.
struct Stored {
    password_file: String,
    bundle: AccountBundle,
    vault_id: String,
    wrapped_vault_key: String,
}

fn login(
    server: &OpaqueServer,
    stored: &Stored,
    keys: &AccountKeys,
    rng: &mut ChaCha20Rng,
) -> Result<(), Error> {
    let (client, credential_request) = LoginClient::start(&keys.auth_secret, rng)?;
    let (state, credential_response) = server.login_start(
        &stored.bundle.email,
        Some(&stored.password_file),
        &credential_request,
        rng,
    )?;
    let credential_finalization = client.finish(&keys.auth_secret, &credential_response, rng)?;
    state.finish(&credential_finalization)
}

#[test]
fn signup_login_encrypt_decrypt_reauth_recover() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let server = OpaqueServer::generate(&mut rng);

    // Sign-up: generate the account, register with OPAQUE, upload the bundle.
    let account =
        NewAccount::create(EMAIL, PASSWORD, KdfParams::DEFAULT, NOW_MS, &mut rng).unwrap();
    let secret_key_text = account.secret_key.to_text().to_string();
    let recovery_code_text = account.recovery_code.to_text().to_string();
    let (registration, registration_request) =
        RegistrationClient::start(&account.keys.auth_secret, &mut rng).unwrap();
    let registration_response = server
        .registration_start(&account.bundle.email, &registration_request)
        .unwrap();
    let registration_upload = registration
        .finish(&account.keys.auth_secret, &registration_response, &mut rng)
        .unwrap();
    let stored = Stored {
        password_file: OpaqueServer::registration_finish(&registration_upload).unwrap(),
        bundle: account.bundle.clone(),
        vault_id: account.personal_vault.id.clone(),
        wrapped_vault_key: account.personal_vault.wrapped_vault_key.clone(),
    };
    assert_eq!(stored.bundle.email, "alice@example.com");

    // The bundle as the server returns it (JSON, camelCase, with accountId).
    let mut bundle_json = serde_json::to_value(&stored.bundle).unwrap();
    bundle_json["accountId"] = json!("0192f0c8-0000-7000-8000-000000000001");
    let bundle: AccountBundle = serde_json::from_value(bundle_json.clone()).unwrap();
    for field in [
        "email",
        "kdf",
        "accountSalt",
        "wrappedAsk",
        "publicEncKey",
        "publicSignKey",
        "wrappedPrivateKeys",
        "recoveryWrappedAsk",
    ] {
        assert!(bundle_json.get(field).is_some(), "{field}");
    }

    // The sign-up session can already encrypt into the personal vault.
    let signup_session = Session::from_new_account(&account).unwrap();
    let item_id = new_id(NOW_MS, &mut rng);
    let item_json = json!({
        "overview": { "schemaVersion": 1, "title": "GitHub", "type": "login", "urls": ["https://github.com"] },
        "details": { "schemaVersion": 1, "username": "alice", "password": "hunter2", "fromTheFuture": [1] }
    });
    let item = Item::from_json(&item_json.to_string()).unwrap();
    let encrypted = signup_session
        .encrypt_item(&stored.vault_id, &item_id, &item, None, &mut rng)
        .unwrap();
    drop(signup_session);

    // A new device: prelogin gives salt + KDF, the user types password and Secret Key.
    let secret_key = SecretKey::parse(&secret_key_text.to_lowercase()).unwrap();
    let keys = AccountKeys::derive(
        PASSWORD,
        &secret_key,
        EMAIL,
        &bundle.account_salt_bytes().unwrap(),
        &bundle.kdf,
    )
    .unwrap();
    login(&server, &stored, &keys, &mut rng).unwrap();

    let mut session = Session::unlock(bundle.clone(), &keys.auk).unwrap();
    assert_eq!(
        session
            .decrypt_item(&stored.vault_id, &item_id, &encrypted)
            .unwrap_err(),
        Error::VaultNotOpen
    );
    session
        .open_vault(&stored.vault_id, &stored.wrapped_vault_key)
        .unwrap();
    let decrypted = session
        .decrypt_item(&stored.vault_id, &item_id, &encrypted)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&decrypted.to_json()).unwrap(),
        item_json
    );
    assert_eq!(
        session
            .decrypt_overview(&stored.vault_id, &item_id, &encrypted)
            .unwrap()
            .title,
        "GitHub"
    );

    // Updating keeps the item key; the server can't move the ciphertext to another item.
    let updated = session
        .encrypt_item(
            &stored.vault_id,
            &item_id,
            &item,
            Some(&encrypted.encrypted_item_key),
            &mut rng,
        )
        .unwrap();
    assert_ne!(updated.overview, encrypted.overview);
    let other_item = new_id(NOW_MS, &mut rng);
    assert!(
        session
            .decrypt_item(&stored.vault_id, &other_item, &updated)
            .is_err()
    );

    // Reauth for a dangerous action: same OPAQUE login, the session keeps working.
    let reauth_keys = AccountKeys::derive(
        PASSWORD,
        &secret_key,
        EMAIL,
        &bundle.account_salt_bytes().unwrap(),
        &bundle.kdf,
    )
    .unwrap();
    let (reauth, credential_request) =
        ReauthClient::start(&reauth_keys.auth_secret, &mut rng).unwrap();
    let (state, credential_response) = server
        .login_start(
            EMAIL,
            Some(&stored.password_file),
            &credential_request,
            &mut rng,
        )
        .unwrap();
    let finalization = reauth
        .finish(&reauth_keys.auth_secret, &credential_response, &mut rng)
        .unwrap();
    state.finish(&finalization).unwrap();
    session
        .decrypt_item(&stored.vault_id, &item_id, &updated)
        .unwrap();

    // Device unlock: a passkey PRF output wraps the ASK on this device; it reopens the account.
    let prf_output = [0x5a; 32];
    let device = session.enable_device_unlock(&prf_output, &mut rng).unwrap();
    let mut by_device = Session::unlock_with_device_key(
        bundle.clone(),
        &prf_output,
        &device.device_salt,
        &device.wrapped_ask,
    )
    .unwrap();
    by_device
        .open_vault(&stored.vault_id, &stored.wrapped_vault_key)
        .unwrap();
    assert_eq!(
        by_device
            .decrypt_item(&stored.vault_id, &item_id, &updated)
            .unwrap(),
        item
    );

    // Wrong password: the AUK can't open the ASK and OPAQUE login fails.
    let wrong = AccountKeys::derive(
        "Correct horse battery staple",
        &secret_key,
        EMAIL,
        &bundle.account_salt_bytes().unwrap(),
        &bundle.kdf,
    )
    .unwrap();
    assert_eq!(
        Session::unlock(bundle.clone(), &wrong.auk)
            .err()
            .map(|e| e.code()),
        Some("login_failed")
    );
    assert_eq!(
        login(&server, &stored, &wrong, &mut rng).unwrap_err(),
        Error::LoginFailed
    );

    // Recovery: the recovery code alone opens the ASK and everything below it.
    let code = RecoveryCode::parse(&recovery_code_text).unwrap();
    let mut recovered = Session::recover(bundle.clone(), &code).unwrap();
    recovered
        .open_vault(&stored.vault_id, &stored.wrapped_vault_key)
        .unwrap();
    assert_eq!(
        recovered
            .decrypt_item(&stored.vault_id, &item_id, &updated)
            .unwrap(),
        item
    );
    let not_the_code = RecoveryCode::generate(&mut rng);
    assert_eq!(
        Session::recover(bundle, &not_the_code)
            .err()
            .map(|e| e.code()),
        Some("invalid_recovery_code")
    );
}
