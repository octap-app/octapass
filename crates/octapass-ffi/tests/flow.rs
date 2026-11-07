//! The mobile lifecycle through the exported API, against the in-process `TestServer`:
//! sign-up → sync → save → upload → login on another device → fill → TOTP → passkeys (web,
//! iOS hash, Android app) → device unlock in an extension → conflicts → reauth → delete.

use std::sync::Arc;

use octapass_core::encoding::b64_decode;
use octapass_ffi::{
    ClientData, DeviceInfo, HttpClient, HttpRequest, HttpResponse, LocalStore, LogInResult,
    LoginDraft, MatchQuality, OctaPassError, OctaPassServer, PasskeyAssertionRequest,
    PasskeyCreationRequest, PasskeyPrfCredentialInput, PasskeyPrfInput, PasskeyPrfRequest,
    ReauthPurpose, SecondFactorLogin, SecondFactorMethod, Session, SignedIn, TestServer,
    passkey_assertion_request_from_json, passkey_creation_request_from_json,
};
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const EMAIL: &str = "Alice@Example.com";
const PASSWORD: &str = "correct horse battery staple";
const GITHUB_TOTP: &str = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

/// What the apps do with URLSession or OkHttp, minus the network.
struct Loopback(Arc<TestServer>);

impl HttpClient for Loopback {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, OctaPassError> {
        Ok(self.0.handle(request))
    }
}

struct Account {
    server: Arc<TestServer>,
    api: Arc<OctaPassServer>,
    secret_key: String,
    signed_in: SignedIn,
    dir: TempDir,
}

impl Account {
    fn token(&self) -> String {
        self.signed_in.tokens.access_token.clone()
    }

    fn store(&self, name: &str, session: &Arc<Session>) -> Arc<LocalStore> {
        let path = self.dir.path().join(name).to_string_lossy().into_owned();
        let store = LocalStore::create(path, self.api.base_url(), session.clone()).unwrap();
        self.api.sync(self.token(), store.clone()).unwrap();
        store
    }
}

fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        name: name.into(),
        platform: "ios".into(),
    }
}

fn sign_up() -> Account {
    let server = Arc::new(TestServer::new());
    let api = OctaPassServer::new(
        "https://octapass.test".into(),
        Arc::new(Loopback(server.clone())),
    )
    .unwrap();
    assert_eq!(api.server_info().unwrap().api_version, 1);

    let signup = api.start_signup(EMAIL.into(), PASSWORD.into()).unwrap();
    assert_eq!(signup.email(), "alice@example.com");
    assert!(signup.secret_key().starts_with("OP1-"));
    assert_eq!(signup.recovery_code().split('-').count(), 11);
    assert_eq!(
        signup.finish("000000".into(), device("iPhone")).err(),
        Some(OctaPassError::InvalidVerificationCode),
        "a wrong code can be retried"
    );
    let code = signup.dev_verification_code().unwrap();
    let signed_in = signup.finish(code.clone(), device("iPhone")).unwrap();
    assert_eq!(
        signup.finish(code, device("iPhone")).err(),
        Some(OctaPassError::FlowFinished)
    );
    Account {
        server,
        api,
        secret_key: signup.secret_key(),
        signed_in,
        dir: tempfile::tempdir().unwrap(),
    }
}

fn login(url: &str, username: &str, password: &str) -> LoginDraft {
    LoginDraft {
        item_id: None,
        title: None,
        url: Some(url.into()),
        username: Some(username.into()),
        password: Some(password.into()),
        totp: None,
    }
}

/// Checks an ES256 assertion as a relying party would.
fn verify(
    public_key_der: &[u8],
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
) {
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(public_key_der).unwrap();
    let signature = p256::ecdsa::Signature::from_der(signature).unwrap();
    key.verify(&[authenticator_data, client_data_hash].concat(), &signature)
        .expect("the passkey signature verifies");
}

fn public_key(response_json: &str) -> Vec<u8> {
    let response: serde_json::Value = serde_json::from_str(response_json).unwrap();
    b64_decode(response["response"]["publicKey"].as_str().unwrap()).unwrap()
}

#[test]
fn the_whole_mobile_lifecycle() {
    let account = sign_up();
    let laptop = account.signed_in.session.clone();
    let laptop_store = account.store("laptop.store", &laptop);
    assert_eq!(laptop_store.email(), "alice@example.com");
    assert!(laptop_store.account_id().is_some());

    // Encrypt: a login saved here reaches the server only as ciphertext.
    let github = laptop
        .save_login(
            laptop_store.clone(),
            LoginDraft {
                totp: Some(GITHUB_TOTP.into()),
                ..login("https://github.com/login", "alice", "hunter2")
            },
        )
        .unwrap();
    assert!(laptop_store.has_pending_changes());
    account
        .api
        .upload_pending(account.token(), laptop.clone(), laptop_store.clone())
        .unwrap();
    assert!(!laptop_store.has_pending_changes());
    assert_eq!(account.server.item_count(EMAIL.into()), 1);

    // A new phone: email + password + Secret Key, then decrypt what the laptop saved.
    assert_eq!(
        account
            .api
            .log_in(
                EMAIL.into(),
                "wrong".into(),
                account.secret_key.clone(),
                device("Phone")
            )
            .err(),
        Some(OctaPassError::LoginFailed)
    );
    let phone = account
        .api
        .log_in(
            EMAIL.into(),
            PASSWORD.into(),
            account.secret_key.clone(),
            device("Phone"),
        )
        .unwrap();
    let store = account.store("phone.store", &phone.session);
    let session = phone.session.clone();
    let items = session.list_items(store.clone()).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "github.com");
    assert!(items[0].has_totp);

    let fill = session
        .match_logins(store.clone(), "https://github.com/session".into())
        .unwrap();
    assert_eq!(fill.len(), 1);
    assert_eq!(fill[0].quality, MatchQuality::Exact);
    let item = session
        .get_item(store.clone(), fill[0].item.item_id.clone())
        .unwrap();
    assert_eq!(item.item_id, github);
    assert_eq!(
        item.login.as_ref().unwrap().password.as_deref(),
        Some("hunter2")
    );
    assert_eq!(
        session
            .match_logins(store.clone(), "https://gist.github.com".into())
            .unwrap()[0]
            .quality,
        MatchQuality::Domain
    );
    assert!(
        session
            .match_logins(store.clone(), "https://github.com.evil.io".into())
            .unwrap()
            .is_empty()
    );

    let code = session.totp_code(store.clone(), github.clone()).unwrap();
    assert_eq!(code.code.len(), 6);
    assert_eq!(code.period, 30);

    passkeys(&session, &store);

    // The system's credential lists.
    let identities = session.credential_identities(store.clone()).unwrap();
    assert!(identities.len() >= 4, "{identities:?}");

    // An autofill extension opens the shared store and unlocks with the device's lock.
    let path = account
        .dir
        .path()
        .join("phone.store")
        .to_string_lossy()
        .into_owned();
    let extension_store = LocalStore::open(path).unwrap();
    let device_secret = vec![42u8; 32];
    assert_eq!(
        extension_store
            .unlock_with_device(device_secret.clone())
            .err(),
        Some(OctaPassError::PasswordRequired),
        "device unlock is off until the app turns it on"
    );
    store
        .enable_device_unlock(session.clone(), device_secret.clone())
        .unwrap();
    extension_store.reload().unwrap();
    assert!(extension_store.device_unlock_status().enabled);
    assert_eq!(
        extension_store.unlock_with_device(vec![41u8; 32]).err(),
        Some(OctaPassError::DeviceUnlockFailed)
    );
    let extension = extension_store.unlock_with_device(device_secret).unwrap();
    assert_eq!(
        extension.list_items(extension_store.clone()).unwrap().len(),
        session.list_items(store.clone()).unwrap().len()
    );
    extension.lock();
    assert!(extension.is_locked());
    assert_eq!(
        extension.list_items(extension_store.clone()).err(),
        Some(OctaPassError::Locked)
    );
    assert_eq!(
        extension_store
            .unlock_with_password("wrong".into(), account.secret_key.clone())
            .err(),
        Some(OctaPassError::LoginFailed)
    );
    assert_eq!(
        session.list_items(laptop_store.clone()).err(),
        None,
        "same account, so any of its stores works"
    );

    // Passkeys made on the phone sync back to the laptop.
    account
        .api
        .upload_pending(
            phone.tokens.access_token.clone(),
            session.clone(),
            store.clone(),
        )
        .unwrap();
    account
        .api
        .sync(account.token(), laptop_store.clone())
        .unwrap();
    assert!(
        laptop
            .list_items(laptop_store.clone())
            .unwrap()
            .iter()
            .any(|item| item.has_passkey)
    );

    // Reauth, then delete the account; every device learns about it.
    let reauth_token = account
        .api
        .reauth(
            account.token(),
            laptop.clone(),
            PASSWORD.into(),
            account.secret_key.clone(),
            ReauthPurpose::DeleteAccount,
        )
        .unwrap();
    account
        .api
        .delete_account(account.token(), reauth_token, "alice@example.com".into())
        .unwrap();
    assert_eq!(
        account
            .api
            .sync(phone.tokens.access_token.clone(), store)
            .err(),
        Some(OctaPassError::AccountDeleted)
    );
}

fn passkeys(session: &Arc<Session>, store: &Arc<LocalStore>) {
    // A web view: the core checks the origin and writes clientDataJSON.
    let web = ClientData::Web {
        origin: "https://github.com".into(),
        top_origin: None,
        frame_allowed: false,
    };
    let request = passkey_creation_request_from_json(
        serde_json::json!({
            "rp": { "id": "github.com", "name": "GitHub" },
            "user": { "id": "dXNlci0x", "name": "alice", "displayName": "Alice" },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        })
        .to_string(),
    )
    .unwrap();
    let created = session
        .create_passkey(store.clone(), request.clone(), web.clone())
        .unwrap();
    let github = session
        .match_logins(store.clone(), "https://github.com".into())
        .unwrap();
    assert_eq!(github.len(), 1, "the passkey went into the existing login");
    assert_eq!(created.item_id, github[0].item.item_id);
    assert_eq!(
        session
            .create_passkey(
                store.clone(),
                PasskeyCreationRequest {
                    excluded_credentials: vec![created.credential_id.clone()],
                    ..request
                },
                web.clone()
            )
            .err(),
        Some(OctaPassError::PasskeyExcluded)
    );
    assert_eq!(
        session
            .create_passkey(
                store.clone(),
                PasskeyCreationRequest {
                    rp_id: Some("evil.com".into()),
                    ..passkey_creation_request_from_json(
                        r#"{"rp":{"name":"x"},"user":{"id":"AQ","name":"a"},"challenge":"AA"}"#
                            .into()
                    )
                    .unwrap()
                },
                web.clone()
            )
            .err(),
        Some(OctaPassError::PasskeyRpMismatch)
    );

    let get = passkey_assertion_request_from_json(
        r#"{"challenge":"bm9uY2U","rpId":"github.com"}"#.into(),
    )
    .unwrap();
    let found = session
        .find_passkeys(store.clone(), get.clone(), web.clone())
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].user_name, "alice");
    let assertion = session
        .get_passkey_assertion(
            store.clone(),
            get.clone(),
            web,
            created.credential_id.clone(),
        )
        .unwrap();
    let response: serde_json::Value = serde_json::from_str(&assertion.response_json).unwrap();
    let client_data = b64_decode(response["response"]["clientDataJSON"].as_str().unwrap()).unwrap();
    assert!(String::from_utf8_lossy(&client_data).contains("\"origin\":\"https://github.com\""));
    verify(
        &public_key(&created.response_json),
        &assertion.authenticator_data,
        &Sha256::digest(&client_data),
        &assertion.signature,
    );
    assert_eq!(assertion.user_handle, b"user-1");

    // iOS: the system built clientDataJSON and passes only its hash.
    let hash = Sha256::digest(b"{\"type\":\"webauthn.create\"}").to_vec();
    let ios = ClientData::Hash {
        client_data_hash: hash.clone(),
    };
    let created = session
        .create_passkey(
            store.clone(),
            PasskeyCreationRequest {
                rp_id: Some("example.com".into()),
                rp_name: "example.com".into(),
                user_handle: vec![9; 16],
                user_name: "alice@example.com".into(),
                user_display_name: String::new(),
                algorithms: vec![-7],
                excluded_credentials: Vec::new(),
                challenge: Vec::new(),
                cred_props: false,
                prf: None,
            },
            ios.clone(),
        )
        .unwrap();
    assert!(created.response_json.contains("\"clientDataJSON\":\"\""));
    assert_eq!(created.prf, None, "not asked for");
    let example = session
        .match_logins(store.clone(), "https://example.com".into())
        .unwrap();
    assert_eq!(example.len(), 1, "a new login for the rpId");
    assert_eq!(created.item_id, example[0].item.item_id);
    // With no origin to check, the platform's rpId must be given and not a public suffix.
    for (rp_id, error) in [
        (None, OctaPassError::PasskeyInvalidRequest),
        (Some("github.io"), OctaPassError::PasskeyRpMismatch),
        (Some("com"), OctaPassError::PasskeyRpMismatch),
    ] {
        let request = PasskeyAssertionRequest {
            rp_id: rp_id.map(Into::into),
            allowed_credentials: Vec::new(),
            challenge: Vec::new(),
            prf: None,
        };
        assert_eq!(
            session
                .find_passkeys(store.clone(), request, ios.clone())
                .err(),
            Some(error),
            "{rp_id:?}"
        );
    }
    let request = PasskeyAssertionRequest {
        rp_id: Some("example.com".into()),
        allowed_credentials: vec![created.credential_id.clone()],
        challenge: Vec::new(),
        prf: None,
    };
    let assertion = session
        .get_passkey_assertion(
            store.clone(),
            request.clone(),
            ios.clone(),
            created.credential_id.clone(),
        )
        .unwrap();
    assert_eq!(
        &assertion.authenticator_data[..32],
        Sha256::digest(b"example.com").as_slice()
    );
    assert_eq!(assertion.authenticator_data[32], 0x1d);
    verify(
        &public_key(&created.response_json),
        &assertion.authenticator_data,
        &hash,
        &assertion.signature,
    );
    assert_eq!(
        session
            .get_passkey_assertion(
                store.clone(),
                PasskeyAssertionRequest {
                    allowed_credentials: vec![vec![1, 2, 3]],
                    ..request.clone()
                },
                ios,
                created.credential_id.clone()
            )
            .err(),
        Some(OctaPassError::PasskeyNotFound),
        "allowCredentials is enforced"
    );
    assert_eq!(
        session
            .get_passkey_assertion(
                store.clone(),
                request.clone(),
                ClientData::Hash {
                    client_data_hash: vec![0; 5]
                },
                created.credential_id.clone()
            )
            .err(),
        Some(OctaPassError::PasskeyInvalidRequest)
    );

    // An Android app: the provider built clientDataJSON with the app's origin.
    let client_data_json =
        r#"{"type":"webauthn.get","challenge":"AA","origin":"android:apk-key-hash:abc"}"#;
    let assertion = session
        .get_passkey_assertion(
            store.clone(),
            request,
            ClientData::Json {
                client_data_json: client_data_json.into(),
            },
            created.credential_id.clone(),
        )
        .unwrap();
    let response: serde_json::Value = serde_json::from_str(&assertion.response_json).unwrap();
    assert_eq!(
        b64_decode(response["response"]["clientDataJSON"].as_str().unwrap()).unwrap(),
        client_data_json.as_bytes()
    );
    verify(
        &public_key(&created.response_json),
        &assertion.authenticator_data,
        &Sha256::digest(client_data_json.as_bytes()),
        &assertion.signature,
    );

    // PRF (plan 05): the browser extension's own unlock passkey, saved through Apple's AutoFill,
    // whose RP ID is the extension's ID. The same input gives the same 32 bytes at sign-in.
    let extension = "oojckfebkmiogiahdggohbdnndbfcjnm";
    let input = PasskeyPrfInput {
        first: b"unlock".to_vec(),
        second: None,
    };
    let platform = ClientData::Hash {
        client_data_hash: hash.clone(),
    };
    let created = session
        .create_passkey(
            store.clone(),
            PasskeyCreationRequest {
                rp_id: Some(extension.into()),
                rp_name: extension.into(),
                user_handle: vec![7; 16],
                user_name: "alice@example.com".into(),
                user_display_name: String::new(),
                algorithms: vec![-7],
                excluded_credentials: Vec::new(),
                challenge: Vec::new(),
                cred_props: false,
                prf: Some(PasskeyPrfRequest {
                    eval: Some(input.clone()),
                    by_credential: Vec::new(),
                }),
            },
            platform.clone(),
        )
        .unwrap();
    let registered = created.prf.clone().unwrap();
    assert!(registered.enabled);
    assert_eq!(registered.first.as_ref().map(Vec::len), Some(32));
    let sign_in = |prf: PasskeyPrfRequest| {
        session
            .get_passkey_assertion(
                store.clone(),
                PasskeyAssertionRequest {
                    rp_id: Some(extension.into()),
                    allowed_credentials: Vec::new(),
                    challenge: Vec::new(),
                    prf: Some(prf),
                },
                platform.clone(),
                created.credential_id.clone(),
            )
            .unwrap()
            .prf
            .unwrap()
    };
    let signed = sign_in(PasskeyPrfRequest {
        eval: Some(input.clone()),
        by_credential: Vec::new(),
    });
    assert!(!signed.enabled);
    assert_eq!(signed.first, registered.first);
    let own = sign_in(PasskeyPrfRequest {
        eval: Some(PasskeyPrfInput {
            first: b"other".to_vec(),
            second: None,
        }),
        by_credential: vec![PasskeyPrfCredentialInput {
            credential_id: created.credential_id.clone(),
            input,
        }],
    });
    assert_eq!(
        own.first, registered.first,
        "its own entry in evalByCredential wins"
    );
    // The JSON forms carry it too (Android's requestJson).
    let parsed = passkey_assertion_request_from_json(
        r#"{"challenge":"AA","extensions":{"prf":{"eval":{"first":"dW5sb2Nr"}}}}"#.into(),
    )
    .unwrap();
    assert_eq!(parsed.prf.unwrap().eval.unwrap().first, b"unlock");
}

#[test]
fn two_step_sign_in_and_trusted_devices() {
    let account = sign_up();
    let laptop_trust = account.signed_in.tokens.trusted_device_token.clone();
    assert!(laptop_trust.is_some(), "every sign-in trusts its device");
    account.server.enable_two_step(EMAIL.into());
    let log_in = |trusted: Option<String>| {
        account.api.log_in_trusted(
            EMAIL.into(),
            PASSWORD.into(),
            account.secret_key.clone(),
            device("Phone"),
            trusted,
        )
    };
    let second_step = |result: LogInResult| -> Arc<SecondFactorLogin> {
        match result {
            LogInResult::SecondFactorRequired { second_factor } => second_factor,
            _ => panic!("expected a second step"),
        }
    };

    // The old call can't finish it and says why.
    assert_eq!(
        account
            .api
            .log_in(
                EMAIL.into(),
                PASSWORD.into(),
                account.secret_key.clone(),
                device("Phone")
            )
            .err(),
        Some(OctaPassError::Server {
            status: 401,
            problem_type: "second-factor-required".into(),
            detail: None
        })
    );
    assert!(matches!(
        account.api.log_in_trusted(
            EMAIL.into(),
            "wrong".into(),
            account.secret_key.clone(),
            device("Phone"),
            None
        ),
        Err(OctaPassError::LoginFailed)
    ));

    let challenge = second_step(log_in(None).unwrap());
    assert_eq!(
        challenge.methods(),
        [SecondFactorMethod::Totp, SecondFactorMethod::RecoveryCode]
    );
    assert_eq!(challenge.expires_in(), 300);
    let wrong_code = OctaPassError::Server {
        status: 401,
        problem_type: "invalid-second-factor".into(),
        detail: None,
    };
    assert_eq!(
        challenge.finish_with_totp("000000".into()).err(),
        Some(wrong_code.clone())
    );
    let phone = challenge.finish_with_totp(" 654321 ".into()).unwrap();
    assert_eq!(phone.session.email().unwrap(), "alice@example.com");
    assert_eq!(
        challenge.finish_with_totp("654321".into()).err(),
        Some(OctaPassError::FlowFinished)
    );

    // Trusted devices skip the second step, with the token they kept, and get a new one.
    let phone_trust = phone.tokens.trusted_device_token.clone().unwrap();
    let again = match log_in(Some(phone_trust.clone())).unwrap() {
        LogInResult::SignedIn { signed_in } => signed_in,
        _ => panic!("a trusted device skips it"),
    };
    assert_ne!(again.tokens.trusted_device_token, Some(phone_trust.clone()));
    assert!(matches!(
        log_in(laptop_trust).unwrap(),
        LogInResult::SignedIn { .. }
    ));
    second_step(log_in(Some(phone_trust)).unwrap());

    // A recovery code works once; too many wrong tries end the challenge.
    let challenge = second_step(log_in(None).unwrap());
    challenge
        .finish_with_recovery_code("abcde-12345".into())
        .unwrap();
    let challenge = second_step(log_in(None).unwrap());
    for _ in 0..5 {
        assert_eq!(
            challenge
                .finish_with_recovery_code("ABCDE-12345".into())
                .err(),
            Some(wrong_code.clone())
        );
    }
    assert_eq!(
        challenge.finish_with_totp("654321".into()).err(),
        Some(OctaPassError::LoginFailed)
    );
}

#[test]
fn a_stale_edit_becomes_a_conflicting_copy() {
    let account = sign_up();
    let session = account.signed_in.session.clone();
    let laptop = account.store("laptop.store", &session);
    let phone = account.store("phone.store", &session);
    let token = account.token();
    let id = session
        .save_login(
            laptop.clone(),
            login("https://router.local", "admin", "one"),
        )
        .unwrap();
    account
        .api
        .upload_pending(token.clone(), session.clone(), laptop.clone())
        .unwrap();
    account.api.sync(token.clone(), phone.clone()).unwrap();

    let change = |password: &str| LoginDraft {
        item_id: Some(id.clone()),
        title: Some("Router".into()),
        url: None,
        username: None,
        password: Some(password.into()),
        totp: None,
    };
    session.save_login(laptop.clone(), change("two")).unwrap();
    account
        .api
        .upload_pending(token.clone(), session.clone(), laptop.clone())
        .unwrap();
    session.save_login(phone.clone(), change("three")).unwrap();
    account
        .api
        .upload_pending(token.clone(), session.clone(), phone.clone())
        .unwrap();
    assert!(!phone.has_pending_changes());

    account.api.sync(token, laptop.clone()).unwrap();
    let titles: Vec<String> = session
        .list_items(laptop.clone())
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    assert_eq!(titles, ["Router", "Router (conflicting copy)"]);
    let item = session.get_item(laptop, id).unwrap();
    let login = item.login.unwrap();
    assert_eq!(
        login.password.as_deref(),
        Some("two"),
        "the server's version wins the id"
    );
}

#[test]
fn a_store_only_opens_for_its_own_account() {
    let alice = sign_up();
    let bob = sign_up();
    let alice_store = alice.store("alice.store", &alice.signed_in.session);
    assert_eq!(
        bob.signed_in.session.list_items(alice_store).err(),
        Some(OctaPassError::InvalidStore)
    );
    let missing = alice
        .dir
        .path()
        .join("missing")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        LocalStore::open(missing).err(),
        Some(OctaPassError::InvalidStore)
    );
}

#[test]
fn another_app_gets_only_the_credential_types_it_asked_for() {
    let account = sign_up();
    let session = account.signed_in.session.clone();
    let store = account.store("phone.store", &session);
    let mut github = login("https://github.com", "alice", "s3cret-pass");
    github.totp = Some(GITHUB_TOTP.into());
    session.save_login(store.clone(), github).unwrap();

    let export = session
        .export_for_app(
            store.clone(),
            vec!["basic-auth".into(), "passkey".into()],
            "octapass.test".into(),
        )
        .unwrap();
    assert_eq!(export.exported, 1);
    let header: serde_json::Value = serde_json::from_str(&export.json).unwrap();
    assert_eq!(header["exporterRpId"], "octapass.test");
    let account_json = &header["accounts"][0];
    assert_eq!(account_json["email"], "alice@example.com");
    let credentials = account_json["items"][0]["credentials"].as_array().unwrap();
    // The one-time code wasn't asked for.
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["type"], "basic-auth");
    assert_eq!(credentials[0]["password"]["value"], "s3cret-pass");

    let nothing = session
        .export_for_app(store.clone(), vec!["wifi".into()], "octapass.test".into())
        .unwrap();
    assert_eq!(nothing.exported, 0);
    session.lock();
    assert_eq!(
        session
            .export_for_app(store, vec!["basic-auth".into()], "octapass.test".into())
            .err(),
        Some(OctaPassError::Locked)
    );
}

#[test]
fn other_parts_of_a_site_are_listed_apart_and_can_join_the_login() {
    let account = sign_up();
    let session = account.signed_in.session.clone();
    let store = account.store("phone.store", &session);
    let shop = session
        .save_login(
            store.clone(),
            login("https://shop.example.com/login", "alice", "s3cret-pass"),
        )
        .unwrap();
    let page = "https://login.example.com/signin";

    // Not a suggestion on another part of the domain…
    assert!(
        session
            .match_logins(store.clone(), page.into())
            .unwrap()
            .is_empty()
    );
    // …but one tap away.
    let others = session.other_logins(store.clone(), page.into()).unwrap();
    assert_eq!(others.len(), 1);
    assert_eq!(others[0].item.item_id, shop);
    assert_eq!(others[0].host, "shop.example.com");
    assert_eq!(others[0].site, "example.com");
    assert!(others[0].can_add_website);
    assert!(
        session
            .other_logins(store.clone(), "androidapp://com.example".into())
            .unwrap()
            .is_empty()
    );

    // After filling it, "Add login.example.com to this login?" → Add.
    let website = octapass_ffi::website_for_page(page.into()).unwrap();
    assert_eq!(website, "https://login.example.com");
    let add = || LoginDraft {
        item_id: Some(shop.clone()),
        title: None,
        url: Some(website.clone()),
        username: None,
        password: None,
        totp: None,
    };
    session.save_login(store.clone(), add()).unwrap();
    let found = session.match_logins(store.clone(), page.into()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].quality, MatchQuality::Exact);
    assert!(
        session
            .other_logins(store.clone(), page.into())
            .unwrap()
            .is_empty()
    );
    // Adding it again changes nothing.
    session.save_login(store.clone(), add()).unwrap();
    let item = session.get_item(store.clone(), shop.clone()).unwrap();
    assert_eq!(
        item.urls,
        [
            "https://shop.example.com/login",
            "https://login.example.com"
        ]
    );
    assert_eq!(item.login.unwrap().password.as_deref(), Some("s3cret-pass"));
    session.lock();
}
