//! A new master password: changed while signed in, or reset with the recovery code.
//! Real account keys from octapass-core, so the bundle the server ends up with really opens.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::now_ms;
use common::*;
use octapass_core::account::{AccountBundle, NewAccount};
use octapass_core::credentials::NewCredentials;
use octapass_core::kdf::{AccountKeys, KdfParams};
use octapass_core::opaque::RegistrationClient;
use octapass_core::recovery::RecoveryCode;
use octapass_core::session::Session;
use rand_core::OsRng;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

/// Signs up with real keys.
async fn sign_up(server: &TestServer) -> NewAccount {
    let account = NewAccount::create(
        EMAIL,
        "old password",
        KdfParams::DEFAULT,
        now_ms(),
        &mut OsRng,
    )
    .unwrap();
    let (client, request) =
        RegistrationClient::start(&account.keys.auth_secret, &mut OsRng).unwrap();
    let started = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": EMAIL, "registrationRequest": request }),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let upload = client
        .finish(
            &account.keys.auth_secret,
            started.body["registrationResponse"].as_str().unwrap(),
            &mut OsRng,
        )
        .unwrap();
    let finished = server
        .post(
            "/v1/auth/register/finish",
            json!({
                "email": EMAIL,
                "verificationCode": started.body["devVerificationCode"],
                "registrationUpload": upload,
                "account": account.bundle,
                "personalVault": account.personal_vault,
            }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    account
}

async fn login(server: &TestServer, keys: &AccountKeys, device: &str) -> Response {
    server
        .login_with(EMAIL, keys.auth_secret.as_bytes(), device)
        .await
}

async fn refresh(server: &TestServer, device: &Device) -> StatusCode {
    server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": device.refresh_token }),
        )
        .await
        .status
}

fn bundle_of(device: &Device) -> AccountBundle {
    serde_json::from_value(device.account.clone()).unwrap()
}

/// OPAQUE registration for the new password through `path`, returning the upload.
async fn register_new(
    server: &TestServer,
    path: &str,
    token: Option<&str>,
    recovery_id: Option<&str>,
    new: &NewCredentials,
) -> String {
    let (client, request) = RegistrationClient::start(&new.keys.auth_secret, &mut OsRng).unwrap();
    let mut body = json!({ "registrationRequest": request });
    if let Some(id) = recovery_id {
        body["recoveryId"] = json!(id);
    }
    let response = server
        .call(Method::POST, path, token, &[], Some(body))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    client
        .finish(
            &new.keys.auth_secret,
            response.body["registrationResponse"].as_str().unwrap(),
            &mut OsRng,
        )
        .unwrap()
}

async fn security_log(server: &TestServer, token: &str) -> Vec<String> {
    let response = server.get("/v1/security-log", token).await;
    assert_eq!(response.status, StatusCode::OK);
    response.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["type"].as_str().unwrap().to_owned())
        .collect()
}

fn last_email_subject(server: &TestServer) -> String {
    server.state.dev_outbox().last().unwrap().1.clone()
}

#[tokio::test]
async fn changing_the_password_keeps_this_device_and_signs_out_the_others() {
    let server = TestServer::new().await;
    let account = sign_up(&server).await;
    let laptop = Device::from_login(&login(&server, &account.keys, "Laptop").await.body);
    let phone = Device::from_login(&login(&server, &account.keys, "Phone").await.body);

    let session = Session::unlock(bundle_of(&laptop), &account.keys.auk).unwrap();
    let new = session
        .new_credentials(
            "new password",
            Some(account.secret_key.clone()),
            false,
            KdfParams::DEFAULT,
            &mut OsRng,
        )
        .unwrap();
    let upload = register_new(
        &server,
        "/v1/account/password/registration",
        Some(&laptop.access_token),
        None,
        &new,
    )
    .await;
    let body = json!({ "registrationUpload": upload, "account": new.update });
    let change = |token: Option<String>| {
        let headers: Vec<(&str, String)> =
            token.map(|t| ("x-reauth-token", t)).into_iter().collect();
        let body = body.clone();
        let access = laptop.access_token.clone();
        let server = &server;
        async move {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            server
                .call(
                    Method::PUT,
                    "/v1/account/password",
                    Some(&access),
                    &headers,
                    Some(body),
                )
                .await
        }
    };

    // It needs a fresh change-password reauth.
    assert!(change(None).await.is_problem("reauth-required"));
    let delete_token = server
        .reauth_with(&laptop.access_token, account.keys.auth_secret.as_bytes())
        .await
        .body["reauthToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        change(Some(delete_token))
            .await
            .is_problem("reauth-required")
    );
    let reauth = server
        .reauth_for(
            &laptop.access_token,
            account.keys.auth_secret.as_bytes(),
            "change-password",
        )
        .await;
    let token = reauth.body["reauthToken"].as_str().unwrap().to_owned();
    assert_eq!(
        change(Some(token.clone())).await.status,
        StatusCode::NO_CONTENT
    );
    // Single use.
    assert!(change(Some(token)).await.is_problem("reauth-required"));

    let stored: AccountBundle =
        serde_json::from_value(server.get("/v1/account", &laptop.access_token).await.body).unwrap();
    assert_eq!(stored, new.apply(&bundle_of(&laptop)));
    let reopened = Session::unlock(stored, &new.keys.auk).unwrap();
    assert_eq!(
        reopened.key_pairs().public_sign_key(),
        session.key_pairs().public_sign_key()
    );

    assert!(
        login(&server, &account.keys, "Old")
            .await
            .is_problem("login-failed")
    );
    assert_eq!(
        login(&server, &new.keys, "New").await.status,
        StatusCode::OK
    );
    assert!(
        security_log(&server, &laptop.access_token)
            .await
            .contains(&"password-changed".to_owned())
    );
    // This device keeps going; the phone was signed out.
    assert_eq!(refresh(&server, &laptop).await, StatusCode::OK);
    assert_eq!(refresh(&server, &phone).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        last_email_subject(&server),
        "New sign-in to your Octa Pass account"
    );
    assert!(
        server
            .state
            .dev_outbox()
            .iter()
            .any(|(_, subject)| subject == "Your Octa Pass master password was changed")
    );
}

/// Runs recover/start and recover/verify. Returns the recovery id and the verify response.
async fn verified_reset(server: &TestServer) -> (String, Value) {
    let started = server
        .post("/v1/auth/recover/start", json!({ "email": EMAIL }))
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    assert_eq!(
        last_email_subject(server),
        format!(
            "Your Octa Pass reset code: {}",
            started.body["devVerificationCode"].as_str().unwrap()
        )
    );
    let recovery_id = started.body["recoveryId"].as_str().unwrap().to_owned();
    let verify = |code: Value| {
        server.post(
            "/v1/auth/recover/verify",
            json!({ "recoveryId": recovery_id, "verificationCode": code }),
        )
    };
    assert!(
        verify(json!("000000"))
            .await
            .is_problem("invalid-verification-code")
    );
    let verified = verify(started.body["devVerificationCode"].clone()).await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.body);
    (recovery_id, verified.body)
}

#[tokio::test]
async fn resetting_with_the_recovery_code_replaces_it_and_signs_out_every_device() {
    let server = TestServer::new().await;
    let account = sign_up(&server).await;
    let laptop = Device::from_login(&login(&server, &account.keys, "Laptop").await.body);

    let (recovery_id, verified) = verified_reset(&server).await;
    let bundle: AccountBundle = serde_json::from_value(verified["account"].clone()).unwrap();
    assert_eq!(bundle, bundle_of(&laptop));
    let session = Session::recover(bundle.clone(), &account.recovery_code).unwrap();
    let new = session
        .new_credentials("new password", None, true, KdfParams::DEFAULT, &mut OsRng)
        .unwrap();
    let upload = register_new(
        &server,
        "/v1/auth/recover/registration",
        None,
        Some(&recovery_id),
        &new,
    )
    .await;
    let challenge = verified["challenge"].as_str().unwrap();
    let signature = session
        .sign_recovery(challenge, &upload, &new.update)
        .unwrap();
    let finished = server
        .post(
            "/v1/auth/recover/finish",
            json!({
                "recoveryId": recovery_id,
                "registrationUpload": upload,
                "account": new.update,
                "signature": signature,
            }),
        )
        .await;
    assert_eq!(
        finished.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        finished.body
    );
    assert_eq!(
        last_email_subject(&server),
        "Your Octa Pass master password was reset"
    );

    assert_eq!(refresh(&server, &laptop).await, StatusCode::UNAUTHORIZED);
    assert!(
        login(&server, &account.keys, "Old")
            .await
            .is_problem("login-failed")
    );
    let signed_in = login(&server, &new.keys, "New").await;
    assert_eq!(signed_in.status, StatusCode::OK);
    let device = Device::from_login(&signed_in.body);
    let stored = bundle_of(&device);
    assert_eq!(stored, new.apply(&bundle));
    assert!(Session::unlock(stored.clone(), &new.keys.auk).is_ok());
    let new_code = RecoveryCode::parse(&new.recovery_code.as_ref().unwrap().to_text()).unwrap();
    assert!(Session::recover(stored.clone(), &new_code).is_ok());
    assert!(Session::recover(stored, &account.recovery_code).is_err());
    assert!(
        security_log(&server, &device.access_token)
            .await
            .contains(&"password-reset".to_owned())
    );

    // The reset is used up.
    let again = server
        .post(
            "/v1/auth/recover/finish",
            json!({
                "recoveryId": recovery_id,
                "registrationUpload": "x",
                "account": new.update,
                "signature": "x",
            }),
        )
        .await;
    assert!(again.is_problem("recovery-expired"));
}

#[tokio::test]
async fn a_reset_must_be_signed_by_the_account() {
    let server = TestServer::new().await;
    let account = sign_up(&server).await;
    let (recovery_id, verified) = verified_reset(&server).await;

    // Someone who can read the email but has no recovery code signs with a key of their own.
    let stranger_account = NewAccount::create(
        "eve@example.com",
        "x",
        KdfParams::DEFAULT,
        now_ms(),
        &mut OsRng,
    )
    .unwrap();
    let mut stranger_bundle = stranger_account.bundle.clone();
    stranger_bundle.account_id = verified["account"]["accountId"].as_str().map(str::to_owned);
    stranger_bundle.email = EMAIL.into();
    let session = Session::unlock(stranger_bundle, &stranger_account.keys.auk).unwrap();
    let new = session
        .new_credentials("new password", None, true, KdfParams::DEFAULT, &mut OsRng)
        .unwrap();
    let upload = register_new(
        &server,
        "/v1/auth/recover/registration",
        None,
        Some(&recovery_id),
        &new,
    )
    .await;
    let signature = session
        .sign_recovery(
            verified["challenge"].as_str().unwrap(),
            &upload,
            &new.update,
        )
        .unwrap();
    let body = json!({
        "recoveryId": recovery_id,
        "registrationUpload": upload,
        "account": new.update,
        "signature": signature,
    });
    let finished = server.post("/v1/auth/recover/finish", body.clone()).await;
    assert!(finished.is_problem("login-failed"), "{:?}", finished.body);
    // The reset is gone, and the account kept its password.
    assert!(
        server
            .post("/v1/auth/recover/finish", body)
            .await
            .is_problem("recovery-expired")
    );
    assert_eq!(
        login(&server, &account.keys, "Laptop").await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_reset_needs_the_emailed_code_first() {
    let server = TestServer::new().await;
    sign_up(&server).await;

    let started = server
        .post("/v1/auth/recover/start", json!({ "email": EMAIL }))
        .await;
    let recovery_id = started.body["recoveryId"].as_str().unwrap();
    let early = server
        .post(
            "/v1/auth/recover/registration",
            json!({ "recoveryId": recovery_id, "registrationRequest": "x" }),
        )
        .await;
    assert!(early.is_problem("recovery-expired"));

    // Five wrong codes use it up.
    for _ in 0..5 {
        let wrong = server
            .post(
                "/v1/auth/recover/verify",
                json!({ "recoveryId": recovery_id, "verificationCode": "000000" }),
            )
            .await;
        assert!(wrong.is_problem("invalid-verification-code"));
    }
    let right = server
        .post(
            "/v1/auth/recover/verify",
            json!({ "recoveryId": recovery_id, "verificationCode": started.body["devVerificationCode"] }),
        )
        .await;
    assert!(right.is_problem("recovery-expired"));
}

#[tokio::test]
async fn unknown_emails_look_the_same_but_never_verify() {
    let server = TestServer::new().await;
    let sent = server.state.dev_outbox().len();
    let started = server
        .post(
            "/v1/auth/recover/start",
            json!({ "email": "nobody@example.com" }),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK);
    assert!(started.body["recoveryId"].is_string());
    assert_eq!(server.state.dev_outbox().len(), sent, "no email went out");
    let verified = server
        .post(
            "/v1/auth/recover/verify",
            json!({
                "recoveryId": started.body["recoveryId"],
                "verificationCode": started.body["devVerificationCode"],
            }),
        )
        .await;
    assert!(verified.is_problem("invalid-verification-code"));
}
