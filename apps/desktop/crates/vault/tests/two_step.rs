//! Two-step sign-in against the real sync server: turning it on with an authenticator app, the
//! second step on a new device (code, recovery code, wrong codes), trusted devices skipping it,
//! also when an expired session signs in again by itself, and the settings.

use crate::common;

use std::time::Duration;

use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::{SessionStatus, SignInResult, TwoStepMethod, TwoStepProof};
use serde_json::json;

/// Turns two-step sign-in on from `device`. Returns the authenticator secret and the recovery
/// codes.
async fn enable(server: &Server, device: &Device) -> (String, Vec<String>) {
    let setup = device
        .vault
        .start_totp_setup(secret(PASSWORD))
        .await
        .unwrap();
    assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
    let confirmed = device
        .vault
        .confirm_totp_setup(&server.totp(&setup.secret))
        .await
        .unwrap();
    (
        setup.secret,
        confirmed.recovery_codes.expect("codes when turning it on"),
    )
}

fn totp(code: String) -> TwoStepProof {
    TwoStepProof::Totp { code }
}

/// A code that isn't `code`.
fn wrong(code: &str) -> TwoStepProof {
    let other = (code.parse::<u32>().unwrap() + 1) % 1_000_000;
    totp(format!("{other:06}"))
}

fn two_step_required() -> SignInResult {
    SignInResult::TwoStepRequired {
        methods: vec![TwoStepMethod::Totp, TwoStepMethod::RecoveryCode],
    }
}

/// Changes this device's `state.json` while the app is closed.
fn edit_state(
    device: Device,
    server: &Server,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Device {
    let path = device.dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut state["accounts"][0]);
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    device.restart(server)
}

fn stored(device: &Device, field: &str) -> Option<String> {
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(device.dir.path().join("state.json")).unwrap())
            .unwrap();
    state["accounts"][0][field].as_str().map(str::to_owned)
}

/// Waits for the sync that follows an unlock, run in the background.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_device_finishes_with_an_authenticator_code_then_is_trusted() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let vault_id = first.personal_vault();
    first
        .vault
        .save_item(login(&vault_id, "Bank", "pw"))
        .await
        .unwrap();
    let status = first.vault.two_step_status().await.unwrap();
    assert!(!status.enabled && !status.security_keys_supported);

    assert_eq!(
        first
            .vault
            .start_totp_setup(secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    assert_eq!(
        first
            .vault
            .confirm_totp_setup("123456")
            .await
            .unwrap_err()
            .code,
        ErrorCode::TwoStepExpired,
        "no setup started"
    );
    let setup = first
        .vault
        .start_totp_setup(secret(PASSWORD))
        .await
        .unwrap();
    let code = server.totp(&setup.secret);
    let TwoStepProof::Totp { code: wrong_code } = wrong(&code) else {
        unreachable!()
    };
    assert_eq!(
        first
            .vault
            .confirm_totp_setup(&wrong_code)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode
    );
    let confirmed = first.vault.confirm_totp_setup(&code).await.unwrap();
    assert_eq!(confirmed.recovery_codes.unwrap().len(), 10);
    let status = first.vault.two_step_status().await.unwrap();
    assert!(status.enabled && !status.security_keys_supported);
    assert_eq!(status.recovery_codes_left, 10);

    // A new device: the password and Secret Key are right, then the second step.
    let second = Device::new(&server);
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)).await.unwrap(),
        two_step_required()
    );
    assert_eq!(second.status(), SessionStatus::SignedOut);
    let code = server.totp(&setup.secret);
    assert_eq!(
        second
            .vault
            .finish_two_step(wrong(&code))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode
    );
    assert_eq!(
        second
            .vault
            .finish_two_step(TwoStepProof::SecurityKey)
            .await
            .unwrap_err()
            .code,
        ErrorCode::SecurityKeyUnsupported
    );
    second.vault.finish_two_step(totp(code)).await.unwrap();
    assert_eq!(second.status(), SessionStatus::Unlocked);
    assert_eq!(second.vault.list_items().unwrap()[0].title, "Bank");
    assert!(stored(&second, "trustedDeviceToken").is_some());
    assert_eq!(
        second
            .vault
            .finish_two_step(totp(server.totp(&setup.secret)))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TwoStepExpired,
        "the sign-in is over"
    );

    // Signing in again on either device skips the second step.
    second.vault.lock();
    assert_eq!(
        second.sign_in(&server, None).await.unwrap(),
        SignInResult::SignedIn
    );
    assert_eq!(
        first.sign_in(&server, None).await.unwrap(),
        SignInResult::SignedIn
    );

    // Signing out ends the trust: the next sign-in asks again.
    second.vault.sign_out().await.unwrap();
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)).await.unwrap(),
        two_step_required()
    );
    assert!(
        second.sync_failures().is_empty(),
        "{:?}",
        second.sync_failures()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_codes_work_once_and_can_be_renewed() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let (authenticator, codes) = enable(&server, &first).await;

    let second = Device::new(&server);
    second.sign_in(&server, Some(&secret_key)).await.unwrap();
    second
        .vault
        .finish_two_step(TwoStepProof::RecoveryCode {
            code: format!(" {} ", codes[0].to_lowercase()),
        })
        .await
        .unwrap();
    assert_eq!(second.status(), SessionStatus::Unlocked);

    let third = Device::new(&server);
    third.sign_in(&server, Some(&secret_key)).await.unwrap();
    assert_eq!(
        third
            .vault
            .finish_two_step(TwoStepProof::RecoveryCode {
                code: codes[0].clone()
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode,
        "a recovery code works once"
    );
    third
        .vault
        .finish_two_step(totp(server.totp(&authenticator)))
        .await
        .unwrap();
    assert_eq!(
        first
            .vault
            .two_step_status()
            .await
            .unwrap()
            .recovery_codes_left,
        9
    );

    assert_eq!(
        first
            .vault
            .renew_recovery_codes(secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    let renewed = first
        .vault
        .renew_recovery_codes(secret(PASSWORD))
        .await
        .unwrap();
    assert_eq!(renewed.len(), 10);
    assert!(renewed.iter().all(|code| !codes.contains(code)));
    assert_eq!(
        first
            .vault
            .two_step_status()
            .await
            .unwrap()
            .recovery_codes_left,
        10
    );
    let fourth = Device::new(&server);
    fourth.sign_in(&server, Some(&secret_key)).await.unwrap();
    assert_eq!(
        fourth
            .vault
            .finish_two_step(TwoStepProof::RecoveryCode {
                code: codes[1].clone()
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode,
        "the old codes stopped working"
    );
    fourth
        .vault
        .finish_two_step(TwoStepProof::RecoveryCode {
            code: renewed[0].clone(),
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_codes_end_the_sign_in() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let (authenticator, _) = enable(&server, &first).await;

    let second = Device::new(&server);
    second.sign_in(&server, Some(&secret_key)).await.unwrap();
    let code = server.totp(&authenticator);
    for _ in 0..5 {
        assert_eq!(
            second
                .vault
                .finish_two_step(wrong(&code))
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidTwoStepCode
        );
    }
    assert_eq!(
        second
            .vault
            .finish_two_step(totp(code))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TwoStepExpired,
        "five wrong codes end the challenge"
    );
    assert_eq!(
        second
            .vault
            .finish_two_step(totp(server.totp(&authenticator)))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TwoStepExpired
    );

    // Starting over works.
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)).await.unwrap(),
        two_step_required()
    );
    second
        .vault
        .finish_two_step(totp(server.totp(&authenticator)))
        .await
        .unwrap();
    assert_eq!(second.status(), SessionStatus::Unlocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_session_signs_in_again_on_a_trusted_device_only() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let (authenticator, _) = enable(&server, &device).await;
    device.vault.lock();

    // The refresh token died; the trusted-device token lets the unlock sign in again by itself.
    let device = edit_state(device, &server, |account| {
        account["refreshToken"] = json!("expired");
    });
    let trusted = stored(&device, "trustedDeviceToken").unwrap();
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    eventually("the new session", || {
        stored(&device, "refreshToken").is_some_and(|token| token != "expired")
    })
    .await;
    assert!(
        device.sync_failures().is_empty(),
        "{:?}",
        device.sync_failures()
    );
    assert_ne!(stored(&device, "trustedDeviceToken").unwrap(), trusted);
    device.vault.sync().await.unwrap();

    // Without trust, that sign-in would need the second step: the session can't be resumed,
    // and the user signs in again.
    device.vault.lock();
    let device = edit_state(device, &server, |account| {
        account["refreshToken"] = json!("expired");
        account
            .as_object_mut()
            .unwrap()
            .remove("trustedDeviceToken");
    });
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    eventually("the failed sync", || !device.sync_failures().is_empty()).await;
    assert_eq!(
        device.vault.sync().await.unwrap_err().code,
        ErrorCode::SessionExpired
    );
    assert_eq!(
        device.sign_in(&server, None).await.unwrap(),
        two_step_required()
    );
    device
        .vault
        .finish_two_step(totp(server.totp(&authenticator)))
        .await
        .unwrap();
    device.vault.sync().await.unwrap();
    assert!(stored(&device, "trustedDeviceToken").is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn replacing_the_authenticator_and_turning_it_off() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let (old, _) = enable(&server, &first).await;

    // A new authenticator replaces the old one, without new recovery codes.
    let setup = first
        .vault
        .start_totp_setup(secret(PASSWORD))
        .await
        .unwrap();
    assert_ne!(setup.secret, old);
    let confirmed = first
        .vault
        .confirm_totp_setup(&server.totp(&setup.secret))
        .await
        .unwrap();
    assert!(confirmed.recovery_codes.is_none());
    let second = Device::new(&server);
    second.sign_in(&server, Some(&secret_key)).await.unwrap();
    assert_eq!(
        second
            .vault
            .finish_two_step(totp(server.totp(&old)))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode
    );
    second
        .vault
        .finish_two_step(totp(server.totp(&setup.secret)))
        .await
        .unwrap();

    // There are no security keys to remove; ids that can't be one never reach the server.
    for id in ["0190b3a2-0000-7000-8000-000000000000", "../../account"] {
        assert_eq!(
            first
                .vault
                .remove_security_key(id, secret(PASSWORD))
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound,
            "{id}"
        );
    }

    assert_eq!(
        first
            .vault
            .disable_two_step(secret("wrong"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    first
        .vault
        .disable_two_step(secret(PASSWORD))
        .await
        .unwrap();
    let status = first.vault.two_step_status().await.unwrap();
    assert!(!status.enabled && status.security_keys.is_empty());
    assert_eq!(status.recovery_codes_left, 0);
    assert_eq!(
        Device::new(&server)
            .sign_in(&server, Some(&secret_key))
            .await
            .unwrap(),
        SignInResult::SignedIn
    );

    first.vault.lock();
    assert_eq!(
        first.vault.two_step_status().await.unwrap_err().code,
        ErrorCode::Locked
    );
}
