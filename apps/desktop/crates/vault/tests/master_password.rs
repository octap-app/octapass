//! The master password against the real sync server: changing it while signed in, and resetting
//! a forgotten one with the recovery code from the Recovery Kit.

use crate::common;

use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::{RecoveryKit, SessionStatus, SignInResult};

const NEW_PASSWORD: &str = "a brand new master password 7";

/// Signs up on `device` and returns the whole Recovery Kit.
async fn sign_up_with_kit(server: &Server, device: &Device) -> RecoveryKit {
    let started = device
        .vault
        .start_signup(&server.url, EMAIL, secret(PASSWORD))
        .await
        .unwrap();
    device
        .vault
        .finish_signup(&started.signup_id, &started.dev_verification_code.unwrap())
        .await
        .unwrap()
}

fn titles(device: &Device) -> Vec<String> {
    let mut titles: Vec<String> = device
        .vault
        .list_items()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

#[tokio::test]
async fn changing_the_master_password_keeps_the_vault_and_signs_out_other_devices() {
    let server = server().await;
    let first = Device::new(&server);
    let secret_key = first.sign_up(&server).await;
    let vault_id = first.personal_vault();
    first
        .vault
        .save_item(login(&vault_id, "Bank", "pw"))
        .await
        .unwrap();
    let second = Device::new(&server);
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)).await.unwrap(),
        SignInResult::SignedIn
    );

    let wrong = first
        .vault
        .change_master_password(secret("not my password"), secret(NEW_PASSWORD))
        .await
        .unwrap_err();
    assert_eq!(wrong.code, ErrorCode::InvalidCredentials);

    first
        .vault
        .change_master_password(secret(PASSWORD), secret(NEW_PASSWORD))
        .await
        .unwrap();
    assert_eq!(first.status(), SessionStatus::Unlocked);

    // This device unlocks with the new password only, and the vault is the same.
    first.vault.lock();
    assert_eq!(
        first.vault.unlock(secret(PASSWORD)).await.unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    first.vault.unlock(secret(NEW_PASSWORD)).await.unwrap();
    assert_eq!(titles(&first), ["Bank"]);

    // The other device was signed out; it signs in again with the new password.
    let other = Device::new(&server);
    assert_eq!(
        other
            .vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(PASSWORD),
                Some(secret(&secret_key))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    assert_eq!(
        other
            .vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(NEW_PASSWORD),
                Some(secret(&secret_key))
            )
            .await
            .unwrap(),
        SignInResult::SignedIn
    );
    assert_eq!(titles(&other), ["Bank"]);
}

#[tokio::test]
async fn a_forgotten_master_password_is_reset_with_the_recovery_code() {
    let server = server().await;
    let first = Device::new(&server);
    let kit = sign_up_with_kit(&server, &first).await;
    let vault_id = first.personal_vault();
    first
        .vault
        .save_item(login(&vault_id, "Bank", "pw"))
        .await
        .unwrap();

    // A new computer that has never seen the account.
    let device = Device::new(&server);
    assert_eq!(
        device
            .vault
            .verify_password_reset("no-such-reset", "123456")
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResetExpired
    );
    let started = device
        .vault
        .start_password_reset(&server.url, EMAIL)
        .await
        .unwrap();
    let code = started
        .dev_verification_code
        .expect("dev mode returns the code");
    let wrong_code = if code == "000000" { "111111" } else { "000000" };
    assert_eq!(
        device
            .vault
            .verify_password_reset(&started.reset_id, wrong_code)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidVerificationCode
    );
    device
        .vault
        .verify_password_reset(&started.reset_id, &code)
        .await
        .unwrap();
    assert_eq!(
        device
            .vault
            .finish_password_reset(
                &started.reset_id,
                "not a recovery code",
                secret(NEW_PASSWORD)
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidRecoveryCode
    );

    let reset = device
        .vault
        .finish_password_reset(&started.reset_id, &kit.recovery_code, secret(NEW_PASSWORD))
        .await
        .unwrap();
    // A new recovery code always, and a new Secret Key because this device didn't know it.
    assert_ne!(reset.recovery_kit.recovery_code, kit.recovery_code);
    assert_ne!(reset.recovery_kit.secret_key, kit.secret_key);
    assert_eq!(reset.sign_in, Some(SignInResult::SignedIn));
    assert_eq!(device.status(), SessionStatus::Unlocked);
    assert_eq!(titles(&device), ["Bank"]);

    // The old password, Secret Key and recovery code stop working.
    let again = Device::new(&server);
    assert_eq!(
        again
            .vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(PASSWORD),
                Some(secret(&kit.secret_key))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    assert_eq!(
        again
            .vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(NEW_PASSWORD),
                Some(secret(&reset.recovery_kit.secret_key))
            )
            .await
            .unwrap(),
        SignInResult::SignedIn
    );
    assert_eq!(titles(&again), ["Bank"]);

    // The reset is used up.
    assert_eq!(
        device
            .vault
            .verify_password_reset(&started.reset_id, &code)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResetExpired
    );
}
