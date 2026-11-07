//! Changing the master password, then resetting it with the recovery code, through the real
//! commands and a real server.

use crate::common;

use common::*;

const CHANGED: &str = "another correct horse battery staple 43";
const RESET: &str = "reset correct horse battery staple 44";

#[tokio::test]
async fn changes_then_resets_the_master_password() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();

    // Change it. The keyring session is already unlocked, so the current password is asked.
    let changed = cli
        .run_with(
            &["change-master-password"],
            Run {
                interactive: true,
                answers: vec![PASSWORD.into(), CHANGED.into(), CHANGED.into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(changed.stdout.contains("Master password changed"));
    assert!(
        changed
            .asked
            .iter()
            .any(|prompt| prompt == "Master password: ")
    );
    assert!(
        changed
            .asked
            .iter()
            .any(|prompt| prompt == "New master password: ")
    );

    // The old one no longer opens the account; the new one does.
    cli.run(&["logout"]).await.ok();
    let old = cli.login_with(PASSWORD, &other.secret_key).await;
    assert_ne!(old.code, 0, "{old:#?}");
    cli.login_with(CHANGED, &other.secret_key).await.ok();
    cli.run(&["logout"]).await.ok();

    // Reset it from signed out: the development server returns the emailed code, so the
    // answers are the recovery code and the new password twice.
    let reset = cli
        .run_with(
            &[
                "--json",
                "reset-master-password",
                "--server",
                &cli.server_url,
                "--email",
                EMAIL,
            ],
            Run {
                interactive: true,
                answers: vec![other.recovery_code.clone(), RESET.into(), RESET.into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    let reset = reset.json();
    assert_eq!(reset["recoveryKit"]["email"], EMAIL);
    assert_ne!(reset["recoveryKit"]["recoveryCode"], other.recovery_code);
    assert_eq!(reset["signedIn"], true);
    let secret_key = reset["recoveryKit"]["secretKey"]
        .as_str()
        .expect("the kit has a Secret Key")
        .to_owned();

    // The reset signed in, so the new password opens the vault from here.
    let status = cli.run(&["--json", "status"]).await.ok();
    assert_eq!(status.json()["status"], "unlocked");
    cli.run(&["logout"]).await.ok();
    cli.login_with(RESET, &secret_key).await.ok();

    // The old recovery code no longer starts a reset: the kit was replaced.
    cli.run(&["logout"]).await.ok();
    let stale = cli
        .run_with(
            &[
                "reset-master-password",
                "--server",
                &cli.server_url,
                "--email",
                EMAIL,
            ],
            Run {
                interactive: true,
                answers: vec![other.recovery_code.clone(), RESET.into(), RESET.into()],
                ..Run::default()
            },
        )
        .await;
    assert_ne!(stale.code, 0, "{stale:#?}");
}

#[tokio::test]
async fn rotates_a_vault_key_and_the_secret_key() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("Bank", "ada", "pw").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();

    // The vault gets a new key; the other device is still on the old one, and catches up.
    let rotated = cli.run(&["rotate-vault-key", "Personal"]).await.ok();
    assert!(rotated.stdout.contains("has a new key"));
    other.save_login("After", "ada", "pw").await;
    let listed = cli.run(&["list"]).await.ok();
    assert!(listed.stdout.contains("Bank"), "{listed:#?}");
    assert!(listed.stdout.contains("After"), "{listed:#?}");

    let rotated = cli
        .run_with(
            &["--json", "rotate-secret-key"],
            Run {
                interactive: true,
                answers: vec![PASSWORD.into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    let kit: serde_json::Value = serde_json::from_str(&rotated.stdout).unwrap();
    let new_key = kit["recoveryKit"]["secretKey"].as_str().unwrap().to_owned();
    assert_ne!(new_key, other.secret_key);
    assert!(kit["recoveryKit"].get("recoveryCode").is_none());
    let listed = cli.run(&["list"]).await.ok();
    assert!(listed.stdout.contains("Bank"), "{listed:#?}");

    // A device that knew the old key has to use the new one.
    cli.run(&["logout"]).await.ok();
    let old = cli.login_with(PASSWORD, &other.secret_key).await;
    assert_ne!(old.code, 0, "{old:#?}");
    cli.login_with(PASSWORD, &new_key).await.ok();
    let listed = cli.run(&["list"]).await.ok();
    assert!(listed.stdout.contains("After"), "{listed:#?}");
}
