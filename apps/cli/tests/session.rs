//! Signing in, staying unlocked in the keyring, the idle timeout, lock, logout, and computers
//! without a keyring.

use crate::common;

use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn login_keeps_the_vault_unlocked_until_lock() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let cli = Cli::new(&server);

    assert_eq!(cli.run(&["status"]).await.code, 3);
    let login = cli.login(&other.secret_key).await.ok();
    assert!(
        login.stderr.contains("Signed in as ada@example.com"),
        "{login:?}"
    );
    assert!(login.stderr.contains("30 minutes"));

    let status = cli.run(&["status", "--json"]).await.ok().json();
    assert_eq!(status["status"], "unlocked");
    assert_eq!(status["email"], EMAIL);
    assert_eq!(status["serverUrl"], server.url);
    assert_eq!(status["keyring"], true);

    // No password needed while unlocked.
    let password = cli
        .run(&["get", "GitHub", "--field", "password"])
        .await
        .ok();
    assert_eq!(password.stdout, "hunter2\n");

    // The keyring holds a random session secret, and the files only ciphertext.
    let keyring = cli.keyring.as_ref().unwrap();
    assert_eq!(keyring.entries(), 1);
    for secret in ["hunter2", PASSWORD, "octocat", "GitHub"] {
        assert!(
            !contains(&keyring.contents(), secret),
            "{secret} in the keyring"
        );
        assert!(!contains(&cli.files_on_disk(), secret), "{secret} on disk");
    }

    let lock = cli.run(&["lock"]).await.ok();
    assert_eq!(lock.stderr, "Locked.\n");
    assert_eq!(keyring.entries(), 0);
    let status = cli.run(&["status"]).await;
    assert_eq!(status.code, 4);
    assert!(status.stdout.contains("Locked"));

    // Locked, and nobody to ask: exit 4, without touching stdout.
    let locked = cli.run(&["get", "GitHub", "--field", "password"]).await;
    assert_eq!(locked.code, 4);
    assert_eq!(locked.stdout, "");
    assert!(locked.stderr.contains("octapass unlock"));

    // A master password on stdin works for one command without starting a session.
    let once = cli
        .run_password(&["get", "GitHub", "--field", "password"])
        .await
        .ok();
    assert_eq!(once.stdout, "hunter2\n");
    assert_eq!(cli.run(&["status"]).await.code, 4);

    let wrong = cli
        .run_with(
            &["--password-stdin", "unlock"],
            Run {
                stdin: "not my password\n".into(),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(wrong.code, 5);

    let unlock = cli.run_password(&["unlock", "--timeout", "2h"]).await.ok();
    assert!(unlock.stderr.contains("2 hours"), "{unlock:?}");
    assert_eq!(cli.run(&["status"]).await.code, 0);
    let again = cli.run(&["unlock"]).await.ok();
    assert_eq!(again.stderr, "Already unlocked.\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_ends_after_the_idle_timeout() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    cli.run_password(&["unlock", "--timeout", "10m"]).await.ok();

    // Each command moves the deadline.
    cli.advance(9 * 60);
    cli.run(&["list"]).await.ok();
    cli.advance(9 * 60);
    cli.run(&["list"]).await.ok();

    cli.advance(10 * 60 + 1);
    assert_eq!(cli.run(&["status"]).await.code, 4);
    assert_eq!(cli.run(&["list"]).await.code, 4);
    assert_eq!(
        cli.keyring.as_ref().unwrap().entries(),
        0,
        "the expired entry is gone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_asks_at_a_terminal() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    let login = cli
        .run_with(
            &["login", "--server", &server.url],
            Run {
                interactive: true,
                answers: vec![EMAIL.into(), PASSWORD.into(), other.secret_key.clone()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(
        login.asked,
        [
            "Email: ",
            "Master password: ",
            "Secret Key (on your Recovery Kit): "
        ]
    );

    // Signing in again on this computer doesn't need the Secret Key.
    cli.run(&["logout"]).await.ok();
    let wrong_key = cli
        .run_with(
            &["login", "--server", &server.url, "--email", EMAIL],
            Run {
                interactive: true,
                answers: vec![PASSWORD.into(), "OP1-NOT-A-KEY".into()],
                ..Run::default()
            },
        )
        .await;
    assert_eq!(wrong_key.code, 5, "{wrong_key:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_forgets_the_account_here() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    let state = std::fs::read_to_string(cli.data_dir().join("state.json")).unwrap();
    assert!(state.contains(&other.secret_key));

    let logout = cli.run(&["logout"]).await.ok();
    assert!(logout.stderr.contains("Signed out of ada@example.com"));
    assert_eq!(cli.run(&["status"]).await.code, 3);
    assert_eq!(cli.keyring.as_ref().unwrap().entries(), 0);
    let state = std::fs::read_to_string(cli.data_dir().join("state.json")).unwrap();
    assert!(!state.contains(&other.secret_key));
    assert!(
        !std::fs::read_dir(cli.data_dir()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("vault-")),
        "the encrypted copy is deleted"
    );

    let list = cli.run(&["list"]).await;
    assert_eq!(list.code, 3);
    assert_eq!(cli.run(&["logout"]).await.stderr, "Not signed in.\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_keyring_every_command_asks_for_the_password() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let cli = Cli::with_keyring(&server, None);

    let login = cli.login(&other.secret_key).await.ok();
    assert!(login.stderr.contains("no OS keyring"), "{login:?}");
    let status = cli.run(&["status", "--json"]).await;
    assert_eq!(status.code, 4);
    assert_eq!(status.json()["keyring"], false);

    let unlock = cli.run_password(&["unlock"]).await;
    assert_eq!(unlock.code, 1);
    assert!(unlock.stderr.contains("can't stay unlocked"));

    assert_eq!(cli.run(&["list"]).await.code, 4);
    let list = cli
        .run_with(
            &["list"],
            Run {
                interactive: true,
                answers: vec![PASSWORD.into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(list.asked, ["Master password: "]);
    assert!(list.stdout.contains("GitHub"));
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_the_local_copy_is_used() {
    let mut server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    drop(other);
    server.stop();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let get = cli
        .run(&["get", "GitHub", "--field", "password"])
        .await
        .ok();
    assert_eq!(get.stdout, "hunter2\n");
    assert!(get.stderr.contains("Couldn't sync"), "{get:?}");
}

/// The authenticator code `offset` seconds from now: each code works once, so a sign-in uses the
/// next one after the code that turned two-step on.
fn authenticator_code(secret: &str, offset: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    octapass_core::tools::totp::totp_code(secret, now + offset)
        .unwrap()
        .code
}

#[tokio::test(flavor = "multi_thread")]
async fn login_asks_for_the_second_step_when_two_step_is_on() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let setup = other
        .vault
        .start_totp_setup(zeroize::Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let confirmed = other
        .vault
        .confirm_totp_setup(&authenticator_code(&setup.secret, 0))
        .await
        .unwrap();
    let recovery = confirmed.recovery_codes.unwrap().remove(0);
    let login = |env: Vec<(String, String)>, interactive: bool, answers: Vec<String>| {
        let mut all = vec![("OCTAPASS_SECRET_KEY".to_owned(), other.secret_key.clone())];
        all.extend(env);
        two_step_login(&server, all, interactive, answers)
    };

    // No terminal and no code: a clear usage error, not signed in.
    let (output, cli) = login(vec![], false, vec![]).await;
    assert_ne!(output.code, 0);
    assert!(
        output.stderr.contains("OCTAPASS_TWO_STEP_CODE"),
        "{output:?}"
    );
    assert_eq!(cli.run(&["status"]).await.code, 3);

    // A code from the environment.
    let code = authenticator_code(&setup.secret, 30);
    let (output, cli) = login(vec![("OCTAPASS_TWO_STEP_CODE".into(), code)], false, vec![]).await;
    assert_eq!(output.code, 0, "{output:?}");
    assert_eq!(cli.run(&["status"]).await.code, 0);
    let password = cli
        .run(&["get", "GitHub", "--field", "password"])
        .await
        .ok();
    assert_eq!(password.stdout, "hunter2\n");

    // Asked for on a terminal, here with a recovery code.
    let (output, cli) = login(vec![], true, vec![recovery]).await;
    assert_eq!(output.code, 0, "{output:?}");
    assert!(
        output
            .asked
            .iter()
            .any(|prompt| prompt.contains("authenticator app"))
    );
    assert_eq!(cli.run(&["status"]).await.code, 0);

    // A wrong code doesn't sign in.
    let (output, cli) = login(
        vec![("OCTAPASS_TWO_STEP_CODE".into(), "000000".into())],
        false,
        vec![],
    )
    .await;
    assert_ne!(output.code, 0);
    assert_eq!(cli.run(&["status"]).await.code, 3);
}

async fn two_step_login(
    server: &Server,
    env: Vec<(String, String)>,
    interactive: bool,
    answers: Vec<String>,
) -> (Output, Cli) {
    let cli = Cli::new(server);
    let args = [
        "login",
        "--server",
        &server.url,
        "--email",
        EMAIL,
        "--password-stdin",
    ];
    let run = Run {
        stdin: format!("{PASSWORD}\n"),
        env,
        interactive,
        answers,
        ..Run::default()
    };
    (cli.run_with(&args, run).await, cli)
}
