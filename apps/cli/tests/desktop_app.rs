//! The CLI following the running desktop app (plan 05): unlocking through it, and linking to its
//! account. The real socket, server and vault code on both sides, with a fake device lock that
//! records its prompts.

#![cfg(unix)]

use crate::common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use octapass_desktop_vault::cli_session::{self, CliPeer};
use octapass_device_unlock::Error as UnlockError;
use octapass_device_unlock::fake::FakeDeviceUnlock;

struct App {
    _server: Server,
    other: OtherDevice,
    unlock: Arc<FakeDeviceUnlock>,
    cli: Cli,
    endpoint: PathBuf,
    _dir: tempfile::TempDir,
}

async fn app() -> App {
    let server = server().await;
    let unlock = Arc::new(FakeDeviceUnlock::default());
    let other = OtherDevice::sign_up_with(&server, unlock.clone()).await;
    other.save_login("GitHub", "ada", "hunter2").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    cli.run(&["lock"]).await.ok();
    let dir = tempfile::Builder::new()
        .prefix("opd")
        .tempdir_in("/tmp")
        .unwrap();
    let endpoint = cli_session::endpoint(dir.path());
    let (vault, socket) = (Arc::clone(&other.vault), endpoint.clone());
    tokio::spawn(async move {
        cli_session::serve(vault, socket, |_| {
            Ok(CliPeer {
                executable: "/usr/local/bin/octapass".into(),
                session: Some(42),
            })
        })
        .await
    });
    while !endpoint.exists() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    App {
        _server: server,
        other,
        unlock,
        cli,
        endpoint,
        _dir: dir,
    }
}

impl App {
    fn run(&self) -> Run {
        Run {
            desktop_app: Some(self.endpoint.clone()),
            ..Run::default()
        }
    }

    async fn get(&self) -> Output {
        self.cli
            .run_with(&["get", "GitHub", "--field", "password"], self.run())
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_unlocked_app_opens_the_cli_without_asking_and_nothing_stays_on_disk() {
    let app = app().await;
    // Without the app, the vault is locked.
    assert_eq!(app.cli.run(&["get", "GitHub"]).await.code, 4);

    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    assert!(app.unlock.prompts().is_empty(), "{:?}", app.unlock.prompts());

    let status = app
        .cli
        .run_with(&["status", "--json"], app.run())
        .await
        .ok()
        .json();
    assert_eq!(status["status"], "unlocked");
    assert_eq!(status["desktopApp"], true);
    assert_eq!(status["locksAt"], serde_json::Value::Null);

    // No session was kept: the keyring is empty and the password isn't anywhere.
    assert_eq!(app.cli.keyring.as_ref().unwrap().entries(), 0);
    assert!(!contains(&app.cli.files_on_disk(), PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_the_app_locks_the_cli_and_the_cli_locks_the_app() {
    let app = app().await;
    app.get().await.ok();
    app.other.vault.lock();
    let locked = app.get().await;
    assert_eq!(locked.code, 4, "{locked:?}");
    assert!(locked.stderr.contains("Octa Pass app"), "{locked:?}");
    let status = app.cli.run_with(&["status"], app.run()).await;
    assert_eq!(status.code, 4);

    app.other
        .vault
        .unlock(zeroize::Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    let lock = app.cli.run_with(&["lock"], app.run()).await.ok();
    assert!(lock.stderr.contains("Octa Pass app"), "{lock:?}");
    assert_eq!(
        app.other.vault.snapshot().session.status,
        octapass_desktop_vault::model::SessionStatus::Locked
    );
    assert_eq!(app.get().await.code, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_app_asks_the_device_lock_and_a_refusal_gives_nothing() {
    let app = app().await;
    app.other.vault.enable_device_unlock().await.unwrap();
    app.other.vault.lock();
    let asked = app.unlock.prompts().len();
    // The device lock unlocks the app for the CLI: one prompt.
    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    assert_eq!(app.unlock.prompts().len(), asked + 1);

    app.other.vault.lock();
    app.unlock.refuse_prompts(Some(UnlockError::Cancelled));
    let refused = app.get().await;    assert_eq!(refused.code, 4, "{refused:?}");
    assert!(!refused.stdout.contains("hunter2"));
    // And the master password still works.
    let typed = app
        .cli
        .run_with(
            &["--password-stdin", "get", "GitHub", "--field", "password"],
            Run {
                stdin: format!("{PASSWORD}\n"),
                ..app.run()
            },
        )
        .await
        .ok();
    assert_eq!(typed.stdout, "hunter2\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn another_account_gets_nothing_from_the_app() {
    let app = app().await;
    let server = server().await;
    let stranger = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&stranger.secret_key).await.ok();
    cli.run(&["lock"]).await.ok();
    let run = Run {
        desktop_app: Some(app.endpoint.clone()),
        ..Run::default()
    };
    assert_eq!(cli.run_with(&["list"], run).await.code, 4);
    assert!(app.unlock.prompts().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn exports_still_ask_for_the_master_password() {
    let app = app().await;
    app.get().await.ok();
    let export = app.cli.run_with(&["export"], app.run()).await;
    assert_eq!(export.code, 2, "{export:?}");
    assert!(!export.stdout.contains("hunter2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn no_app_means_the_usual_ways() {
    let app = app().await;
    let gone = Run {
        desktop_app: Some("/tmp/octapass-no-such-socket".into()),
        ..Run::default()
    };
    let locked = app.cli.run_with(&["get", "GitHub"], gone.clone()).await;
    assert_eq!(locked.code, 4);
    assert!(!locked.stderr.contains("app"), "{locked:?}");
    assert_eq!(app.cli.run_with(&["status"], gone).await.code, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cli_that_isnt_signed_in_links_to_the_apps_account() {
    let app = app().await;
    let fresh = Cli::new(&app._server);
    let run = app.run();
    let before = app.other.vault.list_devices().await.unwrap().len();

    // Any command links it: no login, no master password, no prompt.
    let got = fresh
        .run_with(&["get", "GitHub", "--field", "password"], run.clone())
        .await
        .ok();
    assert_eq!(got.stdout, "hunter2\n");
    assert!(got.stderr.contains("Octa Pass app"), "{got:?}");
    assert!(app.unlock.prompts().is_empty());

    // It's a device of its own in the account, and keeps its sign-in like `octapass login`.
    let devices = app.other.vault.list_devices().await.unwrap();
    assert_eq!(devices.len(), before + 1, "{devices:?}");
    assert!(devices.iter().any(|device| device.platform == "cli"));
    let status = fresh
        .run_with(&["status", "--json"], run.clone())
        .await
        .ok()
        .json();
    assert_eq!(status["status"], "unlocked");
    assert_eq!(status["email"], EMAIL);
    assert!(!contains(&fresh.files_on_disk(), PASSWORD));

    // Signed in, `link` says so instead of replacing the account.
    let again = fresh.run_with(&["link"], run.clone()).await;
    assert_ne!(again.code, 0, "{again:?}");
    assert!(again.stderr.contains("Already signed in"), "{again:?}");

    // It follows the app from now on.
    app.other.vault.lock();
    assert_eq!(fresh.run_with(&["get", "GitHub"], run.clone()).await.code, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_app_signing_out_points_at_it() {
    let server = server().await;
    let fresh = Cli::new(&server);
    let gone = Run {
        desktop_app: Some("/tmp/octapass-no-such-socket".into()),
        ..Run::default()
    };
    let out = fresh.run_with(&["list"], gone).await;
    assert_eq!(out.code, 3, "{out:?}");
    assert!(out.stderr.contains("octapass login"), "{out:?}");
    assert!(out.stderr.contains("desktop app"), "{out:?}");
}
