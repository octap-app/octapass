//! Unlocking through the running desktop app (plan 05): the real socket and the real vault code on
//! both sides, with a fake device lock that records its prompts.

#![cfg(unix)]

use crate::common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use octapass_desktop_vault::cli_session::{self, CliGrants, CliPeer};
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
        cli_session::serve(vault, Arc::new(CliGrants::default()), socket, |_| {
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
async fn one_approval_covers_this_terminal_and_nothing_stays_on_disk() {
    let app = app().await;
    // Without the app, the vault is locked.
    assert_eq!(app.cli.run(&["get", "GitHub"]).await.code, 4);

    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    let prompts = app.unlock.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(
        prompts[0].contains("/usr/local/bin/octapass"),
        "{prompts:?}"
    );

    // The next commands use the grant.
    assert_eq!(app.get().await.ok().stdout, "hunter2\n");
    assert_eq!(app.unlock.prompts().len(), 1);

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
async fn locking_the_app_or_the_cli_ends_the_grant() {
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
    app.get().await.ok();
    let asked = app.unlock.prompts().len();
    app.cli.run_with(&["lock"], app.run()).await.ok();
    app.get().await.ok();
    assert_eq!(
        app.unlock.prompts().len(),
        asked + 1,
        "lock ended the grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_prompt_gives_nothing() {
    let app = app().await;
    app.unlock.refuse_prompts(Some(UnlockError::Cancelled));
    let refused = app.get().await;
    assert_eq!(refused.code, 4, "{refused:?}");
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
