//! Git: the credential helper and commit signing. The real `git`, `ssh-keygen` and `gpg` run the
//! real helpers, as separate processes, which unlock through a desktop app on a socket: the only
//! way a real process can stay unlocked in a test without touching this computer's keyring.

#![cfg(unix)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use common::*;
use octapass_desktop_vault::cli_session::{self, CliGrants, CliPeer};
use octapass_device_unlock::fake::FakeDeviceUnlock;
use serde_json::json;

const CREDENTIAL: &str = env!("CARGO_BIN_EXE_git-credential-octapass");
const SIGN: &str = env!("CARGO_BIN_EXE_octapass-git-sign");

fn gpg_fixture() -> String {
    format!(
        "{}/../../crates/octapass-core/tests/gpg-fixtures/ed25519-subkey.asc",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// A signed-in account, a CLI on the same account, and an app answering on a socket.
struct World {
    _server: Server,
    other: OtherDevice,
    cli: Cli,
    /// The app's data folder: `cli_session::endpoint` of it is where it listens.
    app_dir: tempfile::TempDir,
}

async fn world() -> World {
    let server = server().await;
    let unlock = Arc::new(FakeDeviceUnlock::default());
    let other = OtherDevice::sign_up_with(&server, unlock).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    cli.run(&["lock"]).await.ok();
    let app_dir = tempfile::Builder::new()
        .prefix("opg")
        .tempdir_in("/tmp")
        .unwrap();
    let endpoint = cli_session::endpoint(app_dir.path());
    let vault = Arc::clone(&other.vault);
    let socket = endpoint.clone();
    tokio::spawn(async move {
        cli_session::serve(vault, Arc::new(CliGrants::default()), socket, |_| {
            Ok(CliPeer {
                executable: "/usr/local/bin/octapass".into(),
                session: Some(1),
            })
        })
        .await
    });
    while !endpoint.exists() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    World {
        _server: server,
        other,
        cli,
        app_dir,
    }
}

impl World {
    /// A real program, on this CLI's data, unlocking through the app.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>, home: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env("HOME", home)
            .env("OCTAPASS_CLI_DATA_DIR", self.cli.data_dir())
            .env("OCTAPASS_DESKTOP_DATA_DIR", self.app_dir.path())
            .env("OCTAPASS_NO_KEYRING", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GNUPGHOME", home.join("gnupg"))
            .stdin(Stdio::null());
        command
    }
}

async fn output(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

async fn with_input(mut command: Command, input: &'static str) -> Output {
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn git_gets_a_password_from_the_vault() {
    let world = world().await;
    world
        .other
        .save(
            json!({ "schemaVersion": 1, "type": "login", "title": "Forge", "urls": ["https://git.example"] }),
            json!({ "schemaVersion": 1, "username": "ada", "password": "forge-password" }),
        )
        .await;
    let home = tempfile::tempdir().unwrap();
    let fill = |host: &str| {
        let mut git = world.command("git", home.path());
        git.args(["-c", "credential.helper="])
            .arg("-c")
            .arg(format!("credential.helper={CREDENTIAL}"))
            .args(["credential", "fill"]);
        let input = format!("protocol=https\nhost={host}\n\n");
        (git, Box::leak(input.into_boxed_str()) as &'static str)
    };
    let (git, input) = fill("git.example");
    let filled = with_input(git, input).await;
    let out = text(&filled.stdout);
    assert!(
        out.contains("username=ada") && out.contains("password=forge-password"),
        "{filled:?}"
    );

    // Another host gets nothing from Octa Pass: Git falls through, and gives up without a prompt.
    let (git, input) = fill("git.example.evil.test");
    let refused = with_input(git, input).await;
    assert!(
        !text(&refused.stdout).contains("forge-password"),
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_helper_never_erases_and_stores_only_when_asked() {
    let world = world().await;
    world.other.save_login("Keep", "ada", "pw").await;
    let cli = &world.cli;
    let endpoint = cli_session::endpoint(world.app_dir.path());
    let run = Run {
        stdin: "protocol=https\nhost=example.com\nusername=ada\npassword=wrong\n\n".into(),
        desktop_app: Some(endpoint),
        ..Run::default()
    };
    cli.run_with(&["git", "credential", "erase"], run.clone())
        .await
        .ok();
    cli.run_with(&["git", "credential", "store"], run.clone())
        .await
        .ok();
    assert_eq!(
        cli.run_with(&["get", "Keep", "--field", "password"], run.clone())
            .await
            .ok()
            .stdout,
        "pw\n",
        "neither touched the vault"
    );
    cli.run_with(&["git", "credential", "--store", "store"], run.clone())
        .await
        .ok();
    assert_eq!(
        cli.run_with(&["get", "Keep", "--field", "password"], run)
            .await
            .ok()
            .stdout,
        "wrong\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn several_logins_for_a_host_need_a_username() {
    let world = world().await;
    for (title, user) in [("One", "ada"), ("Two", "grace")] {
        world
            .other
            .save(
                json!({ "schemaVersion": 1, "type": "login", "title": title, "urls": ["https://git.example"] }),
                json!({ "schemaVersion": 1, "username": user, "password": format!("{user}-pw") }),
            )
            .await;
    }
    let endpoint = cli_session::endpoint(world.app_dir.path());
    let run = |stdin: &str| Run {
        stdin: stdin.into(),
        desktop_app: Some(endpoint.clone()),
        ..Run::default()
    };
    let both = world
        .cli
        .run_with(
            &["git", "credential", "get"],
            run("protocol=https\nhost=git.example\n\n"),
        )
        .await
        .ok();
    assert_eq!(both.stdout, "");
    assert!(both.stderr.contains("2 logins"), "{both:?}");
    let one = world
        .cli
        .run_with(
            &["git", "credential", "get"],
            run("protocol=https\nhost=git.example\nusername=grace\n\n"),
        )
        .await
        .ok();
    assert_eq!(one.stdout, "username=grace\npassword=grace-pw\n");
}

/// Makes a repository with an identity, and an `allowed_signers` file for `verify-commit`.
async fn repository(world: &World, home: &Path) -> PathBuf {
    let repo = home.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(home.join("gnupg")).unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.name", "Ada"],
        vec!["config", "user.email", "fixture@octap.app"],
    ] {
        let mut git = world.command("git", home);
        git.args(args).current_dir(&repo);
        assert!(output(git).await.status.success());
    }
    std::fs::write(repo.join("file"), "hello").unwrap();
    let mut git = world.command("git", home);
    git.args(["add", "file"]).current_dir(&repo);
    assert!(output(git).await.status.success());
    repo
}

#[tokio::test(flavor = "multi_thread")]
async fn git_signs_a_commit_with_an_ssh_key_from_the_vault() {
    let world = world().await;
    let endpoint = cli_session::endpoint(world.app_dir.path());
    let app = Run {
        desktop_app: Some(endpoint),
        ..Run::default()
    };
    let public = world
        .cli
        .run_with(
            &[
                "ssh",
                "generate",
                "--title",
                "Signing",
                "--comment",
                "ada@laptop",
            ],
            app.clone(),
        )
        .await
        .ok()
        .stdout;
    let public: Vec<&str> = public.split_whitespace().take(2).collect();
    let public = public.join(" ");

    let home = tempfile::Builder::new()
        .prefix("opg")
        .tempdir_in("/tmp")
        .unwrap();
    let repo = repository(&world, home.path()).await;
    let allowed = home.path().join("allowed");
    std::fs::write(&allowed, format!("fixture@octap.app {public}\n")).unwrap();
    let done = world
        .cli
        .run_with(
            &[
                "git",
                "setup",
                "--no-credentials",
                "--signing-key",
                "Signing",
            ],
            Run {
                cwd: Some(repo.clone()),
                env: vec![("HOME".into(), home.path().display().to_string())],
                ..app.clone()
            },
        )
        .await
        .ok();
    assert!(done.stderr.contains("Git now uses Octa Pass"), "{done:?}");

    // The setup points at `octapass-git-sign` next to the test binary only if it's there: here
    // the program is given directly, as `octapass git setup` writes it for an installed CLI.
    let mut commit = world.command("git", home.path());
    commit
        .args(["-c", "gpg.format=ssh"])
        .arg("-c")
        .arg(format!("gpg.ssh.program={SIGN}"))
        .arg("-c")
        .arg(format!("user.signingkey=key::{public}"))
        .arg("-c")
        .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
        .args(["commit", "-q", "-S", "-m", "signed by the vault"])
        .current_dir(&repo);
    let committed = output(commit).await;
    assert!(committed.status.success(), "{committed:?}");

    let mut raw = world.command("git", home.path());
    raw.args(["cat-file", "commit", "HEAD"]).current_dir(&repo);
    assert!(text(&output(raw).await.stdout).contains("BEGIN SSH SIGNATURE"));

    let mut verify = world.command("git", home.path());
    verify
        .arg("-c")
        .arg(format!("gpg.ssh.program={SIGN}"))
        .arg("-c")
        .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
        .args(["verify-commit", "HEAD"])
        .current_dir(&repo);
    let verified = output(verify).await;
    assert!(verified.status.success(), "{verified:?}");
    assert!(text(&verified.stderr).contains("Good"), "{verified:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn git_signs_a_commit_with_a_gpg_key_from_the_vault() {
    if Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipped: no gpg");
        return;
    }
    let world = world().await;
    let endpoint = cli_session::endpoint(world.app_dir.path());
    let app = Run {
        desktop_app: Some(endpoint),
        ..Run::default()
    };
    let import = world
        .cli
        .run_with(
            &["gpg", "import", &gpg_fixture(), "--title", "Commits"],
            app.clone(),
        )
        .await
        .ok();
    assert!(import.stderr.contains("Imported “Commits”"), "{import:?}");
    let listed = world
        .cli
        .run_with(&["gpg", "list", "--json"], app.clone())
        .await
        .ok()
        .json();
    let fingerprint = listed[0]["fingerprint"].as_str().unwrap().to_owned();
    let public = world
        .cli
        .run_with(&["gpg", "public", "Commits"], app.clone())
        .await
        .ok()
        .stdout;
    assert!(public.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(!public.contains("PRIVATE"));

    let again = world
        .cli
        .run_with(&["gpg", "import", &gpg_fixture()], app.clone())
        .await;
    assert_eq!(again.code, 2, "{again:?}");

    let home = tempfile::Builder::new()
        .prefix("opg")
        .tempdir_in("/tmp")
        .unwrap();
    let repo = repository(&world, home.path()).await;
    let gnupg = home.path().join("gnupg");
    std::fs::set_permissions(&gnupg, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let key_file = home.path().join("public.asc");
    std::fs::write(&key_file, &public).unwrap();
    let mut import = world.command("gpg", home.path());
    import
        .args(["--batch", "--no-autostart", "--import"])
        .arg(&key_file);
    assert!(output(import).await.status.success());

    let mut commit = world.command("git", home.path());
    commit
        .arg("-c")
        .arg(format!("gpg.program={SIGN}"))
        .arg("-c")
        .arg(format!("user.signingkey={fingerprint}"))
        .args(["commit", "-q", "-S", "-m", "signed by the vault"])
        .current_dir(&repo);
    let committed = output(commit).await;
    assert!(committed.status.success(), "{committed:?}");

    let mut raw = world.command("git", home.path());
    raw.args(["cat-file", "commit", "HEAD"]).current_dir(&repo);
    assert!(text(&output(raw).await.stdout).contains("BEGIN PGP SIGNATURE"));

    // Verifying goes to the real gpg.
    let mut verify = world.command("git", home.path());
    verify
        .arg("-c")
        .arg(format!("gpg.program={SIGN}"))
        .args(["verify-commit", "--raw", "HEAD"])
        .current_dir(&repo);
    let verified = output(verify).await;
    assert!(text(&verified.stderr).contains("GOODSIG"), "{verified:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_shows_its_settings_and_refuses_other_items() {
    let world = world().await;
    world.other.save_login("Not a key", "ada", "pw").await;
    let app = Run {
        desktop_app: Some(cli_session::endpoint(world.app_dir.path())),
        ..Run::default()
    };
    let home = tempfile::Builder::new()
        .prefix("opg")
        .tempdir_in("/tmp")
        .unwrap();
    let repo = repository(&world, home.path()).await;
    let here = Run {
        cwd: Some(repo.clone()),
        env: vec![("HOME".into(), home.path().display().to_string())],
        ..app
    };
    let dry = world
        .cli
        .run_with(&["git", "setup", "--dry-run"], here.clone())
        .await
        .ok();
    assert!(dry.stdout.starts_with("credential.helper "), "{dry:?}");
    assert!(
        !std::fs::read_to_string(repo.join(".git/config"))
            .unwrap()
            .contains("credential"),
        "a dry run changes nothing"
    );
    world
        .cli
        .run_with(&["git", "setup"], here.clone())
        .await
        .ok();
    world
        .cli
        .run_with(&["git", "setup"], here.clone())
        .await
        .ok();
    let config = std::fs::read_to_string(repo.join(".git/config")).unwrap();
    assert_eq!(
        config.matches("git-credential-octapass").count(),
        1,
        "{config}"
    );

    let refused = world
        .cli
        .run_with(&["git", "setup", "--signing-key", "Not a key"], here)
        .await;
    assert_eq!(refused.code, 2, "{refused:?}");
}
