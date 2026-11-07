//! The real `octapass` binary: arguments, environment, exit codes, and `run` replacing the
//! process. `OCTAPASS_NO_KEYRING` keeps it out of this computer's keyring.

use crate::common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::*;

fn octapass(data_dir: &std::path::Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_octapass"))
        .args(args)
        .env("OCTAPASS_CLI_DATA_DIR", data_dir)
        .env("OCTAPASS_NO_KEYRING", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn generate_help_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let password = octapass(
        dir.path(),
        &["generate", "--length", "32", "--no-symbols"],
        "",
    );
    assert!(password.status.success());
    let password = text(&password.stdout);
    assert_eq!(password.trim_end().len(), 32);
    assert!(password.trim_end().chars().all(char::is_alphanumeric));

    let phrase = octapass(
        dir.path(),
        &["generate", "--words", "4", "--separator", "_"],
        "",
    );
    assert_eq!(text(&phrase.stdout).trim_end().split('_').count(), 4);

    let too_short = octapass(dir.path(), &["generate", "--length", "2"], "");
    assert_eq!(too_short.status.code(), Some(2));

    let help = octapass(dir.path(), &["--help"], "");
    assert!(help.status.success());
    assert!(text(&help.stdout).contains("octapass://"));
    // No colours when the output isn't a terminal.
    assert!(!help.stdout.contains(&0x1b));

    let unknown = octapass(dir.path(), &["frobnicate"], "");
    assert_eq!(unknown.status.code(), Some(2));
    assert!(!text(&unknown.stderr).is_empty());

    assert_eq!(octapass(dir.path(), &["status"], "").status.code(), Some(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_read_and_run_with_the_real_binary() {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("Postgres", "app", "pg-secret").await;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_owned();
    let url = server.url.clone();
    let secret_key = other.secret_key.clone();

    tokio::task::spawn_blocking(move || {
        let login = Command::new(env!("CARGO_BIN_EXE_octapass"))
            .args([
                "login",
                "--server",
                &url,
                "--email",
                EMAIL,
                "--password-stdin",
            ])
            .env("OCTAPASS_CLI_DATA_DIR", &data)
            .env("OCTAPASS_NO_KEYRING", "1")
            .env("OCTAPASS_SECRET_KEY", &secret_key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(format!("{PASSWORD}\n").as_bytes())?;
                child.wait_with_output()
            })
            .unwrap();
        assert!(login.status.success(), "{login:?}");

        // No keyring: locked, and each command takes the password.
        assert_eq!(octapass(&data, &["status"], "").status.code(), Some(4));
        let read = octapass(
            &data,
            &[
                "--password-stdin",
                "read",
                "octapass://Personal/Postgres/password",
            ],
            &format!("{PASSWORD}\n"),
        );
        assert_eq!(text(&read.stdout), "pg-secret\n", "{read:?}");

        let run = octapass(
            &data,
            &[
                "--password-stdin",
                "run",
                "--",
                "sh",
                "-c",
                "printf %s \"$DB\"",
            ],
            &format!("{PASSWORD}\n"),
        );
        // `DB` isn't set: run passes the environment through unchanged.
        assert!(run.status.success(), "{run:?}");
        assert_eq!(text(&run.stdout), "");

        let run_command = |masking: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_octapass"))
                .args(["--password-stdin", "run"])
                .args(masking)
                .args(["--", "sh", "-c", "printf %s \"$DB\"; exit 7"])
                .env("OCTAPASS_CLI_DATA_DIR", &data)
                .env("OCTAPASS_NO_KEYRING", "1")
                .env("DB", "octapass://Personal/Postgres/password")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    child
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(format!("{PASSWORD}\n").as_bytes())?;
                    child.wait_with_output()
                })
                .unwrap()
        };
        let run = run_command(&[]);
        assert_eq!(run.status.code(), Some(7), "{run:?}");
        assert_eq!(text(&run.stdout), "<concealed by Octa Pass>");
        assert!(!text(&run.stderr).contains("pg-secret"));

        let run = run_command(&["--no-masking"]);
        assert_eq!(run.status.code(), Some(7), "{run:?}");
        assert_eq!(text(&run.stdout), "pg-secret");
        assert!(!text(&run.stderr).contains("pg-secret"));
    })
    .await
    .unwrap();
}
