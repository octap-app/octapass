//! `octapass run`: references in the environment and env files reach the child process and
//! nothing else.

#![cfg(unix)]

use crate::common;

use common::*;

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("Postgres", "app", "pg-secret").await;
    other.save_login("Stripe", "acct", "sk_live_123").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

#[tokio::test(flavor = "multi_thread")]
async fn references_reach_the_child_only() {
    let (_server, _other, cli) = setup().await;
    let work = tempfile::tempdir().unwrap();
    std::fs::write(
        work.path().join(".env.octapass"),
        "# app\nDATABASE_PASSWORD=octapass://Personal/Postgres/password\nPLAIN=hello\n",
    )
    .unwrap();
    let env_file = work.path().join(".env.octapass");
    let run = cli
        .run_with(
            &[
                "run",
                "--env-file",
                env_file.to_str().unwrap(),
                "--",
                "sh",
                "-c",
                "printf '%s|%s|%s|%s' \"$DATABASE_PASSWORD\" \"$STRIPE\" \"$PLAIN\" \"$KEPT\" > out.txt",
            ],
            Run {
                env: vec![
                    ("STRIPE".into(), "octapass://Personal/Stripe/password".into()),
                    ("KEPT".into(), "as is".into()),
                ],
                cwd: Some(work.path().to_owned()),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(
        std::fs::read_to_string(work.path().join("out.txt")).unwrap(),
        "pg-secret|sk_live_123|hello|as is"
    );
    for secret in ["pg-secret", "sk_live_123"] {
        assert!(!run.stdout.contains(secret) && !run.stderr.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_child_exit_code_is_passed_on() {
    let (_server, _other, cli) = setup().await;
    let run = cli.run(&["run", "--", "sh", "-c", "exit 3"]).await;
    assert_eq!(run.code, 3);
    let missing = cli.run(&["run", "--", "no-such-command-here"]).await;
    assert_eq!(missing.code, 127);
    assert!(missing.stderr.contains("command not found"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_reference_stops_before_the_command_runs() {
    let (_server, _other, cli) = setup().await;
    let work = tempfile::tempdir().unwrap();
    let run = cli
        .run_with(
            &["run", "--", "sh", "-c", "touch ran"],
            Run {
                env: vec![(
                    "API_KEY".into(),
                    "octapass://Personal/Nothing/password".into(),
                )],
                cwd: Some(work.path().to_owned()),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(run.code, 6);
    assert!(
        run.stderr.contains("API_KEY: No item called \"Nothing\""),
        "{run:?}"
    );
    assert!(!work.path().join("ran").exists());

    let bad_file = work.path().join("bad.env");
    std::fs::write(&bad_file, "OK=1\nnot a line\n").unwrap();
    let run = cli
        .run(&[
            "run",
            "--env-file",
            bad_file.to_str().unwrap(),
            "--",
            "true",
        ])
        .await;
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("line 2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_references_the_vault_isnt_needed() {
    let server = server().await;
    let cli = Cli::new(&server);
    assert_eq!(cli.run(&["run", "--", "true"]).await.code, 0);
    let locked = cli
        .run_with(
            &["run", "--", "true"],
            Run {
                env: vec![("A".into(), "octapass://Personal/X/password".into())],
                ..Run::default()
            },
        )
        .await;
    assert_eq!(locked.code, 3, "signed out");
}

// ---------- Masking ----------

const MASK: &str = "<concealed by Octa Pass>";

async fn masked_run(cli: &Cli, args: &[&str], script: &str) -> Output {
    let mut all = vec!["run"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["--", "sh", "-c", script]);
    cli.run_with(
        &all,
        Run {
            env: vec![
                ("TOKEN".into(), "octapass://Personal/Stripe/password".into()),
                (
                    "USERNAME".into(),
                    "octapass://Personal/Stripe/username".into(),
                ),
            ],
            ..Run::default()
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_are_hidden_in_the_commands_output() {
    let (_server, _other, cli) = setup().await;
    let run = masked_run(
        &cli,
        &[],
        "echo \"token=$TOKEN user=$USERNAME\"; echo \"err=$TOKEN\" >&2; printf '%s' \"$TOKEN\" | wc -c",
    )
    .await
    .ok();
    assert_eq!(
        run.stdout.lines().next().unwrap(),
        format!("token={MASK} user=acct"),
        "usernames aren't secrets"
    );
    assert!(
        run.stdout.contains("11"),
        "the program still got the value: {run:?}"
    );
    assert_eq!(run.stderr.trim(), format!("err={MASK}"));
    assert!(!run.stdout.contains("sk_live_123"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_written_in_pieces_is_still_hidden() {
    let (_server, _other, cli) = setup().await;
    let run = masked_run(
        &cli,
        &[],
        "printf sk_live; sleep 0.1; printf _123; sleep 0.1; printf ' done\\n'",
    )
    .await
    .ok();
    assert_eq!(run.stdout, format!("{MASK} done\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_codes_and_signals_pass_through_masking() {
    let (_server, _other, cli) = setup().await;
    assert_eq!(masked_run(&cli, &[], "exit 7").await.code, 7);
    assert_eq!(masked_run(&cli, &[], "kill -9 $$").await.code, 137);
    let missing = cli
        .run_with(
            &["run", "--", "/no/such/program"],
            Run {
                env: vec![("TOKEN".into(), "octapass://Personal/Stripe/password".into())],
                ..Run::default()
            },
        )
        .await;
    assert_eq!(missing.code, 127, "{missing:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_masking_asks_for_the_real_output() {
    let (_server, _other, cli) = setup().await;
    let script = "test -t 1; echo \"$TOKEN\" > /dev/null";
    masked_run(&cli, &["--no-masking"], script).await;
    // The harness's `exec` runs it with this test's stdout, so nothing is captured: the value
    // isn't filtered because it never passes through Octa Pass.
    let work = tempfile::tempdir().unwrap();
    let run = masked_run(
        &cli,
        &["--no-masking"],
        &format!("echo \"$TOKEN\" > {}/plain", work.path().display()),
    )
    .await
    .ok();
    assert_eq!(run.stdout, "");
    assert_eq!(
        std::fs::read_to_string(work.path().join("plain")).unwrap(),
        "sk_live_123\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_runs_stay_unfiltered() {
    let (_server, _other, cli) = setup().await;
    // No secret loaded: the command replaces Octa Pass as before.
    let work = tempfile::tempdir().unwrap();
    let run = cli
        .run_with(
            &["run", "--", "sh", "-c", "echo hello > plain"],
            Run {
                cwd: Some(work.path().to_owned()),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(run.stdout, "");
    assert_eq!(
        std::fs::read_to_string(work.path().join("plain")).unwrap(),
        "hello\n"
    );
}
