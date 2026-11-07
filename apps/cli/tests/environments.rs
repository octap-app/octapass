//! Environments: `octapass env`, `run --env` and `--env-file-out`, `inject`, `octapass.toml`, the
//! shell hook and production confirmations, against a real server.

#![cfg(unix)]

use crate::common;

use std::fs;
use std::path::Path;

use common::*;
use serde_json::{Value, json};

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other.save_login("Postgres", "app", "pg-secret").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

fn vars(list: &[(&str, &str)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(key, value)| json!({ "key": key, "value": value, "concealed": true }))
            .collect(),
    )
}

async fn save_env(
    other: &OtherDevice,
    title: &str,
    project: Option<&str>,
    stage: Option<&str>,
    list: &[(&str, &str)],
) {
    other
        .save(
            json!({ "schemaVersion": 1, "type": "environment", "title": title }),
            json!({ "schemaVersion": 1, "project": project, "stage": stage, "variables": vars(list) }),
        )
        .await;
}

/// The shop-api project: shared variables and three stages.
async fn shop_api(other: &OtherDevice) {
    save_env(
        other,
        "Shop API (shared)",
        Some("shop-api"),
        None,
        &[("LOG_LEVEL", "info"), ("REGION", "eu"), ("DB", "shared")],
    )
    .await;
    save_env(
        other,
        "Shop API (dev)",
        Some("shop-api"),
        Some("development"),
        &[("DB", "dev-db"), ("LOG_LEVEL", "debug")],
    )
    .await;
    save_env(
        other,
        "Shop API (staging)",
        Some("shop-api"),
        Some("staging"),
        &[("DB", "staging-db"), ("ONLY_STAGING", "1")],
    )
    .await;
    save_env(
        other,
        "Shop API (production)",
        Some("shop-api"),
        Some("production"),
        &[
            ("DB", "octapass://Personal/Postgres/password"),
            ("SENTRY", "on"),
        ],
    )
    .await;
}

fn printenv(keys: &[&str]) -> String {
    let parts: Vec<String> = keys.iter().map(|key| format!("${{{key}-unset}}")).collect();
    format!("printf '%s' \"{}\" > out.txt", parts.join("|"))
}

fn work() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    // The project file is looked for no further up than here.
    fs::create_dir(dir.path().join(".git")).unwrap();
    dir
}

fn out(dir: &Path) -> String {
    fs::read_to_string(dir.join("out.txt")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn create_set_show_unset_and_list() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    cli.run(&[
        "env",
        "create",
        "Stripe",
        "--project",
        "billing",
        "--stage",
        "staging",
    ])
    .await
    .ok();
    let set = cli
        .run(&[
            "env",
            "set",
            "Stripe",
            "API_KEY=sk_test_1",
            "URL=https://x?a=b",
        ])
        .await
        .ok();
    assert!(
        set.stderr.contains("Set API_KEY, URL in \"Stripe\""),
        "{set:?}"
    );
    cli.run(&["env", "set", "Stripe", "--plain", "PORT=8080"])
        .await
        .ok();
    // A value typed without it showing (here: stdin, as in a script).
    cli.run_with(
        &["env", "set", "Stripe", "TYPED"],
        Run {
            stdin: "typed-secret\n".into(),
            ..Run::default()
        },
    )
    .await
    .ok();

    let shown = cli.run(&["env", "show", "Stripe"]).await.ok();
    assert!(!shown.stdout.contains("sk_test_1") && !shown.stdout.contains("typed-secret"));
    assert!(shown.stdout.contains("PORT"), "{}", shown.stdout);
    assert!(shown.stdout.contains("8080"), "plain values show");
    assert!(shown.stdout.contains("hidden (--reveal shows it)"));
    let revealed = cli
        .run(&["--json", "env", "show", "billing:staging", "--reveal"])
        .await
        .ok()
        .json();
    let keys: Vec<(&str, &str)> = revealed["variables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["key"].as_str().unwrap(), v["value"].as_str().unwrap()))
        .collect();
    assert_eq!(
        keys,
        [
            ("API_KEY", "sk_test_1"),
            ("URL", "https://x?a=b"),
            ("PORT", "8080"),
            ("TYPED", "typed-secret")
        ]
    );
    assert_eq!(revealed["stage"], "staging");
    let hidden = cli
        .run(&["--json", "env", "show", "Stripe"])
        .await
        .ok()
        .json();
    assert_eq!(hidden["variables"][0]["value"], Value::Null);
    assert_eq!(hidden["variables"][2]["value"], "8080");

    let bad = cli.run(&["env", "set", "Stripe", "1BAD=x"]).await;
    assert_eq!(bad.code, 2, "{bad:?}");
    let missing = cli.run(&["env", "unset", "Stripe", "NOPE"]).await;
    assert_eq!(missing.code, 6);
    cli.run(&["env", "unset", "Stripe", "URL", "TYPED"])
        .await
        .ok();
    let after = cli
        .run(&["--json", "env", "show", "Stripe"])
        .await
        .ok()
        .json();
    assert_eq!(after["variables"].as_array().unwrap().len(), 2);

    let bad_stage = cli.run(&["env", "create", "X", "--stage", "prod:eu"]).await;
    assert_eq!(bad_stage.code, 2);
    assert!(bad_stage.stderr.contains("a stage is"), "{bad_stage:?}");

    let list = cli.run(&["env", "list"]).await.ok().stdout;
    let lines: Vec<&str> = list.lines().collect();
    assert!(lines[0].trim_start().starts_with("STAGE"), "{list}");
    let at = |text: &str| lines.iter().position(|line| line.contains(text)).unwrap();
    assert!(at("billing") < at("Stripe"));
    assert!(at("shop-api") < at("(shared)"));
    assert!(at("(shared)") < at("Shop API (dev)"));
    assert!(at("Shop API (dev)") < at("Shop API (staging)"));
    assert!(at("Shop API (staging)") < at("Shop API (production)"));
    assert!(!list.contains("sk_test_1"));
    let json = cli
        .run(&["--json", "env", "list", "--project", "shop-api"])
        .await
        .ok()
        .json();
    assert_eq!(json.as_array().unwrap().len(), 4);
    assert_eq!(json[1]["stage"], "development");
    assert_eq!(json[1]["keys"], json!(["DB", "LOG_LEVEL"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn import_export_and_files() {
    let (_server, _other, cli) = setup().await;
    let dir = work();
    let file = dir.path().join("app.env");
    fs::write(
        &file,
        "# app\nDB_PASSWORD=octapass://Personal/Postgres/password\nKEY=\"-----BEGIN-----\nabc\n-----END-----\"\nexport GREETING='hi there'\n",
    )
    .unwrap();
    let imported = cli
        .run(&[
            "env",
            "import",
            file.to_str().unwrap(),
            "--new",
            "App",
            "--project",
            "app",
        ])
        .await
        .ok();
    assert!(imported.stderr.contains("3 variables"), "{imported:?}");
    let dupes = dir.path().join("dupes.env");
    fs::write(&dupes, "A=1\nA=2\n").unwrap();
    let error = cli
        .run(&["env", "import", dupes.to_str().unwrap(), "--into", "App"])
        .await;
    assert_eq!(error.code, 2);
    assert!(
        error
            .stderr
            .contains("line 2 (A): this name is already used"),
        "{error:?}"
    );
    let more = dir.path().join("more.env");
    fs::write(&more, "GREETING=replaced\nNEW=1\n").unwrap();
    cli.run(&["env", "import", more.to_str().unwrap(), "--into", "App"])
        .await
        .ok();

    let dotenv = cli.run(&["env", "export", "App"]).await.ok().stdout;
    assert_eq!(
        dotenv,
        "DB_PASSWORD=pg-secret\nKEY=\"-----BEGIN-----\nabc\n-----END-----\"\nGREETING=replaced\nNEW=1\n"
    );
    let kept = cli
        .run(&[
            "env",
            "export",
            "App",
            "--keep-references",
            "--format",
            "shell",
        ])
        .await
        .ok()
        .stdout;
    assert!(kept.starts_with("export DB_PASSWORD='octapass://Personal/Postgres/password'\n"));
    let json = cli
        .run(&["env", "export", "App", "--format", "json"])
        .await
        .ok()
        .json();
    assert_eq!(json["DB_PASSWORD"], "pg-secret");
    let ps = cli
        .run(&["env", "export", "App", "--format", "powershell"])
        .await
        .ok()
        .stdout;
    assert!(ps.contains("$env:GREETING = 'replaced'"));
    let docker = cli
        .run(&["env", "export", "App", "--format", "docker"])
        .await;
    assert_eq!(docker.code, 2);
    assert!(
        docker.stderr.contains("KEY: Docker's env file format"),
        "{docker:?}"
    );
    cli.run(&["env", "unset", "App", "KEY"]).await.ok();
    let docker = cli
        .run(&["env", "export", "App", "--format", "docker"])
        .await
        .ok()
        .stdout;
    assert_eq!(docker, "DB_PASSWORD=pg-secret\nGREETING=replaced\nNEW=1\n");

    let target = dir.path().join("exported.env");
    let path = target.to_str().unwrap();
    cli.run(&["env", "export", "App", "-o", path]).await.ok();
    assert_eq!(mode(&target), 0o600);
    let again = cli.run(&["env", "export", "App", "-o", path]).await;
    assert_eq!(again.code, 2);
    assert!(again.stderr.contains("--force"));
    cli.run(&[
        "env", "export", "App", "-o", path, "--force", "--format", "docker",
    ])
    .await
    .ok();
    assert!(
        fs::read_to_string(&target)
            .unwrap()
            .starts_with("DB_PASSWORD=pg-secret")
    );
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn references_to_variables_follow_one_step() {
    let (_server, other, cli) = setup().await;
    save_env(
        &other,
        "Chain",
        None,
        None,
        &[
            ("DIRECT", "plain-value"),
            ("VIA", "octapass://Personal/Postgres/password"),
            ("TWICE", "octapass://Personal/Chain/VIA"),
            ("MISSING", "octapass://Personal/Nothing/password"),
        ],
    )
    .await;
    let read = |field: &'static str| {
        let cli = &cli;
        async move {
            cli.run(&["read", "-n", &format!("octapass://Personal/Chain/{field}")])
                .await
        }
    };
    assert_eq!(read("DIRECT").await.ok().stdout, "plain-value");
    assert_eq!(read("VIA").await.ok().stdout, "pg-secret");
    let twice = read("TWICE").await;
    assert_eq!(twice.code, 2, "{twice:?}");
    assert!(
        twice.stderr.contains("Only one step is followed"),
        "{twice:?}"
    );
    let missing = read("MISSING").await;
    assert_eq!(missing.code, 6);
    assert!(missing.stderr.contains("No item called \"Nothing\""));
    let unknown = read("NOT_A_KEY").await;
    assert_eq!(unknown.code, 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_loads_environments_in_order() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    save_env(
        &other,
        "Overrides",
        None,
        None,
        &[("REGION", "us"), ("EXTRA", "x")],
    )
    .await;
    let dir = work();
    let env_file = dir.path().join("local.env");
    fs::write(&env_file, "EXTRA=from-file\n").unwrap();
    let keys = ["DB", "LOG_LEVEL", "REGION", "EXTRA", "SENTRY", "EXPLICIT"];
    let run = cli
        .run_with(
            &[
                "run",
                "--env",
                "shop-api:development",
                "--env",
                "Overrides",
                "--env-file",
                env_file.to_str().unwrap(),
                "--",
                "sh",
                "-c",
                &printenv(&keys),
            ],
            Run {
                env: vec![(
                    "EXPLICIT".into(),
                    "octapass://Personal/Postgres/password".into(),
                )],
                cwd: Some(dir.path().to_owned()),
                ..Run::default()
            },
        )
        .await
        .ok();
    // Shared, then the stage, then later environments, then the file, then references.
    assert_eq!(out(dir.path()), "dev-db|debug|us|from-file|unset|pg-secret");
    assert!(!run.stdout.contains("pg-secret") && !run.stderr.contains("pg-secret"));

    // --project and --stage, with a variable that is a reference to a login's password.
    cli.run_with(
        &[
            "run",
            "--project",
            "shop-api",
            "--stage",
            "production",
            "--",
            "sh",
            "-c",
            &printenv(&keys),
        ],
        Run {
            cwd: Some(dir.path().to_owned()),
            ..Run::default()
        },
    )
    .await
    .ok();
    assert_eq!(out(dir.path()), "pg-secret|info|eu|unset|on|unset");

    let no_stage = cli
        .run(&[
            "run",
            "--project",
            "shop-api",
            "--stage",
            "qa",
            "--",
            "true",
        ])
        .await;
    assert_eq!(no_stage.code, 6);
    assert!(no_stage.stderr.contains("has no qa stage"), "{no_stage:?}");
    let stage_alone = cli
        .run_with(
            &["run", "--stage", "staging", "--", "true"],
            Run {
                cwd: Some(dir.path().to_owned()),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(stage_alone.code, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_project_file_and_production_confirmation() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    let dir = work();
    let sub = dir.path().join("services/api");
    fs::create_dir_all(&sub).unwrap();
    fs::write(
        dir.path().join("octapass.toml"),
        "project = \"shop-api\"\nstage = \"development\"\n",
    )
    .unwrap();
    let keys = ["DB", "LOG_LEVEL", "SENTRY"];
    let in_sub = |env: Vec<(String, String)>, interactive: bool, answers: Vec<String>| Run {
        cwd: Some(sub.clone()),
        env,
        interactive,
        answers,
        ..Run::default()
    };
    let script = printenv(&keys);
    let command = ["run", "--", "sh", "-c", script.as_str()];
    cli.run_with(&command, in_sub(vec![], false, vec![]))
        .await
        .ok();
    assert_eq!(out(&sub), "dev-db|debug|unset");

    cli.run_with(
        &["run", "--stage", "staging", "--", "sh", "-c", &script],
        in_sub(vec![], false, vec![]),
    )
    .await
    .ok();
    assert_eq!(out(&sub), "staging-db|info|unset");

    // Production from OCTAPASS_STAGE (or the file) asks first.
    let prod = vec![("OCTAPASS_STAGE".to_owned(), "production".to_owned())];
    let refused = cli
        .run_with(&command, in_sub(prod.clone(), false, vec![]))
        .await;
    assert_eq!(refused.code, 2, "{refused:?}");
    assert!(refused.stderr.contains("--stage production or --yes"));
    fs::remove_file(sub.join("out.txt")).unwrap();
    let declined = cli
        .run_with(&command, in_sub(prod.clone(), true, vec!["n".into()]))
        .await;
    assert_eq!(declined.code, 1);
    assert!(declined.asked[0].contains("Run with production variables (Shop API (production))?"));
    assert!(!sub.join("out.txt").exists());
    cli.run_with(&command, in_sub(prod.clone(), true, vec!["y".into()]))
        .await
        .ok();
    assert_eq!(out(&sub), "pg-secret|info|on");
    let mut yes = vec!["run", "--yes"];
    yes.extend_from_slice(&command[1..]);
    cli.run_with(&yes, in_sub(prod, false, vec![])).await.ok();
    // Named on the command line: no question.
    let explicit = cli
        .run_with(
            &["run", "--stage", "production", "--", "sh", "-c", &script],
            in_sub(vec![], false, vec![]),
        )
        .await
        .ok();
    assert!(explicit.asked.is_empty());

    // An env list in the file, by vault/title.
    fs::write(
        dir.path().join("octapass.toml"),
        "env = [\"Personal/Shop API (staging)\"]\n",
    )
    .unwrap();
    cli.run_with(&command, in_sub(vec![], false, vec![]))
        .await
        .ok();
    assert_eq!(out(&sub), "staging-db|unset|unset");
    fs::write(dir.path().join("octapass.toml"), "envs = 1\n").unwrap();
    let bad = cli.run_with(&command, in_sub(vec![], false, vec![])).await;
    assert_eq!(bad.code, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn env_file_out_exists_only_while_the_command_runs() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    let dir = work();
    cli.run_with(
        &[
            "run",
            "--env",
            "shop-api:development",
            "--env-file-out",
            ".env",
            "--",
            "sh",
            "-c",
            "ls -l .env | cut -c1-10 > out.txt; cat .env >> out.txt",
        ],
        Run {
            cwd: Some(dir.path().to_owned()),
            ..Run::default()
        },
    )
    .await
    .ok();
    assert_eq!(
        out(dir.path()),
        "-rw-------\nLOG_LEVEL=debug\nREGION=eu\nDB=dev-db\n"
    );
    assert!(!dir.path().join(".env").exists());

    // An existing file is never replaced (it would be deleted afterwards).
    fs::write(dir.path().join(".env"), "MINE=1\n").unwrap();
    let refused = cli
        .run_with(
            &[
                "run",
                "--env",
                "shop-api:",
                "--env-file-out",
                ".env",
                "--",
                "true",
            ],
            Run {
                cwd: Some(dir.path().to_owned()),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(refused.code, 2);
    assert_eq!(
        fs::read_to_string(dir.path().join(".env")).unwrap(),
        "MINE=1\n"
    );

    // The file goes when the command fails too.
    let failed = cli
        .run_with(
            &[
                "run",
                "--env",
                "shop-api:",
                "--env-file-out",
                "x.env",
                "--",
                "sh",
                "-c",
                "exit 4",
            ],
            Run {
                cwd: Some(dir.path().to_owned()),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(failed.code, 4);
    assert!(!dir.path().join("x.env").exists());
}

/// Ctrl-C reaches the whole foreground process group: the real binary waits for the command to
/// stop, then deletes the file.
#[test]
fn env_file_out_is_deleted_after_an_interrupt() {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let dir = work();
    let data = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("vars.env"), "TOKEN=abc\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_octapass"))
        .args([
            "run",
            "--env-file",
            "vars.env",
            "--env-file-out",
            "out.env",
            "--",
            "sh",
            "-c",
            "touch started; sleep 30",
        ])
        .current_dir(dir.path())
        .env("OCTAPASS_CLI_DATA_DIR", data.path())
        .env("OCTAPASS_NO_KEYRING", "1")
        .stdin(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !dir.path().join("started").exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the command never started"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let file = dir.path().join("out.env");
    assert_eq!(fs::read_to_string(&file).unwrap(), "TOKEN=abc\n");
    assert_eq!(mode(&file), 0o600);
    let group = format!("-{}", child.id());
    let killed = Command::new("kill")
        .args(["-INT", "--", &group])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    assert!(start.elapsed() < Duration::from_secs(25));
    assert_eq!(
        status.code(),
        Some(130),
        "128 + SIGINT, passed on from the command"
    );
    assert!(!file.exists(), "the file is deleted after Ctrl-C");
}

#[tokio::test(flavor = "multi_thread")]
async fn inject_fills_in_a_template() {
    let (_server, _other, cli) = setup().await;
    let dir = work();
    let template = dir.path().join("config.tpl");
    fs::write(
        &template,
        "database:\n  url: postgres://app:{{ octapass://Personal/Postgres/password }}@db/app\n  user: octapass://Personal/Postgres/username\n",
    )
    .unwrap();
    let output = dir.path().join("config.yml");
    let (tpl, outp) = (template.to_str().unwrap(), output.to_str().unwrap());
    cli.run(&["inject", "-i", tpl, "-o", outp]).await.ok();
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "database:\n  url: postgres://app:pg-secret@db/app\n  user: app\n"
    );
    assert_eq!(mode(&output), 0o600);
    assert_eq!(cli.run(&["inject", "-i", tpl, "-o", outp]).await.code, 2);
    cli.run(&["inject", "-i", tpl, "-o", outp, "--force"])
        .await
        .ok();
    let stdin = cli
        .run_with(
            &["inject"],
            Run {
                stdin: "pw=octapass://Personal/Postgres/password;\n".into(),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(stdin.stdout, "pw=pg-secret;\n");
    let broken = dir.path().join("broken.tpl");
    fs::write(&broken, "a: octapass://Personal/Nothing/password\n").unwrap();
    let missing = dir.path().join("never.yml");
    let failed = cli
        .run(&[
            "inject",
            "-i",
            broken.to_str().unwrap(),
            "-o",
            missing.to_str().unwrap(),
        ])
        .await;
    assert_eq!(failed.code, 6);
    assert!(
        !missing.exists(),
        "nothing is written when a reference fails"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn env_diff_hides_values() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    let diff = cli
        .run(&["env", "diff", "shop-api", "staging", "production"])
        .await
        .ok()
        .stdout;
    assert!(
        diff.contains("DB") && diff.contains("different values"),
        "{diff}"
    );
    assert!(diff.contains("ONLY_STAGING") && diff.contains("only in staging"));
    assert!(diff.contains("SENTRY") && diff.contains("only in production"));
    assert!(
        !diff.contains("LOG_LEVEL"),
        "the shared set is the same on both sides"
    );
    assert!(!diff.contains("staging-db") && !diff.contains("pg-secret"));
    let json = cli
        .run(&[
            "--json",
            "env",
            "diff",
            "Shop API (dev)",
            "Shop API (staging)",
        ])
        .await
        .ok()
        .json();
    assert_eq!(
        json,
        json!([
            { "key": "DB", "kind": "different" },
            { "key": "LOG_LEVEL", "kind": "onlyInFirst" },
            { "key": "ONLY_STAGING", "kind": "onlyInSecond" }
        ])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shell_hook_loads_allowed_projects_while_unlocked() {
    let (_server, other, cli) = setup().await;
    shop_api(&other).await;
    let script = cli.run(&["env", "hook", "zsh"]).await.ok().stdout;
    assert!(script.contains("octapass env hook-env zsh"));
    for shell in ["bash", "fish", "powershell"] {
        let hook = cli.run(&["env", "hook", shell]).await.ok().stdout;
        assert!(hook.contains(&format!("hook-env {shell}")), "{shell}");
    }

    let dir = work();
    fs::write(
        dir.path().join("octapass.toml"),
        "project = \"shop-api\"\nstage = \"development\"\n",
    )
    .unwrap();
    let hook = |cwd: &Path, env: Vec<(String, String)>| Run {
        cwd: Some(cwd.to_owned()),
        env,
        ..Run::default()
    };
    // Not allowed yet: nothing loads, once.
    let blocked = cli
        .run_with(&["env", "hook-env", "bash"], hook(dir.path(), vec![]))
        .await
        .ok();
    assert!(blocked.stderr.contains("isn't allowed yet"), "{blocked:?}");
    assert!(!blocked.stdout.contains("DB="));
    let state = state_of(&blocked.stdout);
    let quiet = cli
        .run_with(
            &["env", "hook-env", "bash"],
            hook(dir.path(), vec![("OCTAPASS_ENV_STATE".into(), state)]),
        )
        .await
        .ok();
    assert_eq!(quiet.stdout, "");

    cli.run_with(&["env", "allow"], hook(dir.path(), vec![]))
        .await
        .ok();
    let loaded = cli
        .run_with(
            &["env", "hook-env", "bash"],
            hook(dir.path(), vec![("DB".into(), "mine".into())]),
        )
        .await
        .ok();
    assert!(loaded.stdout.contains("export DB='dev-db'\n"), "{loaded:?}");
    assert!(loaded.stdout.contains("export LOG_LEVEL='debug'\n"));
    let state = state_of(&loaded.stdout);
    let shell_env = |state: &str| {
        vec![
            ("OCTAPASS_ENV_STATE".to_owned(), state.to_owned()),
            ("DB".to_owned(), "dev-db".to_owned()),
        ]
    };
    // The next prompt in the same project does nothing.
    let same = cli
        .run_with(
            &["env", "hook-env", "bash"],
            hook(dir.path(), shell_env(&state)),
        )
        .await
        .ok();
    assert_eq!(same.stdout, "");
    // Leaving puts back what was there before.
    let elsewhere = tempfile::tempdir().unwrap();
    let left = cli
        .run_with(
            &["env", "hook-env", "fish"],
            hook(elsewhere.path(), shell_env(&state)),
        )
        .await
        .ok();
    assert!(left.stdout.contains("set -gx DB 'mine'\n"), "{left:?}");
    assert!(left.stdout.contains("set -e LOG_LEVEL\n"));
    assert!(left.stdout.contains("set -e OCTAPASS_ENV_STATE\n"));

    // Locking unloads at the next prompt.
    cli.run(&["lock"]).await.ok();
    let locked = cli
        .run_with(
            &["env", "hook-env", "zsh"],
            hook(dir.path(), shell_env(&state)),
        )
        .await
        .ok();
    assert!(locked.stdout.contains("export DB='mine'"), "{locked:?}");
    assert!(locked.stdout.contains("unset LOG_LEVEL"));
    assert!(locked.stderr.contains("locked"));
    cli.run_password(&["unlock"]).await.ok();

    // A changed file has to be allowed again.
    fs::write(
        dir.path().join("octapass.toml"),
        "project = \"shop-api\"\nstage = \"production\"\n",
    )
    .unwrap();
    let changed = cli
        .run_with(
            &["env", "hook-env", "bash"],
            hook(dir.path(), shell_env(&state)),
        )
        .await
        .ok();
    assert!(changed.stderr.contains("isn't allowed yet"));
    assert!(
        changed.stdout.contains("export DB='mine'"),
        "the old variables go"
    );
    cli.run_with(&["env", "allow"], hook(dir.path(), vec![]))
        .await
        .ok();
    // Production from the project file needs a yes, which a hook without a terminal can't get.
    let production = cli
        .run_with(&["env", "hook-env", "bash"], hook(dir.path(), vec![]))
        .await
        .ok();
    assert!(!production.stdout.contains("SENTRY"), "{production:?}");
    assert!(production.stderr.contains("production"));
    let confirmed = cli
        .run_with(
            &["env", "hook-env", "powershell"],
            Run {
                interactive: true,
                answers: vec!["yes".into()],
                ..hook(dir.path(), vec![])
            },
        )
        .await
        .ok();
    assert!(
        confirmed.stdout.contains("$env:SENTRY = 'on'"),
        "{confirmed:?}"
    );
    assert!(confirmed.stdout.contains("$env:DB = 'pg-secret'"));

    cli.run_with(&["env", "deny"], hook(dir.path(), vec![]))
        .await
        .ok();
    let denied = cli
        .run_with(&["env", "hook-env", "bash"], hook(dir.path(), vec![]))
        .await
        .ok();
    assert!(denied.stderr.contains("isn't allowed yet"));
}

/// The value the hook's script gives OCTAPASS_ENV_STATE.
fn state_of(script: &str) -> String {
    let line = script
        .lines()
        .find(|line| line.starts_with("export OCTAPASS_ENV_STATE="))
        .unwrap_or_else(|| panic!("no state in {script}"));
    let quoted = line.trim_start_matches("export OCTAPASS_ENV_STATE=");
    quoted[1..quoted.len() - 1].replace("'\\''", "'")
}
