//! Importing other apps' files into the vault and exporting it again.

use crate::common;

use common::*;
use serde_json::{Value, json};

const CHROME_CSV: &str = "name,url,username,password,note\n\
GitHub,https://github.com/login,octocat,hunter2,main account\n\
Example,https://example.com,ada,p4ss,\n";

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

#[tokio::test(flavor = "multi_thread")]
async fn import_a_browser_export() {
    let (_server, other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("chrome.csv");
    std::fs::write(&file, CHROME_CSV).unwrap();
    let path = file.to_str().unwrap();

    let dry = cli.run(&["import", "chrome", path, "--dry-run"]).await.ok();
    assert_eq!(dry.stderr, "Would import 2 items into Personal.\n");
    assert!(other.vault.live_items().unwrap().is_empty());

    let import = cli
        .run(&["import", "chrome", path, "--json"])
        .await
        .ok()
        .json();
    assert_eq!(import["items"], 2);
    assert_eq!(import["dryRun"], false);
    assert_eq!(
        cli.run(&["get", "GitHub", "--field", "password"])
            .await
            .ok()
            .stdout,
        "hunter2\n"
    );
    other.vault.sync().await.unwrap();
    assert_eq!(other.vault.live_items().unwrap().len(), 2, "uploaded");

    // The same file again adds no copies; a changed password updates its login.
    let again = cli.run(&["import", "chrome", path]).await.ok();
    assert_eq!(
        again.stderr,
        "Imported 0 items into Personal; 0 updated and 2 unchanged.\n"
    );
    std::fs::write(&file, CHROME_CSV.replace("hunter2", "hunter3")).unwrap();
    let dry = cli.run(&["import", "chrome", path, "--dry-run"]).await.ok();
    assert_eq!(
        dry.stderr,
        "Would import 0 items into Personal; 1 to update and 1 unchanged.\n"
    );
    let changed = cli
        .run(&["import", "chrome", path, "--json"])
        .await
        .ok()
        .json();
    assert_eq!(
        (changed["updated"].clone(), changed["unchanged"].clone()),
        (json!(1), json!(1))
    );
    let github = cli.run(&["get", "GitHub", "--json"]).await.ok().json();
    assert_eq!(github["details"]["password"], "hunter3");
    assert_eq!(
        github["details"]["passwordHistory"][0]["password"],
        "hunter2"
    );
    std::fs::write(&file, CHROME_CSV).unwrap();

    // A one-time code joins the login it belongs to instead of making a new item.
    let codes = dir.path().join("codes.txt");
    std::fs::write(
        &codes,
        "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n",
    )
    .unwrap();
    let import = cli
        .run(&["import", "otpauth", codes.to_str().unwrap()])
        .await
        .ok();
    assert!(
        import
            .stderr
            .contains("one-time codes for 1 existing login"),
        "{import:?}"
    );
    assert_eq!(
        cli.run(&["totp", "GitHub"]).await.ok().stdout.trim().len(),
        6
    );

    let wrong = dir.path().join("wrong.json");
    std::fs::write(&wrong, "not json").unwrap();
    assert_eq!(
        cli.run(&["import", "bitwarden", wrong.to_str().unwrap()])
            .await
            .code,
        2
    );
    assert_eq!(
        cli.run(&["import", "chrome", "/no/such/file.csv"])
            .await
            .code,
        2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn export_asks_for_the_password_again() {
    let (_server, other, cli) = setup().await;
    other.save_login("GitHub", "octocat", "hunter2").await;

    // Unlocked, but nobody to ask for the master password.
    let refused = cli.run(&["export", "--format", "json"]).await;
    assert_eq!(refused.code, 2);
    assert_eq!(refused.stdout, "");
    let wrong = cli
        .run_with(
            &["--password-stdin", "export", "--format", "json"],
            Run {
                stdin: "wrong\n".into(),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(wrong.code, 5);
    assert_eq!(wrong.stdout, "");

    let json: Value = cli
        .run_password(&["export", "--format", "json"])
        .await
        .ok()
        .json();
    assert_eq!(json["format"], "octapass-export");
    assert_eq!(json["vaults"][0]["name"], "Personal");
    assert_eq!(json["items"][0]["details"]["password"], "hunter2");

    let csv = cli.run_password(&["export", "--format", "csv"]).await.ok();
    assert!(
        csv.stdout
            .starts_with("vault,type,title,url,username,password")
    );
    assert!(
        csv.stdout
            .contains("Personal,login,GitHub,https://example.com,octocat,hunter2")
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("backup.json");
    let written = cli
        .run_password(&[
            "export",
            "--format",
            "json",
            "--output",
            out.to_str().unwrap(),
        ])
        .await
        .ok();
    assert_eq!(written.stdout, "");
    assert!(written.stderr.contains("Exported 1 item to"));
    assert!(std::fs::read_to_string(&out).unwrap().contains("hunter2"));
    // Each export went in the security log, naming the CLI.
    let log = other.vault.security_log().await.unwrap();
    let exports: Vec<_> = log
        .iter()
        .filter(|event| event.event_type == octapass_api::SecurityEventType::VaultExported)
        .collect();
    assert_eq!(exports.len(), 3, "{log:?}");
    assert!(exports.iter().all(|event| {
        event
            .device_name
            .as_deref()
            .unwrap()
            .starts_with("Octa Pass CLI")
    }));
    assert_eq!(
        exports[1].export_format,
        Some(octapass_api::ExportFormat::Csv)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

/// Another account, on another server, with the CLI signed in and unlocked.
async fn fresh_account() -> (Server, OtherDevice, Cli) {
    setup().await
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_export_moves_everything_to_another_account() {
    let (_server, other, cli) = setup().await;
    let github = other.save_login("GitHub", "octocat", "hunter2").await;
    other
        .vault
        .add_attachment(
            &github.id,
            "codes.txt",
            "text/plain",
            b"backup codes".to_vec(),
        )
        .await
        .unwrap();
    other
        .save(
            json!({ "schemaVersion": 1, "type": "secureNote", "title": "واي فاي" }),
            json!({ "schemaVersion": 1, "notes": "SSID: home" }),
        )
        .await;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("backup.octapass");
    let out_path = out.to_str().unwrap();
    let with_passwords = |stdout_is_terminal| Run {
        stdin: format!("{PASSWORD}\nexport password 1\n"),
        stdout_is_terminal,
        ..Run::default()
    };

    // Binary into a terminal, or CSV encrypted, is refused before anything is asked.
    let to_terminal = cli
        .run_with(
            &["--password-stdin", "export", "--encrypted"],
            with_passwords(true),
        )
        .await;
    assert_eq!(to_terminal.code, 2);
    let csv = cli
        .run_with(
            &[
                "--password-stdin",
                "export",
                "--format",
                "csv",
                "--encrypted",
            ],
            with_passwords(false),
        )
        .await;
    assert_eq!(csv.code, 2);

    let written = cli
        .run_with(
            &[
                "--password-stdin",
                "export",
                "--encrypted",
                "--output",
                out_path,
            ],
            with_passwords(false),
        )
        .await
        .ok();
    assert!(
        written
            .stderr
            .contains("Exported 2 items and 1 attached file to"),
        "{written:?}"
    );
    let file = std::fs::read(&out).unwrap();
    assert_eq!(&file[..4], b"OPEX");
    assert!(!file.windows(7).any(|w| w == b"hunter2"));

    // Into another account: the wrong password is refused, the right one brings everything back.
    let (_server2, other2, cli2) = fresh_account().await;
    let wrong = cli2
        .run_with(
            &["--password-stdin", "import", "octapass", out_path],
            Run {
                stdin: "nope\n".into(),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(wrong.code, 5, "{wrong:?}");
    let import = cli2
        .run_with(
            &["--password-stdin", "--json", "import", "octapass", out_path],
            Run {
                stdin: "export password 1\n".into(),
                ..Run::default()
            },
        )
        .await
        .ok()
        .json();
    assert_eq!(import["items"], 2);
    assert_eq!(import["files"], 1);
    other2.vault.sync().await.unwrap();
    let items = other2.vault.live_items().unwrap();
    let restored = items.iter().find(|item| item.title() == "GitHub").unwrap();
    assert_eq!(restored.detail("password"), Some("hunter2"));
    assert_ne!(restored.id, github.id, "a new item, with new keys");
    let files = restored.details["attachments"].as_array().unwrap();
    assert_eq!(files[0]["name"], "codes.txt");
    let id = files[0]["id"].as_str().unwrap();
    assert_eq!(
        other2.vault.get_attachment(&restored.id, id).await.unwrap(),
        b"backup codes"
    );
    assert!(items.iter().any(|item| item.title() == "واي فاي"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cxf_export_imports_into_another_account() {
    let (_server, other, cli) = setup().await;
    other.save_login("GitHub", "octocat", "hunter2").await;
    let exported = cli.run_password(&["export", "--format", "cxf"]).await.ok();
    let header: Value = serde_json::from_str(&exported.stdout).unwrap();
    assert_eq!(header["version"]["major"], 1);
    assert_eq!(header["exporterDisplayName"], "Octa Pass");
    assert_eq!(header["exporterRpId"], "127.0.0.1");
    assert_eq!(header["accounts"][0]["email"], EMAIL);
    let credential = &header["accounts"][0]["items"][0]["credentials"][0];
    assert_eq!(credential["type"], "basic-auth");
    assert_eq!(credential["password"]["value"], "hunter2");

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("export.cxf.json");
    std::fs::write(&file, &exported.stdout).unwrap();
    let (_server2, other2, cli2) = fresh_account().await;
    let import = cli2
        .run(&["--json", "import", "cxf", file.to_str().unwrap()])
        .await
        .ok()
        .json();
    assert_eq!(import["items"], 1);
    other2.vault.sync().await.unwrap();
    let items = other2.vault.live_items().unwrap();
    assert_eq!(items[0].detail("password"), Some("hunter2"));
    assert_eq!(items[0].overview["urls"][0], "https://example.com");
}
