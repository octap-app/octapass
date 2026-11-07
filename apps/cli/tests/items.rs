//! Listing items, reading fields and one-time codes, and `octapass://` references, against items
//! made on another device.

use crate::common;

use common::*;
use octapass_core::tools::totp::totp_code;
use serde_json::json;

const TOTP: &str = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP";

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    other
        .save(
            json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "subtitle": "octocat", "urls": ["https://github.com"], "tags": ["dev"] }),
            json!({
                "schemaVersion": 1, "username": "octocat", "password": "hunter2", "totp": TOTP,
                "customFields": [
                    { "label": "API key", "value": "ghp_123", "hidden": true },
                    { "label": "Org", "value": "octapass", "hidden": false }
                ]
            }),
        )
        .await;
    other
        .save(
            json!({ "schemaVersion": 1, "type": "secureNote", "title": "Wi-Fi" }),
            json!({ "schemaVersion": 1, "notes": "SSID home, key 42" }),
        )
        .await;
    other.save_login("Bank", "ada", "one").await;
    other.save_login("bank", "ada2", "two").await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

#[tokio::test(flavor = "multi_thread")]
async fn list_and_search() {
    let (_server, other, cli) = setup().await;
    let list = cli.run(&["list"]).await.ok();
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert!(lines[0].starts_with("TITLE"), "{lines:?}");
    assert_eq!(lines.len(), 5);
    assert!(lines[1].starts_with("Bank") && lines[3].starts_with("GitHub"));
    assert!(!list.stdout.contains("hunter2"));

    let json = cli
        .run(&["list", "--json", "--search", "GITHUB.COM"])
        .await
        .ok()
        .json();
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["title"], "GitHub");
    assert_eq!(rows[0]["vault"], "Personal");
    assert_eq!(rows[0]["hasTotp"], true);
    assert!(!json.to_string().contains("hunter2"));

    assert_eq!(
        cli.run(&["list", "--vault", "personal", "--search", "wi-fi", "--json"])
            .await
            .ok()
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(cli.run(&["list", "--vault", "Work"]).await.code, 6);
    let none = cli.run(&["list", "--search", "nothing"]).await.ok();
    assert_eq!(
        (none.stdout.as_str(), none.stderr.as_str()),
        ("", "No items.\n")
    );

    // An item saved elsewhere shows up on the next command.
    other.save_login("New one", "ada", "three").await;
    assert!(cli.run(&["list"]).await.ok().stdout.contains("New one"));
}

#[tokio::test(flavor = "multi_thread")]
async fn get_shows_fields_and_hides_secrets_unless_asked() {
    let (_server, _other, cli) = setup().await;
    let shown = cli.run(&["get", "github"]).await.ok();
    for hidden in ["hunter2", "ghp_123", "JBSWY3DPEHPK3PXP"] {
        assert!(!shown.stdout.contains(hidden), "{hidden}: {}", shown.stdout);
    }
    assert!(shown.stdout.contains("Username"));
    assert!(shown.stdout.contains("octocat"));
    assert!(shown.stdout.contains("Org"));
    assert!(shown.stdout.contains("octapass totp GitHub"));

    let field = |args: &'static [&'static str]| {
        let cli = &cli;
        async move { cli.run(args).await }
    };
    assert_eq!(
        field(&["get", "GitHub", "--field", "password"])
            .await
            .ok()
            .stdout,
        "hunter2\n"
    );
    assert_eq!(
        field(&["get", "GitHub", "--field", "API KEY", "-n"])
            .await
            .ok()
            .stdout,
        "ghp_123"
    );
    assert_eq!(
        field(&["get", "GitHub", "--field", "username"])
            .await
            .ok()
            .stdout,
        "octocat\n"
    );
    assert_eq!(
        field(&["get", "Wi-Fi", "--field", "notes"])
            .await
            .ok()
            .stdout,
        "SSID home, key 42\n"
    );
    let json = field(&["get", "GitHub", "--field", "password", "--json"])
        .await
        .ok()
        .json();
    assert_eq!(json, json!({ "field": "password", "value": "hunter2" }));
    let item = field(&["get", "GitHub", "--json"]).await.ok().json();
    assert_eq!(item["details"]["password"], "hunter2");
    assert_eq!(item["vault"], "Personal");

    // A secret printed to a terminal comes with a warning; a username doesn't.
    let tty = Run {
        stdout_is_terminal: true,
        ..Run::default()
    };
    let secret = cli
        .run_with(&["get", "GitHub", "--field", "password"], tty.clone())
        .await
        .ok();
    assert!(secret.stderr.contains("Warning"), "{secret:?}");
    let plain = cli
        .run_with(&["get", "GitHub", "--field", "username"], tty)
        .await
        .ok();
    assert_eq!(plain.stderr, "");

    let missing = cli.run(&["get", "GitHub", "--field", "cvv"]).await;
    assert_eq!(missing.code, 6);
    assert!(missing.stderr.contains("no field called \"cvv\""));
    assert_eq!(cli.run(&["get", "Nope"]).await.code, 6);
    let ambiguous = cli.run(&["get", "bank", "--field", "password"]).await;
    assert_eq!(ambiguous.code, 7);
    assert_eq!(ambiguous.stdout, "");

    // An id picks one of them.
    let rows = cli
        .run(&["list", "--json", "--search", "bank"])
        .await
        .ok()
        .json();
    let id = rows[0]["id"].as_str().unwrap().to_owned();
    let by_id = cli
        .run_with(&["get", &id, "--field", "password"], Run::default())
        .await
        .ok();
    assert!(by_id.stdout == "one\n" || by_id.stdout == "two\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_time_codes() {
    let (_server, _other, cli) = setup().await;
    let code = cli.run(&["totp", "GitHub"]).await.ok().stdout;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The code from a moment before or after, in case the period ticked over.
    let expected: Vec<String> = [now - 5, now, now + 5]
        .iter()
        .map(|at| format!("{}\n", totp_code(TOTP, *at).unwrap().code))
        .collect();
    assert!(expected.contains(&code), "{code}");

    let json = cli.run(&["totp", "GitHub", "--json"]).await.ok().json();
    assert_eq!(json["period"], 30);
    assert_eq!(json["code"].as_str().unwrap().len(), 6);
    let field = cli
        .run(&["get", "GitHub", "--field", "totp"])
        .await
        .ok()
        .stdout;
    assert_eq!(field.trim().len(), 6);

    let none = cli.run(&["totp", "Wi-Fi"]).await;
    assert_eq!(none.code, 6);
    assert!(none.stderr.contains("no one-time code"));
}

#[tokio::test(flavor = "multi_thread")]
async fn read_resolves_references() {
    let (_server, _other, cli) = setup().await;
    let read = |reference: &'static str| {
        let cli = &cli;
        async move { cli.run(&["read", reference]).await }
    };
    assert_eq!(
        read("octapass://Personal/GitHub/password")
            .await
            .ok()
            .stdout,
        "hunter2\n"
    );
    assert_eq!(
        read("octapass://personal/github/api key").await.ok().stdout,
        "ghp_123\n"
    );
    assert_eq!(
        read("octapass://Personal/GitHub/API%20key")
            .await
            .ok()
            .stdout,
        "ghp_123\n"
    );
    assert_eq!(read("octapass://Work/GitHub/password").await.code, 6);
    assert_eq!(read("octapass://Personal/GitHub").await.code, 2);
    assert_eq!(read("octapass://Personal/Bank/password").await.code, 7);
}
