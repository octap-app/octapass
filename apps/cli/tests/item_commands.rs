//! `create`, `edit`, `delete`, `restore` and `signup` against the real server; another device sees
//! the changes.

use crate::common;

use common::*;
use serde_json::{Value, json};

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

async fn on_other_device(other: &OtherDevice, title: &str) -> octapass_desktop_vault::model::Item {
    other.vault.sync().await.unwrap();
    other
        .vault
        .live_items()
        .unwrap()
        .into_iter()
        .find(|item| item.title() == title)
        .unwrap_or_else(|| panic!("no {title}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_made_here_reaches_other_devices() {
    let (_server, other, cli) = setup().await;
    let made = cli
        .run(&[
            "create",
            "login",
            "--title",
            "GitHub",
            "--url",
            "https://github.com",
            "--tag",
            "dev",
            "--favorite",
            "username=ada",
            "password=hunter2",
            "API key=ghp_123",
        ])
        .await
        .ok();
    assert_eq!(made.stdout.trim().len(), 36, "the id: {made:?}");
    assert!(!made.stdout.contains("hunter2") && !made.stderr.contains("hunter2"));

    let item = on_other_device(&other, "GitHub").await;
    assert_eq!(item.overview["subtitle"], "ada");
    assert_eq!(item.overview["urls"], json!(["https://github.com"]));
    assert_eq!(item.overview["tags"], json!(["dev"]));
    assert_eq!(item.overview["favorite"], true);
    assert_eq!(item.details["password"], "hunter2");
    assert_eq!(
        item.details["customFields"],
        json!([{ "label": "API key", "value": "ghp_123", "hidden": true }])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_values_generated_passwords_and_stdin() {
    let (_server, other, cli) = setup().await;
    let typed = cli
        .run_with(
            &["create", "login", "--title", "Typed", "password"],
            Run {
                interactive: true,
                answers: vec!["typed-secret".into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(typed.asked, ["password: "]);
    assert_eq!(
        on_other_device(&other, "Typed").await.details["password"],
        "typed-secret"
    );

    let refused = cli
        .run(&["create", "login", "--title", "No terminal", "password"])
        .await;
    assert_eq!(refused.code, 2, "{refused:?}");

    cli.run(&[
        "create",
        "login",
        "--title",
        "Made",
        "--generate",
        "--length",
        "32",
    ])
    .await
    .ok();
    let password = on_other_device(&other, "Made").await.details["password"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(password.len(), 32);

    cli.run_with(
        &["create", "note", "--title", "Long", "--stdin", "notes"],
        Run {
            stdin: "line one\nline two\n".into(),
            ..Run::default()
        },
    )
    .await
    .ok();
    assert_eq!(
        on_other_device(&other, "Long").await.details["notes"],
        "line one\nline two"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cards_identities_and_wifi() {
    let (_server, other, cli) = setup().await;
    cli.run(&[
        "create",
        "card",
        "--title",
        "Visa",
        "number=4111 1111 1111 1234",
        "brand=Visa",
        "cvv=123",
    ])
    .await
    .ok();
    assert_eq!(
        on_other_device(&other, "Visa").await.overview["subtitle"],
        "Visa ending 1234"
    );
    cli.run(&[
        "create",
        "identity",
        "--title",
        "Me",
        "firstname=Ada",
        "lastName=Lovelace",
        "address.city=London",
    ])
    .await
    .ok();
    let me = on_other_device(&other, "Me").await;
    assert_eq!(me.details["address"]["city"], "London");
    assert_eq!(me.overview["subtitle"], "Ada Lovelace");
    cli.run(&["create", "wifi", "ssid=Home-5G", "password=wifi-pass"])
        .await
        .ok();
    let wifi = on_other_device(&other, "Home-5G").await;
    assert_eq!(wifi.details["security"], "wpa2");

    let bad = cli
        .run(&["create", "card", "--title", "x", "colour=red"])
        .await;
    assert_eq!(bad.code, 2);
    assert!(bad.stderr.contains("colour"), "{bad:?}");
    let own = cli.run(&["create", "sshKey", "--title", "x"]).await;
    assert!(own.stderr.contains("octapass ssh generate"), "{own:?}");
    let untitled = cli.run(&["create", "login", "username=a"]).await;
    assert_eq!(untitled.code, 2);
    let bad_code = cli
        .run(&["create", "login", "--title", "x", "totp=not base32!"])
        .await;
    assert_eq!(bad_code.code, 2, "{bad_code:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn edits_change_only_what_is_named_and_keep_unknown_fields() {
    let (_server, other, cli) = setup().await;
    let future = json!({ "kept": true });
    other
        .save(
            json!({ "schemaVersion": 1, "type": "login", "title": "Site", "subtitle": "ada", "tags": ["old"], "urls": ["https://a.example"], "futureOverview": future }),
            json!({ "schemaVersion": 1, "username": "ada", "password": "first", "futureDetail": future, "customFields": [{ "label": "PIN", "value": "1", "hidden": true }] }),
        )
        .await;
    cli.run(&["list"]).await.ok();
    cli.run(&[
        "edit",
        "Site",
        "--title",
        "Site 2",
        "password=second",
        "username=grace",
        "--add-tag",
        "new",
        "--remove-tag",
        "old",
        "--add-url",
        "https://b.example",
        "--remove-url",
        "https://a.example",
        "--unset",
        "PIN",
        "--favorite",
    ])
    .await
    .ok();
    let item = on_other_device(&other, "Site 2").await;
    assert_eq!(item.overview["subtitle"], "grace");
    assert_eq!(item.overview["tags"], json!(["new"]));
    assert_eq!(item.overview["urls"], json!(["https://b.example"]));
    assert_eq!(item.overview["futureOverview"], future);
    assert_eq!(item.details["futureDetail"], future);
    assert_eq!(item.details["password"], "second");
    assert_eq!(item.details.get("customFields"), None);
    // The vault keeps the old password, as in every client.
    assert_eq!(item.details["passwordHistory"][0]["password"], "first");

    let nothing = cli.run(&["edit", "Site 2"]).await.ok();
    assert!(nothing.stderr.contains("Nothing to change"), "{nothing:?}");
    let missing = cli.run(&["edit", "Nope", "password=x"]).await;
    assert_eq!(missing.code, 6);
    let unknown = cli.run(&["edit", "Site 2", "--unset", "Nope"]).await;
    assert_eq!(unknown.code, 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_that_lost_a_race_keeps_both_versions() {
    let (_server, other, cli) = setup().await;
    let item = other.save_login("Raced", "ada", "first").await;
    cli.run(&["list"]).await.ok();
    // Saved elsewhere after this device last synced: the server has a newer revision, which the
    // CLI's sync picks up first, so the edit applies on top rather than overwriting it.
    let draft: octapass_desktop_vault::model::ItemDraft = serde_json::from_value(json!({
        "id": item.id, "vaultId": item.vault_id, "revision": item.revision,
        "overview": item.overview, "details": { "schemaVersion": 1, "username": "ada", "password": "other" },
    }))
    .unwrap();
    other.vault.save_item(draft).await.unwrap();
    cli.run(&["edit", "Raced", "username=grace"]).await.ok();
    let item = on_other_device(&other, "Raced").await;
    assert_eq!(item.details["password"], "other");
    assert_eq!(item.details["username"], "grace");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_goes_to_the_trash_and_restore_brings_it_back() {
    let (_server, other, cli) = setup().await;
    other.save_login("Old", "ada", "pw").await;
    cli.run(&["list"]).await.ok();
    cli.run(&["delete", "Old"]).await.ok();
    assert_eq!(cli.run(&["get", "Old"]).await.code, 6);
    other.vault.sync().await.unwrap();
    assert!(other.vault.live_items().unwrap().is_empty());

    assert_eq!(cli.run(&["restore", "Missing"]).await.code, 6);
    cli.run(&["restore", "Old"]).await.ok();
    assert_eq!(
        cli.run(&["get", "Old", "--field", "username"])
            .await
            .ok()
            .stdout,
        "ada\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn json_output_for_scripts() {
    let (_server, _other, cli) = setup().await;
    let made = cli
        .run(&["create", "login", "--title", "S", "--json", "password=abcd"])
        .await
        .ok()
        .json();
    assert_eq!(made["title"], "S");
    assert_eq!(made["type"], "login");
    assert_eq!(made.get("details"), None::<&Value>);
}

// ---------- Sign-up ----------

const NEW_PASSWORD: &str = "wide lantern orbit 92 quartz";

#[tokio::test(flavor = "multi_thread")]
async fn signing_up_prints_the_kit_and_leaves_the_vault_unlocked() {
    let server = server().await;
    let cli = Cli::new(&server);
    let signup = cli
        .run_with(
            &[
                "signup",
                "--server",
                &server.url,
                "--email",
                "new@example.com",
                "--password-stdin",
            ],
            Run {
                stdin: format!("{NEW_PASSWORD}\n"),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(signup.stdout.contains("Secret Key: OP1-"), "{signup:?}");
    assert!(signup.stdout.contains("Recovery code: "));
    cli.run(&["create", "login", "--title", "First", "password=abcd"])
        .await
        .ok();

    // The kit opens the account on another device.
    let key = signup
        .stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Secret Key: "))
        .unwrap()
        .to_owned();
    let second = Cli::new(&server);
    let login = second
        .run_with(
            &[
                "login",
                "--server",
                &server.url,
                "--email",
                "new@example.com",
                "--password-stdin",
            ],
            Run {
                stdin: format!("{NEW_PASSWORD}\n"),
                env: vec![("OCTAPASS_SECRET_KEY".into(), key)],
                ..Run::default()
            },
        )
        .await;
    login.ok();
    assert!(second.run(&["list"]).await.ok().stdout.contains("First"));
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_up_asks_in_a_terminal_and_retries_a_wrong_code() {
    let server = server().await;
    let cli = Cli::new(&server);
    let signup = cli
        .run_with(
            &["signup", "--server", &server.url, "--code", "000000"],
            Run {
                interactive: true,
                answers: vec![
                    "typed@example.com".into(),
                    NEW_PASSWORD.into(),
                    NEW_PASSWORD.into(),
                ],
                ..Run::default()
            },
        )
        .await;
    // Dev mode's code isn't 000000, and there are no answers left for a second try.
    assert_ne!(signup.code, 0);
    assert!(
        signup
            .asked
            .iter()
            .any(|prompt| prompt.contains("Code from the email")),
        "{signup:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_weak_password_or_a_signed_in_device_is_refused() {
    let server = server().await;
    let cli = Cli::new(&server);
    let weak = cli
        .run_with(
            &[
                "signup",
                "--server",
                &server.url,
                "--email",
                "a@example.com",
                "--password-stdin",
            ],
            Run {
                stdin: "password1\n".into(),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(weak.code, 2);
    assert!(weak.stderr.contains("too weak"), "{weak:?}");

    let other = OtherDevice::sign_up(&server).await;
    cli.login(&other.secret_key).await.ok();
    let again = cli
        .run_with(
            &[
                "signup",
                "--server",
                &server.url,
                "--email",
                "b@example.com",
                "--password-stdin",
            ],
            Run {
                stdin: format!("{NEW_PASSWORD}\n"),
                ..Run::default()
            },
        )
        .await;
    assert_eq!(again.code, 2);
    assert!(again.stderr.contains("logout"), "{again:?}");
}

/// Shared vaults show their real names (plan 05 asked for this; the vault already reads them).
#[tokio::test(flavor = "multi_thread")]
async fn shared_vaults_go_by_their_own_names() {
    let (_server, other, cli) = setup().await;
    let team = other.vault.create_vault("Team Ops").await.unwrap();
    let draft: octapass_desktop_vault::model::ItemDraft = serde_json::from_value(json!({
        "vaultId": team.id,
        "overview": { "schemaVersion": 1, "type": "login", "title": "Deploy" },
        "details": { "schemaVersion": 1, "username": "ci", "password": "team-secret" },
    }))
    .unwrap();
    other.vault.save_item(draft).await.unwrap();
    let list = cli.run(&["list", "--vault", "team ops"]).await.ok();
    assert!(list.stdout.contains("Team Ops"), "{list:?}");
    assert_eq!(
        cli.run(&["read", "octapass://Team Ops/Deploy/password"])
            .await
            .ok()
            .stdout,
        "team-secret\n"
    );
    cli.run(&[
        "create",
        "login",
        "--title",
        "New",
        "--vault",
        "Team Ops",
        "password=abcd",
    ])
    .await
    .ok();
    assert!(
        cli.run(&["list", "--vault", "Team Ops"])
            .await
            .ok()
            .stdout
            .contains("New")
    );
}
