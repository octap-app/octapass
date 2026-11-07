//! Service accounts end to end: a person makes one with the CLI, and a machine with only the token
//! reads, runs and fills templates against a real server, with nothing signed in.

use crate::common;

use common::{Cli, OtherDevice, Run, Server, server};
use serde_json::json;

const VAULT: &str = "CI";

struct Setup {
    server: Server,
    device: OtherDevice,
    person: Cli,
    machine: Cli,
    vault_id: String,
    token: String,
}

async fn setup() -> Setup {
    let server = server().await;
    let device = OtherDevice::sign_up(&server).await;
    let vault = device.vault.create_vault(VAULT).await.unwrap();
    let person = Cli::new(&server);
    person.login(&device.secret_key).await.ok();
    device
        .save_in(
            &vault.id,
            json!({ "schemaVersion": 1, "type": "login", "title": "Deploy key" }),
            json!({ "schemaVersion": 1, "username": "ci", "password": "s3cret-value" }),
        )
        .await;
    device.save_login("Personal only", "me", "not-for-ci").await;
    let created = person
        .run(&[
            "--json",
            "service-account",
            "create",
            "--vault",
            VAULT,
            "--name",
            "deploy",
        ])
        .await
        .ok();
    let token = created.json()["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("opsa1_"));
    Setup {
        machine: Cli::with_keyring(&server, None),
        vault_id: vault.id,
        server,
        device,
        person,
        token,
    }
}

impl Setup {
    fn env(&self) -> Run {
        Run {
            env: vec![("OCTAPASS_SERVICE_ACCOUNT_TOKEN".into(), self.token.clone())],
            ..Run::default()
        }
    }
}

#[tokio::test]
async fn a_machine_reads_with_only_the_token() {
    let setup = setup().await;
    let read = setup
        .machine
        .run_with(
            &["read", "-n", "octapass://CI/Deploy key/password"],
            setup.env(),
        )
        .await
        .ok();
    assert_eq!(read.stdout, "s3cret-value");

    let listed = setup
        .machine
        .run_with(&["--json", "list"], setup.env())
        .await
        .ok();
    let text = listed.stdout;
    assert!(text.contains("Deploy key"));
    assert!(
        !text.contains("Personal only"),
        "only its one vault: {text}"
    );

    let log = setup.device.vault.security_log().await.unwrap();
    let kinds: Vec<&str> = log.iter().map(|event| event.event_type.as_str()).collect();
    assert!(kinds.contains(&"service-account-read"), "{kinds:?}");
    assert!(kinds.contains(&"service-account-created"), "{kinds:?}");
}

#[tokio::test]
async fn run_and_inject_resolve_references() {
    let setup = setup().await;
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("seen");
    let mut run = setup.env();
    run.env
        .push(("DEPLOY".into(), "octapass://CI/Deploy key/password".into()));
    run.env
        .push(("SEEN".into(), file.to_str().unwrap().to_owned()));
    let output = setup
        .machine
        .run_with(
            &["run", "--", "sh", "-c", "printf %s \"$DEPLOY\" > \"$SEEN\""],
            run,
        )
        .await;
    assert_eq!(output.code, 0, "{output:#?}");
    assert_eq!(std::fs::read_to_string(file).unwrap(), "s3cret-value");

    let mut run = setup.env();
    run.stdin = "key={{ octapass://CI/Deploy key/password }}\n".into();
    let output = setup.machine.run_with(&["inject"], run).await.ok();
    assert_eq!(output.stdout, "key=s3cret-value\n");
}

#[tokio::test]
async fn commands_that_change_things_are_refused() {
    let setup = setup().await;
    for args in [
        vec!["logout"],
        vec!["export"],
        vec!["env", "set", "Shop", "A=1"],
        vec!["connect", "serve"],
        vec!["service-account", "list", "--vault", VAULT],
    ] {
        let output = setup.machine.run_with(&args, setup.env()).await;
        assert_ne!(output.code, 0, "{args:?}");
        assert!(
            output.stderr.contains("only commands that read"),
            "{output:#?}"
        );
    }
}

#[tokio::test]
async fn revoking_stops_it_and_rotates_the_key() {
    let setup = setup().await;
    let listed = setup
        .person
        .run(&["--json", "service-account", "list", "--vault", VAULT])
        .await
        .ok();
    let id = listed.json()[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(listed.json()[0]["name"], "deploy");
    assert_eq!(listed.json()[0]["role"], "read");
    assert_eq!(listed.json()[0]["needsNewToken"], false);

    let before = setup.vault_key_id().await;
    setup
        .person
        .run(&["service-account", "revoke", &id, "--vault", VAULT])
        .await
        .ok();
    assert_ne!(setup.vault_key_id().await, before, "the key rotated");

    let refused = setup
        .machine
        .run_with(&["read", "octapass://CI/Deploy key/password"], setup.env())
        .await;
    assert_ne!(refused.code, 0);
    assert!(!refused.stdout.contains("s3cret-value"));
    assert!(refused.stderr.contains("refused"), "{refused:#?}");

    // The person's own access went on working through the rotation.
    let read = setup
        .person
        .run(&["read", "-n", "octapass://CI/Deploy key/password"])
        .await
        .ok();
    assert_eq!(read.stdout, "s3cret-value");
}

#[tokio::test]
async fn a_rotation_by_the_creator_keeps_a_token_working() {
    let setup = setup().await;
    let second = setup
        .person
        .run(&[
            "--json",
            "service-account",
            "create",
            "--vault",
            VAULT,
            "--name",
            "other",
        ])
        .await
        .ok();
    let id = second.json()["id"].as_str().unwrap().to_owned();
    setup
        .person
        .run(&["service-account", "revoke", &id, "--vault", VAULT])
        .await
        .ok();
    let read = setup
        .machine
        .run_with(
            &["read", "-n", "octapass://CI/Deploy key/password"],
            setup.env(),
        )
        .await
        .ok();
    assert_eq!(read.stdout, "s3cret-value");
}

#[tokio::test]
async fn a_personal_vault_is_refused_and_a_damaged_token_is_plain_about_it() {
    let setup = setup().await;
    let refused = setup
        .person
        .run(&[
            "service-account",
            "create",
            "--vault",
            "Personal",
            "--name",
            "x",
        ])
        .await;
    assert_ne!(refused.code, 0);
    assert!(
        refused.stderr.contains("shared vaults only"),
        "{refused:#?}"
    );

    let mut run = setup.env();
    run.env[0].1.truncate(40);
    let damaged = setup
        .machine
        .run_with(&["read", "octapass://CI/Deploy key/password"], run)
        .await;
    assert_ne!(damaged.code, 0);
    assert!(damaged.stderr.contains("isn't a whole"), "{damaged:#?}");
}

impl Setup {
    async fn vault_key_id(&self) -> String {
        let _ = &self.server;
        self.device.vault.sync().await.unwrap();
        self.device
            .vault
            .with_keys(|session, _| session.vault_key_id(&self.vault_id).unwrap())
            .unwrap()
    }
}
