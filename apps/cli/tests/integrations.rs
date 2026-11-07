//! The formats other tools read (AWS, kubectl, Docker), live OAuth2 tokens against a fake token
//! endpoint, and Connect from the CLI: every secret handed out reaches the security log, sealed.

use crate::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Form, Json, Router};
use common::{Cli, OtherDevice, Run, Server, server};
use serde_json::{Value, json};
use std::collections::HashMap;

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let device = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&device.secret_key).await.ok();
    (server, device, cli)
}

fn stdin(text: &str) -> Run {
    Run {
        stdin: text.into(),
        ..Run::default()
    }
}

#[tokio::test]
async fn aws_credential_process_prints_its_format() {
    let (_server, device, cli) = setup().await;
    device
        .save(
            json!({ "schemaVersion": 1, "type": "login", "title": "AWS prod" }),
            json!({
                "schemaVersion": 1,
                "customFields": [
                    { "label": "accessKeyId", "value": "AKIAEXAMPLE", "hidden": false },
                    { "label": "secretAccessKey", "value": "shh", "hidden": true },
                ],
            }),
        )
        .await;
    let output = cli
        .run(&["aws", "credential-process", "AWS prod"])
        .await
        .ok();
    assert_eq!(
        output.json(),
        json!({ "Version": 1, "AccessKeyId": "AKIAEXAMPLE", "SecretAccessKey": "shh" })
    );

    device.save_login("Plain", "AKIALOGIN", "pw").await;
    let output = cli.run(&["aws", "credential-process", "Plain"]).await.ok();
    assert_eq!(output.json()["AccessKeyId"], "AKIALOGIN");
}

#[tokio::test]
async fn kube_credential_answers_in_the_version_kubectl_speaks() {
    let (_server, device, cli) = setup().await;
    device
        .save(
            json!({ "schemaVersion": 1, "type": "login", "title": "Cluster" }),
            json!({ "schemaVersion": 1, "customFields": [
                { "label": "token", "value": "kube-token", "hidden": true },
            ]}),
        )
        .await;
    let output = cli.run(&["kube", "credential", "Cluster"]).await.ok();
    let value = output.json();
    assert_eq!(value["apiVersion"], "client.authentication.k8s.io/v1");
    assert_eq!(value["kind"], "ExecCredential");
    assert_eq!(value["status"]["token"], "kube-token");

    let run = Run {
        env: vec![(
            "KUBERNETES_EXEC_INFO".into(),
            r#"{"apiVersion":"client.authentication.k8s.io/v1beta1"}"#.into(),
        )],
        ..Run::default()
    };
    let output = cli
        .run_with(&["kube", "credential", "Cluster"], run)
        .await
        .ok();
    assert_eq!(
        output.json()["apiVersion"],
        "client.authentication.k8s.io/v1beta1"
    );
}

#[tokio::test]
async fn docker_stores_gets_lists_and_erases() {
    let (_server, _device, cli) = setup().await;
    let host = "https://registry.example";
    let store = json!({ "ServerURL": host, "Username": "ada", "Secret": "tok" }).to_string();
    cli.run_with(&["docker-credential", "store"], stdin(&store))
        .await
        .ok();

    let got = cli
        .run_with(&["docker-credential", "get"], stdin(host))
        .await
        .ok();
    assert_eq!(
        got.json(),
        json!({ "ServerURL": host, "Username": "ada", "Secret": "tok" })
    );

    // Storing again replaces, it doesn't add.
    let store = json!({ "ServerURL": host, "Username": "ada", "Secret": "new" }).to_string();
    cli.run_with(&["docker-credential", "store"], stdin(&store))
        .await
        .ok();
    let listed = cli.run(&["docker-credential", "list"]).await.ok();
    assert_eq!(listed.json(), json!({ host: "ada" }));
    let got = cli
        .run_with(&["docker-credential", "get"], stdin(host))
        .await
        .ok();
    assert_eq!(got.json()["Secret"], "new");

    cli.run_with(&["docker-credential", "erase"], stdin(host))
        .await
        .ok();
    let missing = cli
        .run_with(&["docker-credential", "get"], stdin(host))
        .await;
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.stdout.trim(),
        "credentials not found in native keychain"
    );
}

#[derive(Clone)]
struct TokenServer {
    calls: Arc<AtomicUsize>,
    rotate: bool,
}

async fn token(
    State(server): State<TokenServer>,
    Form(form): Form<HashMap<String, String>>,
) -> Json<Value> {
    let call = server.calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(form["client_id"], "abc");
    let mut body = json!({
        "access_token": format!("live-{call}"),
        "token_type": "Bearer",
        // Shorter than the session's idle timeout, so moving the clock past it doesn't lock.
        "expires_in": 600,
    });
    if server.rotate {
        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], format!("refresh-{call}"));
        body["refresh_token"] = json!(format!("refresh-{}", call + 1));
    } else {
        assert_eq!(form["grant_type"], "client_credentials");
        assert_eq!(form["client_secret"], "shh");
    }
    Json(body)
}

async fn token_server(rotate: bool) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/token", post(token))
        .with_state(TokenServer {
            calls: calls.clone(),
            rotate,
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}/token"), calls)
}

#[tokio::test]
async fn client_credentials_tokens_are_fetched_cached_and_refetched() {
    let (_server, _device, cli) = setup().await;
    let (url, calls) = token_server(false).await;
    let run = Run {
        env: vec![("OCTAPASS_OAUTH_CLIENT_SECRET".into(), "shh".into())],
        ..Run::default()
    };
    cli.run_with(
        &[
            "oauth",
            "create",
            "Billing",
            "--flow",
            "client-credentials",
            "--token-url",
            &url,
            "--client-id",
            "abc",
        ],
        run,
    )
    .await
    .ok();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "creating proves it works");

    let read = cli
        .run(&["read", "-n", "octapass://Personal/Billing/accessToken"])
        .await
        .ok();
    assert_eq!(read.stdout, "live-0", "the cached one");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let details = cli.run(&["--json", "get", "Billing"]).await.ok().json();
    let expires = details["details"]["oauth2"]["expiresAt"].as_u64().unwrap();
    // Near its end it's replaced, and that's saved for the next command.
    cli.time.store(expires - 30, Ordering::SeqCst);
    let token = cli.run(&["oauth", "token", "-n", "Billing"]).await.ok();
    assert_eq!(token.stdout, "live-1");
    let token = cli.run(&["oauth", "token", "-n", "Billing"]).await.ok();
    assert_eq!(token.stdout, "live-1");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_rotated_refresh_token_is_saved_before_the_token_is_used() {
    let (_server, _device, cli) = setup().await;
    let (url, calls) = token_server(true).await;
    let run = Run {
        env: vec![("OCTAPASS_OAUTH_REFRESH_TOKEN".into(), "refresh-0".into())],
        ..Run::default()
    };
    cli.run_with(
        &[
            "oauth",
            "create",
            "Rotating",
            "--flow",
            "refresh-token",
            "--token-url",
            &url,
            "--client-id",
            "abc",
        ],
        run,
    )
    .await
    .ok();
    let details = cli.run(&["--json", "get", "Rotating"]).await.ok().json();
    assert_eq!(details["details"]["oauth2"]["refreshToken"], "refresh-1");
    let expires = details["details"]["oauth2"]["expiresAt"].as_u64().unwrap();
    cli.time.store(expires, Ordering::SeqCst);
    let token = cli.run(&["oauth", "token", "-n", "Rotating"]).await.ok();
    assert_eq!(token.stdout, "live-1");
    let details = cli.run(&["--json", "get", "Rotating"]).await.ok().json();
    assert_eq!(details["details"]["oauth2"]["refreshToken"], "refresh-2");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_token_url_that_isnt_https_is_refused_and_no_secret_is_sent() {
    let (_server, _device, cli) = setup().await;
    let run = Run {
        env: vec![("OCTAPASS_OAUTH_CLIENT_SECRET".into(), "shh".into())],
        ..Run::default()
    };
    let refused = cli
        .run_with(
            &[
                "oauth",
                "create",
                "Bad",
                "--flow",
                "client-credentials",
                "--token-url",
                "http://auth.example/token",
                "--client-id",
                "abc",
            ],
            run,
        )
        .await;
    assert_ne!(refused.code, 0);
    assert!(refused.stderr.contains("https"), "{refused:#?}");
}

/// Runs `octapass connect serve` on a thread and answers through a real socket.
fn serve(cli: &Cli, folder: &std::path::Path, answers: Vec<String>) {
    let args = ["connect", "serve"];
    let run = Run {
        interactive: true,
        answers,
        env: vec![(
            "OCTAPASS_CONNECT_DIR".into(),
            folder.to_str().unwrap().to_owned(),
        )],
        ..Run::default()
    };
    cli.spawn_with(&args, run);
}

fn connect_env(folder: &std::path::Path, token: Option<&str>) -> Run {
    let mut env = vec![(
        "OCTAPASS_CONNECT_DIR".to_owned(),
        folder.to_str().unwrap().to_owned(),
    )];
    if let Some(token) = token {
        env.push(("OCTAPASS_CONNECT_TOKEN".into(), token.to_owned()));
    }
    Run {
        env,
        ..Run::default()
    }
}

async fn until_listening(folder: &std::path::Path) {
    for _ in 0..200 {
        if folder.join("connect.sock").exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("Connect didn't start");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_hands_out_a_secret_and_the_log_shows_it_sealed() {
    let (_server, device, cli) = setup().await;
    device.save_login("GitHub", "octocat", "hunter2").await;
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    serve(&cli, dir.path(), vec!["y".into()]);
    until_listening(dir.path()).await;

    let paired = cli
        .run_with(
            &["connect", "pair", "--name", "Test tool"],
            connect_env(dir.path(), None),
        )
        .await
        .ok();
    let token = paired.stdout.trim().to_owned();
    assert!(token.starts_with("opc1_"));

    let read = cli
        .run_with(
            &["connect", "read", "octapass://Personal/GitHub/password"],
            connect_env(dir.path(), Some(&token)),
        )
        .await
        .ok();
    assert_eq!(read.stdout.trim(), "hunter2");

    // What the server stored is ciphertext, and only the account opens it.
    let events = device.vault.security_log().await.unwrap();
    let entry = events
        .iter()
        .find(|event| event.event_type.as_str() == "connect-secret-read")
        .expect("in the log");
    let sealed = entry.sealed_detail.clone().unwrap();
    assert!(!sealed.contains("GitHub") && !sealed.contains("Test tool"));
    let opened = device.vault.security_log_opened().await.unwrap();
    let opened = opened
        .iter()
        .find(|event| event.event_type.as_str() == "connect-secret-read")
        .unwrap();
    let detail: Value = serde_json::from_str(opened.sealed_detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["clientName"], "Test tool");
    assert_eq!(detail["reference"], "octapass://Personal/GitHub/password");

    // Nothing's left waiting once the server has it.
    let queued = std::fs::read_dir(dir.path())
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_string_lossy().ends_with(".queue")
        })
        .count();
    assert_eq!(queued, 0);

    // A missing item is that reference's answer, and isn't logged as handed out.
    let missing = cli
        .run_with(
            &["connect", "read", "octapass://Personal/Nope/password"],
            connect_env(dir.path(), Some(&token)),
        )
        .await;
    assert_ne!(missing.code, 0);

    // Locking stops it at once.
    cli.run(&["lock"]).await.ok();
    let locked = cli
        .run_with(
            &["connect", "read", "octapass://Personal/GitHub/password"],
            connect_env(dir.path(), Some(&token)),
        )
        .await;
    assert_ne!(locked.code, 0);
    assert!(!locked.stdout.contains("hunter2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_entries_wait_and_nothing_is_handed_out_unrecorded() {
    let (mut server, device, cli) = setup().await;
    device.save_login("GitHub", "octocat", "hunter2").await;
    cli.run(&["list"]).await.ok();
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    serve(&cli, dir.path(), vec!["y".into()]);
    until_listening(dir.path()).await;
    let paired = cli
        .run_with(
            &["connect", "pair", "--name", "Tool"],
            connect_env(dir.path(), None),
        )
        .await
        .ok();
    let token = paired.stdout.trim().to_owned();

    server.stop();
    let read = cli
        .run_with(
            &["connect", "read", "octapass://Personal/GitHub/password"],
            connect_env(dir.path(), Some(&token)),
        )
        .await;
    assert_eq!(read.code, 0, "{read:#?}");
    assert_eq!(read.stdout.trim(), "hunter2");
    // The entry is on disk, waiting, because the server couldn't take it.
    let queues: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "queue"))
        .collect();
    assert_eq!(queues.len(), 1, "{read:#?}");
    let queued = std::fs::read_to_string(&queues[0]).unwrap();
    assert_eq!(queued.lines().count(), 1);
    assert!(!queued.contains("GitHub"), "sealed on disk too");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_gives_no_token() {
    let (_server, _device, cli) = setup().await;
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    serve(&cli, dir.path(), vec!["n".into()]);
    until_listening(dir.path()).await;
    let refused = cli
        .run_with(
            &["connect", "pair", "--name", "Nope"],
            connect_env(dir.path(), None),
        )
        .await;
    assert_ne!(refused.code, 0);
    assert!(refused.stdout.is_empty());
    let clients = cli
        .run_with(
            &["--json", "connect", "clients"],
            connect_env(dir.path(), None),
        )
        .await
        .ok();
    assert_eq!(clients.json(), json!([]));
}
