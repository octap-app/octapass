//! What a single-server deployment relies on: the web vault served next to the API, invites
//! from the configuration, sign-up codes in the log instead of email, and backups.

use crate::common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::*;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use octapass_server::{Config, StorageConfig, admin};
use rand_core::OsRng;
use serde_json::json;

fn web_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>Octa Pass</title>",
    )
    .unwrap();
    std::fs::write(dir.path().join("favicon.svg"), "<svg/>").unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/index-abc123.js"), "export {}").unwrap();
    std::fs::write(dir.path().join("assets/core-def456.wasm"), b"\0asm").unwrap();
    dir
}

async fn get(server: &TestServer, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let request = Request::get(path).body(Body::empty()).unwrap();
    let (status, headers, body) = server.send_raw(request).await;
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn serves_the_web_vault_next_to_the_api() {
    let web = web_dir();
    let path = web.path().to_owned();
    let server = TestServer::with_config(|config| {
        config.web_dir = Some(path);
        config.public_url = "https://pass.example.com".into();
    })
    .await;

    let (status, headers, body) = get(&server, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<title>Octa Pass</title>"));
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self' 'wasm-unsafe-eval'"),
        "{csp}"
    );
    assert!(
        csp.contains("connect-src 'self' wss://pass.example.com"),
        "{csp}"
    );
    assert_eq!(headers["cache-control"], "no-cache");
    assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert!(headers.contains_key("strict-transport-security"));

    // The vault's own routes get the page, so a reload works.
    let (status, _, body) = get(&server, "/vault/items/123").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<title>Octa Pass</title>"));

    let (status, headers, _) = get(&server, "/assets/index-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    let (_, headers, _) = get(&server, "/assets/core-def456.wasm").await;
    assert_eq!(headers["content-type"], "application/wasm");

    // A missing file is a 404, not the page.
    let (status, headers, _) = get(&server, "/assets/gone-000.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["cache-control"], "no-cache");

    // The API keeps its JSON errors and its own headers.
    let missing = server
        .call(Method::GET, "/v1/nothing", None, &[], None)
        .await;
    assert!(missing.is_problem("not-found"), "{missing:?}");
    let info = server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(
        info.headers["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(info.headers["cache-control"], "no-store");
    let post = server
        .call(Method::POST, "/vault", None, &[], Some(json!({})))
        .await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn without_a_web_folder_only_the_api_answers() {
    let server = TestServer::new().await;
    let (status, headers, _) = get(&server, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["content-type"], "application/problem+json");
}

#[tokio::test]
async fn a_web_folder_without_index_html_stops_startup() {
    let empty = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut config = Config::from_lookup(|name| match name {
        "OCTAPASS_DATA_DIR" => Some(data.path().to_str().unwrap().into()),
        _ => None,
    })
    .unwrap();
    config.web_dir = Some(empty.path().to_owned());
    let error = octapass_server::AppState::new(config).await.err().unwrap();
    assert!(error.to_string().contains("index.html"), "{error}");
}

#[tokio::test]
async fn configured_invites_let_only_those_emails_sign_up() {
    let server = TestServer::with_config(|config| {
        config.signups = octapass_api::SignupMode::Invite;
        config.invites = vec!["owner@example.com".into()];
    })
    .await;
    admin::invite_configured(&server.state).await.unwrap();

    let start = |email: &str| {
        let request = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
        json!({ "email": email, "registrationRequest": b64(request.message.serialize()) })
    };
    let refused = server
        .post("/v1/auth/register/start", start("other@example.com"))
        .await;
    assert!(refused.is_problem("invite-required"), "{refused:?}");

    server.register("Owner@Example.com").await;
    // Starting again doesn't invite an email that has its account.
    admin::invite_configured(&server.state).await.unwrap();
    let again = server
        .post("/v1/auth/register/start", start("owner@example.com"))
        .await;
    assert!(again.is_problem("invite-required"), "{again:?}");
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn without_smtp_codes_go_to_the_log_and_never_to_the_client() {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let closed = TestServer::with_config(|config| config.dev_mode = false).await;
    let request = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let body = json!({ "email": "a@example.com", "registrationRequest": b64(request.message.serialize()) });
    let refused = closed.post("/v1/auth/register/start", body).await;
    assert!(refused.is_problem("email-unavailable"), "{refused:?}");

    let server = TestServer::with_config(|config| {
        config.dev_mode = false;
        config.email_to_log = true;
    })
    .await;
    let email = "owner@example.com";
    let start = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let started = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": email, "registrationRequest": b64(start.message.serialize()) }),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    assert!(
        started.body.get("devVerificationCode").is_none(),
        "{:?}",
        started.body
    );

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let marker = "verification code: ";
    let at = logged.find(marker).expect("the code is logged") + marker.len();
    let code = &logged[at..at + 6];
    assert!(logged.contains("owner@example.com"), "{logged}");

    let response =
        RegistrationResponse::<Suite>::deserialize(&unb64(&started.body["registrationResponse"]))
            .unwrap();
    let finish = start
        .state
        .finish(
            &mut OsRng,
            PASSWORD,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let finished = server
        .post(
            "/v1/auth/register/finish",
            register_finish_body(email, code, &b64(finish.message.serialize()), &new_id()),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
}

fn attachments_dir(config: &Config) -> &Path {
    match &config.attachments.storage {
        StorageConfig::Local { dir } => dir,
        StorageConfig::S3(_) => unreachable!("tests store files locally"),
    }
}

#[tokio::test]
async fn a_backup_restores_accounts_items_secrets_and_files() {
    let server = TestServer::new().await;
    if server.is_postgres() {
        let error = admin::backup(&server.state, server.dir.path())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("pg_dump"), "{error}");
        return;
    }
    let vault_id = server.register("owner@example.com").await;
    let device = server.login("owner@example.com", "Laptop").await;
    let item_id = new_id();
    let put = server
        .put_item(
            &device.access_token,
            &vault_id,
            &item_id,
            ("if-none-match", "*"),
            7,
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.body);
    std::fs::write(
        attachments_dir(&server.state.config).join("ab12"),
        b"ciphertext",
    )
    .unwrap();

    let backups = tempfile::tempdir().unwrap();
    let backup = admin::backup(&server.state, backups.path()).await.unwrap();
    assert!(
        backup
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("octapass-")
    );
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&backup), 0o700);
    assert_eq!(mode(&backup.join("octapass.db")), 0o600);
    for file in [
        "octapass.db",
        "opaque-server-setup.bin",
        "server-secret.bin",
        "attachments/ab12",
    ] {
        assert!(backup.join(file).is_file(), "{file}");
    }

    // A new machine: restore, then start on the restored data.
    let fresh = tempfile::tempdir().unwrap();
    let fresh_dir = fresh.path().to_str().unwrap().to_owned();
    let config = Config::from_lookup(|name| match name {
        "OCTAPASS_DATA_DIR" => Some(fresh_dir.clone()),
        "OCTAPASS_DEV_MODE" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    std::fs::create_dir_all(fresh.path()).unwrap();
    std::fs::write(fresh.path().join("octapass.db"), b"replaced").unwrap();
    let aside = admin::restore(&config, &backup).unwrap();
    assert_eq!(
        std::fs::read(aside.join("octapass.db")).unwrap(),
        b"replaced"
    );
    assert_eq!(
        std::fs::read(attachments_dir(&config).join("ab12")).unwrap(),
        b"ciphertext"
    );

    let restored = TestServer::with_config(|c| *c = config.clone()).await;
    let device = restored.login("owner@example.com", "New laptop").await;
    let sync = restored.get("/v1/sync", &device.access_token).await;
    assert_eq!(sync.status, StatusCode::OK, "{:?}", sync.body);
    assert!(sync.body.to_string().contains(&item_id), "{:?}", sync.body);

    let empty = tempfile::tempdir().unwrap();
    assert!(
        admin::restore(&config, empty.path()).is_err(),
        "not a backup"
    );
}
