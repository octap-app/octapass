//! The desktop app's path through Connect: an unlocked vault in memory, against a real server.

use std::net::SocketAddr;
use std::sync::Arc;

use octapass_api::DeviceInfo;
use octapass_connect::clients::Clients;
use octapass_connect::log::Entry;
use octapass_connect::server::{Backend, ConnectError};
use octapass_connect::vault_backend::{Ask, VaultBackend};
use octapass_desktop_vault::model::ItemDraft;
use octapass_desktop_vault::{Config, Vault};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct Setup {
    vault: Arc<Vault>,
    backend: VaultBackend,
    folder: TempDir,
    stop: tokio::sync::oneshot::Sender<()>,
    _dirs: (TempDir, TempDir),
}

async fn setup() -> Setup {
    let server_dir = tempfile::tempdir().unwrap();
    let data_dir = server_dir.path().to_str().unwrap().to_owned();
    let config = octapass_server::Config::from_lookup(|name| match name {
        "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
        "OCTAPASS_DEV_MODE" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    let state = octapass_server::AppState::new(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });

    let vault_dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(
        Config {
            data_dir: vault_dir.path().to_owned(),
            device: DeviceInfo {
                name: "Desktop".into(),
                platform: "macos".into(),
            },
            pwned_passwords_url: url.clone(),
        },
        Arc::new(octapass_device_unlock::Unsupported),
        Box::new(|_| {}),
    )
    .unwrap();
    let started = vault
        .start_signup(&url, EMAIL, Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let code = started.dev_verification_code.unwrap();
    vault
        .finish_signup(&started.signup_id, &code)
        .await
        .unwrap();
    let personal = vault.list_vaults().unwrap()[0].id.clone();
    let draft: ItemDraft = serde_json::from_value(json!({
        "vaultId": personal,
        "overview": { "schemaVersion": 1, "type": "login", "title": "GitHub" },
        "details": { "schemaVersion": 1, "username": "octocat", "password": "hunter2" },
    }))
    .unwrap();
    vault.save_item(draft).await.unwrap();

    let folder = tempfile::tempdir().unwrap();
    let ask: Ask = Arc::new(|_| Box::pin(async { true }));
    let backend = VaultBackend::new(Arc::clone(&vault), folder.path().to_owned(), ask);
    Setup {
        vault,
        backend,
        folder,
        stop,
        _dirs: (server_dir, vault_dir),
    }
}

fn client(setup: &Setup) -> octapass_connect::clients::Client {
    let dir = setup.folder.path();
    Clients::open(dir)
        .approve("Tool", None, 1_800_000_000)
        .unwrap()
        .0
}

fn queued(folder: &TempDir) -> usize {
    std::fs::read_dir(folder.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "queue"))
        .map(|path| std::fs::read_to_string(path).unwrap().lines().count())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_is_answered_and_sealed_into_the_log() {
    let setup = setup().await;
    let client = client(&setup);
    let reference = "octapass://Personal/GitHub/password".to_owned();
    let secrets = setup
        .backend
        .read(
            client.clone(),
            vec![
                reference.clone(),
                "octapass://Personal/Nope/password".into(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(secrets[0].value.as_deref(), Some("hunter2"));
    assert!(secrets[1].value.is_none());
    assert!(secrets[1].error.as_deref().unwrap().contains("Nope"));

    let items = setup.backend.items(client).await.unwrap();
    assert!(items.iter().any(|item| item.item == "GitHub"));
    assert!(!serde_json::to_string(&items).unwrap().contains("hunter2"));

    assert_eq!(queued(&setup.folder), 0, "the server has it");
    let log = setup.vault.security_log_opened().await.unwrap();
    let entries: Vec<_> = log
        .iter()
        .filter(|event| event.event_type.as_str() == "connect-secret-read")
        .collect();
    assert_eq!(entries.len(), 1, "only what was handed out");
    let entry: Entry = serde_json::from_str(entries[0].sealed_detail.as_deref().unwrap()).unwrap();
    assert_eq!(entry.reference, reference);
    assert_eq!(entry.client_name, "Tool");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_vault_answers_locked_and_hands_nothing_out() {
    let setup = setup().await;
    let client = client(&setup);
    setup.vault.lock();
    assert!(!setup.backend.unlocked().await);
    let error = setup
        .backend
        .read(client, vec!["octapass://Personal/GitHub/password".into()])
        .await
        .unwrap_err();
    assert_eq!(error, ConnectError::locked());
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_the_entry_waits_on_disk() {
    let setup = setup().await;
    let client = client(&setup);
    let Setup {
        vault: _vault,
        backend,
        folder,
        stop,
        _dirs,
    } = setup;
    let _ = stop.send(());
    let secrets = backend
        .read(client, vec!["octapass://Personal/GitHub/password".into()])
        .await
        .unwrap();
    assert_eq!(secrets[0].value.as_deref(), Some("hunter2"));
    assert_eq!(queued(&folder), 1);
}
