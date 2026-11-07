//! The real sync server on a temporary SQLite database, and desktop vaults talking to it over
//! HTTP, each with its own data directory and a fake device lock.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use octapass_api::DeviceInfo;
use octapass_desktop_vault::model::{ItemDraft, SessionStatus, SignInResult};
use octapass_desktop_vault::{Config, Event, Vault};
use octapass_device_unlock::fake::FakeDeviceUnlock;
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const EMAIL: &str = "ada@example.com";
pub const PASSWORD: &str = "correct horse battery staple";

pub struct Server {
    pub url: String,
    /// The server's own state, for its clock.
    pub state: octapass_server::AppState,
    _data: TempDir,
}

pub async fn server() -> Server {
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().to_str().unwrap().to_owned();
    let mut config = octapass_server::Config::from_lookup(|name| match name {
        "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
        "OCTAPASS_DEV_MODE" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    // The identity provider in the SSO tests listens on this machine.
    config.sso_private_network = true;
    let state = octapass_server::AppState::new(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app =
        octapass_server::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        url,
        state,
        _data: data,
    }
}

impl Server {
    /// The current code of the authenticator app with base32 `secret`, by the server's clock.
    /// Each code works once, so the clock then moves on to the next 30 seconds.
    pub fn totp(&self, secret: &str) -> String {
        let now = u64::try_from(self.state.clock.now()).unwrap() / 1000;
        let code = octapass_core::tools::totp::totp_code(secret, now)
            .unwrap()
            .code;
        self.state.clock.advance(std::time::Duration::from_secs(30));
        code
    }
}

pub struct Device {
    pub vault: Arc<Vault>,
    pub unlock: Arc<FakeDeviceUnlock>,
    pub events: Arc<Mutex<Vec<Event>>>,
    pub dir: TempDir,
}

impl Device {
    pub fn new(server: &Server) -> Self {
        Self::with_unlock(server, FakeDeviceUnlock::default())
    }

    pub fn with_unlock(server: &Server, unlock: FakeDeviceUnlock) -> Self {
        Self::open(server, Arc::new(unlock), tempfile::tempdir().unwrap())
    }

    /// The same data directory opened again, as when the app restarts.
    pub fn restart(self, server: &Server) -> Self {
        let Device { unlock, dir, .. } = self;
        Self::open(server, unlock, dir)
    }

    /// A data directory opened again with a given device lock, after changing its files.
    pub fn reopen(server: &Server, unlock: Arc<FakeDeviceUnlock>, dir: TempDir) -> Self {
        Self::open(server, unlock, dir)
    }

    fn open(server: &Server, unlock: Arc<FakeDeviceUnlock>, dir: TempDir) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&events);
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                device: DeviceInfo {
                    name: "Test Mac".into(),
                    platform: "macos".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            unlock.clone(),
            Box::new(move |event| recorded.lock().unwrap().push(event)),
        )
        .unwrap();
        Self {
            vault,
            unlock,
            events,
            dir,
        }
    }

    pub fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }

    /// Signs up and returns the Secret Key from the Recovery Kit.
    pub async fn sign_up(&self, server: &Server) -> String {
        let started = self
            .vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .await
            .unwrap();
        let code = started
            .dev_verification_code
            .expect("dev mode returns the code");
        let kit = self
            .vault
            .finish_signup(&started.signup_id, &code)
            .await
            .unwrap();
        kit.secret_key
    }

    pub async fn sign_in(
        &self,
        server: &Server,
        secret_key: Option<&str>,
    ) -> octapass_desktop_vault::Result<SignInResult> {
        self.vault
            .sign_in(&server.url, EMAIL, secret(PASSWORD), secret_key.map(secret))
            .await
    }

    pub fn personal_vault(&self) -> String {
        self.vault.list_vaults().unwrap()[0].id.clone()
    }

    pub fn sync_failures(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                Event::SyncFailed { message } => Some(message.clone()),
                _ => None,
            })
            .collect()
    }
}

pub fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

pub fn login(vault_id: &str, title: &str, password: &str) -> ItemDraft {
    serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "login", "title": title, "urls": ["https://example.com"] },
        "details": { "schemaVersion": 1, "username": "ada", "password": password },
    }))
    .unwrap()
}
