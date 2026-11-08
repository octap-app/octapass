//! Push sync on the phone, against the real sync server with a fake push relay on a local port:
//! the token reaches the server, a change elsewhere becomes a push to this phone's token, and a
//! push to a locked phone brings the change into its store without unlocking.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{ItemDraft, RecoveryKit};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::vault::{PushPlatform, PushToken};
use octapass_mobile_vault::{Config, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
const TOKEN: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

/// What the fake relay was asked to push: (token, kind).
type Pushed = Arc<Mutex<Vec<(String, String)>>>;

async fn relay_answer(State(pushed): State<Pushed>, request: Request) -> axum::response::Response {
    let path = request.uri().path().to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 1 << 20)
        .await
        .unwrap();
    if path == "/v1/installations" {
        return (
            axum::http::StatusCode::CREATED,
            axum::Json(json!({ "installationId": "phone-test", "installationKey": "k" })),
        )
            .into_response();
    }
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let messages = body["messages"].as_array().unwrap();
    for message in messages {
        pushed.lock().unwrap().push((
            message["token"].as_str().unwrap().to_owned(),
            message["kind"].as_str().unwrap().to_owned(),
        ));
    }
    axum::Json(json!({ "results": vec!["sent"; messages.len()] })).into_response()
}

struct Server {
    url: String,
    pushed: Pushed,
    _data: TempDir,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Server {
    fn start(push: bool) -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let pushed = Pushed::default();
        let relay_pushed = pushed.clone();
        let url = runtime.block_on(async move {
            let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay_url = format!("http://{}", relay.local_addr().unwrap());
            let app = Router::new()
                .fallback(relay_answer)
                .with_state(relay_pushed);
            tokio::spawn(async move { axum::serve(relay, app).await.unwrap() });

            let mut config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
            if push {
                config.push = Some(octapass_server::config::PushRelay {
                    url: relay_url,
                    batch_delay: Duration::from_millis(20),
                });
            }
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app =
                octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            url
        });
        Self {
            url,
            pushed,
            _data: data,
            runtime: Some(runtime),
        }
    }

    /// Waits for the server's next round of pushes.
    fn pushes(&self) -> Vec<(String, String)> {
        for _ in 0..200 {
            if !self.pushed.lock().unwrap().is_empty() {
                std::thread::sleep(Duration::from_millis(100));
                return std::mem::take(&mut *self.pushed.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Vec::new()
    }

    /// Stops the server: the phone is offline from here on.
    fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

struct Phone {
    vault: Arc<Vault>,
    _dir: TempDir,
}

impl Phone {
    fn new(server: &Server, name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                temp_dir: dir.path().join("tmp"),
                device: DeviceInfo {
                    name: name.into(),
                    platform: "ios".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            Arc::new(FakeNative::default()),
            Box::new(|_| {}),
        )
        .unwrap();
        Self { vault, _dir: dir }
    }

    fn sign_up(&self, server: &Server) -> RecoveryKit {
        let started = self
            .vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .unwrap();
        self.vault
            .finish_signup(&started.signup_id, &started.dev_verification_code.unwrap())
            .unwrap()
    }

    fn sign_in(&self, server: &Server, kit: &RecoveryKit) {
        self.vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(PASSWORD),
                Some(secret(&kit.secret_key)),
            )
            .unwrap();
    }

    fn save_login(&self, title: &str) {
        let vault_id = self.vault.list_vaults().unwrap()[0].id.clone();
        self.vault
            .save_item(ItemDraft {
                id: None,
                vault_id,
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": "login", "title": title }),
                details: json!({ "schemaVersion": 1, "username": "ada", "password": "pw" }),
            })
            .unwrap();
    }

    fn titles(&self) -> Vec<String> {
        let mut titles: Vec<String> = self
            .vault
            .list_items()
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect();
        titles.sort();
        titles
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn apns(token: &str) -> Option<PushToken> {
    Some(PushToken {
        platform: PushPlatform::Apns,
        token: token.into(),
        sandbox: false,
    })
}

#[test]
fn a_locked_phone_takes_changes_from_a_push() {
    let mut server = Server::start(true);
    let iphone = Phone::new(&server, "iPhone");
    let kit = iphone.sign_up(&server);
    assert!(iphone.vault.set_push_token(apns(TOKEN)).unwrap());

    let ipad = Phone::new(&server, "iPad");
    ipad.sign_in(&server, &kit);
    iphone.vault.lock();
    ipad.save_login("Bank");
    let pushed = server.pushes();
    assert!(
        pushed.contains(&(TOKEN.to_owned(), "sync".to_owned())),
        "{pushed:?}"
    );

    // The push wakes the locked iPhone, which pulls the change as ciphertext.
    iphone.vault.sync_on_push().unwrap();
    server.stop();
    // Offline now: what the unlock shows is what the push brought.
    iphone.vault.unlock(secret(PASSWORD)).unwrap();
    assert_eq!(iphone.titles(), ["Bank"]);
}

#[test]
fn the_token_follows_sign_in_and_can_be_withdrawn() {
    let server = Server::start(true);
    let iphone = Phone::new(&server, "iPhone");
    // Before there's an account, the token waits.
    assert!(!iphone.vault.set_push_token(apns(TOKEN)).unwrap());
    let kit = iphone.sign_up(&server);
    // Signing up ends with a sync, which sends it.
    iphone.vault.sync().unwrap();

    let ipad = Phone::new(&server, "iPad");
    ipad.sign_in(&server, &kit);
    ipad.save_login("Bank");
    assert!(
        server
            .pushes()
            .contains(&(TOKEN.to_owned(), "sync".to_owned()))
    );

    // Withdrawn: nothing more reaches this phone.
    assert!(!iphone.vault.set_push_token(None).unwrap());
    ipad.save_login("Mail");
    assert!(server.pushes().iter().all(|(token, _)| token != TOKEN));
}

#[test]
fn a_server_without_a_relay_is_left_alone() {
    let server = Server::start(false);
    let iphone = Phone::new(&server, "iPhone");
    iphone.sign_up(&server);
    assert!(!iphone.vault.set_push_token(apns(TOKEN)).unwrap());
    // Syncs go on as before, and a push does nothing worse than a sync.
    iphone.vault.sync().unwrap();
    iphone.vault.sync_on_push().unwrap();
    iphone.vault.lock();
    iphone.vault.sync_on_push().unwrap();
}
