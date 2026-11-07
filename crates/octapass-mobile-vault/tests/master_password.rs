//! The master password against the real sync server, through `octapass-ffi`: changing it while
//! signed in, and resetting a forgotten one with the recovery code from the Recovery Kit.

use std::net::SocketAddr;
use std::sync::Arc;

use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{ItemDraft, RecoveryKit, SessionStatus, SignInResult};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Vault};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a brand new master password 7";

struct Server {
    url: String,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
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
            _data: data,
            _runtime: runtime,
        }
    }
}

struct Phone {
    vault: Arc<Vault>,
    _dir: TempDir,
}

impl Phone {
    fn new(server: &Server) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                temp_dir: dir.path().join("tmp"),
                device: DeviceInfo {
                    name: "Test iPhone".into(),
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

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
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

    fn sign_in(&self, server: &Server, password: &str, secret_key: &str) -> Option<ErrorCode> {
        self.vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(password),
                Some(secret(secret_key)),
            )
            .err()
            .map(|error| error.code)
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

#[test]
fn changing_the_master_password_keeps_the_vault_and_signs_out_other_devices() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let kit = phone.sign_up(&server);
    phone.save_login("Bank");

    assert_eq!(
        phone
            .vault
            .change_master_password(secret("not my password"), secret(NEW_PASSWORD))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    phone
        .vault
        .change_master_password(secret(PASSWORD), secret(NEW_PASSWORD))
        .unwrap();
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    // This phone unlocks with the new password only, and the vault is the same.
    phone.vault.lock();
    assert_eq!(
        phone.vault.unlock(secret(PASSWORD)).unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.unlock(secret(NEW_PASSWORD)).unwrap();
    assert_eq!(phone.titles(), ["Bank"]);

    // Another phone signs in with the new password, not the old one.
    let other = Phone::new(&server);
    assert_eq!(
        other.sign_in(&server, PASSWORD, &kit.secret_key),
        Some(ErrorCode::InvalidCredentials)
    );
    assert_eq!(other.sign_in(&server, NEW_PASSWORD, &kit.secret_key), None);
    assert_eq!(other.titles(), ["Bank"]);
}

#[test]
fn a_forgotten_master_password_is_reset_with_the_recovery_code() {
    let server = Server::start();
    let first = Phone::new(&server);
    let kit = first.sign_up(&server);
    first.save_login("Bank");

    // A new phone that has never seen the account.
    let phone = Phone::new(&server);
    assert_eq!(
        phone
            .vault
            .verify_password_reset("no-such-reset", "123456")
            .unwrap_err()
            .code,
        ErrorCode::ResetExpired
    );
    let started = phone
        .vault
        .start_password_reset(&server.url, EMAIL)
        .unwrap();
    let code = started
        .dev_verification_code
        .expect("dev mode returns the code");
    let wrong_code = if code == "000000" { "111111" } else { "000000" };
    assert_eq!(
        phone
            .vault
            .verify_password_reset(&started.reset_id, wrong_code)
            .unwrap_err()
            .code,
        ErrorCode::InvalidVerificationCode
    );
    phone
        .vault
        .verify_password_reset(&started.reset_id, &code)
        .unwrap();
    assert_eq!(
        phone
            .vault
            .finish_password_reset(
                &started.reset_id,
                "not a recovery code",
                secret(NEW_PASSWORD)
            )
            .unwrap_err()
            .code,
        ErrorCode::InvalidRecoveryCode
    );

    let reset = phone
        .vault
        .finish_password_reset(&started.reset_id, &kit.recovery_code, secret(NEW_PASSWORD))
        .unwrap();
    assert_ne!(reset.recovery_kit.recovery_code, kit.recovery_code);
    assert_ne!(reset.recovery_kit.secret_key, kit.secret_key);
    assert_eq!(reset.sign_in, Some(SignInResult::SignedIn));
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    assert_eq!(phone.titles(), ["Bank"]);

    // The old password and Secret Key stop working; the new ones work.
    let again = Phone::new(&server);
    assert_eq!(
        again.sign_in(&server, PASSWORD, &kit.secret_key),
        Some(ErrorCode::InvalidCredentials)
    );
    assert_eq!(
        again.sign_in(&server, NEW_PASSWORD, &reset.recovery_kit.secret_key),
        None
    );
    assert_eq!(again.titles(), ["Bank"]);

    // The reset is used up.
    assert_eq!(
        phone
            .vault
            .verify_password_reset(&started.reset_id, &code)
            .unwrap_err()
            .code,
        ErrorCode::ResetExpired
    );
}
