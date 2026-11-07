//! `OctaPassVault`'s master password calls against the real sync server (in-process): changing
//! it while signed in, and resetting a forgotten one with the recovery code.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use octapass_mobile::items::{ItemDetails, ItemType, LoginDetails, new_item_draft};
use octapass_mobile::list::ItemFilter;
use octapass_mobile::platform::{CredentialIdentity, DeviceLock, NativePlatform, VaultObserver};
use octapass_mobile::vault::{
    DevicePlatform, PasswordResetResult, RecoveryKit, SessionSnapshot, SessionStatus, SignInResult,
    SyncState, VaultConfig,
};
use octapass_mobile::{ErrorCode, OctaPassVault, Result};
use tempfile::TempDir;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a brand new master password 7";

struct Server {
    url: String,
    _data: TempDir,
    runtime: tokio::runtime::Runtime,
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
            runtime,
        }
    }

    fn wait<T>(&self, call: impl Future<Output = Result<T>>) -> T {
        self.runtime.block_on(call).unwrap()
    }

    fn fail<T: std::fmt::Debug>(&self, call: impl Future<Output = Result<T>>) -> ErrorCode {
        self.runtime.block_on(call).unwrap_err().code()
    }
}

/// The Keychain and the device lock, in memory.
#[derive(Default)]
struct Platform {
    secrets: Mutex<HashMap<String, String>>,
    device_secrets: Mutex<HashMap<String, Vec<u8>>>,
    stay_unlocked: Mutex<HashMap<String, Vec<u8>>>,
}

impl NativePlatform for Platform {
    fn secret(&self, name: String) -> Result<Option<String>> {
        Ok(self.secrets.lock().unwrap().get(&name).cloned())
    }

    fn set_secret(&self, name: String, value: String) -> Result<()> {
        self.secrets.lock().unwrap().insert(name, value);
        Ok(())
    }

    fn delete_secret(&self, name: String) -> Result<()> {
        self.secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn device_lock(&self) -> DeviceLock {
        DeviceLock {
            available: true,
            label: "Face ID".into(),
        }
    }

    fn store_device_secret(&self, name: String, secret: Vec<u8>) -> Result<()> {
        self.device_secrets.lock().unwrap().insert(name, secret);
        Ok(())
    }

    fn device_secret(&self, name: String, _reason: String) -> Result<Vec<u8>> {
        self.device_secrets
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .ok_or_else(|| ErrorCode::DeviceUnlockFailed.into())
    }

    fn chip_available(&self) -> bool {
        false
    }

    fn create_chip_key(&self, _name: String) -> Result<Option<octapass_mobile::platform::ChipKey>> {
        Ok(None)
    }

    fn chip_secret(&self, _name: String, _context: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn delete_chip_key(&self, _name: String) -> Result<()> {
        Ok(())
    }

    fn low_memory(&self) -> bool {
        true
    }

    fn backup_folder_files(&self, _folder: String) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn write_backup_file(&self, _folder: String, _name: String, _source: String) -> Result<()> {
        Ok(())
    }

    fn delete_backup_file(&self, _folder: String, _name: String) -> Result<()> {
        Ok(())
    }

    fn delete_device_secret(&self, name: String) -> Result<()> {
        self.device_secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn verify_user(&self, _reason: String) -> Result<()> {
        Err(octapass_mobile::VaultError::new(
            octapass_mobile::ErrorCode::DeviceUnlockUnsupported,
            "not in tests",
        ))
    }

    fn store_stay_unlocked_key(&self, name: String, key: Vec<u8>) -> Result<()> {
        self.stay_unlocked.lock().unwrap().insert(name, key);
        Ok(())
    }

    fn stay_unlocked_key(&self, name: String) -> Result<Option<Vec<u8>>> {
        Ok(self.stay_unlocked.lock().unwrap().get(&name).cloned())
    }

    fn delete_stay_unlocked_key(&self, name: String) -> Result<()> {
        self.stay_unlocked.lock().unwrap().remove(&name);
        Ok(())
    }

    fn set_credential_identities(&self, _identities: Vec<CredentialIdentity>) -> Result<()> {
        Ok(())
    }
}

struct Events;

impl VaultObserver for Events {
    fn session_changed(&self, _snapshot: SessionSnapshot) {}
    fn items_changed(&self) {}
    fn sync_changed(&self, _state: SyncState) {}
    fn sharing_changed(&self) {}
}

struct Phone {
    vault: Arc<OctaPassVault>,
    _dir: TempDir,
}

impl Phone {
    fn new(server: &Server) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = OctaPassVault::new(
            VaultConfig {
                data_dir: dir.path().join("group").to_string_lossy().into(),
                temp_dir: dir.path().join("tmp").to_string_lossy().into(),
                device_name: "Test iPhone".into(),
                platform: DevicePlatform::Ios,
                // Answers 404, so breach checks don't complete, without the internet.
                pwned_passwords_url: server.url.clone(),
                web_vault_url: "https://vault.octap.app".into(),
                default_server_url: "https://vault.octap.app".into(),
                cache_dir: dir.path().join("icons").to_string_lossy().into(),
            },
            Arc::new(Platform::default()),
            Arc::new(Events),
        )
        .unwrap();
        Self { vault, _dir: dir }
    }

    fn v(&self) -> Arc<OctaPassVault> {
        self.vault.clone()
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().status
    }

    fn sign_up(&self, server: &Server) -> RecoveryKit {
        let started = server.wait(self.v().start_signup(
            server.url.clone(),
            EMAIL.into(),
            PASSWORD.into(),
        ));
        let code = started.dev_verification_code.expect("a development server");
        server.wait(self.v().finish_signup(started.signup_id, code))
    }

    fn save_login(&self, server: &Server, title: &str) {
        let vault_id = server.wait(self.v().list_vaults())[0].id.clone();
        let mut draft = new_item_draft(ItemType::Login, vault_id);
        draft.title = title.into();
        draft.details = ItemDetails::Login {
            login: LoginDetails {
                username: Some("ada".into()),
                password: Some("pw".into()),
                ..LoginDetails::default()
            },
        };
        server.wait(self.v().save_item(draft));
    }

    fn titles(&self, server: &Server) -> Vec<String> {
        let mut titles: Vec<String> = server
            .wait(self.v().list_items(ItemFilter::default()))
            .into_iter()
            .map(|item| item.title)
            .collect();
        titles.sort();
        titles
    }

    fn sign_in(&self, server: &Server, password: &str, secret_key: &str) -> Option<ErrorCode> {
        server
            .runtime
            .block_on(self.v().sign_in(
                server.url.clone(),
                EMAIL.into(),
                password.into(),
                Some(secret_key.into()),
            ))
            .err()
            .map(|error| error.code())
    }
}

#[test]
fn changing_the_master_password_keeps_the_vault_and_signs_out_other_devices() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let kit = phone.sign_up(&server);
    phone.save_login(&server, "Bank");
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    assert_eq!(
        server.fail(
            phone
                .v()
                .change_master_password("not my password".into(), NEW_PASSWORD.into())
        ),
        ErrorCode::InvalidCredentials
    );
    server.wait(
        phone
            .v()
            .change_master_password(PASSWORD.into(), NEW_PASSWORD.into()),
    );
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    // This phone unlocks with the new password only, and the vault is the same.
    phone.vault.lock();
    assert_eq!(
        server.fail(phone.v().unlock(PASSWORD.into())),
        ErrorCode::InvalidCredentials
    );
    server.wait(phone.v().unlock(NEW_PASSWORD.into()));
    assert_eq!(phone.titles(&server), ["Bank"]);

    // Another phone signs in with the new password, not the old one.
    let other = Phone::new(&server);
    assert_eq!(
        other.sign_in(&server, PASSWORD, &kit.secret_key),
        Some(ErrorCode::InvalidCredentials)
    );
    assert_eq!(other.sign_in(&server, NEW_PASSWORD, &kit.secret_key), None);
    assert_eq!(other.titles(&server), ["Bank"]);
}

#[test]
fn a_forgotten_master_password_is_reset_with_the_recovery_code() {
    let server = Server::start();
    let first = Phone::new(&server);
    let kit = first.sign_up(&server);
    first.save_login(&server, "Bank");

    // A new phone that has never seen the account.
    let phone = Phone::new(&server);
    assert_eq!(
        server.fail(
            phone
                .v()
                .verify_password_reset("no-such-reset".into(), "123456".into())
        ),
        ErrorCode::ResetExpired
    );
    let started = server.wait(
        phone
            .v()
            .start_password_reset(server.url.clone(), EMAIL.into()),
    );
    let code = started.dev_verification_code.expect("a development server");
    let wrong_code = if code == "000000" { "111111" } else { "000000" };
    assert_eq!(
        server.fail(
            phone
                .v()
                .verify_password_reset(started.reset_id.clone(), wrong_code.into())
        ),
        ErrorCode::InvalidVerificationCode
    );
    server.wait(
        phone
            .v()
            .verify_password_reset(started.reset_id.clone(), code.clone()),
    );
    assert_eq!(
        server.fail(phone.v().finish_password_reset(
            started.reset_id.clone(),
            "not a recovery code".into(),
            NEW_PASSWORD.into(),
        )),
        ErrorCode::InvalidRecoveryCode
    );

    let reset: PasswordResetResult = server.wait(phone.v().finish_password_reset(
        started.reset_id.clone(),
        kit.recovery_code.clone(),
        NEW_PASSWORD.into(),
    ));
    assert_ne!(reset.recovery_kit.recovery_code, kit.recovery_code);
    assert_ne!(reset.recovery_kit.secret_key, kit.secret_key);
    assert_eq!(reset.sign_in, Some(SignInResult::SignedIn));
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    assert_eq!(phone.titles(&server), ["Bank"]);

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
    assert_eq!(again.titles(&server), ["Bank"]);

    // The reset is used up.
    assert_eq!(
        server.fail(phone.v().verify_password_reset(started.reset_id, code)),
        ErrorCode::ResetExpired
    );
}
