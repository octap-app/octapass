//! The mobile vault against the real sync server (in-process, temporary SQLite database), over
//! HTTP: sign-up, items of every kind, the trash, conflicts, lock and unlock, device unlock, a
//! second phone, what the AutoFill extension writes, sign-out and account deletion.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use octapass_ffi::{CredentialIdentity, DeviceInfo, LocalStore, LoginDraft};
use octapass_mobile_vault::accounts::{Accounts, store_path};
use octapass_mobile_vault::model::{ItemDraft, SessionStatus};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Event, Vault};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct Server {
    url: String,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

fn server() -> Server {
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
    Server {
        url,
        _data: data,
        _runtime: runtime,
    }
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    events: Arc<Mutex<Vec<Event>>>,
    dir: TempDir,
}

impl Phone {
    fn new(server: &Server) -> Self {
        Self::open(server, Arc::default(), tempfile::tempdir().unwrap())
    }

    /// The same container and Keychain opened again, as when the app restarts.
    fn restart(self, server: &Server) -> Self {
        Self::open(server, self.native, self.dir)
    }

    fn open(server: &Server, native: Arc<FakeNative>, dir: TempDir) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = events.clone();
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
            native.clone(),
            Box::new(move |event| recorded.lock().unwrap().push(event)),
        )
        .unwrap();
        Self {
            vault,
            native,
            events,
            dir,
        }
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }

    fn sign_up(&self, server: &Server) -> String {
        let started = self
            .vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .unwrap();
        let code = started.dev_verification_code.unwrap();
        assert_eq!(
            self.vault
                .finish_signup(&started.signup_id, "000000")
                .unwrap_err()
                .code,
            ErrorCode::InvalidVerificationCode,
            "a wrong code can be retried"
        );
        let kit = self.vault.finish_signup(&started.signup_id, &code).unwrap();
        assert_eq!(kit.email, EMAIL);
        assert!(kit.secret_key.starts_with("OP1-"));
        kit.secret_key
    }

    fn vault_id(&self) -> String {
        self.vault.list_vaults().unwrap()[0].id.clone()
    }

    fn save(&self, overview: serde_json::Value, details: serde_json::Value) -> String {
        self.vault
            .save_item(ItemDraft {
                id: None,
                vault_id: self.vault_id(),
                revision: None,
                overview,
                details,
            })
            .unwrap()
            .id
    }

    fn titles(&self) -> Vec<String> {
        let mut titles: Vec<String> = self
            .vault
            .list_items()
            .unwrap()
            .into_iter()
            .filter(|item| item.deleted_at.is_none())
            .map(|item| item.title)
            .collect();
        titles.sort();
        titles
    }

    fn identities(&self) -> Vec<CredentialIdentity> {
        self.native.identities.lock().unwrap().clone()
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn wifi() -> (serde_json::Value, serde_json::Value) {
    (
        json!({ "schemaVersion": 1, "type": "password", "title": "Home Wi-Fi" }),
        json!({ "schemaVersion": 1, "password": "hunter22", "customFields": [{ "label": "SSID", "value": "Home", "hidden": false }] }),
    )
}

#[test]
fn sign_up_items_trash_and_conflicts() {
    let server = server();
    let phone = Phone::new(&server);
    assert_eq!(phone.status(), SessionStatus::SignedOut);
    phone.sign_up(&server);
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    let accounts = Accounts::load(phone.dir.path()).unwrap();
    let account = accounts.current().unwrap().clone();
    assert!(store_path(phone.dir.path(), &account).exists());
    assert!(
        phone
            .native
            .secret_names()
            .contains(&account.secret_key_name())
    );

    let github = phone.save(
        json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "urls": ["https://github.com"] }),
        json!({ "schemaVersion": 1, "username": "ada", "password": "old-password", "totp": "JBSWY3DPEHPK3PXP" }),
    );
    let (overview, details) = wifi();
    let router = phone.save(overview, details);
    assert_eq!(phone.titles(), ["GitHub", "Home Wi-Fi"]);
    let item = phone.vault.get_item(&router).unwrap();
    assert_eq!(item.details["customFields"][0]["value"], "Home");
    assert!(item.revision > 0, "uploaded at once");
    assert!(
        phone.identities().iter().any(|identity| matches!(
            identity,
            CredentialIdentity::Password { url, user, .. } if url == "https://github.com" && user == "ada"
        )),
        "saving updates the AutoFill suggestions"
    );

    // An edit keeps the old password in the history.
    let saved = phone.vault.get_item(&github).unwrap();
    let mut details = saved.details.clone();
    details["password"] = json!("new-password");
    let edited = phone
        .vault
        .save_item(ItemDraft {
            id: Some(github.clone()),
            vault_id: saved.vault_id.clone(),
            revision: Some(saved.revision),
            overview: saved.overview.clone(),
            details,
        })
        .unwrap();
    assert_eq!(
        edited.details["passwordHistory"][0]["password"],
        "old-password"
    );

    // An edit made from a stale copy doesn't overwrite the newer one.
    phone
        .vault
        .save_item(ItemDraft {
            id: Some(github.clone()),
            vault_id: saved.vault_id.clone(),
            revision: Some(saved.revision),
            overview: saved.overview.clone(),
            details: saved.details.clone(),
        })
        .unwrap();
    assert_eq!(
        phone.titles(),
        ["GitHub", "GitHub (conflicting copy)", "Home Wi-Fi"]
    );
    assert_eq!(
        phone.vault.get_item(&github).unwrap().details["password"],
        "new-password"
    );

    // The trash.
    phone.vault.delete_item(&router).unwrap();
    assert!(phone.vault.get_item(&router).unwrap().deleted_at.is_some());
    assert_eq!(phone.titles(), ["GitHub", "GitHub (conflicting copy)"]);
    phone.vault.restore_item(&router).unwrap();
    assert!(phone.vault.get_item(&router).unwrap().deleted_at.is_none());

    let code = phone.vault.totp("JBSWY3DPEHPK3PXP", Some(59_000)).unwrap();
    assert_eq!((code.code.len(), code.period, code.remaining), (6, 30, 1));
    let summary = phone.vault.account_summary().unwrap();
    assert_eq!((summary.item_count, summary.device_count), (3, 1));
    assert!(
        phone
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::ItemsChanged))
    );
}

#[test]
fn lock_unlock_and_device_unlock() {
    let server = server();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let methods = phone.vault.unlock_methods();
    assert!(methods.device_unlock_supported && !methods.device_unlock_enabled);
    assert_eq!(
        (methods.platform, methods.label.as_str()),
        ("ios", "Face ID")
    );

    phone.vault.enable_device_unlock().unwrap();
    assert!(phone.vault.unlock_methods().device_unlock_enabled);
    phone.vault.lock();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert_eq!(
        phone.vault.list_items().unwrap_err().code,
        ErrorCode::Locked
    );

    // After a restart the account opens locked; Face ID or the passcode unlocks it.
    let phone = phone.restart(&server);
    assert_eq!(phone.status(), SessionStatus::Locked);
    *phone.native.cancel_next_prompt.lock().unwrap() = true;
    assert_eq!(
        phone.vault.unlock_with_device().unwrap_err().code,
        ErrorCode::DeviceUnlockCancelled
    );
    phone.vault.unlock_with_device().unwrap();
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    phone.vault.lock();
    assert_eq!(
        phone.vault.unlock(secret("wrong")).unwrap_err().code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.unlock(secret(PASSWORD)).unwrap();

    // Before a secret is shown as a QR code: the device lock, or the master password.
    phone.vault.confirm_user(None).unwrap();
    *phone.native.cancel_next_prompt.lock().unwrap() = true;
    assert_eq!(
        phone.vault.confirm_user(None).unwrap_err().code,
        ErrorCode::DeviceUnlockCancelled
    );
    assert_eq!(
        phone
            .vault
            .confirm_user(Some(secret("wrong")))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    phone.vault.confirm_user(Some(secret(PASSWORD))).unwrap();
    assert_eq!(
        phone.status(),
        SessionStatus::Unlocked,
        "confirming doesn't lock"
    );

    phone.vault.disable_device_unlock().unwrap();
    phone.vault.lock();
    assert_eq!(
        phone.vault.unlock_with_device().unwrap_err().code,
        ErrorCode::PasswordRequired
    );
    assert!(phone.native.device_secrets.lock().unwrap().is_empty());
}

#[test]
fn a_second_phone_and_the_autofill_extension() {
    let server = server();
    let phone = Phone::new(&server);
    let secret_key = phone.sign_up(&server);
    phone.save(
        json!({ "schemaVersion": 1, "type": "secureNote", "title": "Door code" }),
        json!({ "schemaVersion": 1, "notes": "4711" }),
    );

    let tablet = Phone::new(&server);
    assert_eq!(
        tablet
            .vault
            .sign_in(&server.url, EMAIL, secret(PASSWORD), None)
            .unwrap_err()
            .code,
        ErrorCode::SecretKeyRequired
    );
    tablet
        .vault
        .sign_in(
            &server.url,
            "Ada@Example.com",
            secret(PASSWORD),
            Some(secret(&secret_key)),
        )
        .unwrap();
    assert_eq!(tablet.titles(), ["Door code"]);

    // The extension saves a login into the shared store (here: a second view of the file,
    // unlocked with the device secret), and the app uploads it on its next sync.
    phone.vault.enable_device_unlock().unwrap();
    let account = Accounts::load(phone.dir.path())
        .unwrap()
        .current()
        .unwrap()
        .clone();
    let device_secret =
        phone.native.device_secrets.lock().unwrap()[&account.device_secret_name()].clone();
    let store = LocalStore::open(
        store_path(phone.dir.path(), &account)
            .to_string_lossy()
            .into_owned(),
    )
    .unwrap();
    let extension = store.unlock_with_device(device_secret).unwrap();
    extension
        .save_login(
            store.clone(),
            LoginDraft {
                item_id: None,
                title: None,
                url: Some("https://example.com/login".into()),
                username: Some("ada".into()),
                password: Some("from-the-extension".into()),
                totp: None,
            },
        )
        .unwrap();
    extension.lock();
    phone.vault.sync().unwrap();
    assert_eq!(phone.titles(), ["Door code", "example.com"]);
    tablet.vault.sync().unwrap();
    assert_eq!(tablet.titles(), ["Door code", "example.com"]);

    // Signing out forgets the account here and only here.
    tablet.vault.sign_out().unwrap();
    assert_eq!(tablet.status(), SessionStatus::SignedOut);
    assert!(tablet.vault.snapshot().remembered_accounts.is_empty());
    assert!(tablet.native.secret_names().is_empty());
    assert!(tablet.identities().is_empty());
    phone.vault.sync().unwrap();

    // Deleting the account needs the email and the master password.
    assert_eq!(
        phone
            .vault
            .delete_account("someone@example.com", secret(PASSWORD))
            .unwrap_err()
            .code,
        ErrorCode::EmailMismatch
    );
    phone.vault.delete_account(EMAIL, secret(PASSWORD)).unwrap();
    assert_eq!(phone.status(), SessionStatus::SignedOut);
    assert!(!store_path(phone.dir.path(), &account).exists());
}

const HOTP: &str = "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0";

fn hotp_login() -> (serde_json::Value, serde_json::Value) {
    (
        json!({ "schemaVersion": 1, "type": "login", "title": "Bank" }),
        json!({ "schemaVersion": 1, "password": "first", "totp": HOTP }),
    )
}

#[test]
fn versions_are_kept_and_restored() {
    let server = server();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let (overview, details) = hotp_login();
    let id = phone.save(overview, details);
    assert!(phone.vault.item_versions(&id).unwrap().is_empty());

    let item = phone.vault.get_item(&id).unwrap();
    let mut details = item.details.clone();
    details["password"] = json!("second");
    phone
        .vault
        .save_item(ItemDraft {
            id: Some(id.clone()),
            vault_id: item.vault_id.clone(),
            revision: Some(item.revision),
            overview: item.overview.clone(),
            details,
        })
        .unwrap();

    let versions = phone.vault.item_versions(&id).unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].details["password"], "first");
    // Counter moves aren't edits, and a restore doesn't take the counter back.
    assert_eq!(phone.vault.next_hotp_code(&id).unwrap().code, "755224");
    assert_eq!(phone.vault.item_versions(&id).unwrap().len(), 1);
    let restored = phone
        .vault
        .restore_item_version(&id, versions[0].revision)
        .unwrap();
    assert_eq!(restored.details["password"], "first");
    assert!(
        restored.details["totp"]
            .as_str()
            .unwrap()
            .contains("counter=1")
    );
    assert_eq!(restored.details["passwordHistory"][0]["password"], "second");
}

#[test]
fn counters_move_here_and_reach_the_other_phone() {
    let server = server();
    let phone = Phone::new(&server);
    let secret_key = phone.sign_up(&server);
    let (overview, details) = hotp_login();
    let id = phone.save(overview, details);

    let tablet = Phone::new(&server);
    tablet
        .vault
        .sign_in(
            &server.url,
            EMAIL,
            secret(PASSWORD),
            Some(secret(&secret_key)),
        )
        .unwrap();
    assert_eq!(phone.vault.next_hotp_code(&id).unwrap().counter, 0);
    // The tablet asks for the newest counter first, so it doesn't repeat the code.
    let next = tablet.vault.next_hotp_code(&id).unwrap();
    assert_eq!((next.code.as_str(), next.counter), ("287082", 1));
    phone.vault.set_hotp_counter(&id, 7).unwrap();
    assert_eq!(tablet.vault.next_hotp_code(&id).unwrap().code, "162583");
    assert_eq!(phone.titles(), ["Bank"], "no conflicting copies");
}

#[test]
fn equivalent_domains_stay_hidden_and_reach_matching() {
    use octapass_mobile_vault::vault::EquivalentDomainsInput;
    let server = server();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let saved = phone
        .vault
        .save_equivalent_domains(EquivalentDomainsInput {
            groups: vec![vec![
                "mail.example.com".into(),
                "example.org".into(),
                "co.uk".into(),
            ]],
            excluded_defaults: vec!["google.com".into()],
        })
        .unwrap();
    assert_eq!(saved.groups, [["example.com", "example.org"]]);
    assert_eq!(saved.rejected, ["co.uk"]);
    let options = phone.vault.match_options().unwrap();
    assert_eq!(options.equivalent_domains, saved.groups);
    assert_eq!(options.excluded_defaults, ["google.com"]);
}
