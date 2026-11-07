//! `OctaPassVault` against the real sync server (in-process, temporary SQLite database), over
//! HTTP, as the native apps call it: accounts and two-step sign-in, device unlock, items of every
//! type, lists, attachments, exports and imports, sharing between two accounts, families, share
//! links, emergency access, devices and the security log.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octapass_mobile::emergency::{EmergencyAccessLevel, EmergencyScope, EmergencyStatus};
use octapass_mobile::environments::{
    EnvironmentDetails, EnvironmentVariable, environment_dotenv, missing_environment_keys,
};
use octapass_mobile::health::EmailBreachCheck;
use octapass_mobile::items::{
    CardDetails, CustomField, DocumentDetails, IdentityDetails, ItemDetails, ItemDraft, ItemType,
    LoginDetails, SecureNoteDetails, WifiDetails, item_draft, new_item_draft,
};
use octapass_mobile::links::{ShareLinkOptions, parse_share_link_url};
use octapass_mobile::list::{ItemFilter, ListArrangement, ListEntry, ListGrouping, ListSort};
use octapass_mobile::platform::{CredentialIdentity, DeviceLock, NativePlatform, VaultObserver};
use octapass_mobile::qr::{qr_choices, scanned_draft};
use octapass_mobile::safe::safe_root_id;
use octapass_mobile::sharing::{VaultRole, VaultType};
use octapass_mobile::ssh::{SshKeyKind, with_ssh_key};
use octapass_mobile::tools::totp_code;
use octapass_mobile::transfer::{ExportFormat, ImportSource};
use octapass_mobile::vault::{
    DevicePlatform, PendingTwoStep, SessionSnapshot, SessionStatus, SignInResult, SyncState,
    SyncStatus, TwoStepMethod, TwoStepProof, VaultConfig,
};
use octapass_mobile::{ErrorCode, OctaPassVault, Result, VaultError};
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery staple";

struct Server {
    url: String,
    state: octapass_server::AppState,
    _data: TempDir,
    runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (url, state) = runtime.block_on(async {
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
            let app = octapass_server::router(state.clone())
                .into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (url, state)
        });
        Self {
            url,
            state,
            _data: data,
            runtime,
        }
    }

    /// Waits for an `async` call, as Swift's `await` would.
    fn wait<T>(&self, call: impl Future<Output = Result<T>>) -> T {
        self.runtime.block_on(call).unwrap()
    }

    fn fail<T: std::fmt::Debug>(&self, call: impl Future<Output = Result<T>>) -> ErrorCode {
        self.runtime.block_on(call).unwrap_err().code()
    }

    /// The authenticator's current code by the server's clock. Each code works once, so the
    /// clock then moves on.
    fn totp(&self, secret: &str) -> String {
        let now = u64::try_from(self.state.clock.now()).unwrap();
        let code = totp_code(secret.into(), Some(now)).unwrap().code;
        self.state.clock.advance(Duration::from_secs(30));
        code
    }
}

/// The Keychain and the device lock, in memory.
#[derive(Default)]
struct Platform {
    secrets: Mutex<HashMap<String, String>>,
    device_secrets: Mutex<HashMap<String, Vec<u8>>>,
    stay_unlocked: Mutex<HashMap<String, Vec<u8>>>,
    identities: Mutex<Vec<CredentialIdentity>>,
    cancel_next_prompt: Mutex<bool>,
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
        if std::mem::take(&mut *self.cancel_next_prompt.lock().unwrap()) {
            return Err(ErrorCode::DeviceUnlockCancelled.into());
        }
        self.device_secrets
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .ok_or_else(|| VaultError::new(ErrorCode::DeviceUnlockFailed, "no secret"))
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

    fn set_credential_identities(&self, identities: Vec<CredentialIdentity>) -> Result<()> {
        *self.identities.lock().unwrap() = identities;
        Ok(())
    }
}

#[derive(Default)]
struct Events {
    sessions: Mutex<Vec<SessionSnapshot>>,
    items: AtomicUsize,
    syncs: Mutex<Vec<SyncState>>,
    sharing: AtomicUsize,
}

impl VaultObserver for Events {
    fn session_changed(&self, snapshot: SessionSnapshot) {
        self.sessions.lock().unwrap().push(snapshot);
    }

    fn items_changed(&self) {
        self.items.fetch_add(1, Ordering::Relaxed);
    }

    fn sync_changed(&self, state: SyncState) {
        self.syncs.lock().unwrap().push(state);
    }

    fn sharing_changed(&self) {
        self.sharing.fetch_add(1, Ordering::Relaxed);
    }
}

struct Phone {
    vault: Arc<OctaPassVault>,
    platform: Arc<Platform>,
    events: Arc<Events>,
    email: String,
    dir: TempDir,
}

impl Phone {
    fn new(server: &Server, email: &str) -> Self {
        Self::open(server, email, Arc::default(), tempfile::tempdir().unwrap())
    }

    fn open(server: &Server, email: &str, platform: Arc<Platform>, dir: TempDir) -> Self {
        let events = Arc::new(Events::default());
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
            platform.clone(),
            events.clone(),
        )
        .unwrap();
        Self {
            vault,
            platform,
            events,
            email: email.into(),
            dir,
        }
    }

    fn v(&self) -> Arc<OctaPassVault> {
        self.vault.clone()
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().status
    }

    /// Signs up and returns the Secret Key.
    fn sign_up(&self, server: &Server) -> String {
        let started = server.wait(self.v().start_signup(
            server.url.clone(),
            self.email.clone(),
            PASSWORD.into(),
        ));
        let code = started.dev_verification_code.expect("a development server");
        let kit = server.wait(self.v().finish_signup(started.signup_id, code));
        assert_eq!(kit.email, self.email);
        assert!(kit.secret_key.starts_with("OP1-"));
        kit.secret_key
    }

    fn personal(&self, server: &Server) -> String {
        server
            .wait(self.v().list_vaults())
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .unwrap()
            .id
    }

    fn save(&self, server: &Server, draft: ItemDraft) -> octapass_mobile::items::Item {
        server.wait(self.v().save_item(draft))
    }

    fn titles(&self, server: &Server, filter: ItemFilter) -> Vec<String> {
        let mut titles: Vec<String> = server
            .wait(self.v().list_items(filter))
            .into_iter()
            .map(|item| item.title)
            .collect();
        titles.sort();
        titles
    }
}

fn login(title: &str, vault_id: &str, username: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.into(),
        urls: vec![format!("https://{}.example", title.to_lowercase())],
        details: ItemDetails::Login {
            login: LoginDetails {
                username: Some(username.into()),
                password: Some(password.into()),
                ..LoginDetails::default()
            },
        },
        ..new_item_draft(ItemType::Login, vault_id.into())
    }
}

#[test]
fn accounts_two_step_and_device_unlock() {
    let server = Server::start();
    let phone = Phone::new(&server, "ada@example.com");
    assert_eq!(phone.status(), SessionStatus::SignedOut);
    assert_eq!(
        server
            .wait(phone.v().server_info(server.url.clone()))
            .api_version,
        1
    );
    let secret_key = phone.sign_up(&server);
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    assert_eq!(server.wait(phone.v().secret_key()), secret_key);
    let seen = phone.events.sessions.lock().unwrap().clone();
    assert_eq!(seen.last().unwrap().status, SessionStatus::Unlocked);

    // Lock, then the master password and the device lock.
    phone.vault.lock();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert_eq!(
        server.fail(phone.v().unlock("wrong".into())),
        ErrorCode::InvalidCredentials
    );
    server.wait(phone.v().unlock(PASSWORD.into()));
    let methods = server.wait(phone.v().unlock_methods());
    assert!(methods.device_unlock_supported && !methods.device_unlock_enabled);
    server.wait(phone.v().enable_device_unlock());
    phone.vault.lock();
    *phone.platform.cancel_next_prompt.lock().unwrap() = true;
    assert_eq!(
        server.fail(phone.v().unlock_with_device()),
        ErrorCode::DeviceUnlockCancelled
    );
    server.wait(phone.v().unlock_with_device());
    assert_eq!(phone.status(), SessionStatus::Unlocked);
    server.wait(phone.v().confirm_user(None));
    assert_eq!(
        server.fail(phone.v().confirm_user(Some("wrong".into()))),
        ErrorCode::InvalidCredentials
    );

    // Two-step sign-in on, then a new phone needs the second step.
    let setup = server.wait(phone.v().start_totp_setup(PASSWORD.into()));
    assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
    let codes = server
        .wait(phone.v().confirm_totp_setup(server.totp(&setup.secret)))
        .expect("recovery codes the first time");
    assert!(!codes.is_empty());
    assert!(server.wait(phone.v().two_step_status()).enabled);

    let other = Phone::new(&server, "ada@example.com");
    assert_eq!(
        server.fail(other.v().sign_in(
            server.url.clone(),
            other.email.clone(),
            PASSWORD.into(),
            None
        )),
        ErrorCode::SecretKeyRequired
    );
    let result = server.wait(other.v().sign_in(
        server.url.clone(),
        other.email.clone(),
        PASSWORD.into(),
        Some(secret_key.to_lowercase()),
    ));
    let SignInResult::TwoStepRequired { methods } = result else {
        panic!("a second step");
    };
    assert_eq!(methods, [TwoStepMethod::Totp, TwoStepMethod::RecoveryCode]);
    assert!(matches!(
        other.vault.pending_two_step(),
        Some(PendingTwoStep::Required { .. })
    ));
    assert_eq!(
        server.fail(other.v().finish_two_step(TwoStepProof::Totp {
            code: "000000".into()
        })),
        ErrorCode::InvalidTwoStepCode
    );
    server.wait(other.v().finish_two_step(TwoStepProof::RecoveryCode {
        code: codes[0].clone(),
    }));
    assert_eq!(other.status(), SessionStatus::Unlocked);
    assert!(other.vault.pending_two_step().is_none());

    // Devices and the security log.
    let devices = server.wait(other.v().list_devices());
    assert_eq!(devices.len(), 2);
    server.wait(other.v().rename_device("Ada's iPad".into()));
    assert_eq!(
        server.fail(other.v().rename_device(" ".into())),
        ErrorCode::InvalidInput
    );
    let devices = server.wait(other.v().list_devices());
    let mine = devices.iter().find(|d| d.current).unwrap();
    assert_eq!(mine.name, "Ada's iPad");
    let theirs = devices.iter().find(|d| !d.current).unwrap().id.clone();
    let events: Vec<String> = server
        .wait(other.v().security_log())
        .into_iter()
        .map(|e| e.event_type)
        .collect();
    assert!(events.contains(&"two-step-enabled".to_owned()));
    assert!(events.contains(&"recovery-code-used".to_owned()));
    server.wait(other.v().forget_trusted_devices());
    server.wait(other.v().sign_out_device(theirs));
    assert_eq!(server.wait(other.v().list_devices()).len(), 1);

    server.wait(other.v().disable_two_step(PASSWORD.into()));
    assert!(!server.wait(other.v().two_step_status()).enabled);
    let summary = server.wait(other.v().account_summary());
    assert_eq!(
        (summary.email.as_str(), summary.vault_count),
        ("ada@example.com", 1)
    );

    // Signing out forgets the account here; deleting it forgets it everywhere.
    server.wait(other.v().sign_out());
    assert_eq!(other.status(), SessionStatus::SignedOut);
    assert!(other.platform.secrets.lock().unwrap().is_empty());
    let later = Phone::new(&server, "ada@example.com");
    server.wait(later.v().sign_in(
        server.url.clone(),
        later.email.clone(),
        PASSWORD.into(),
        Some(secret_key),
    ));
    assert_eq!(
        server.fail(
            later
                .v()
                .delete_account("someone@else.example".into(), PASSWORD.into())
        ),
        ErrorCode::EmailMismatch
    );
    server.wait(
        later
            .v()
            .delete_account(later.email.clone(), PASSWORD.into()),
    );
    assert_eq!(later.status(), SessionStatus::SignedOut);
}

#[test]
fn items_lists_attachments_and_transfers() {
    let server = Server::start();
    let phone = Phone::new(&server, "grace@example.com");
    phone.sign_up(&server);
    let personal = phone.personal(&server);

    // One of each type.
    let github = phone.save(&server, login("GitHub", &personal, "grace", "hunter2"));
    assert_eq!(github.subtitle.as_deref(), Some("grace"));
    let mut wifi = scanned_draft(
        "WIFI:T:WPA;S:Home;P:wifi-password;;".into(),
        personal.clone(),
    )
    .unwrap();
    wifi.tags = vec!["home".into()];
    let wifi = phone.save(&server, wifi);
    assert_eq!(wifi.wifi.as_ref().unwrap().ssid, "Home");
    let note = phone.save(
        &server,
        ItemDraft {
            title: "Ideas".into(),
            details: ItemDetails::SecureNote {
                note: SecureNoteDetails {
                    notes: "Écrire".into(),
                },
            },
            ..new_item_draft(ItemType::SecureNote, personal.clone())
        },
    );
    let card = phone.save(
        &server,
        ItemDraft {
            title: "Visa".into(),
            details: ItemDetails::Card {
                card: CardDetails {
                    number: Some("4111 1111 1111 1111".into()),
                    expiry: Some("01/30".into()),
                    ..CardDetails::default()
                },
            },
            ..new_item_draft(ItemType::Card, personal.clone())
        },
    );
    assert_eq!(card.subtitle.as_deref(), Some("Visa ending 1111"));
    let identity = phone.save(
        &server,
        ItemDraft {
            title: "Me".into(),
            details: ItemDetails::Identity {
                identity: IdentityDetails {
                    first_name: Some("Grace".into()),
                    email: Some("grace@example.com".into()),
                    ..IdentityDetails::default()
                },
            },
            ..new_item_draft(ItemType::Identity, personal.clone())
        },
    );
    let document = phone.save(
        &server,
        ItemDraft {
            title: "Lease".into(),
            details: ItemDetails::Document {
                document: DocumentDetails {
                    notes: Some("signed".into()),
                },
            },
            ..new_item_draft(ItemType::Document, personal.clone())
        },
    );
    let invalid = ItemDraft {
        title: " ".into(),
        ..new_item_draft(ItemType::Login, personal.clone())
    };
    assert_eq!(
        server.fail(phone.v().save_item(invalid)),
        ErrorCode::InvalidInput
    );

    // Editing keeps the old password, and a stale revision becomes a conflicting copy.
    let mut draft = item_draft(github.clone());
    if let ItemDetails::Login { login } = &mut draft.details {
        login.password = Some("new-password".into());
        login.custom_fields.push(CustomField {
            label: "PIN".into(),
            value: "1234".into(),
            hidden: true,
        });
    }
    let edited = phone.save(&server, draft.clone());
    let ItemDetails::Login {
        login: edited_login,
    } = &edited.details
    else {
        panic!("a login")
    };
    assert_eq!(edited_login.password_history[0].password, "hunter2");
    phone.save(
        &server,
        ItemDraft {
            title: "GitHub".into(),
            ..draft
        },
    );
    let favourite = server.wait(phone.v().set_favorite(edited.id.clone(), true));
    assert!(favourite.favorite);

    // Lists: filters, search, order and sections.
    let all = phone.titles(&server, ItemFilter::default());
    assert_eq!(
        all,
        [
            "GitHub",
            "GitHub (conflicting copy)",
            "Home",
            "Ideas",
            "Lease",
            "Me",
            "Visa"
        ]
    );
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                query: Some("ecrire".into()),
                ..ItemFilter::default()
            }
        ),
        Vec::<String>::new(),
        "notes aren't searched"
    );
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                query: Some("grace".into()),
                ..ItemFilter::default()
            }
        ),
        ["GitHub", "GitHub (conflicting copy)", "Me"]
    );
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                favorites: true,
                ..ItemFilter::default()
            }
        ),
        ["GitHub"]
    );
    let sections = server.wait(phone.v().arrange_items(
        ItemFilter::default(),
        ListSort::Name,
        ListGrouping::Type,
        false,
    ));
    let keys: Vec<&str> = sections.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(
        keys,
        // "Home", a password item with an SSID field, was moved to the Wi-Fi type.
        [
            "login",
            "card",
            "identity",
            "secureNote",
            "wifi",
            "document"
        ]
    );
    let letters = server.wait(phone.v().arrange_items(
        ItemFilter::default(),
        ListSort::NameDesc,
        ListGrouping::Letter,
        false,
    ));
    assert_eq!(letters[0].key, "V");

    // The trash.
    server.wait(phone.v().delete_item(note.id.clone()));
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                trash: true,
                ..ItemFilter::default()
            }
        ),
        ["Ideas"]
    );
    server.wait(phone.v().restore_item(note.id.clone()));
    assert!(
        phone
            .titles(
                &server,
                ItemFilter {
                    trash: true,
                    ..ItemFilter::default()
                }
            )
            .is_empty()
    );

    // QR codes.
    let choices: Vec<String> = qr_choices(server.wait(phone.v().get_item(wifi.id.clone())))
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(choices, ["wifi", "password"]);
    assert_eq!(qr_choices(identity.clone())[0].kind, "contact");

    // Attachments: added from a path, opened to a path, removed.
    let picked = phone.dir.path().join("lease.pdf");
    std::fs::write(&picked, b"%PDF-1.7 lease").unwrap();
    let with_file = server.wait(phone.v().add_attachment(
        document.id.clone(),
        picked.to_string_lossy().into(),
        "lease.pdf".into(),
        "application/pdf".into(),
    ));
    assert_eq!(with_file.attachments.len(), 1);
    let file = with_file.attachments[0].clone();
    let opened = server.wait(
        phone
            .v()
            .open_attachment(document.id.clone(), file.id.clone()),
    );
    assert!(opened.ends_with("lease.pdf"));
    assert_eq!(std::fs::read(&opened).unwrap(), b"%PDF-1.7 lease");
    phone.vault.close_attachment(opened.clone());
    assert!(!std::path::Path::new(&opened).exists());
    let usage = server.wait(phone.v().storage_usage());
    assert!(usage.attachment_bytes > 0 && usage.max_file_bytes > 0);
    server.wait(phone.v().sync());
    let state = phone.vault.sync_state();
    assert_eq!(
        (state.status, state.pending_files, state.pending_changes),
        (SyncStatus::Idle, 0, false)
    );
    assert!(state.last_synced_at.is_some());

    // Health: a reused password, no breach check without Pwned Passwords.
    phone.save(&server, login("Forum", &personal, "grace", "new-password"));
    let report = server.wait(phone.v().health_report());
    assert!(!report.breach_check_completed);
    assert_eq!(report.reused.len(), 1);
    assert!(report.score < 100);

    // Dismissing a reused group: gone from the report and the score, kept in a hidden item.
    let before = server
        .wait(phone.v().list_items(ItemFilter::default()))
        .len();
    let keys: Vec<String> = report.reused[0]
        .iter()
        .map(|entry| entry.warning.clone().unwrap())
        .collect();
    server.wait(phone.v().dismiss_health_warnings(keys.clone()));
    let quiet = server.wait(phone.v().health_report());
    assert!(quiet.reused.is_empty());
    assert_eq!(quiet.dismissed.len(), keys.len());
    assert_eq!(
        server
            .wait(phone.v().list_items(ItemFilter::default()))
            .len(),
        before,
        "the settings item is never listed"
    );
    server.wait(phone.v().restore_health_warnings(keys));
    assert_eq!(server.wait(phone.v().health_report()).reused.len(), 1);

    // Alerts are off until asked for, and this server has no HIBP key.
    assert!(!server.wait(phone.v().email_breach_checks_available()));
    assert_eq!(
        server.wait(phone.v().check_email_breaches(true)),
        EmailBreachCheck::Off
    );
    server.wait(phone.v().set_email_breach_alerts(true));
    assert_eq!(
        server.wait(phone.v().check_email_breaches(true)),
        EmailBreachCheck::Failed,
        "the server answers 404 without a key, and the last results stay"
    );
    let on = server.wait(phone.v().health_report());
    assert!(on.email_alerts_enabled && on.email_breaches_checked_at.is_none());
    server.wait(phone.v().set_email_breach_alerts(false));

    // A new password from Health: the old one goes to the history.
    let forum = report.reused[0]
        .iter()
        .find(|entry| entry.title == "Forum")
        .unwrap();
    server.wait(
        phone
            .v()
            .update_password(forum.item_id.clone(), "Xq7!vP2#mK9$wL4@zR".into()),
    );
    let saved = server.wait(phone.v().get_item(forum.item_id.clone()));
    let ItemDetails::Login { login: saved } = saved.details else {
        panic!("a login");
    };
    assert_eq!(saved.password.as_deref(), Some("Xq7!vP2#mK9$wL4@zR"));
    assert_eq!(saved.password_history[0].password, "new-password");
    let after = server.wait(phone.v().health_report());
    assert!(
        !after
            .reused
            .iter()
            .flatten()
            .any(|entry| entry.item_id == forum.item_id),
        "the new password isn't reused"
    );

    // Exports, then imports into a second account.
    let json = server.wait(
        phone
            .v()
            .export_vault(ExportFormat::Json, None, Some(PASSWORD.into())),
    );
    assert!(json.ends_with(".json"));
    let text = std::fs::read_to_string(&json).unwrap();
    assert!(text.contains("\"format\": \"octapass-export\"") && text.contains("new-password"));
    let csv = server.wait(phone.v().export_vault(ExportFormat::Csv, None, None));
    assert!(
        std::fs::read_to_string(&csv)
            .unwrap()
            .starts_with("vault,type,title")
    );
    let cxf = server.wait(phone.v().export_vault(ExportFormat::Cxf, None, None));
    assert!(cxf.ends_with(".cxf.json"));
    assert_eq!(
        server.fail(
            phone
                .v()
                .export_vault(ExportFormat::Json, None, Some("wrong".into()))
        ),
        ErrorCode::InvalidCredentials
    );
    let encrypted = server.wait(phone.v().export_vault(
        ExportFormat::Encrypted,
        Some("export pass".into()),
        None,
    ));
    // Each export is in the security log, naming this phone; the refused one isn't.
    let exports: Vec<_> = server
        .wait(phone.v().security_log())
        .into_iter()
        .filter(|e| e.event_type == "vault-exported")
        .collect();
    assert_eq!(
        exports
            .iter()
            .map(|e| (e.export_format, e.export_attachments))
            .collect::<Vec<_>>(),
        [
            (Some(ExportFormat::Encrypted), Some(true)),
            (Some(ExportFormat::Cxf), Some(false)),
            (Some(ExportFormat::Csv), Some(false)),
            (Some(ExportFormat::Json), Some(false)),
        ]
    );
    assert!(
        exports
            .iter()
            .all(|e| e.device_name.is_some() && e.device_platform.is_some())
    );

    let other = Phone::new(&server, "hopper@example.com");
    other.sign_up(&server);
    let imported = server.wait(other.v().import_file(
        ImportSource::OctaPass,
        json.clone(),
        None,
        None,
    ));
    assert_eq!(imported.imported, 8);
    let other_2 = Phone::new(&server, "lovelace@example.com");
    other_2.sign_up(&server);
    assert_eq!(
        server.fail(
            other_2
                .v()
                .import_file(ImportSource::OctaPass, encrypted.clone(), None, None)
        ),
        ErrorCode::ImportPasswordRequired
    );
    let restored = server.wait(other_2.v().import_file(
        ImportSource::OctaPass,
        encrypted,
        Some("export pass".into()),
        None,
    ));
    assert_eq!((restored.imported, restored.files), (8, 1));

    // Settings and locking.
    let mut settings = phone.vault.settings();
    assert_eq!(settings.auto_lock_minutes, 15);
    // Stay unlocked (plan 18) is on for a new install; off, the lock settings apply again.
    assert!(settings.stay_unlocked);
    settings.stay_unlocked = false;
    settings.lock_on_background = true;
    settings.list_sort = ListSort::Newest;
    phone.vault.update_settings(settings.clone()).unwrap();
    settings.auto_lock_minutes = 7;
    assert_eq!(
        phone.vault.update_settings(settings).unwrap_err().code(),
        ErrorCode::InvalidInput
    );
    phone.vault.app_did_enter_background();
    assert_eq!(phone.status(), SessionStatus::Locked);
    assert!(
        !std::path::Path::new(&json).exists(),
        "locking deletes exported files"
    );
    let restarted = Phone::open(&server, &phone.email, phone.platform.clone(), phone.dir);
    assert_eq!(restarted.vault.settings().list_sort, ListSort::Newest);
    assert_eq!(restarted.status(), SessionStatus::Locked);
    assert!(phone.events.items.load(Ordering::Relaxed) > 0);
}

#[test]
fn sharing_families_links_and_emergency_access() {
    let server = Server::start();
    let alice = Phone::new(&server, "alice@example.com");
    let bob = Phone::new(&server, "bob@example.com");
    alice.sign_up(&server);
    bob.sign_up(&server);
    let personal = alice.personal(&server);

    // Alice compares Bob's fingerprint, then shares a vault with him.
    let lookup = server.wait(alice.v().lookup_account("Bob@Example.com".into()));
    assert_eq!(lookup.fingerprint, server.wait(bob.v().my_fingerprint()));
    assert_eq!(
        server.fail(alice.v().lookup_account("nobody@example.com".into())),
        ErrorCode::AccountNotFound
    );
    server.wait(alice.v().mark_verified(lookup.clone()));
    let vault = server.wait(alice.v().create_vault("Family recipes".into()));
    assert_eq!(
        (vault.name.as_str(), vault.role, vault.untrusted),
        ("Family recipes", VaultRole::Owner, false)
    );
    let mut forged = lookup.clone();
    forged.fingerprint.digits = "0000 0000 0000 0000 0000 0000".into();
    assert_eq!(
        server.fail(
            alice
                .v()
                .add_member(vault.id.clone(), forged, VaultRole::Write)
        ),
        ErrorCode::UntrustedVault
    );
    server.wait(
        alice
            .v()
            .add_member(vault.id.clone(), lookup.clone(), VaultRole::Write),
    );
    let pasta = alice.save(&server, login("Pasta", &vault.id, "chef", "al-dente"));
    let members = server.wait(alice.v().list_members(vault.id.clone()));
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m.verified));
    assert!(alice.events.sharing.load(Ordering::Relaxed) > 0);

    server.wait(bob.v().sync());
    let bobs: Vec<String> = server
        .wait(bob.v().list_vaults())
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(bobs, ["Personal", "Family recipes"]);
    let seen = server.wait(bob.v().get_item(pasta.id.clone()));
    let ItemDetails::Login { login } = &seen.details else {
        panic!("a login")
    };
    assert_eq!(login.password.as_deref(), Some("al-dente"));
    bob.save(&server, login_for(&vault.id, "Soup"));
    assert!(
        server
            .wait(bob.v().list_items(ItemFilter::default()))
            .iter()
            .all(|i| i.title != "Family recipes"),
        "a vault's name isn't an item"
    );

    // Read-only, then copies and moves between vaults.
    server.wait(alice.v().change_role(
        vault.id.clone(),
        lookup.account_id.clone(),
        VaultRole::Read,
    ));
    server.wait(bob.v().sync());
    assert_eq!(
        server.fail(bob.v().save_item(login_for(&vault.id, "Stew"))),
        ErrorCode::ReadOnlyVault
    );
    let copy = server.wait(alice.v().copy_item(pasta.id.clone(), personal.clone()));
    assert_eq!(copy.vault_id, personal);
    let moved = server.wait(alice.v().move_item(copy.id.clone(), vault.id.clone()));
    assert_eq!(moved.vault_id, vault.id);

    // Removing Bob rotates the key; he loses the vault, Alice keeps reading it.
    server.wait(
        alice
            .v()
            .remove_member(vault.id.clone(), lookup.account_id.clone()),
    );
    server.wait(bob.v().sync());
    assert_eq!(server.wait(bob.v().list_vaults()).len(), 1);
    server.wait(alice.v().sync());
    assert_eq!(
        server.wait(alice.v().get_item(pasta.id.clone())).title,
        "Pasta"
    );
    server.wait(alice.v().rename_vault(vault.id.clone(), "Recipes".into()));
    assert!(
        server
            .wait(alice.v().list_vaults())
            .iter()
            .any(|v| v.name == "Recipes")
    );

    // A family: invite, accept, the Family vault, then leaving.
    server.wait(alice.v().create_family());
    server.wait(alice.v().invite_to_family(lookup.clone()));
    let invitations = server.wait(bob.v().get_family()).invitations;
    assert_eq!(invitations.len(), 1);
    server.wait(
        bob.v()
            .accept_family_invite(invitations[0].family_id.clone()),
    );
    let family = server.wait(bob.v().get_family()).family.unwrap();
    assert!(!family.is_organiser && family.members.len() == 2);
    assert!(
        server
            .wait(bob.v().list_vaults())
            .iter()
            .any(|v| v.vault_type == VaultType::Family)
    );
    server.wait(alice.v().remove_family_member(lookup.account_id.clone()));
    server.wait(bob.v().sync());
    assert!(server.wait(bob.v().get_family()).family.is_none());
    server.wait(alice.v().delete_family());

    // A share link, opened without an account.
    let link = server.wait(alice.v().create_share_link(
        pasta.id.clone(),
        ShareLinkOptions {
            expires_in_hours: 24,
            max_views: 2,
            passphrase: Some("open sesame".into()),
        },
    ));
    assert!(link.url.starts_with("https://vault.octap.app/s/"));
    let address = parse_share_link_url(link.url.clone(), "https://vault.octap.app".into()).unwrap();
    assert_eq!(address.key, link.key);
    assert_eq!(
        address.server_url, server.url,
        "a link from another server names it"
    );
    let links = server.wait(alice.v().list_share_links());
    assert_eq!(links[0].item_title.as_deref(), Some("Pasta"));
    let stranger = Phone::new(&server, "eve@example.com");
    let envelope = server.wait(
        stranger
            .v()
            .fetch_share_link(address.server_url.clone(), address.id.clone()),
    );
    assert!(envelope.passphrase_required);
    assert_eq!(
        server.fail(stranger.v().open_share_link(
            envelope.ciphertext.clone(),
            address.key.clone(),
            Some("wrong".into())
        )),
        ErrorCode::WrongPassphrase
    );
    let shared = server.wait(stranger.v().open_share_link(
        envelope.ciphertext,
        address.key,
        Some("open sesame".into()),
    ));
    assert_eq!(shared.title, "Pasta");
    server.wait(alice.v().revoke_share_link(link.id.clone()));
    assert_eq!(
        server.fail(stranger.v().fetch_share_link(server.url.clone(), link.id)),
        ErrorCode::NotFound
    );

    // Emergency access: Bob asks, the waiting period passes, he reads Alice's vaults.
    let contact = server.wait(alice.v().add_emergency_contact(
        lookup.clone(),
        1,
        EmergencyAccessLevel::View,
        EmergencyScope::Account,
    ));
    assert_eq!(contact.status, EmergencyStatus::Idle);
    let received = server.wait(bob.v().list_emergency_contacts()).received;
    assert_eq!(received.len(), 1);
    assert_eq!(
        server.fail(bob.v().open_emergency_access(contact.id.clone())),
        ErrorCode::NotAllowed
    );
    server.wait(bob.v().request_emergency_access(contact.id.clone()));
    server.state.clock.advance(Duration::from_secs(2 * 86_400));
    let view = server.wait(bob.v().open_emergency_access(contact.id.clone()));
    let titles: Vec<&str> = view.items.iter().map(|i| i.title.as_str()).collect();
    assert!(titles.contains(&"Pasta"), "{titles:?}");
    assert!(view.vaults.iter().any(|v| v.name == "Recipes"));
    server.wait(alice.v().remove_emergency_contact(contact.id));
    assert!(
        server
            .wait(alice.v().list_emergency_contacts())
            .granted
            .is_empty()
    );
}

fn login_for(vault_id: &str, title: &str) -> ItemDraft {
    login(title, vault_id, "cook", "secret")
}

#[test]
fn ssh_keys_and_environments_through_the_vault() {
    let server = Server::start();
    let phone = Phone::new(&server, "dev@example.com");
    phone.sign_up(&server);
    let vault_id = phone.personal(&server);

    // A key generated on the phone, saved, and read back whole. The comment names it.
    let made = server.wait(
        phone
            .v()
            .generate_ssh_key(SshKeyKind::Ed25519, "me@phone".into()),
    );
    let draft = new_item_draft(ItemType::SshKey, vault_id.clone());
    let ItemDetails::SshKey { key } = draft.details.clone() else {
        panic!("an SSH key draft");
    };
    let saved = phone.save(
        &server,
        ItemDraft {
            details: ItemDetails::SshKey {
                key: with_ssh_key(key, made.clone(), None),
            },
            ..draft
        },
    );
    assert_eq!(saved.title, "me@phone");
    assert_eq!(saved.subtitle.as_deref(), Some(made.fingerprint.as_str()));
    let ItemDetails::SshKey { key } = &saved.details else {
        panic!("typed as an SSH key: {:?}", saved.details);
    };
    assert_eq!(key.private_key.as_deref(), Some(made.private_key.as_str()));

    // A copy on disk needs its passphrase, and the file is gone once it's closed.
    let path = server.wait(phone.v().export_ssh_key(
        key.clone(),
        "id_test".into(),
        Some("hunter2".into()),
    ));
    assert!(path.ends_with("id_test"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        server.fail(phone.v().read_ssh_key(text.clone(), None)),
        ErrorCode::SshPassphraseRequired
    );
    let opened = server.wait(phone.v().read_ssh_key(text, Some("hunter2".into())));
    assert_eq!(opened.fingerprint, made.fingerprint);
    phone.v().close_attachment(path.clone());
    assert!(!std::path::Path::new(&path).exists());

    // Two stages of a project: grouped by it, filtered, searched by variable name.
    let environment = |title: &str, stage: &str, keys: &[&str]| ItemDraft {
        title: title.into(),
        details: ItemDetails::Environment {
            environment: EnvironmentDetails {
                project: Some("shop-api".into()),
                stage: Some(stage.into()),
                variables: keys
                    .iter()
                    .map(|key| EnvironmentVariable {
                        key: (*key).into(),
                        value: "s3cret".into(),
                        concealed: true,
                        note: None,
                    })
                    .collect(),
                ..EnvironmentDetails::default()
            },
        },
        ..new_item_draft(ItemType::Environment, vault_id.clone())
    };
    let production = phone.save(
        &server,
        environment("Shop production", "production", &["API_KEY"]),
    );
    phone.save(
        &server,
        environment("Shop staging", "staging", &["API_KEY", "DEBUG"]),
    );
    phone.save(&server, new_item_draft_named(&vault_id, "Loose"));
    assert_eq!(
        production.subtitle.as_deref(),
        Some("shop-api · production")
    );

    let filter = ItemFilter {
        item_type: Some(ItemType::Environment),
        ..ItemFilter::default()
    };
    let sections = server.wait(phone.v().arrange_items(
        filter.clone(),
        ListSort::Name,
        ListGrouping::Project,
        false,
    ));
    let keys: Vec<&str> = sections.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(keys, ["shop-api", ""], "no project comes last");

    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                stage: Some("staging".into()),
                ..filter.clone()
            }
        ),
        ["Shop staging"]
    );
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                query: Some("debug".into()),
                ..ItemFilter::default()
            }
        ),
        ["Shop staging"],
        "variable names are searched"
    );
    assert!(
        phone
            .titles(
                &server,
                ItemFilter {
                    query: Some("s3cret".into()),
                    ..ItemFilter::default()
                }
            )
            .is_empty(),
        "values never are"
    );

    let ItemDetails::Environment { environment } = &production.details else {
        panic!("typed as an environment");
    };
    let all = server.wait(phone.v().list_items(filter));
    assert_eq!(
        missing_environment_keys(production.id.clone(), environment.clone(), all),
        ["DEBUG"]
    );

    // Saving the file: the path keeps its name, ready for the share sheet.
    let text = environment_dotenv(environment.clone()).unwrap();
    let path = server.wait(phone.v().write_share_file("Shop.env".into(), text));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "API_KEY=s3cret\n");
    phone.v().close_attachment(path);
}

fn new_item_draft_named(vault_id: &str, title: &str) -> ItemDraft {
    ItemDraft {
        title: title.into(),
        ..new_item_draft(ItemType::Environment, vault_id.into())
    }
}

#[test]
fn wifi_site_rows_codes_and_items_from_other_apps() {
    let server = Server::start();
    let phone = Phone::new(&server, "katherine@example.com");
    phone.sign_up(&server);
    let personal = phone.personal(&server);

    // Wi-Fi networks are their own type, named after the network, with Connect and a code.
    let wifi = phone.save(
        &server,
        ItemDraft {
            details: ItemDetails::Wifi {
                wifi: WifiDetails {
                    ssid: "Cafe".into(),
                    password: Some("espresso1".into()),
                    ..WifiDetails::default()
                },
            },
            ..new_item_draft(ItemType::Wifi, personal.clone())
        },
    );
    assert_eq!(
        (wifi.item_type.clone(), wifi.title.as_str()),
        (ItemType::Wifi, "Cafe")
    );
    assert_eq!(
        wifi.wifi.as_ref().unwrap().password.as_deref(),
        Some("espresso1")
    );
    assert_eq!(qr_choices(wifi.clone())[0].id, "wifi");
    let scanned = scanned_draft("WIFI:T:WPA;S:Home;P:hunter22;;".into(), personal.clone()).unwrap();
    assert_eq!(phone.save(&server, scanned).item_type, ItemType::Wifi);
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                item_type: Some(ItemType::Wifi),
                ..ItemFilter::default()
            }
        ),
        ["Cafe", "Home"]
    );

    // Two logins for one website share a row; the One-time codes list has only logins with one.
    phone.save(&server, login("Work", &personal, "kj", "pw"));
    let mut personal_login = login("Personal", &personal, "kat", "pw");
    personal_login.urls = vec!["https://www.work.example/login".into()];
    if let ItemDetails::Login { login } = &mut personal_login.details {
        login.totp = Some("JBSWY3DPEHPK3PXP".into());
    }
    phone.save(&server, personal_login);
    let sections = server.wait(phone.v().arrange_items(
        ItemFilter::default(),
        ListSort::Name,
        ListGrouping::None,
        true,
    ));
    let sites: Vec<(String, usize)> = sections[0]
        .entries
        .iter()
        .filter_map(|entry| match entry {
            ListEntry::Site { host, items } => Some((host.clone(), items.len())),
            ListEntry::Item { .. } => None,
        })
        .collect();
    assert_eq!(sites, [("work.example".to_owned(), 2)]);
    assert_eq!(
        phone.titles(
            &server,
            ItemFilter {
                totp: true,
                ..ItemFilter::default()
            }
        ),
        ["Personal"]
    );

    // A scanned one-time code goes through the import review and joins the login picked.
    let work = phone
        .titles(&server, ItemFilter::default())
        .into_iter()
        .find(|t| t == "Work")
        .unwrap();
    assert_eq!(work, "Work");
    let work_id = server
        .wait(phone.v().list_items(ItemFilter {
            query: Some("Work".into()),
            ..ItemFilter::default()
        }))
        .into_iter()
        .find(|item| item.title == "Work")
        .unwrap()
        .id;
    let scan = octapass_mobile::qr::summarize_qr_scans(vec![
        "otpauth://totp/Work:kj?secret=JBSWY3DPEHPK3PXQ&issuer=Work".into(),
        "https://example.com".into(),
    ]);
    assert_eq!((scan.codes.len(), scan.other), (1, 1));
    let review = server.wait(
        phone
            .v()
            .review_scanned_codes(scan.codes.iter().map(|c| c.uri.clone()).collect()),
    );
    assert_eq!(review.codes.len(), 1);
    server.wait(phone.v().finish_import(
        review.id.clone(),
        vec![octapass_mobile::transfer::CodeLink {
            code: review.codes[0].index,
            login_id: Some(work_id.clone()),
        }],
    ));
    let linked = server.wait(phone.v().get_item(work_id));
    let ItemDetails::Login { login } = linked.details else {
        panic!("a login")
    };
    assert!(login.totp.is_some_and(|t| t.contains("JBSWY3DPEHPK3PXQ")));
    assert_eq!(
        server.fail(phone.v().finish_import(review.id, Vec::new())),
        ErrorCode::ImportReviewExpired
    );

    // Each list remembers its own order.
    assert_eq!(
        phone.vault.list_arrangement("login".into(), 1).grouping,
        ListGrouping::Letter
    );
    let newest = ListArrangement {
        sort: ListSort::Newest,
        grouping: ListGrouping::None,
    };
    phone
        .vault
        .set_list_arrangement("login".into(), newest)
        .unwrap();
    assert_eq!(phone.vault.list_arrangement("login".into(), 1), newest);
    assert_eq!(
        phone.vault.list_arrangement("all".into(), 1).grouping,
        ListGrouping::Type
    );

    // This server has no icon endpoint: no icon, and nothing breaks.
    assert_eq!(
        server.wait(phone.v().site_icon("work.example".into())),
        None
    );

    // What another password manager hands over is previewed, then imported or discarded.
    let cxf = server.wait(phone.v().export_vault(ExportFormat::Cxf, None, None));
    let json = std::fs::read_to_string(&cxf).unwrap();
    let other = Phone::new(&server, "dorothy@example.com");
    other.sign_up(&server);
    let preview = server.wait(other.v().preview_received(json.clone(), "Passwords".into()));
    assert_eq!(preview.from, "Passwords");
    let counted: u32 = preview.items.iter().map(|c| c.count).sum();
    assert_eq!(counted, 4);
    other.vault.discard_received();
    assert_eq!(
        server.fail(other.v().import_received()),
        ErrorCode::NotFound
    );
    server.wait(other.v().preview_received(json, "Passwords".into()));
    assert_eq!(server.wait(other.v().import_received()).imported, 4);
    assert_eq!(other.titles(&server, ItemFilter::default()).len(), 4);
}

#[test]
fn a_watch_gets_codes_only_while_unlocked_and_turned_on() {
    let server = Server::start();
    let phone = Phone::new(&server, "watch@example.com");
    phone.sign_up(&server);
    let personal = phone.personal(&server);
    let with_code = |title: &str, totp: &str| {
        let mut draft = login(title, &personal, "jane-private", "password-private");
        if let ItemDetails::Login { login } = &mut draft.details {
            login.totp = Some(totp.into());
        }
        draft
    };
    phone.save(&server, with_code("Zebra", "JBSWY3DPEHPK3PXP"));
    let favourite = phone.save(&server, with_code("Yak", "JBSWY3DPEHPK3PXP"));
    server.wait(phone.v().set_favorite(favourite.id, true));
    phone.save(&server, with_code("Apple", "JBSWY3DPEHPK3PXP"));
    phone.save(&server, login("Plain", &personal, "cook", "secret"));
    let gone = phone.save(&server, with_code("Trashed", "JBSWY3DPEHPK3PXP"));
    server.wait(phone.v().delete_item(gone.id));

    let payload = |phone: &Phone| {
        let text = server
            .runtime
            .block_on(phone.v().watch_payload(Some(1_700_000_000_000)));
        serde_json::from_str::<serde_json::Value>(&text).unwrap()
    };
    let clear = serde_json::json!({ "v": 1, "clear": true, "issuedAtMs": 1_700_000_000_000u64 });

    assert!(
        !phone.vault.settings().show_codes_on_watch,
        "off until asked for"
    );
    assert_eq!(payload(&phone), clear, "turned off");

    let mut settings = phone.vault.settings();
    settings.show_codes_on_watch = true;
    phone.vault.update_settings(settings).unwrap();
    let bundle = payload(&phone);
    let titles: Vec<&str> = bundle["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["Yak", "Apple", "Zebra"],
        "favourites first, then by name"
    );
    let text = bundle.to_string();
    for leak in [
        "JBSWY3DPEHPK3PXP",
        "jane-private",
        "password-private",
        ".example",
    ] {
        assert!(!text.contains(leak), "{leak} crossed");
    }

    phone.vault.lock();
    assert_eq!(payload(&phone), clear, "locked");
}

fn safes_folder(phone: &Phone) -> String {
    phone
        .dir
        .path()
        .join("safes")
        .to_string_lossy()
        .into_owned()
}

fn second_device(server: &Server, email: &str, secret_key: String) -> Phone {
    let tablet = Phone::new(server, email);
    server.wait(tablet.v().sign_in(
        server.url.clone(),
        tablet.email.clone(),
        PASSWORD.into(),
        Some(secret_key),
    ));
    server.wait(tablet.v().sync());
    tablet
}

#[test]
fn a_safe_kept_on_one_device_stays_there() {
    let server = Server::start();
    let phone = Phone::new(&server, "ada@example.com");
    let secret_key = phone.sign_up(&server);
    let here = server.wait(phone.v().create_safe("Receipts".into(), false));
    let synced = server.wait(phone.v().create_safe("Papers".into(), true));
    assert_eq!(
        server.wait(phone.v().list_safes(Some(safes_folder(&phone)))),
        vec![synced.clone(), here.clone()]
    );
    server.wait(phone.v().sync());

    // Its item comes with the vault, its files don't: the tablet doesn't list it, open it, or make
    // a folder for it.
    let tablet = second_device(&server, "ada@example.com", secret_key);
    assert_eq!(
        server.wait(tablet.v().list_safes(Some(safes_folder(&tablet)))),
        vec![synced.clone()]
    );
    assert_eq!(server.wait(tablet.v().list_safes(None)), vec![synced]);
    let refused = server.runtime.block_on(
        tablet
            .v()
            .open_safe(here.item_id.clone(), safes_folder(&tablet)),
    );
    assert_eq!(
        refused.err().map(|error| error.code()),
        Some(ErrorCode::NotFound)
    );
    assert!(!tablet.dir.path().join("safes").join(&here.safe_id).exists());
    // The phone still has it, after a sync too.
    server.wait(phone.v().sync());
    assert!(
        server
            .wait(phone.v().list_safes(Some(safes_folder(&phone))))
            .contains(&here)
    );
}

#[test]
fn a_safe_deleted_on_another_device_deletes_here_too() {
    let server = Server::start();
    let phone = Phone::new(&server, "grace@example.com");
    let secret_key = phone.sign_up(&server);
    let made = server.wait(phone.v().create_safe("Papers".into(), true));
    let drive = server.wait(
        phone
            .v()
            .open_safe(made.item_id.clone(), safes_folder(&phone)),
    );
    drive.lock().unwrap();
    server.wait(phone.v().sync());

    let tablet = second_device(&server, "grace@example.com", secret_key);
    server.wait(
        tablet
            .v()
            .delete_safe(made.item_id.clone(), safes_folder(&tablet)),
    );

    // The phone hasn't synced since: its copy of the item is older than the server's, which the
    // server refuses. Deleting still works, and takes the folder here.
    server.wait(
        phone
            .v()
            .delete_safe(made.item_id.clone(), safes_folder(&phone)),
    );
    assert!(server.wait(phone.v().list_safes(None)).is_empty());
    assert!(!phone.dir.path().join("safes").join(&made.safe_id).exists());
}

#[test]
fn a_safe_reaches_a_second_device() {
    let server = Server::start();
    let phone = Phone::new(&server, "hedy@example.com");
    let secret_key = phone.sign_up(&server);

    let made = server.wait(phone.v().create_safe("Papers".into(), true));
    assert!(made.sync);
    assert_eq!(server.wait(phone.v().list_safes(None)), vec![made.clone()]);
    // A Safe is its own place in the app, never a row in the item lists.
    assert!(phone.titles(&server, ItemFilter::default()).is_empty());

    let folder = phone.dir.path().join("safes");
    let drive = server.wait(
        phone
            .v()
            .open_safe(made.item_id.clone(), folder.to_string_lossy().into()),
    );
    let file = drive
        .create_file(safe_root_id(), "passport.txt".into())
        .unwrap();
    drive
        .write(file.id.clone(), 0, b"my passport number".to_vec())
        .unwrap();
    drive.flush(file.id.clone()).unwrap();
    let summary = server.wait(phone.v().sync_safe(made.item_id.clone(), drive.clone()));
    assert!(summary.conflicts.is_empty() && summary.too_big.is_empty());
    server.wait(phone.v().sync());

    let tablet = Phone::new(&server, "hedy@example.com");
    server.wait(tablet.v().sign_in(
        server.url.clone(),
        tablet.email.clone(),
        PASSWORD.into(),
        Some(secret_key),
    ));
    server.wait(tablet.v().sync());
    assert_eq!(server.wait(tablet.v().list_safes(None)), vec![made.clone()]);
    let there = server.wait(tablet.v().open_safe(
        made.item_id.clone(),
        tablet.dir.path().join("safes").to_string_lossy().into(),
    ));
    assert!(there.list(safe_root_id()).unwrap().is_empty());
    server.wait(tablet.v().sync_safe(made.item_id.clone(), there.clone()));
    let seen = there.list(safe_root_id()).unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].name, "passport.txt");
    assert_eq!(
        there.read(seen[0].id.clone(), 0, 100).unwrap(),
        b"my passport number"
    );

    // And back again.
    there.create_folder(safe_root_id(), "Scans".into()).unwrap();
    server.wait(tablet.v().sync_safe(made.item_id.clone(), there.clone()));
    server.wait(phone.v().sync_safe(made.item_id, drive.clone()));
    let names: Vec<String> = drive
        .list(safe_root_id())
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"Scans".to_owned()), "{names:?}");

    // It locks with the app, and only ciphertext stays behind.
    drive.lock().unwrap();
    assert!(drive.is_locked());
    assert_eq!(
        drive.list(safe_root_id()).unwrap_err().code(),
        ErrorCode::Locked
    );
    let mut stack = vec![folder];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(8).any(|window| window == b"passport"),
                    "{path:?}"
                );
            }
        }
    }
}
