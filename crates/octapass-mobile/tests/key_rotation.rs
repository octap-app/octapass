//! Rotating the Secret Key and vault keys, emergency takeover and organiser recovery, through
//! `OctaPassVault` and the real sync server (in-process), as the native apps call them. A small
//! TCP forwarder that can be cut off plays the part of a phone going offline.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octapass_mobile::emergency::{EmergencyAccessLevel, EmergencyScope, EmergencyStatus};
use octapass_mobile::items::{ItemDetails, ItemType, LoginDetails, item_draft, new_item_draft};
use octapass_mobile::list::ItemFilter;
use octapass_mobile::platform::{CredentialIdentity, DeviceLock, NativePlatform, VaultObserver};
use octapass_mobile::vault::{
    DevicePlatform, RecoveryKit, SessionSnapshot, SessionStatus, SyncState, VaultConfig,
};
use octapass_mobile::{ErrorCode, OctaPassVault, Result};
use tempfile::TempDir;

const EMAIL: &str = "ada@example.com";
const OTHER: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a brand new master password 7";

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
            let served = state.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app =
                octapass_server::router(served).into_make_service_with_connect_info::<SocketAddr>();
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

    // No device chip and no backup folder: these tests are about accounts.
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
        Self::through(server, &server.url.clone())
    }

    /// A phone that reaches the server through `url`.
    fn through(server: &Server, url: &str) -> Self {
        let _ = server;
        let dir = tempfile::tempdir().unwrap();
        let vault = OctaPassVault::new(
            VaultConfig {
                data_dir: dir.path().join("group").to_string_lossy().into(),
                temp_dir: dir.path().join("tmp").to_string_lossy().into(),
                device_name: "Test iPhone".into(),
                platform: DevicePlatform::Ios,
                // Answers 404, so breach checks don't complete, without the internet.
                pwned_passwords_url: url.to_owned(),
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
        self.sign_up_as(server, EMAIL)
    }

    fn sign_up_as(&self, server: &Server, email: &str) -> RecoveryKit {
        let started = server.wait(self.v().start_signup(
            server.url.clone(),
            email.into(),
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

/// Forwards TCP to the server until cut off. The HTTP client keeps connections open, so cutting
/// off has to end those too, not just refuse new ones.
struct Forwarder {
    url: String,
    online: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Forwarder {
    fn start(server: &Server) -> Self {
        let online = Arc::new(AtomicBool::new(true));
        let connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let (flag, open) = (online.clone(), connections.clone());
        let target = server.url.trim_start_matches("http://").to_owned();
        let url = server.runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            tokio::spawn(async move {
                loop {
                    let (mut inbound, _) = listener.accept().await.unwrap();
                    if !flag.load(Ordering::SeqCst) {
                        continue;
                    }
                    let target = target.clone();
                    let task = tokio::spawn(async move {
                        let mut outbound = tokio::net::TcpStream::connect(target).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    });
                    open.lock().unwrap().push(task.abort_handle());
                }
            });
            url
        });
        Self {
            url,
            online,
            connections,
        }
    }

    fn cut(&self) {
        self.online.store(false, Ordering::SeqCst);
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    fn restore(&self) {
        self.online.store(true, Ordering::SeqCst);
    }
}

fn security_log(server: &Server, phone: &Phone) -> Vec<String> {
    server
        .wait(phone.v().security_log())
        .into_iter()
        .map(|event| event.event_type)
        .collect()
}

#[test]
fn rotating_the_secret_key_keeps_the_vault_and_needs_the_new_key_elsewhere() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let kit = phone.sign_up(&server);
    phone.save_login(&server, "Bank");
    let tablet = Phone::new(&server);
    assert_eq!(tablet.sign_in(&server, PASSWORD, &kit.secret_key), None);

    assert_eq!(
        server.fail(phone.v().rotate_secret_key("wrong".into(), false)),
        ErrorCode::InvalidCredentials
    );
    let new = server.wait(phone.v().rotate_secret_key(PASSWORD.into(), false));
    assert_ne!(new.secret_key, kit.secret_key);
    assert_eq!(new.recovery_code, None);
    assert_eq!(phone.titles(&server), ["Bank"]);

    // This phone keeps working, and remembers the new key.
    assert_eq!(
        server.wait(phone.v().secret_key()),
        new.secret_key,
        "kept in the Keychain"
    );
    phone.v().lock();
    server.wait(phone.v().unlock(PASSWORD.into()));
    assert_eq!(phone.status(), SessionStatus::Unlocked);

    // Another phone was signed out; it needs the new key.
    assert_eq!(
        tablet.sign_in(&server, PASSWORD, &kit.secret_key),
        Some(ErrorCode::InvalidCredentials)
    );
    assert_eq!(tablet.sign_in(&server, PASSWORD, &new.secret_key), None);
    assert_eq!(tablet.titles(&server), ["Bank"]);
}

#[test]
fn a_personal_vault_key_rotates_and_other_devices_follow() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let kit = phone.sign_up(&server);
    phone.save_login(&server, "Bank");
    let tablet = Phone::new(&server);
    assert_eq!(tablet.sign_in(&server, PASSWORD, &kit.secret_key), None);

    let vault_id = server.wait(phone.v().list_vaults())[0].id.clone();
    server.wait(phone.v().rotate_vault_key(vault_id));
    assert_eq!(phone.titles(&server), ["Bank"]);
    phone.save_login(&server, "After");

    // The other device is still on the old key: its save is refused, re-encrypted and sent again.
    tablet.save_login(&server, "From the tablet");
    server.wait(tablet.v().sync());
    assert_eq!(tablet.titles(&server), ["After", "Bank", "From the tablet"]);
    server.wait(phone.v().sync());
    assert_eq!(phone.titles(&server), ["After", "Bank", "From the tablet"]);
    assert!(
        security_log(&server, &phone)
            .iter()
            .any(|event| event == "vault-key-rotated"),
    );
}

#[test]
fn changes_queued_offline_survive_a_rotation_elsewhere() {
    let server = Server::start();
    let link = Forwarder::start(&server);
    let url = link.url.clone();
    let phone = Phone::new(&server);
    let kit = phone.sign_up(&server);
    phone.save_login(&server, "Bank");

    let offline = Phone::through(&server, &url);
    let signed_in = server.runtime.block_on(offline.v().sign_in(
        url.clone(),
        EMAIL.into(),
        PASSWORD.into(),
        Some(kit.secret_key.clone()),
    ));
    assert!(signed_in.is_ok());
    assert_eq!(offline.titles(&server), ["Bank"]);
    let bank = server.wait(offline.v().list_items(ItemFilter::default()))[0]
        .id
        .clone();

    // Offline: a new item and an edit wait on the device.
    link.cut();
    offline.save_login(&server, "Written offline");
    let mut edit = item_draft(server.wait(offline.v().get_item(bank)));
    edit.title = "Bank, edited offline".into();
    server.wait(offline.v().save_item(edit));

    // Meanwhile the vault's key rotates.
    let vault_id = server.wait(phone.v().list_vaults())[0].id.clone();
    server.wait(phone.v().rotate_vault_key(vault_id));

    // Back online nothing is stuck and nothing is lost: both versions of the edit stay.
    link.restore();
    server.wait(offline.v().sync());
    let expected = [
        "Bank",
        "Bank, edited offline (conflicting copy)",
        "Written offline",
    ];
    assert_eq!(offline.titles(&server), expected);
    server.wait(phone.v().sync());
    assert_eq!(phone.titles(&server), expected);
}

#[test]
fn a_contact_takes_over_after_the_waiting_period() {
    let server = Server::start();
    let grantor = Phone::new(&server);
    let kit = grantor.sign_up(&server);
    grantor.save_login(&server, "Pension");
    let contact = Phone::new(&server);
    contact.sign_up_as(&server, OTHER);

    let lookup = server.wait(grantor.v().lookup_account(OTHER.into()));
    let record = server.wait(grantor.v().add_emergency_contact(
        lookup,
        2,
        EmergencyAccessLevel::Takeover,
        EmergencyScope::Account,
    ));
    let id = record.id.clone();

    // Not before the waiting period.
    assert_eq!(
        server.fail(contact.v().take_over_account(
            id.clone(),
            PASSWORD.into(),
            NEW_PASSWORD.into()
        )),
        ErrorCode::NotAllowed
    );
    server.wait(contact.v().request_emergency_access(id.clone()));
    server.state.clock.advance(Duration::from_secs(3 * 86_400));
    let received = server.wait(contact.v().list_emergency_contacts()).received;
    assert_eq!(received[0].status, EmergencyStatus::Released);

    // The contact's own password is checked.
    assert_eq!(
        server.fail(
            contact
                .v()
                .take_over_account(id.clone(), "wrong".into(), NEW_PASSWORD.into())
        ),
        ErrorCode::InvalidCredentials
    );
    let new = server.wait(contact.v().take_over_account(
        id.clone(),
        PASSWORD.into(),
        NEW_PASSWORD.into(),
    ));
    assert_eq!(new.email, EMAIL);
    assert_ne!(new.secret_key, kit.secret_key);
    assert!(new.recovery_code.is_some());
    assert!(
        server
            .wait(contact.v().list_emergency_contacts())
            .received
            .is_empty()
    );

    // The grantor's device is out, and the kit opens the account on a new one.
    assert_eq!(
        grantor.sign_in(&server, PASSWORD, &kit.secret_key),
        Some(ErrorCode::InvalidCredentials)
    );
    let fresh = Phone::new(&server);
    assert_eq!(fresh.sign_in(&server, NEW_PASSWORD, &new.secret_key), None);
    assert_eq!(fresh.titles(&server), ["Pension"]);
    assert!(
        security_log(&server, &fresh)
            .iter()
            .any(|event| event == "emergency-takeover"),
    );
}

#[test]
fn a_rotated_vault_needs_its_contact_renewed_and_the_organiser_can_recover() {
    let server = Server::start();
    let member = Phone::new(&server);
    member.sign_up(&server);
    let organiser = Phone::new(&server);
    organiser.sign_up_as(&server, OTHER);

    // A vault-scoped contact goes stale with a rotation, until it's renewed.
    let vault_id = server.wait(member.v().list_vaults())[0].id.clone();
    let lookup = server.wait(member.v().lookup_account(OTHER.into()));
    let contact = server.wait(member.v().add_emergency_contact(
        lookup.clone(),
        1,
        EmergencyAccessLevel::View,
        EmergencyScope::Vault {
            vault_id: vault_id.clone(),
        },
    ));
    server.wait(member.v().rotate_vault_key(vault_id));
    let granted = server.wait(member.v().list_emergency_contacts()).granted;
    assert!(granted[0].key_stale);
    server.wait(
        member
            .v()
            .renew_emergency_key(contact.id.clone(), lookup.clone()),
    );
    let granted = server.wait(member.v().list_emergency_contacts()).granted;
    assert!(!granted[0].key_stale);
    server.wait(member.v().remove_emergency_contact(contact.id));

    // Organiser recovery: opt in, and it's a reset with no reading.
    server.wait(organiser.v().create_family());
    let invitee = server.wait(organiser.v().lookup_account(EMAIL.into()));
    server.wait(organiser.v().invite_to_family(invitee));
    let invitation = server.wait(member.v().get_family()).invitations[0].clone();
    server.wait(member.v().accept_family_invite(invitation.family_id));
    let record = server.wait(member.v().enable_organiser_recovery(lookup, 1));
    assert!(record.organiser_recovery);
    assert_eq!(record.access_level, EmergencyAccessLevel::Takeover);

    server.wait(organiser.v().request_emergency_access(record.id.clone()));
    server.wait(member.v().approve_emergency_access(record.id.clone()));
    assert_eq!(
        server.fail(organiser.v().open_emergency_access(record.id.clone())),
        ErrorCode::NotAllowed
    );
    let new = server.wait(organiser.v().take_over_account(
        record.id,
        PASSWORD.into(),
        NEW_PASSWORD.into(),
    ));
    assert_eq!(new.email, EMAIL);
    let fresh = Phone::new(&server);
    assert_eq!(fresh.sign_in(&server, NEW_PASSWORD, &new.secret_key), None);
}
