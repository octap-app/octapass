//! Attachments through the mobile vault against the real sync server, over HTTP: adding picked
//! files, opening them in the (fake) system viewer, edits that keep them, removing them, storage
//! use, a second phone; then the outbox: files added and removed offline, uploaded after their
//! item, merged over another device's edit, and refused by the server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{FileSource, Item, ItemDraft};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Event, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
/// The server's file size limit in these tests, as stored (encrypted).
const MAX_FILE: u64 = 200_000;

/// The sync server behind a proxy that can drop the phone's connection, as when it goes offline.
struct Server {
    url: String,
    online: watch::Sender<bool>,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (online, watching) = watch::channel(true);
        let url = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                "OCTAPASS_MAX_FILE_BYTES" => Some(MAX_FILE.to_string()),
                _ => None,
            })
            .unwrap();
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = listener.local_addr().unwrap();
            let app =
                octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

            let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
            tokio::spawn(async move {
                loop {
                    let (mut phone, _) = proxy.accept().await.unwrap();
                    let mut watching = watching.clone();
                    tokio::spawn(async move {
                        if !*watching.borrow() {
                            let _ = phone.shutdown().await;
                            return;
                        }
                        let mut upstream = tokio::net::TcpStream::connect(server).await.unwrap();
                        tokio::select! {
                            _ = tokio::io::copy_bidirectional(&mut phone, &mut upstream) => {}
                            _ = watching.wait_for(|online| !online) => {}
                        }
                    });
                }
            });
            url
        });
        Self {
            url,
            online,
            _data: data,
            _runtime: runtime,
        }
    }

    fn set_online(&self, online: bool) {
        self.online.send_replace(online);
        // Let the proxy drop the connections it holds.
        std::thread::sleep(std::time::Duration::from_millis(50));
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
        let native = Arc::new(FakeNative::default());
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = events.clone();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().join("group"),
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

    /// Signs up and returns the Secret Key.
    fn sign_up(&self, server: &Server) -> String {
        let started = self
            .vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .unwrap();
        let code = started.dev_verification_code.unwrap();
        self.vault
            .finish_signup(&started.signup_id, &code)
            .unwrap()
            .secret_key
    }

    fn sign_in(&self, server: &Server, secret_key: &str) {
        self.vault
            .sign_in(
                &server.url,
                EMAIL,
                secret(PASSWORD),
                Some(secret(secret_key)),
            )
            .unwrap();
    }

    fn document(&self, title: &str) -> Item {
        self.vault
            .save_item(ItemDraft {
                id: None,
                vault_id: self.vault.list_vaults().unwrap()[0].id.clone(),
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": "document", "title": title }),
                details: json!({ "schemaVersion": 1, "notes": "Signed in March" }),
            })
            .unwrap()
    }

    /// Picks one file in the (fake) system picker and attaches it.
    fn attach(&self, item_id: &str, name: &str, contents: &[u8]) -> Item {
        self.native.picks.lock().unwrap().push((
            name.into(),
            "application/pdf".into(),
            contents.to_vec(),
        ));
        let picked = self.vault.pick_files(FileSource::Files).unwrap();
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].size, contents.len() as u64);
        self.vault.attach_picked(item_id, &picked[0].id).unwrap()
    }

    /// Opens the file in the (fake) viewer and returns what it showed.
    fn open(&self, item_id: &str, attachment_id: &str) -> Vec<u8> {
        self.vault.open_attachment(item_id, attachment_id).unwrap();
        let opened = self.native.opened.lock().unwrap().pop().unwrap();
        assert!(!opened.path.exists(), "deleted once the viewer closed");
        opened.contents
    }

    /// What waits in the outbox: changes not done, and files not uploaded.
    fn outbox(&self) -> (usize, usize) {
        let (mut changes, mut files) = (0, 0);
        for entry in std::fs::read_dir(self.dir.path().join("group")).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_name().to_string_lossy().ends_with(".files") {
                continue;
            }
            for file in std::fs::read_dir(entry.path()).unwrap() {
                let file = file.unwrap();
                let name = file.file_name().to_string_lossy().into_owned();
                if name == "changes.json" {
                    let list: Vec<Value> =
                        serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
                    changes += list.len();
                } else if name.ends_with(".upload") {
                    files += 1;
                }
            }
        }
        (changes, files)
    }

    fn sync_failures(&self) -> Vec<String> {
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

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn files(item: &Item) -> Vec<Value> {
    item.details["attachments"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn id(entry: &Value) -> String {
    entry["id"].as_str().unwrap().to_owned()
}

fn empty(path: &Path) -> bool {
    std::fs::read_dir(path).map_or(true, |mut entries| entries.next().is_none())
}

#[test]
fn add_open_keep_through_edits_and_remove() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let secret_key = phone.sign_up(&server);
    let item = phone.document("Lease");

    // Several slices and chunks, so the streaming paths run.
    let file: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    let added = phone.attach(&item.id, "lease.pdf", &file);
    let entry = &files(&added)[0];
    assert_eq!(entry["name"], "lease.pdf");
    assert_eq!(entry["type"], "application/pdf");
    assert_eq!(entry["size"], file.len());
    assert!(entry.get("pending").is_none(), "uploaded at once");
    assert_eq!(phone.outbox(), (0, 0));
    assert!(
        empty(&phone.dir.path().join("tmp/picked")),
        "the picked copy is gone"
    );
    let attachment = id(entry);

    assert_eq!(phone.open(&item.id, &attachment), file);
    phone.vault.open_attachment(&item.id, &attachment).unwrap();
    let opened = phone.native.opened.lock().unwrap().pop().unwrap();
    assert_eq!(opened.name, "lease.pdf");
    assert_eq!(opened.media_type, "application/pdf");
    assert_eq!(opened.path.file_name().unwrap(), "lease.pdf");
    let usage = phone.vault.storage_usage().unwrap();
    assert!(usage.attachment_bytes > file.len() as u64);
    assert_eq!(usage.max_file_bytes, MAX_FILE);

    // An edit from a form that never saw the file keeps it; a new item never starts with one.
    let edited = phone
        .vault
        .save_item(ItemDraft {
            id: Some(item.id.clone()),
            vault_id: item.vault_id.clone(),
            revision: Some(added.revision),
            overview: json!({ "schemaVersion": 1, "type": "document", "title": "Lease 2026" }),
            details: json!({ "schemaVersion": 1 }),
        })
        .unwrap();
    assert_eq!(id(&files(&edited)[0]), attachment);

    // Another phone downloads and decrypts it.
    let tablet = Phone::new(&server);
    tablet.sign_in(&server, &secret_key);
    assert_eq!(tablet.open(&item.id, &attachment), file);

    let removed = phone
        .vault
        .remove_attachment(&item.id, &attachment)
        .unwrap();
    assert!(files(&removed).is_empty());
    assert_eq!(
        phone
            .vault
            .open_attachment(&item.id, &attachment)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(phone.vault.storage_usage().unwrap().attachment_bytes, 0);
    tablet.vault.sync().unwrap();
    assert_eq!(
        tablet
            .vault
            .get_attachment(&item.id, &attachment)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // Too large for the server: refused before anything is encrypted.
    let large = vec![0u8; MAX_FILE as usize];
    assert_eq!(
        phone
            .vault
            .add_attachment(&item.id, "large.bin", "", &large)
            .unwrap_err()
            .code,
        ErrorCode::FileTooLarge
    );
}

#[test]
fn picked_files_are_plaintext_only_until_attached_or_locked() {
    let server = Server::start();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let picked_dir = phone.dir.path().join("tmp/picked");

    for name in ["a.pdf", "b.pdf"] {
        phone.native.picks.lock().unwrap().push((
            name.into(),
            "application/pdf".into(),
            b"pdf".to_vec(),
        ));
    }
    let picked = phone.vault.pick_files(FileSource::Photos).unwrap();
    assert_eq!(picked.len(), 2);
    assert!(!empty(&picked_dir));
    phone.vault.discard_picked(&[picked[0].id.clone()]);
    assert_eq!(
        phone
            .vault
            .attach_picked("any", &picked[0].id)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    phone.vault.lock();
    assert!(empty(&picked_dir), "locking deletes what wasn't attached");
    phone.vault.unlock(secret(PASSWORD)).unwrap();
    assert_eq!(
        phone
            .vault
            .attach_picked("any", &picked[1].id)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // A cancelled picker picks nothing and leaves nothing.
    assert!(
        phone
            .vault
            .pick_files(FileSource::Files)
            .unwrap()
            .is_empty()
    );
    assert!(empty(&picked_dir));
}

#[test]
fn offline_files_wait_for_their_item_and_then_upload() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let secret_key = phone.sign_up(&server);
    let lease = phone.document("Lease");

    server.set_online(false);
    let passport = phone.document("Passport");
    assert_eq!(passport.revision, 0, "saved here only");
    let scan = b"passport scan".to_vec();
    let added = phone.attach(&passport.id, "passport.pdf", &scan);
    assert_eq!(files(&added)[0]["pending"], true);
    let on_passport = id(&files(&added)[0]);
    let added = phone.attach(&lease.id, "lease.pdf", b"lease");
    let on_lease = id(&files(&added)[0]);
    // Opens offline, from the outbox.
    assert_eq!(phone.open(&passport.id, &on_passport), scan);
    // Added and removed before it ever went up: nothing to tell the server.
    let added = phone.attach(&lease.id, "draft.pdf", b"draft");
    let draft = id(&files(&added)[1]);
    let removed = phone.vault.remove_attachment(&lease.id, &draft).unwrap();
    assert_eq!(files(&removed).len(), 1);
    assert_eq!(phone.outbox(), (2, 2), "the draft left nothing");
    assert_eq!(
        phone.vault.sync().unwrap_err().code,
        ErrorCode::ServerUnreachable
    );

    server.set_online(true);
    phone.vault.sync().unwrap();
    assert_eq!(phone.outbox(), (0, 0));
    let passport = phone.vault.get_item(&passport.id).unwrap();
    assert!(passport.revision > 0);
    assert!(files(&passport)[0].get("pending").is_none());

    let tablet = Phone::new(&server);
    tablet.sign_in(&server, &secret_key);
    assert_eq!(tablet.open(&passport.id, &on_passport), scan);
    assert_eq!(tablet.open(&lease.id, &on_lease), b"lease");
    let lease = tablet.vault.get_item(&lease.id).unwrap();
    assert_eq!(files(&lease).len(), 1, "the draft never reached the server");
}

#[test]
fn files_added_offline_merge_over_another_devices_edit() {
    let server = Server::start();
    let phone = Phone::new(&server);
    let secret_key = phone.sign_up(&server);
    let lease = phone.document("Lease");
    let first = phone.attach(&lease.id, "page-1.pdf", b"one");
    let page_one = id(&files(&first)[0]);
    let tablet = Phone::new(&server);
    tablet.sign_in(&server, &secret_key);

    // The phone, offline, adds a page and removes the first; the tablet renames the item.
    server.set_online(false);
    let added = phone.attach(&lease.id, "page-2.pdf", b"two");
    let page_two = id(&files(&added)[1]);
    phone.vault.remove_attachment(&lease.id, &page_one).unwrap();
    server.set_online(true);
    let renamed = tablet.vault.get_item(&lease.id).unwrap();
    tablet
        .vault
        .save_item(ItemDraft {
            id: Some(lease.id.clone()),
            vault_id: lease.vault_id.clone(),
            revision: Some(renamed.revision),
            overview: json!({ "schemaVersion": 1, "type": "document", "title": "Lease 2026" }),
            details: renamed.details.clone(),
        })
        .unwrap();

    phone.vault.sync().unwrap();
    tablet.vault.sync().unwrap();
    for device in [&phone, &tablet] {
        let items = device.vault.list_items().unwrap();
        let titles: Vec<&str> = items.iter().map(|item| item.title.as_str()).collect();
        assert_eq!(
            titles,
            ["Lease 2026"],
            "no conflicting copy for file changes"
        );
        let lease = device.vault.get_item(&lease.id).unwrap();
        let ids: Vec<String> = files(&lease).iter().map(id).collect();
        assert_eq!(ids, std::slice::from_ref(&page_two));
    }
    assert_eq!(tablet.open(&lease.id, &page_two), b"two");
    assert_eq!(
        tablet
            .vault
            .get_attachment(&lease.id, &page_one)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(phone.outbox(), (0, 0));
}

#[test]
fn a_file_the_server_refuses_comes_off_the_item() {
    let server = Server::start();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let lease = phone.document("Lease");

    // Offline, the size can't be checked.
    server.set_online(false);
    let large = vec![7u8; MAX_FILE as usize];
    let added = phone
        .vault
        .add_attachment(&lease.id, "scan.tiff", "image/tiff", &large)
        .unwrap();
    assert_eq!(files(&added)[0]["pending"], true);
    server.set_online(true);
    phone.vault.sync().unwrap();

    assert!(files(&phone.vault.get_item(&lease.id).unwrap()).is_empty());
    assert_eq!(phone.outbox(), (0, 0));
    assert!(
        phone
            .sync_failures()
            .iter()
            .any(|message| message.contains("scan.tiff") && message.contains("FileTooLarge"))
    );
}

#[test]
fn signing_out_deletes_the_outbox() {
    let server = Server::start();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let lease = phone.document("Lease");
    server.set_online(false);
    phone.attach(&lease.id, "lease.pdf", b"lease");
    assert_eq!(phone.outbox(), (1, 1));
    phone.vault.sign_out().unwrap();
    assert_eq!(phone.outbox(), (0, 0));
}

#[test]
fn an_encrypted_export_moves_items_and_files_to_another_account() {
    use octapass_core::import::{ImportOptions, ImportSource};
    use octapass_core::kdf::KdfParams;
    use octapass_mobile_vault::vault::FileExport;

    let server = Server::start();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let item = phone.document("Lease");
    let file: Vec<u8> = (0..90_000u32).map(|i| (i % 241) as u8).collect();
    phone.attach(&item.id, "عقد.pdf", &file);
    let exported = phone
        .vault
        .export_file(FileExport::Encrypted, Some("export pw"), KdfParams::DEFAULT)
        .unwrap();
    assert_eq!(&exported[..4], b"OPEX");
    let cxf = phone
        .vault
        .export_file(FileExport::Cxf, None, KdfParams::DEFAULT)
        .unwrap();
    let header: Value = serde_json::from_slice(&cxf).unwrap();
    assert_eq!(header["exporterRpId"], "127.0.0.1");
    assert_eq!(header["accounts"][0]["items"][0]["title"], "Lease");

    let other_server = Server::start();
    let other = Phone::new(&other_server);
    other.sign_up(&other_server);
    let personal = other.vault.list_vaults().unwrap()[0].id.clone();
    let wrong = other
        .vault
        .import_file(
            ImportSource::OctaPass,
            &exported,
            ImportOptions::default(),
            &personal,
        )
        .unwrap_err();
    assert_eq!(wrong.code, ErrorCode::ImportPasswordRequired);
    let options = ImportOptions {
        password: Some(secret("export pw")),
        ..ImportOptions::default()
    };
    let summary = other
        .vault
        .import_file(ImportSource::OctaPass, &exported, options, &personal)
        .unwrap();
    assert_eq!((summary.imported, summary.files), (1, Some(1)));
    let items = other.vault.live_items().unwrap();
    let lease = items.iter().find(|item| item.title() == "Lease").unwrap();
    assert_eq!(lease.details["notes"], "Signed in March");
    let entry = &files(lease)[0];
    assert_eq!(entry["name"], "عقد.pdf");
    assert_eq!(other.open(&lease.id, &id(entry)), file);
}

#[test]
fn items_another_app_hands_over_wait_for_the_user() {
    let server = Server::start();
    let phone = Phone::new(&server);
    phone.sign_up(&server);
    let cxf = json!({
        "version": { "major": 1, "minor": 0 },
        "exporterRpId": "passwords.google",
        "exporterDisplayName": "Google Password Manager",
        "timestamp": 1_792_800_000,
        "accounts": [{
            "id": "QQ", "username": "", "email": "ada@example.com",
            "items": [
                { "id": "MQ", "title": "example.com", "scope": { "urls": ["https://example.com"], "androidApps": [] },
                  "credentials": [{ "type": "basic-auth",
                    "username": { "fieldType": "string", "value": "ada" },
                    "password": { "fieldType": "concealed-string", "value": "hunter2" } }] },
                { "id": "Mg", "title": "Visa",
                  "credentials": [{ "type": "credit-card",
                    "number": { "fieldType": "string", "value": "4111111111111111" },
                    "fullName": { "fieldType": "string", "value": "Ada Lovelace" } }] }
            ]
        }]
    })
    .to_string();
    let hand_over = || {
        *phone.native.received.lock().unwrap() =
            Some(("Google Password Manager".into(), cxf.clone()))
    };

    // Backing out of the system's list.
    assert_eq!(phone.vault.receive_from_app().unwrap(), None);

    hand_over();
    let preview = phone.vault.receive_from_app().unwrap().unwrap();
    assert_eq!(preview.from, "Google Password Manager");
    assert_eq!(
        preview.items.into_iter().collect::<Vec<_>>(),
        [("card".to_owned(), 1), ("login".to_owned(), 1)]
    );
    assert_eq!(
        (preview.passkeys, preview.codes, preview.skipped),
        (0, 0, 0)
    );
    // Nothing is saved before the user says so, and locking forgets it.
    assert!(phone.vault.live_items().unwrap().is_empty());
    phone.vault.lock();
    phone.vault.unlock(secret(PASSWORD)).unwrap();
    assert_eq!(
        phone.vault.import_received().unwrap_err().code,
        ErrorCode::NotFound
    );

    hand_over();
    phone.vault.receive_from_app().unwrap().unwrap();
    phone.vault.discard_received();
    assert_eq!(
        phone.vault.import_received().unwrap_err().code,
        ErrorCode::NotFound
    );

    hand_over();
    phone.vault.receive_from_app().unwrap().unwrap();
    let summary = phone.vault.import_received().unwrap();
    assert_eq!(summary.imported, 2);
    let items = phone.vault.live_items().unwrap();
    let login = items
        .iter()
        .find(|item| item.title() == "example.com")
        .unwrap();
    assert_eq!(login.details["password"], "hunter2");
    assert_eq!(login.overview["importedFrom"]["id"], "MQ");
    assert_eq!(
        phone.vault.import_received().unwrap_err().code,
        ErrorCode::NotFound
    );

    // The same app hands over again with a new password: an update, not a copy.
    *phone.native.received.lock().unwrap() = Some((
        "Google Password Manager".into(),
        cxf.replace("hunter2", "hunter3"),
    ));
    let preview = phone.vault.receive_from_app().unwrap().unwrap();
    assert!(preview.items.is_empty());
    assert_eq!((preview.updated, preview.unchanged), (1, 1));
    let summary = phone.vault.import_received().unwrap();
    assert_eq!(
        (summary.imported, summary.updated, summary.unchanged),
        (0, Some(1), Some(1))
    );
    let items = phone.vault.live_items().unwrap();
    assert_eq!(items.len(), 2);
    let login = items
        .iter()
        .find(|item| item.title() == "example.com")
        .unwrap();
    assert_eq!(login.details["password"], "hunter3");
    assert_eq!(login.details["passwordHistory"][0]["password"], "hunter2");
}
