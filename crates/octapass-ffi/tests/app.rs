//! The Rust-only item API the mobile shell uses: any item type, saved on one device and read on
//! another, against the in-process `TestServer`.

use std::sync::Arc;

use octapass_core::item::Item;
use octapass_ffi::{
    DeviceInfo, HttpClient, HttpRequest, HttpResponse, LocalStore, OctaPassError, OctaPassServer,
    Resolution, Session, TestServer, attachments_of, with_attachments, without_attachments,
};
use serde_json::{Value, json};

struct Loopback(Arc<TestServer>);

impl HttpClient for Loopback {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, OctaPassError> {
        Ok(self.0.handle(request))
    }
}

fn device() -> DeviceInfo {
    DeviceInfo {
        name: "iPhone".into(),
        platform: "ios".into(),
    }
}

fn note(title: &str, notes: &str) -> Item {
    Item::from_json(&format!(
        r#"{{"overview":{{"schemaVersion":1,"type":"secureNote","title":"{title}"}},"details":{{"schemaVersion":1,"notes":"{notes}","futureField":1}}}}"#
    ))
    .unwrap()
}

#[test]
fn any_item_type_round_trips_between_devices() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let server = Arc::new(TestServer::new());
    let api = OctaPassServer::new(
        "https://octapass.test".into(),
        Arc::new(Loopback(server.clone())),
    )
    .unwrap();
    let signup = api
        .start_signup("a@example.com".into(), "correct horse".into())
        .unwrap();
    let code = signup.dev_verification_code().unwrap();
    let signed_in = signup.finish(code, device()).unwrap();
    let token = signed_in.tokens.access_token.clone();
    let session = signed_in.session;
    let store = LocalStore::create(path("phone.store"), api.base_url(), session.clone()).unwrap();
    api.sync(token.clone(), store.clone()).unwrap();

    let vaults = store.vaults();
    assert_eq!(vaults.len(), 1);
    let id = session
        .save_item(&store, &vaults[0].id, None, &note("Door", "1234"))
        .unwrap();
    let saved = session.decrypt_item(&store, &id).unwrap();
    assert!(saved.pending);
    assert_eq!(saved.record.vault_id, vaults[0].id);

    // An edit keeps the item's vault and id, and fields this version doesn't know.
    session
        .save_item(&store, "ignored", Some(&id), &note("Door", "5678"))
        .unwrap();
    api.upload_pending(token.clone(), session.clone(), store.clone())
        .unwrap();
    let items = session.decrypt_items(&store).unwrap();
    assert_eq!(items.len(), 1);
    assert!(!items[0].pending);
    assert_eq!(items[0].record.vault_id, vaults[0].id);

    let other = api
        .log_in(
            "a@example.com".into(),
            "correct horse".into(),
            signup.secret_key(),
            device(),
        )
        .unwrap();
    let other_store =
        LocalStore::create(path("tablet.store"), api.base_url(), other.session.clone()).unwrap();
    api.sync(other.tokens.access_token, other_store.clone())
        .unwrap();
    let item = other.session.decrypt_item(&other_store, &id).unwrap().item;
    let details = serde_json::to_value(&item.details).unwrap();
    assert_eq!(details["notes"], "5678");
    assert_eq!(details["futureField"], 1);

    assert_eq!(
        session.decrypt_item(&store, "missing").err(),
        Some(OctaPassError::ItemNotFound)
    );
    session.lock();
    assert_eq!(
        session.decrypt_items(&store).err(),
        Some(OctaPassError::Locked)
    );
}

struct Account {
    api: Arc<OctaPassServer>,
    session: Arc<Session>,
    token: String,
    vault_id: String,
    dir: tempfile::TempDir,
}

impl Account {
    fn new() -> Self {
        let api = OctaPassServer::new(
            "https://octapass.test".into(),
            Arc::new(Loopback(Arc::new(TestServer::new()))),
        )
        .unwrap();
        let signup = api
            .start_signup("a@example.com".into(), "correct horse".into())
            .unwrap();
        let code = signup.dev_verification_code().unwrap();
        let signed_in = signup.finish(code, device()).unwrap();
        let account = Self {
            api,
            session: signed_in.session,
            token: signed_in.tokens.access_token,
            vault_id: String::new(),
            dir: tempfile::tempdir().unwrap(),
        };
        let store = account.store("first.store");
        Self {
            vault_id: store.vaults()[0].id.clone(),
            ..account
        }
    }

    fn store(&self, name: &str) -> Arc<LocalStore> {
        let path = self.dir.path().join(name).to_string_lossy().into_owned();
        let store = LocalStore::create(path, self.api.base_url(), self.session.clone()).unwrap();
        self.api.sync(self.token.clone(), store.clone()).unwrap();
        store
    }

    fn upload(&self, store: &Arc<LocalStore>) {
        self.api
            .upload_pending(self.token.clone(), self.session.clone(), store.clone())
            .unwrap();
    }
}

fn file(id: &str) -> Value {
    json!({ "id": id, "name": format!("{id}.pdf"), "type": "application/pdf", "size": 3, "key": "AQ" })
}

fn document(title: &str, files: &[&str]) -> Item {
    let files: Vec<Value> = files.iter().map(|id| file(id)).collect();
    with_attachments(
        &Item::from_parts(
            serde_json::from_value(
                json!({ "schemaVersion": 1, "type": "document", "title": title }),
            )
            .unwrap(),
            json!({ "schemaVersion": 1, "notes": "signed" }),
        )
        .unwrap(),
        files,
    )
    .unwrap()
}

fn ids(item: &Item) -> Vec<String> {
    attachments_of(item)
        .iter()
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_conflicting_copy_leaves_the_files_with_the_original() {
    let account = Account::new();
    let (laptop, phone) = (account.store("laptop.store"), account.store("phone.store"));
    let session = &account.session;
    let id = session
        .save_item(&laptop, &account.vault_id, None, &document("Lease", &["a"]))
        .unwrap();
    account.upload(&laptop);
    account
        .api
        .sync(account.token.clone(), phone.clone())
        .unwrap();

    session
        .save_item(&laptop, "", Some(&id), &document("Lease 2026", &["a"]))
        .unwrap();
    account.upload(&laptop);
    session
        .save_item(&phone, "", Some(&id), &document("Lease (phone)", &["a"]))
        .unwrap();
    account.upload(&phone);

    let items = session.decrypt_items(&phone).unwrap();
    let copy = items
        .iter()
        .find(|item| item.record.id != id)
        .expect("a copy");
    assert_eq!(copy.item.overview.title, "Lease (phone) (conflicting copy)");
    assert!(
        ids(&copy.item).is_empty(),
        "its keys are bound to the original"
    );
    let original = session.decrypt_item(&phone, &id).unwrap();
    assert_eq!(original.item.overview.title, "Lease 2026");
    assert_eq!(ids(&original.item), ["a"]);
}

#[test]
fn a_resolver_merges_onto_the_server_version() {
    let account = Account::new();
    let (laptop, phone) = (account.store("laptop.store"), account.store("phone.store"));
    let session = &account.session;
    let id = session
        .save_item(&laptop, &account.vault_id, None, &document("Lease", &["a"]))
        .unwrap();
    account.upload(&laptop);
    account
        .api
        .sync(account.token.clone(), phone.clone())
        .unwrap();

    // The laptop renames it and adds a file; the phone adds a file of its own meanwhile.
    session
        .save_item(&laptop, "", Some(&id), &document("Lease 2026", &["a", "b"]))
        .unwrap();
    account.upload(&laptop);
    session
        .save_item(&phone, "", Some(&id), &document("Lease", &["a", "c"]))
        .unwrap();
    let asked = std::sync::Mutex::new(Vec::new());
    account
        .api
        .upload_pending_resolving(
            account.token.clone(),
            session.clone(),
            phone.clone(),
            &|item_id, local, server| {
                let server = server.expect("the server's version");
                asked
                    .lock()
                    .unwrap()
                    .push((item_id.to_owned(), ids(local), ids(server)));
                let mut list = attachments_of(server);
                list.push(file("c"));
                Resolution {
                    merged: Some(with_attachments(server, list).unwrap()),
                    copy: None,
                }
            },
        )
        .unwrap();
    assert_eq!(
        *asked.lock().unwrap(),
        [(
            id.clone(),
            vec!["a".into(), "c".into()],
            vec!["a".into(), "b".into()]
        )]
    );
    assert!(!phone.has_pending_changes(), "the merge was uploaded");

    account
        .api
        .sync(account.token.clone(), laptop.clone())
        .unwrap();
    let items = session.decrypt_items(&laptop).unwrap();
    assert_eq!(items.len(), 1, "no copy");
    assert_eq!(items[0].item.overview.title, "Lease 2026");
    assert_eq!(ids(&items[0].item), ["a", "b", "c"]);
    assert!(without_attachments(&items[0].item).details != items[0].item.details);
}

#[test]
fn files_of_an_item_not_uploaded_yet_encrypt_and_decrypt() {
    let account = Account::new();
    let store = account.store("phone.store");
    let session = &account.session;
    let id = session
        .save_item(&store, &account.vault_id, None, &document("Lease", &[]))
        .unwrap();
    let attachment_id = "0192f0c8-1c2d-7a00-8000-0000000000cc";
    let (wrapped, mut encryptor) = session.new_attachment(&store, &id, attachment_id).unwrap();
    let mut sealed = encryptor.push(b"contract").unwrap();
    sealed.extend(encryptor.finish().unwrap());

    let mut decryptor = session
        .open_attachment(&store, &id, attachment_id, &wrapped)
        .unwrap();
    let mut plain = decryptor.push(&sealed).unwrap().to_vec();
    plain.extend_from_slice(&decryptor.finish().unwrap());
    assert_eq!(plain, b"contract");

    assert_eq!(
        session
            .new_attachment(&store, "missing", attachment_id)
            .err(),
        Some(OctaPassError::ItemNotFound)
    );
}
