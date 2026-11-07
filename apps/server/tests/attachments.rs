//! Attachments: encrypted files kept with items, end to end with real client
//! encryption, on local storage and on an S3-compatible fake.

use crate::common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::fake_s3::{self, FakeS3};
use common::people::Person;
use common::*;
use octapass_core::sharing::Role;
use octapass_server::{Config, S3Config, StorageConfig};
use rand_core::OsRng;
use serde_json::Value;

fn path(vault_id: &str, item_id: &str, attachment_id: &str) -> String {
    format!("/v1/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}")
}

/// A new item in the vault, as the person. Returns its id and encrypted item key.
async fn new_item(server: &TestServer, person: &Person, vault_id: &str) -> (String, String) {
    let item_id = new_id();
    let body = person.item(vault_id, &item_id, "Lease");
    let created = server
        .call(
            Method::PUT,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(&person.token),
            &[("if-none-match", "*")],
            Some(body.clone()),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
    (
        item_id,
        body["encryptedItemKey"].as_str().unwrap().to_owned(),
    )
}

/// A file encrypted as a client would. Returns (attachment id, wrapped key, ciphertext).
fn encrypt(
    person: &Person,
    vault_id: &str,
    item: &(String, String),
    plaintext: &[u8],
) -> (String, String, Vec<u8>) {
    let attachment_id = new_id();
    let (wrapped, mut encryptor) = person
        .session
        .new_attachment(vault_id, &item.0, &item.1, &attachment_id, &mut OsRng)
        .unwrap();
    let mut file = encryptor.push(plaintext).unwrap();
    file.extend(encryptor.finish().unwrap());
    (attachment_id, wrapped, file)
}

async fn put_file(
    server: &TestServer,
    token: &str,
    path: &str,
    bytes: Vec<u8>,
    length: Option<usize>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream");
    if let Some(length) = length {
        request = request.header("content-length", length);
    }
    let (status, _, body) = server
        .send_raw(request.body(Body::from(bytes)).unwrap())
        .await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn upload(
    server: &TestServer,
    token: &str,
    path: &str,
    bytes: Vec<u8>,
) -> (StatusCode, Value) {
    let len = bytes.len();
    put_file(server, token, path, bytes, Some(len)).await
}

async fn download(server: &TestServer, token: &str, path: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = server.send_raw(request).await;
    if status == StatusCode::OK {
        assert_eq!(headers["content-type"], "application/octet-stream");
        assert_eq!(headers["content-length"], body.len().to_string().as_str());
    }
    (status, body)
}

async fn usage(server: &TestServer, person: &Person) -> Value {
    let response = server.get_as(person, "/v1/account/usage").await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body
}

fn stored_files(server: &TestServer) -> usize {
    std::fs::read_dir(server.dir.path().join("attachments"))
        .unwrap()
        .count()
}

/// Lets the background deletion run.
async fn settle(server: &TestServer) {
    server.state.run_maintenance().await.unwrap();
}

#[tokio::test]
async fn upload_download_and_delete() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let vault = alice.personal_vault.clone();
    let item = new_item(&server, &alice, &vault).await;
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (id, wrapped, file) = encrypt(&alice, &vault, &item, &plaintext);
    let file_path = path(&vault, &item.0, &id);

    let (status, record) = upload(&server, &alice.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{record:?}");
    assert_eq!(record["id"], id.as_str());
    assert_eq!(record["itemId"], item.0.as_str());
    assert_eq!(record["size"], file.len());
    assert_eq!(stored_files(&server), 1);

    let listed = server
        .get_as(
            &alice,
            &format!("/v1/vaults/{vault}/items/{}/attachments", item.0),
        )
        .await;
    assert_eq!(listed.body["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(listed.body["attachments"][0]["id"], id.as_str());

    let (status, downloaded) = download(&server, &alice.token, &file_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded, file);
    let mut decryptor = alice
        .session
        .open_attachment(&vault, &item.0, &item.1, &id, &wrapped)
        .unwrap();
    let mut opened = decryptor.push(&downloaded).unwrap().to_vec();
    opened.extend_from_slice(&decryptor.finish().unwrap());
    assert_eq!(opened, plaintext);

    let used = usage(&server, &alice).await;
    assert_eq!(used["attachmentBytes"], file.len());
    assert_eq!(used["maxAttachmentBytes"], 1u64 << 30);
    assert_eq!(used["maxFileBytes"], 100u64 << 20);
    assert_eq!(used["items"], 1);

    let (status, again) = upload(&server, &alice.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{again:?}");

    let deleted = server
        .send_as(&alice, Method::DELETE, &file_path, None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    settle(&server).await;
    assert_eq!(stored_files(&server), 0);
    assert_eq!(usage(&server, &alice).await["attachmentBytes"], 0);
    assert_eq!(
        download(&server, &alice.token, &file_path).await.0,
        StatusCode::NOT_FOUND
    );
    let again = server
        .send_as(&alice, Method::DELETE, &file_path, None)
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uploads_are_checked_before_and_after_the_body() {
    let server =
        TestServer::with_config(|config: &mut Config| config.attachments.max_file_bytes = 1000)
            .await;
    let alice = server.person("alice@example.com").await;
    let vault = alice.personal_vault.clone();
    let item = new_item(&server, &alice, &vault).await;
    let (id, _, file) = encrypt(&alice, &vault, &item, b"small");
    let file_path = path(&vault, &item.0, &id);
    let token = alice.token.as_str();

    let (status, body) = put_file(&server, token, &file_path, file.clone(), None).await;
    assert_eq!(status, StatusCode::LENGTH_REQUIRED);
    assert_eq!(
        body["type"],
        "https://octap.app/problems/length-required"
    );

    let (status, _) = put_file(&server, token, &file_path, vec![1; 1001], Some(1001)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = upload(&server, token, &file_path, vec![1; 20]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "shorter than any encrypted file"
    );
    let (status, _) = upload(&server, token, &file_path, vec![2; 100]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "not envelope version 1");
    let (status, _) = put_file(
        &server,
        token,
        &file_path,
        file.clone(),
        Some(file.len() + 5),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "shorter than its Content-Length"
    );
    let (status, _) = upload(&server, token, &path(&vault, &item.0, "nope"), file.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = upload(&server, token, &path(&vault, &new_id(), &id), file.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such item");
    let (status, _) = upload(&server, "wrong", &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(stored_files(&server), 0);
    assert_eq!(
        std::fs::read_dir(server.dir.path().join("uploads"))
            .unwrap()
            .count(),
        0,
        "refused uploads leave no spool files"
    );

    // Items in the trash take no new files, but keep theirs.
    let (status, _) = upload(&server, token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let trashed = server
        .call(
            Method::DELETE,
            &format!("/v1/vaults/{vault}/items/{}", item.0),
            Some(token),
            &[("if-match", "\"1\"")],
            None,
        )
        .await;
    assert_eq!(trashed.status, StatusCode::OK);
    let (other, _, other_file) = encrypt(&alice, &vault, &item, b"more");
    let (status, _) = upload(&server, token, &path(&vault, &item.0, &other), other_file).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(download(&server, token, &file_path).await.0, StatusCode::OK);
}

#[tokio::test]
async fn the_quota_counts_against_the_vault_owner() {
    let server =
        TestServer::with_config(|config: &mut Config| config.attachments.quota_bytes = 300).await;
    let mut owner = server.person("owner@example.com").await;
    let mut writer = server.person("writer@example.com").await;
    let mut reader = server.person("reader@example.com").await;
    let outsider = server.person("outsider@example.com").await;
    let vault = server.shared_vault(&mut owner).await;
    for (person, role) in [(&mut writer, Role::Write), (&mut reader, Role::Read)] {
        let invited = server.invite(&owner, &vault, person, role).await;
        assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
        server.open_shared_vault(person, &vault).await;
    }
    let item = new_item(&server, &writer, &vault).await;

    let (id, _, file) = encrypt(&writer, &vault, &item, &[7; 100]);
    let file_path = path(&vault, &item.0, &id);
    let (status, _) = upload(&server, &reader.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "read-only");
    let (status, _) = upload(&server, &outsider.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = upload(&server, &writer.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(usage(&server, &owner).await["attachmentBytes"], file.len());
    assert_eq!(usage(&server, &writer).await["attachmentBytes"], 0);

    // Members who can see the item can download it; others can't tell it exists.
    assert_eq!(download(&server, &reader.token, &file_path).await.1, file);
    assert_eq!(
        download(&server, &outsider.token, &file_path).await.0,
        StatusCode::NOT_FOUND
    );
    let listed = server
        .get_as(
            &outsider,
            &format!("/v1/vaults/{vault}/items/{}/attachments", item.0),
        )
        .await;
    assert_eq!(listed.status, StatusCode::NOT_FOUND);
    let refused = server
        .send_as(&reader, Method::DELETE, &file_path, None)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // Over the owner's 300 bytes: refused before the body is read.
    let (big, _, big_file) = encrypt(&writer, &vault, &item, &[8; 200]);
    let (status, body) = upload(
        &server,
        &writer.token,
        &path(&vault, &item.0, &big),
        big_file,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["type"],
        "https://octap.app/problems/quota-exceeded"
    );
    // The writer's own vault has its own quota.
    let own = writer.personal_vault.clone();
    let own_item = new_item(&server, &writer, &own).await;
    let (id, _, file) = encrypt(&writer, &own, &own_item, &[8; 200]);
    let (status, _) = upload(&server, &writer.token, &path(&own, &own_item.0, &id), file).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn purged_items_and_deleted_accounts_take_their_files() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let vault = alice.personal_vault.clone();
    let doomed = new_item(&server, &alice, &vault).await;
    let kept = new_item(&server, &alice, &vault).await;
    for item in [&doomed, &kept] {
        let (id, _, file) = encrypt(&alice, &vault, item, b"scan");
        let (status, _) = upload(&server, &alice.token, &path(&vault, &item.0, &id), file).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    assert_eq!(stored_files(&server), 2);

    // Trashed 31 days ago: the next maintenance purges it with its file.
    sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
        .bind(octapass_now() - 31 * 24 * 60 * 60 * 1000)
        .bind(&doomed.0)
        .execute(&server.state.db)
        .await
        .unwrap();
    settle(&server).await;
    assert_eq!(stored_files(&server), 1);
    let used = usage(&server, &alice).await;
    assert_eq!(used["attachmentBytes"], 36 + 4 + 16);

    let device = server.login("alice@example.com", "Phone").await;
    let token = reauth_token(&server, &device).await;
    let deleted = delete_account(&server, &device, Some(&token), "alice@example.com").await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    settle(&server).await;
    assert_eq!(stored_files(&server), 0);
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attachment_deletions")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(queued, 0);
}

fn octapass_now() -> i64 {
    i64::try_from(common::people::now_ms()).unwrap()
}

#[tokio::test]
async fn object_storage_deletes_are_queued_and_retried() {
    let fake = FakeS3::default();
    let endpoint = fake.start().await;
    let server = TestServer::with_config(|config: &mut Config| {
        config.attachments.storage = StorageConfig::S3(S3Config {
            endpoint,
            bucket: fake_s3::BUCKET.into(),
            region: "eu-central-1".into(),
            access_key_id: fake_s3::ACCESS_KEY_ID.into(),
            secret_access_key: fake_s3::SECRET_ACCESS_KEY.into(),
            path_style: true,
        });
    })
    .await;
    let alice = server.person("alice@example.com").await;
    let vault = alice.personal_vault.clone();
    let item = new_item(&server, &alice, &vault).await;
    let (id, _, file) = encrypt(&alice, &vault, &item, b"passport scan");
    let file_path = path(&vault, &item.0, &id);
    let (status, _) = upload(&server, &alice.token, &file_path, file.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(fake.len(), 1);
    assert_eq!(download(&server, &alice.token, &file_path).await.1, file);
    let ready = server.call(Method::GET, "/readyz", None, &[], None).await;
    assert_eq!(ready.status, StatusCode::OK);

    // The bucket is down: downloads say so, and the account still goes at once.
    fake.set_down(true);
    let (status, _) = download(&server, &alice.token, &file_path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let ready = server.call(Method::GET, "/readyz", None, &[], None).await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    let device = server.login("alice@example.com", "Phone").await;
    let token = reauth_token(&server, &device).await;
    let deleted = delete_account(&server, &device, Some(&token), "alice@example.com").await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    settle(&server).await;
    assert_eq!(fake.len(), 1, "not deleted yet");
    let (attempts, next): (i64, i64) =
        sqlx::query_as("SELECT attempts, next_attempt_at FROM attachment_deletions")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(attempts >= 1);
    assert!(next > octapass_now(), "retried later");

    // Back up, and the retry is due: the file goes.
    fake.set_down(false);
    sqlx::query("UPDATE attachment_deletions SET next_attempt_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
    settle(&server).await;
    assert_eq!(fake.len(), 0);
}

/// Makes `contact` the grantor's emergency contact for `scope` and releases it. Returns the id.
async fn released_contact(
    server: &TestServer,
    grantor: &Person,
    contact: &Person,
    scope: octapass_core::sharing::emergency::EmergencyScope,
) -> String {
    let sealed = grantor
        .session
        .seal_for_emergency_contact(
            &contact.account_id,
            &contact.session.key_pairs().public_enc_key(),
            None,
            &scope,
            &mut OsRng,
        )
        .unwrap();
    let body = serde_json::json!({
        "contactAccountId": contact.account_id,
        "sealedKey": sealed,
        "scope": scope,
        "accessLevel": "view",
        "waitDays": 1,
    });
    let created = server
        .send_as(grantor, Method::POST, "/v1/emergency-contacts", Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let id = created.body["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/emergency-contacts/{id}/request");
    let requested = server.send_as(contact, Method::POST, &path, None).await;
    assert_eq!(requested.status, StatusCode::OK, "{:?}", requested.body);
    id
}

fn release_all(server: &TestServer) {
    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(24 * 60 * 60));
}

#[tokio::test]
async fn emergency_contacts_download_files_from_released_vaults_only() {
    use octapass_core::sharing::emergency::EmergencyScope;

    let server = TestServer::new().await;
    let mut grace = server.person("grace@example.com").await;
    let mut carl = server.person("carl@example.com").await;
    let dana = server.person("dana@example.com").await;
    let eve = server.person("eve@example.com").await;
    let shared = server.shared_vault(&mut grace).await;
    let personal = grace.personal_vault.clone();

    let deeds = new_item(&server, &grace, &shared).await;
    let (deeds_file, deeds_key, deeds_bytes) = encrypt(&grace, &shared, &deeds, b"the deeds");
    let deeds_path = path(&shared, &deeds.0, &deeds_file);
    let (status, _) = upload(&server, &grace.token, &deeds_path, deeds_bytes.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let diary = new_item(&server, &grace, &personal).await;
    let (diary_file, _, diary_bytes) = encrypt(&grace, &personal, &diary, b"dear diary");
    let diary_path = path(&personal, &diary.0, &diary_file);
    let (status, _) = upload(&server, &grace.token, &diary_path, diary_bytes.clone()).await;
    assert_eq!(status, StatusCode::CREATED);

    // Carl gets the shared vault, Dana the whole account.
    let scope = EmergencyScope::Vault {
        vault_id: shared.clone(),
    };
    let carls = released_contact(&server, &grace, &carl, scope).await;
    let danas = released_contact(&server, &grace, &dana, EmergencyScope::Account).await;
    let as_contact = |id: &str, file: &str| {
        let file = file.strip_prefix("/v1").unwrap();
        format!("/v1/emergency-contacts/{id}{file}")
    };

    // Nothing before the waiting period is over.
    let (status, _) = download(&server, &carl.token, &as_contact(&carls, &deeds_path)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    release_all(&server);

    let (status, file) = download(&server, &carl.token, &as_contact(&carls, &deeds_path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(file, deeds_bytes);
    // Carl opens it with the released vault key.
    let released = server
        .get_as(&carl, &format!("/v1/emergency-contacts/{carls}/release"))
        .await;
    let sealed = released.body["sealedKey"].as_str().unwrap();
    carl.session
        .open_emergency_vault(&grace.account_id, &shared, sealed)
        .unwrap();
    let mut decryptor = carl
        .session
        .open_attachment(&shared, &deeds.0, &deeds.1, &deeds_file, &deeds_key)
        .unwrap();
    let mut opened = decryptor.push(&file).unwrap().to_vec();
    opened.extend_from_slice(&decryptor.finish().unwrap());
    assert_eq!(opened, b"the deeds");

    // A vault outside Carl's scope doesn't exist for him; the account scope covers it.
    let (status, _) = download(&server, &carl.token, &as_contact(&carls, &diary_path)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, file) = download(&server, &dana.token, &as_contact(&danas, &diary_path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(file, diary_bytes);

    // Only the contact, and only through their own record.
    let (status, _) = download(&server, &eve.token, &as_contact(&carls, &deeds_path)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = download(&server, &grace.token, &as_contact(&carls, &deeds_path)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = download(&server, &carl.token, &as_contact(&danas, &diary_path)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Not the grantor's ordinary file routes either.
    let (status, _) = download(&server, &carl.token, &deeds_path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Removing the contact ends it.
    let removed = server
        .send_as(
            &grace,
            Method::DELETE,
            &format!("/v1/emergency-contacts/{carls}"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let (status, _) = download(&server, &carl.token, &as_contact(&carls, &deeds_path)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
