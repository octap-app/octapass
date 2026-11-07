//! Service accounts against the real router: a token made with the real core signs in, reads its
//! one vault and decrypts it; everything else about it is refused.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, now_ms};
use common::{Response, TestServer};
use octapass_core::service_account::{NewServiceAccount, ServiceAccountToken};
use octapass_core::session::EncryptedItem;
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::SignedGrant;
use rand_core::OsRng;
use serde_json::{Value, json};

const SERVER: &str = "https://octap.app";

async fn create(
    server: &TestServer,
    person: &Person,
    vault_id: &str,
    role: Role,
    expires_at: Option<&str>,
) -> (NewServiceAccount, Response) {
    let new = person
        .session
        .create_service_account(vault_id, role, "deploy", SERVER, now_ms(), &mut OsRng)
        .unwrap();
    let mut body = serde_json::to_value(&new).unwrap();
    if let Some(at) = expires_at {
        body["expiresAt"] = json!(at);
    }
    let path = format!("/v1/vaults/{vault_id}/service-accounts");
    let response = server
        .send_as(person, Method::POST, &path, Some(body))
        .await;
    (new, response)
}

async fn sign_in(server: &TestServer, token: &ServiceAccountToken) -> Response {
    let challenge = server
        .post(
            "/v1/service-accounts/challenge",
            json!({ "serviceAccountId": token.id() }),
        )
        .await;
    assert_eq!(challenge.status, StatusCode::OK, "{:?}", challenge.body);
    let challenge = challenge.body["challenge"].as_str().unwrap().to_owned();
    let signature = token.keys().sign_challenge(token.id(), &challenge).unwrap();
    server
        .post(
            "/v1/service-accounts/session",
            json!({ "serviceAccountId": token.id(), "challenge": challenge, "signature": signature }),
        )
        .await
}

async fn access_token(server: &TestServer, token: &ServiceAccountToken) -> String {
    let session = sign_in(server, token).await;
    assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
    session.body["accessToken"].as_str().unwrap().to_owned()
}

fn grant_of(record: &Value, id: &str) -> SignedGrant {
    let grant = &record["grant"];
    SignedGrant {
        vault_id: record["id"].as_str().unwrap().into(),
        recipient_account_id: id.into(),
        role: serde_json::from_value(record["role"].clone()).unwrap(),
        wrapped_vault_key: record["wrappedVaultKey"].as_str().unwrap().into(),
        granted_by: grant["grantedBy"].as_str().unwrap().into(),
        granted_at: grant["grantedAt"].as_u64().unwrap(),
        signature: grant["signature"].as_str().unwrap().into(),
    }
}

async fn log(server: &TestServer, person: &Person) -> Vec<Value> {
    let response = server.get_as(person, "/v1/security-log").await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body["events"].as_array().unwrap().clone()
}

#[tokio::test]
async fn a_token_reads_and_decrypts_its_one_vault() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let saved = server.put_new_item(&ada, &vault, "Deploy key").await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    let other_vault = server.shared_vault(&mut ada).await;
    server.put_new_item(&ada, &other_vault, "Not for CI").await;

    let (new, created) = create(&server, &ada, &vault, Role::Read, None).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["role"], "read");
    let text = created.body.to_string();
    assert!(!text.contains(new.token.encode().as_str()), "{text}");

    let token = ServiceAccountToken::parse(&new.token.encode()).unwrap();
    let access = access_token(&server, &token).await;
    let synced = server.get("/v1/service-accounts/sync", &access).await;
    assert_eq!(synced.status, StatusCode::OK, "{:?}", synced.body);
    assert_eq!(synced.body["vaults"].as_array().unwrap().len(), 1);
    let items = synced.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only its own vault");

    let opened = token
        .open_grant(&grant_of(&synced.body["vaults"][0], token.id()))
        .unwrap();
    let record = &items[0];
    let encrypted = EncryptedItem {
        encrypted_item_key: record["encryptedItemKey"].as_str().unwrap().into(),
        overview: record["overview"].as_str().unwrap().into(),
        details: record["details"].as_str().unwrap().into(),
    };
    let item = opened
        .decrypt_item(record["id"].as_str().unwrap(), &encrypted)
        .unwrap();
    assert_eq!(item.overview.title, "Deploy key");

    let events = log(&server, &ada).await;
    assert_eq!(events[0]["type"], "service-account-read");
    assert_eq!(events[0]["serviceAccountId"], token.id());
    assert_eq!(events[1]["type"], "service-account-created");
}

#[tokio::test]
async fn its_tokens_work_nowhere_else() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let (new, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let access = access_token(&server, &new.token).await;

    for path in ["/v1/sync", "/v1/account", "/v1/security-log", "/v1/devices"] {
        let response = server.get(path, &access).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let path = format!("/v1/vaults/{vault}/members");
    assert_eq!(
        server.get(&path, &access).await.status,
        StatusCode::UNAUTHORIZED
    );
    // And a person's token isn't a service account's.
    assert_eq!(
        server
            .get("/v1/service-accounts/sync", &ada.token)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn read_only_by_default_and_write_when_given() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let (reader, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let (writer, _) = create(&server, &ada, &vault, Role::Write, None).await;

    let put = |token: String, id: String, body: Value| {
        let server = &server;
        async move {
            let path = format!("/v1/service-accounts/items/{id}");
            server
                .call(
                    Method::PUT,
                    &path,
                    Some(&token),
                    &[("if-none-match", "*")],
                    Some(body),
                )
                .await
        }
    };

    let item_id = common::new_id();
    let body = ada.item(&vault, &item_id, "From the runner");
    let access = access_token(&server, &reader.token).await;
    let refused = put(access, item_id.clone(), body.clone()).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);

    let access = access_token(&server, &writer.token).await;
    let saved = put(access, item_id, body).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(log(&server, &ada).await[0]["type"], "service-account-wrote");
}

#[tokio::test]
async fn only_managers_of_shared_vaults_make_them() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    assert_eq!(
        server.invite(&ada, &vault, &bob, Role::Read).await.status,
        StatusCode::ACCEPTED
    );
    server.open_shared_vault(&mut bob, &vault).await;

    let (_, refused) = create(&server, &bob, &vault, Role::Read, None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);
    let path = format!("/v1/vaults/{vault}/service-accounts");
    assert_eq!(
        server.get_as(&bob, &path).await.status,
        StatusCode::FORBIDDEN
    );

    // A personal vault's key can't be rotated, so it could never be taken back.
    let mut ada_personal = server.person("cy@example.com").await;
    let personal = ada_personal.personal_vault.clone();
    let wrapped = server.vault_record(&ada_personal, &personal).await.unwrap();
    ada_personal
        .session
        .open_vault(&personal, wrapped["wrappedVaultKey"].as_str().unwrap())
        .unwrap();
    let (_, refused) = create(&server, &ada_personal, &personal, Role::Read, None).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
}

#[tokio::test]
async fn the_grant_must_be_the_callers_own_and_read_or_write() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let new = ada
        .session
        .create_service_account(&vault, Role::Read, "x", SERVER, now_ms(), &mut OsRng)
        .unwrap();
    let path = format!("/v1/vaults/{vault}/service-accounts");

    let mut body = serde_json::to_value(&new).unwrap();
    body["grant"]["role"] = json!("manage");
    let response = server.send_as(&ada, Method::POST, &path, Some(body)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let mut body = serde_json::to_value(&new).unwrap();
    body["grant"]["recipientAccountId"] = json!(common::new_id());
    let response = server.send_as(&ada, Method::POST, &path, Some(body)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let mut body = serde_json::to_value(&new).unwrap();
    body["expiresAt"] = json!("2001-01-01T00:00:00Z");
    let response = server.send_as(&ada, Method::POST, &path, Some(body)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let mut body = serde_json::to_value(&new).unwrap();
    body["keyId"] = json!(common::b64([0u8; 16]));
    let response = server.send_as(&ada, Method::POST, &path, Some(body)).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn revoking_ends_it_at_once_and_later_tries_are_logged() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let (new, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let access = access_token(&server, &new.token).await;

    let path = format!("/v1/vaults/{vault}/service-accounts/{}", new.id);
    let revoked = server.send_as(&ada, Method::DELETE, &path, None).await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{:?}", revoked.body);

    let refused = server.get("/v1/service-accounts/sync", &access).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        sign_in(&server, &new.token).await.status,
        StatusCode::UNAUTHORIZED
    );
    let events = log(&server, &ada).await;
    assert_eq!(events[0]["type"], "service-account-denied");
    assert_eq!(events[1]["type"], "service-account-revoked");

    // It stays listed, for the log, and revoking twice is harmless.
    let again = server.send_as(&ada, Method::DELETE, &path, None).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    let list = format!("/v1/vaults/{vault}/service-accounts");
    let listed = server.get_as(&ada, &list).await;
    assert!(listed.body["serviceAccounts"][0]["revokedAt"].is_string());
    assert_eq!(
        log(&server, &ada)
            .await
            .iter()
            .filter(|event| event["type"] == "service-account-revoked")
            .count(),
        1
    );
}

#[tokio::test]
async fn expiry_is_enforced_by_the_server() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let at = at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (new, created) = create(&server, &ada, &vault, Role::Read, Some(&at)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let access = access_token(&server, &new.token).await;

    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(2 * 3600));
    assert_eq!(
        server
            .get("/v1/service-accounts/sync", &access)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in(&server, &new.token).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_wrong_signature_or_a_used_challenge_gets_nothing() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let (new, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let (other, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let id = new.token.id();

    let challenge = server
        .post(
            "/v1/service-accounts/challenge",
            json!({ "serviceAccountId": id }),
        )
        .await
        .body["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let wrong = other.token.keys().sign_challenge(id, &challenge).unwrap();
    let right = new.token.keys().sign_challenge(id, &challenge).unwrap();
    let body = |signature: &str| json!({ "serviceAccountId": id, "challenge": challenge, "signature": signature });
    let path = "/v1/service-accounts/session";
    assert_eq!(
        server.post(path, body(&wrong)).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A failed try used the challenge up.
    assert_eq!(
        server.post(path, body(&right)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A challenge can't be spent on another id, and unknown ids are told nothing different.
    let unknown = common::new_id();
    let response = server
        .post(
            "/v1/service-accounts/challenge",
            json!({ "serviceAccountId": unknown }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn a_rotation_regrants_it_and_one_left_out_fails_closed() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    server.put_new_item(&ada, &vault, "Deploy key").await;
    let (kept, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let (left_out, _) = create(&server, &ada, &vault, Role::Read, None).await;

    let path = format!("/v1/vaults/{vault}/service-accounts");
    let listed = server.get_as(&ada, &path).await;
    assert_eq!(listed.body["serviceAccounts"].as_array().unwrap().len(), 2);

    let record = server.vault_record(&ada, &vault).await.unwrap();
    let synced = server.sync_all(&ada).await;
    let items: Vec<_> = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["vaultId"] == vault.as_str())
        .map(|item| octapass_core::sharing::vault::ItemKey {
            item_id: item["id"].as_str().unwrap().into(),
            encrypted_item_key: item["encryptedItemKey"].as_str().unwrap().into(),
        })
        .collect();
    let me = ada.recipient(Role::Owner);
    let service = octapass_core::sharing::grant::Recipient {
        account_id: kept.id.clone(),
        public_enc_key: kept.token.keys().public_enc_key(),
        public_pq_key: None,
        role: Role::Read,
    };
    let rotation = ada
        .session
        .rotate_vault_key(&vault, &[me, service], &items, now_ms(), &mut OsRng)
        .unwrap();
    let mut grants = rotation.grants;
    let service_grants = grants.split_off(1);
    let body = json!({
        "revision": record["revision"],
        "keyId": rotation.key_id,
        "grants": grants,
        "items": rotation.items,
        "serviceGrants": service_grants,
    });
    let rotate = format!("/v1/vaults/{vault}/rotate");
    let rotated = server
        .send_as(&ada, Method::POST, &rotate, Some(body))
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);

    for (account, opens) in [(&kept, true), (&left_out, false)] {
        let access = access_token(&server, &account.token).await;
        let synced = server.get("/v1/service-accounts/sync", &access).await;
        let grant = grant_of(&synced.body["vaults"][0], account.token.id());
        let opened = account.token.open_grant(&grant).unwrap();
        let item = &synced.body["items"][0];
        let encrypted = EncryptedItem {
            encrypted_item_key: item["encryptedItemKey"].as_str().unwrap().into(),
            overview: item["overview"].as_str().unwrap().into(),
            details: item["details"].as_str().unwrap().into(),
        };
        let result = opened.decrypt_item(item["id"].as_str().unwrap(), &encrypted);
        assert_eq!(result.is_ok(), opens);
    }
}

#[tokio::test]
async fn a_rotation_cant_grant_a_revoked_or_unknown_service_account() {
    let server = TestServer::new().await;
    let mut ada = server.person("ada@example.com").await;
    let vault = server.shared_vault(&mut ada).await;
    let (new, _) = create(&server, &ada, &vault, Role::Read, None).await;
    let delete = format!("/v1/vaults/{vault}/service-accounts/{}", new.id);
    server.send_as(&ada, Method::DELETE, &delete, None).await;

    let record = server.vault_record(&ada, &vault).await.unwrap();
    let service = octapass_core::sharing::grant::Recipient {
        account_id: new.id.clone(),
        public_enc_key: new.token.keys().public_enc_key(),
        public_pq_key: None,
        role: Role::Read,
    };
    let rotation = ada
        .session
        .rotate_vault_key(
            &vault,
            &[ada.recipient(Role::Owner), service],
            &[],
            now_ms(),
            &mut OsRng,
        )
        .unwrap();
    let mut grants = rotation.grants;
    let service_grants = grants.split_off(1);
    let body = json!({
        "revision": record["revision"], "keyId": rotation.key_id, "grants": grants,
        "items": [], "serviceGrants": service_grants,
    });
    let rotate = format!("/v1/vaults/{vault}/rotate");
    let refused = server
        .send_as(&ada, Method::POST, &rotate, Some(body))
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
}

#[tokio::test]
async fn busy_machines_cant_push_people_out_of_the_log() {
    let server = TestServer::new().await;
    let ada = server.person("ada@example.com").await;
    let sealed = common::envelope(64);
    for _ in 0..6 {
        let body = json!({ "sealedDetails": vec![sealed.clone(); 100] });
        let response = server
            .send_as(&ada, Method::POST, "/v1/security-log/connect", Some(body))
            .await;
        assert_eq!(
            response.status,
            StatusCode::NO_CONTENT,
            "{:?}",
            response.body
        );
    }
    let body = json!({ "format": "csv", "attachments": false });
    server
        .send_as(&ada, Method::POST, "/v1/security-log/exports", Some(body))
        .await;
    for _ in 0..5 {
        let body = json!({ "sealedDetails": vec![sealed.clone(); 100] });
        server
            .send_as(&ada, Method::POST, "/v1/security-log/connect", Some(body))
            .await;
    }
    let events = log(&server, &ada).await;
    assert!(events.iter().any(|event| event["type"] == "vault-exported"));
    assert!(
        events
            .iter()
            .any(|event| event["sealedDetail"] == sealed.as_str())
    );
}

#[tokio::test]
async fn connect_entries_are_opaque_and_bounded() {
    let server = TestServer::new().await;
    let ada = server.person("ada@example.com").await;
    let path = "/v1/security-log/connect";
    let body = json!({ "sealedDetails": vec![common::envelope(64); 101] });
    assert_eq!(
        server
            .send_as(&ada, Method::POST, path, Some(body))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let body = json!({ "sealedDetails": ["not an envelope"] });
    assert_eq!(
        server
            .send_as(&ada, Method::POST, path, Some(body))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let body = json!({ "sealedDetails": ["x"] });
    assert_eq!(
        server
            .call(Method::POST, path, None, &[], Some(body))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}
