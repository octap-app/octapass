//! `POST /v1/batch`: many writes at once, atomic per vault.

use crate::common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

async fn batch(server: &TestServer, token: &str, operations: Vec<Value>) -> Response {
    server
        .call(
            Method::POST,
            "/v1/batch",
            Some(token),
            &[],
            Some(json!({ "operations": operations })),
        )
        .await
}

fn put(vault_id: &str, item_id: &str, if_match: Option<Value>, label: u8) -> Value {
    let mut op =
        json!({ "op": "put", "vaultId": vault_id, "itemId": item_id, "item": item_body(label) });
    if let Some(if_match) = if_match {
        op["ifMatch"] = if_match;
    }
    op
}

fn statuses(response: &Response) -> Vec<u64> {
    response.body["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["status"].as_u64().unwrap())
        .collect()
}

async fn vault_revision(server: &TestServer, token: &str) -> u64 {
    server.get("/v1/sync", token).await.body["vaults"][0]["revision"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn creates_updates_deletes_and_restores_in_one_revision() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let ids: Vec<String> = (0..3).map(|_| new_id()).collect();

    let created = batch(
        &server,
        &device.access_token,
        ids.iter().map(|id| put(&vault_id, id, None, 1)).collect(),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
    for (result, id) in created.body["results"].as_array().unwrap().iter().zip(&ids) {
        assert_eq!(
            result,
            &json!({ "itemId": id, "status": 200, "revision": 1 })
        );
    }
    let synced = server.get("/v1/sync", &device.access_token).await;
    assert_eq!(synced.body["items"].as_array().unwrap().len(), 3);
    assert_eq!(synced.body["vaults"][0]["revision"], 1);

    let mixed = batch(
        &server,
        &device.access_token,
        vec![
            put(&vault_id, &ids[0], Some(json!(1)), 2),
            put(&vault_id, &ids[1], Some(json!("*")), 2),
            json!({ "op": "delete", "vaultId": vault_id, "itemId": ids[2], "ifMatch": "*" }),
        ],
    )
    .await;
    assert_eq!(statuses(&mixed), [200, 200, 200]);
    assert_eq!(mixed.body["results"][2]["revision"], 2);

    let restored = batch(
        &server,
        &device.access_token,
        vec![
            json!({ "op": "restore", "vaultId": vault_id, "itemId": ids[2] }),
            // Restoring an item that isn't in the trash changes nothing.
            json!({ "op": "restore", "vaultId": vault_id, "itemId": ids[0] }),
        ],
    )
    .await;
    assert_eq!(statuses(&restored), [200, 200]);
    assert_eq!(restored.body["results"][0]["revision"], 3);
    assert_eq!(restored.body["results"][1]["revision"], 2);

    let items = server
        .get(
            &format!("/v1/sync?since={vault_id}:1"),
            &device.access_token,
        )
        .await
        .body["items"]
        .clone();
    assert_eq!(items.as_array().unwrap().len(), 3);
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i.get("deletedAt").is_none())
    );
    assert_eq!(unb64(&items[0]["details"]).last(), Some(&2));
}

#[tokio::test]
async fn one_failure_aborts_its_vault_only() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let other_vault = server.register("bob@example.com").await;
    let device = server.login(EMAIL, "Laptop").await;
    let existing = new_id();
    server
        .put_item(
            &device.access_token,
            &vault_id,
            &existing,
            ("if-none-match", "*"),
            1,
        )
        .await;

    let response = batch(
        &server,
        &device.access_token,
        vec![
            put(&vault_id, &new_id(), None, 1),
            put(&vault_id, &existing, Some(json!(7)), 2),
            json!({ "op": "delete", "vaultId": vault_id, "itemId": new_id(), "ifMatch": 1 }),
            put(&other_vault, &new_id(), None, 1),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(statuses(&response), [424, 409, 404, 404]);
    let results = &response.body["results"];
    assert_eq!(
        results[0]["problem"]["type"],
        "https://octap.app/problems/batch-aborted"
    );
    assert_eq!(results[1]["problem"]["current"]["revision"], 1);
    assert!(results[0].get("revision").is_none());

    // Nothing in the vault changed, not even its revision.
    assert_eq!(vault_revision(&server, &device.access_token).await, 1);

    // Another vault in the same batch commits independently.
    let independent = batch(
        &server,
        &device.access_token,
        vec![
            put(&other_vault, &new_id(), None, 1),
            put(&vault_id, &new_id(), None, 1),
        ],
    )
    .await;
    assert_eq!(statuses(&independent), [404, 200]);
    assert_eq!(vault_revision(&server, &device.access_token).await, 2);
}

#[tokio::test]
async fn read_only_vaults_are_forbidden() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    sqlx::query("UPDATE vault_members SET role = 'read' WHERE vault_id = $1")
        .bind(&vault_id)
        .execute(&server.state.db)
        .await
        .unwrap();
    let response = batch(
        &server,
        &device.access_token,
        vec![
            put(&vault_id, &new_id(), None, 1),
            put(&vault_id, &new_id(), None, 1),
        ],
    )
    .await;
    assert_eq!(statuses(&response), [403, 403]);
}

#[tokio::test]
async fn operations_are_checked_like_single_writes() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let mut bad_item = put(&vault_id, &new_id(), None, 1);
    bad_item["item"]["details"] = json!("not-an-envelope");

    let response = batch(
        &server,
        &device.access_token,
        vec![
            put(&vault_id, &new_id(), None, 1),
            json!({ "op": "delete", "vaultId": vault_id, "itemId": new_id() }),
            json!({ "op": "put", "vaultId": vault_id, "itemId": new_id() }),
            bad_item,
        ],
    )
    .await;
    assert_eq!(statuses(&response), [424, 428, 400, 400]);
    assert_eq!(vault_revision(&server, &device.access_token).await, 0);
}

#[tokio::test]
async fn rejects_malformed_batches() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let item_id = new_id();

    let cases = [
        vec![
            put(&vault_id, &item_id, None, 1),
            put(&vault_id, &item_id, None, 2),
        ],
        vec![put("not-a-uuid", &item_id, None, 1)],
        vec![put(&vault_id, &item_id.to_uppercase(), None, 1)],
        (0..1001)
            .map(|_| json!({ "op": "restore", "vaultId": vault_id, "itemId": new_id() }))
            .collect(),
    ];
    for operations in cases {
        let response = batch(&server, &device.access_token, operations).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            response.is_problem("invalid-request"),
            "{:?}",
            response.body
        );
    }
    let unauthenticated = server
        .call(
            Method::POST,
            "/v1/batch",
            None,
            &[],
            Some(json!({ "operations": [] })),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    let empty = batch(&server, &device.access_token, vec![]).await;
    assert_eq!(empty.body, json!({ "results": [] }));
}

#[tokio::test]
async fn a_full_batch_fits_in_one_request() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    // About 3 MiB: over the 1 MiB limit of other endpoints.
    let operations: Vec<Value> = (0..1000)
        .map(|_| {
            let mut op = put(&vault_id, &new_id(), None, 1);
            op["item"]["details"] = json!(envelope(2000));
            op
        })
        .collect();
    assert!(json!(operations).to_string().len() > 2 * 1024 * 1024);
    let response = batch(&server, &device.access_token, operations).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert!(statuses(&response).iter().all(|&s| s == 200));
    let synced = server.get("/v1/sync", &device.access_token).await;
    assert_eq!(synced.body["items"].as_array().unwrap().len(), 1000);
    assert_eq!(synced.body["vaults"][0]["revision"], 1);
}
