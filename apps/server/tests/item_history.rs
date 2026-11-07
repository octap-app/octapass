//! Item version history: the server keeps the last 10 versions of an item as ciphertext.

use crate::common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

fn path(vault_id: &str, item_id: &str) -> String {
    format!("/v1/vaults/{vault_id}/items/{item_id}/history")
}

/// Puts a version of the item for each label and returns its revision.
async fn edit(
    server: &TestServer,
    token: &str,
    vault_id: &str,
    item_id: &str,
    mut revision: u64,
    labels: std::ops::Range<u8>,
) -> u64 {
    for label in labels {
        let tag = format!("\"{revision}\"");
        let written = server
            .put_item(token, vault_id, item_id, ("if-match", &tag), label)
            .await;
        assert_eq!(written.status, StatusCode::OK, "{:?}", written.body);
        revision = written.body["revision"].as_u64().unwrap();
    }
    revision
}

async fn item(server: &TestServer, token: &str, vault_id: &str, item_id: &str) -> u64 {
    let created = server
        .put_item(token, vault_id, item_id, ("if-none-match", "*"), 0)
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
    created.body["revision"].as_u64().unwrap()
}

/// The label `item_body` left in the last byte of each version's `field`.
fn labels(history: &Value, field: &str) -> Vec<u8> {
    history["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| *unb64(&r[field]).last().unwrap())
        .collect()
}

async fn item_bytes(server: &TestServer, token: &str) -> u64 {
    let usage = server.get("/v1/account/usage", token).await;
    usage.body["itemBytes"].as_u64().unwrap()
}

#[tokio::test]
async fn the_last_ten_versions_are_kept_newest_first() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = &device.access_token;
    let item_id = new_id();

    // A new item has no past versions.
    let revision = item(&server, token, &vault_id, &item_id).await;
    let history = server.get(&path(&vault_id, &item_id), token).await;
    assert_eq!(history.status, StatusCode::OK);
    assert_eq!(history.body["revisions"], json!([]));

    // Labels 0..=11 written: 11 is current, 1..=10 are the past versions, 0 fell off.
    edit(&server, token, &vault_id, &item_id, revision, 1..12).await;
    let history = server.get(&path(&vault_id, &item_id), token).await;
    let expected: Vec<u8> = (1..=10).rev().collect();
    assert_eq!(labels(&history.body, "overview"), expected);
    assert_eq!(labels(&history.body, "details"), expected);
    let revisions = history.body["revisions"].as_array().unwrap();
    assert!(revisions[0]["revision"].as_u64() > revisions[1]["revision"].as_u64());
    assert!(revisions[0]["updatedAt"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn trashing_and_restoring_add_no_version() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = &device.access_token;
    let item_id = new_id();
    let revision = item(&server, token, &vault_id, &item_id).await;

    let tag = format!("\"{revision}\"");
    let trashed = server
        .call(
            Method::DELETE,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(token),
            &[("if-match", &tag)],
            None,
        )
        .await;
    assert_eq!(trashed.status, StatusCode::OK);
    let restored = server
        .call(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/items/{item_id}/restore"),
            Some(token),
            &[],
            None,
        )
        .await;
    assert_eq!(restored.status, StatusCode::OK);
    let history = server.get(&path(&vault_id, &item_id), token).await;
    assert_eq!(history.body["revisions"], json!([]));
}

#[tokio::test]
async fn bookkeeping_writes_keep_the_history_as_it_is() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = &device.access_token;
    let item_id = new_id();
    let revision = item(&server, token, &vault_id, &item_id).await;

    let mut body = item_body(1);
    body["skipHistory"] = json!(true);
    let tag = format!("\"{revision}\"");
    let written = server
        .call(
            Method::PUT,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(token),
            &[("if-match", &tag)],
            Some(body),
        )
        .await;
    assert_eq!(written.status, StatusCode::OK, "{:?}", written.body);
    let history = server.get(&path(&vault_id, &item_id), token).await;
    assert_eq!(history.body["revisions"], json!([]));
}

#[tokio::test]
async fn only_vault_members_read_an_items_history() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let item_id = new_id();
    item(&server, &device.access_token, &vault_id, &item_id).await;

    server.register("mallory@example.com").await;
    let other = server.login("mallory@example.com", "Phone").await;
    let refused = server
        .get(&path(&vault_id, &item_id), &other.access_token)
        .await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
    let missing = server
        .get(&path(&vault_id, &new_id()), &device.access_token)
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn history_counts_against_the_quota_and_goes_with_its_item() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = &device.access_token;
    let item_id = new_id();
    let revision = item(&server, token, &vault_id, &item_id).await;
    let before = item_bytes(&server, token).await;

    let revision = edit(&server, token, &vault_id, &item_id, revision, 1..2).await;
    let body = item_body(0);
    let version =
        (body["overview"].as_str().unwrap().len() + body["details"].as_str().unwrap().len()) as u64;
    assert_eq!(item_bytes(&server, token).await, before + version);

    // Past the limit, each new version replaces the oldest: the total stops growing.
    let revision = edit(&server, token, &vault_id, &item_id, revision, 2..11).await;
    let full = item_bytes(&server, token).await;
    assert_eq!(full, before + 10 * version);
    edit(&server, token, &vault_id, &item_id, revision, 11..13).await;
    assert_eq!(item_bytes(&server, token).await, full);

    // Purged from the trash: every version goes, and the bytes are given back.
    let current = server.get("/v1/sync", token).await;
    let revision = current.body["items"][0]["revision"].as_u64().unwrap();
    let tag = format!("\"{revision}\"");
    server
        .call(
            Method::DELETE,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(token),
            &[("if-match", &tag)],
            None,
        )
        .await;
    sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
        .bind(server.state_now() - 31 * 24 * 60 * 60 * 1000)
        .bind(&item_id)
        .execute(&server.state.db)
        .await
        .unwrap();
    server.state.run_maintenance().await.unwrap();
    assert_eq!(item_bytes(&server, token).await, 0);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM item_history")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
