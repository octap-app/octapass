//! Storage quotas and paginated sync.

use crate::common;

use axum::http::{Method, StatusCode};
use common::*;
use octapass_server::Config;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

async fn create_many(server: &TestServer, token: &str, vault_id: &str, count: usize) -> Response {
    let operations: Vec<Value> = (0..count)
        .map(|_| json!({ "op": "put", "vaultId": vault_id, "itemId": new_id(), "item": item_body(1) }))
        .collect();
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

#[tokio::test]
async fn item_count_quota_is_enforced() {
    let server = TestServer::with_config(|config: &mut Config| config.quota.items = 3).await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;

    let over = create_many(&server, &device.access_token, &vault_id, 4).await;
    let results = over.body["results"].as_array().unwrap();
    assert!(results.iter().all(|r| r["status"] == 403), "{results:?}");
    assert_eq!(
        results[0]["problem"]["type"],
        "https://octap.app/problems/quota-exceeded"
    );

    let fits = create_many(&server, &device.access_token, &vault_id, 3).await;
    assert!(
        fits.body["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] == 200)
    );

    // Items in the trash still count, until they're purged.
    let synced = server.get("/v1/sync", &device.access_token).await;
    let first = synced.body["items"][0]["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/vaults/{vault_id}/items/{first}");
    let trashed = server
        .call(
            Method::DELETE,
            &path,
            Some(&device.access_token),
            &[("if-match", "\"1\"")],
            None,
        )
        .await;
    assert_eq!(trashed.status, StatusCode::OK);
    let fourth = server
        .put_item(
            &device.access_token,
            &vault_id,
            &new_id(),
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(fourth.status, StatusCode::FORBIDDEN);
    assert!(fourth.is_problem("quota-exceeded"));

    // Updates that don't grow still work at the limit.
    let restored = server
        .call(
            Method::POST,
            &format!("{path}/restore"),
            Some(&device.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(restored.status, StatusCode::OK);
    let updated = server
        .put_item(
            &device.access_token,
            &vault_id,
            &first,
            ("if-match", "\"3\""),
            2,
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{:?}", updated.body);
}

#[tokio::test]
async fn byte_quota_is_enforced() {
    // item_body is about 760 bytes of base64url.
    let server = TestServer::with_config(|config: &mut Config| config.quota.bytes = 2000).await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    for (i, expected) in [StatusCode::OK, StatusCode::OK, StatusCode::FORBIDDEN]
        .into_iter()
        .enumerate()
    {
        let response = server
            .put_item(
                &device.access_token,
                &vault_id,
                &new_id(),
                ("if-none-match", "*"),
                1,
            )
            .await;
        assert_eq!(response.status, expected, "item {i}");
    }
}

#[tokio::test]
async fn sync_pages_until_has_more_is_false() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    for _ in 0..3 {
        let created = create_many(&server, &device.access_token, &vault_id, 600).await;
        assert_eq!(created.status, StatusCode::OK);
    }

    // 1,000 items per page, but revision 2's batch is never split.
    let first = server.get("/v1/sync", &device.access_token).await;
    assert_eq!(first.body["hasMore"], true);
    assert_eq!(first.body["items"].as_array().unwrap().len(), 1200);
    assert_eq!(first.body["vaults"][0]["revision"], 2);

    let next = server
        .get(
            &format!("/v1/sync?since={vault_id}:2"),
            &device.access_token,
        )
        .await;
    assert_eq!(next.body["hasMore"], false);
    assert_eq!(next.body["items"].as_array().unwrap().len(), 600);
    assert_eq!(next.body["vaults"][0]["revision"], 3);
}
