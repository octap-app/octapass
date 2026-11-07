//! The internal API, on its own socket with a real client-less request path.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{DOMAIN, Harness};
use http_body_util::BodyExt;
use octapass_relay::api;
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "a-test-api-token-that-is-long-enough";

async fn call(
    harness: &Harness,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = api::router(harness.running.relay.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn create(harness: &Harness, account: &str, email: &str) -> (StatusCode, Value) {
    call(
        harness,
        Method::POST,
        &format!("/internal/accounts/{account}/aliases"),
        Some(TOKEN),
        json!({ "email": email }),
    )
    .await
}

#[tokio::test]
async fn nothing_works_without_the_token() {
    let harness = Harness::start().await;
    let path = "/internal/accounts/a";
    for token in [None, Some("wrong"), Some("")] {
        let (status, _) = call(&harness, Method::DELETE, path, token, json!({})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    let (status, _) = call(&harness, Method::GET, "/healthz", None, json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn aliases_can_be_made_listed_switched_and_deleted() {
    let harness = Harness::start().await;
    let (status, alias) = create(&harness, "a", "me@mail.example").await;
    assert_eq!(status, StatusCode::CREATED, "{alias}");
    let id = alias["id"].as_str().unwrap();
    assert_eq!(alias["address"], format!("{id}@{DOMAIN}"));
    assert_eq!(alias["enabled"], true);
    assert_eq!(alias["paused"], false);
    assert_eq!(alias["forwarded"], 0);
    assert!(alias["createdAt"].as_str().unwrap().ends_with('Z'));

    let (status, account) = call(
        &harness,
        Method::PUT,
        "/internal/accounts/a",
        Some(TOKEN),
        json!({ "email": "me@mail.example" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account["aliases"].as_array().unwrap().len(), 1);
    assert_eq!(account["domain"], DOMAIN);
    assert_eq!(account["maxAliases"], 200);

    let path = format!("/internal/accounts/a/aliases/{id}");
    let (status, off) = call(
        &harness,
        Method::PATCH,
        &path,
        Some(TOKEN),
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(off["enabled"], false);

    let (status, _) = call(&harness, Method::DELETE, &path, Some(TOKEN), json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(&harness, Method::DELETE, &path, Some(TOKEN), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_account_can_only_reach_its_own_aliases() {
    let harness = Harness::start().await;
    let (_, alias) = create(&harness, "owner", "me@mail.example").await;
    let id = alias["id"].as_str().unwrap();
    let path = format!("/internal/accounts/other/aliases/{id}");
    let (status, _) = call(
        &harness,
        Method::PATCH,
        &path,
        Some(TOKEN),
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&harness, Method::DELETE, &path, Some(TOKEN), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let block = format!("{path}/block");
    let (status, _) = call(
        &harness,
        Method::POST,
        &block,
        Some(TOKEN),
        json!({ "sender": "a@sender.example" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let store = harness.running.relay.store();
    assert!(store.alias(id).await.unwrap().unwrap().enabled);
}

#[tokio::test]
async fn the_caps_hold() {
    let harness = Harness::with(|config| {
        config.limits.aliases_per_account = 3;
        config.limits.aliases_per_day = 2;
    })
    .await;
    assert_eq!(
        create(&harness, "a", "me@mail.example").await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        create(&harness, "a", "me@mail.example").await.0,
        StatusCode::CREATED
    );
    let (status, body) = create(&harness, "a", "me@mail.example").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "alias-daily-limit");

    let harness = Harness::with(|config| config.limits.aliases_per_account = 1).await;
    assert_eq!(
        create(&harness, "a", "me@mail.example").await.0,
        StatusCode::CREATED
    );
    let (status, body) = create(&harness, "a", "me@mail.example").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "alias-limit");
}

#[tokio::test]
async fn a_destination_must_be_able_to_receive() {
    let harness = Harness::start().await;
    for email in [
        "not an address",
        "loop@relay.example",
        "LOOP@RELAY.EXAMPLE",
        "a%b@mail.example",
    ] {
        let (status, body) = create(&harness, "a", email).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{email}");
        assert_eq!(body["error"], "bad-destination");
    }
}

#[tokio::test]
async fn an_email_change_reaches_forwarding_and_replies() {
    let harness = Harness::start().await;
    let (_, alias) = create(&harness, "a", "old@mail.example").await;
    let (status, _) = call(
        &harness,
        Method::PUT,
        "/internal/accounts/a",
        Some(TOKEN),
        json!({ "email": "new@mail.example" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let store = harness.running.relay.store();
    assert_eq!(
        store.destination("a").await.unwrap().as_deref(),
        Some("new@mail.example")
    );
    assert!(
        store
            .sender_is_destination("a", "new@mail.example")
            .await
            .unwrap()
    );
    assert!(
        !store
            .sender_is_destination("a", "old@mail.example")
            .await
            .unwrap()
    );
    assert!(
        store
            .alias(alias["id"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn deleting_an_account_takes_everything_with_it() {
    let harness = Harness::start().await;
    let (_, alias) = create(&harness, "a", "me@mail.example").await;
    let id = alias["id"].as_str().unwrap().to_owned();
    let store = harness.running.relay.store();
    store
        .contact(&id, "jane@sender.example", 10)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .set_blocked("a", &id, "spam@sender.example", true)
            .await
            .unwrap()
    );

    for _ in 0..2 {
        let (status, _) = call(
            &harness,
            Method::DELETE,
            "/internal/accounts/a",
            Some(TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "and it's safe to repeat");
    }
    assert_eq!(store.destination("a").await.unwrap(), None);
    assert!(store.alias(&id).await.unwrap().is_none());
    for table in ["relay_contacts", "relay_blocked_senders", "relay_aliases"] {
        let (count,): (i64,) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&harness.running.relay.db)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[tokio::test]
async fn a_block_needs_an_address() {
    let harness = Harness::start().await;
    let (_, alias) = create(&harness, "a", "me@mail.example").await;
    let id = alias["id"].as_str().unwrap();
    let block = format!("/internal/accounts/a/aliases/{id}/block");
    let (status, body) = call(
        &harness,
        Method::POST,
        &block,
        Some(TOKEN),
        json!({ "sender": "nope" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad-sender");
    let (status, _) = call(
        &harness,
        Method::POST,
        &block,
        Some(TOKEN),
        json!({ "sender": "Jane@Sender.Example" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let store = harness.running.relay.store();
    assert!(store.is_blocked(id, "jane@sender.example").await.unwrap());
    let unblock = format!("/internal/accounts/a/aliases/{id}/unblock");
    let (status, _) = call(
        &harness,
        Method::POST,
        &unblock,
        Some(TOKEN),
        json!({ "sender": "jane@sender.example" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!store.is_blocked(id, "jane@sender.example").await.unwrap());
}
