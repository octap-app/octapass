//! `GET /v1/ws`: live change notifications.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const EMAIL: &str = "alice@example.com";

async fn device_id(server: &TestServer, device: &Device, name: &str) -> String {
    let list = server.get("/v1/devices", &device.access_token).await.body;
    list.as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn authenticates_with_the_first_message() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;

    let mut socket = ws_connect(addr).await;
    ws_send_auth(&mut socket, &device.access_token).await;
    let reply = ws_next(&mut socket).await;
    assert_eq!(reply["type"], "authenticated");
    let expires_in = reply["expiresIn"].as_u64().unwrap();
    assert!((890..=900).contains(&expires_in), "{expires_in}");

    let mut wrong = ws_connect(addr).await;
    ws_send_auth(&mut wrong, "not-a-token").await;
    assert_eq!(ws_close_code(&mut wrong).await, 4401);

    let mut not_auth = ws_connect(addr).await;
    let hello = json!({ "type": "hello" }).to_string();
    not_auth.send(WsMessage::Text(hello.into())).await.unwrap();
    assert_eq!(ws_close_code(&mut not_auth).await, 4400);

    let mut binary = ws_connect(addr).await;
    binary
        .send(WsMessage::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(ws_close_code(&mut binary).await, 4400);

    // A plain GET is not an upgrade.
    let plain = server.call(Method::GET, "/v1/ws", None, &[], None).await;
    assert_eq!(plain.status, StatusCode::BAD_REQUEST);
    assert!(plain.is_problem("invalid-request"));
}

#[tokio::test]
async fn announces_changes_from_other_sessions() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    let vault_id = server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    let bob_vault = server.register("bob@example.com").await;
    let bob = server.login("bob@example.com", "Bob's laptop").await;
    let mut laptop_socket = ws_auth(addr, &laptop.access_token).await;
    let mut bob_socket = ws_auth(addr, &bob.access_token).await;

    let item_id = new_id();
    let created = server
        .put_item(
            &phone.access_token,
            &vault_id,
            &item_id,
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(created.status, StatusCode::OK);
    let message = ws_next(&mut laptop_socket).await;
    assert_eq!(
        message,
        json!({ "type": "vault-changed", "vaultId": vault_id, "revision": 1 })
    );

    // A batch is one notification, and no-ops and failures are none.
    let batch = |operations: Vec<Value>| {
        server.call(
            Method::POST,
            "/v1/batch",
            Some(&phone.access_token),
            &[],
            Some(json!({ "operations": operations })),
        )
    };
    let restore_noop = json!({ "op": "restore", "vaultId": vault_id, "itemId": item_id });
    batch(vec![restore_noop]).await;
    let conflict =
        json!({ "op": "put", "vaultId": vault_id, "itemId": item_id, "item": item_body(2) });
    batch(vec![conflict]).await;
    let creates = (0..3)
        .map(|_| json!({ "op": "put", "vaultId": vault_id, "itemId": new_id(), "item": item_body(3) }))
        .collect();
    batch(creates).await;
    let message = ws_next(&mut laptop_socket).await;
    assert_eq!(message["revision"], 2, "{message:?}");

    // Bob only hears about his own vault.
    server
        .put_item(
            &bob.access_token,
            &bob_vault,
            &new_id(),
            ("if-none-match", "*"),
            1,
        )
        .await;
    let message = ws_next(&mut bob_socket).await;
    assert_eq!(message["vaultId"], bob_vault.as_str());

    // Deletes and restores are changes too.
    let path = format!("/v1/vaults/{vault_id}/items/{item_id}");
    server
        .call(
            Method::DELETE,
            &path,
            Some(&phone.access_token),
            &[("if-match", "\"1\"")],
            None,
        )
        .await;
    assert_eq!(ws_next(&mut laptop_socket).await["revision"], 3);
}

#[tokio::test]
async fn reauthenticates_after_a_token_refresh() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    let vault_id = server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    let mut socket = ws_auth(addr, &laptop.access_token).await;

    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": laptop.refresh_token }),
        )
        .await;
    let new_token = refreshed.body["accessToken"].as_str().unwrap();
    ws_send_auth(&mut socket, new_token).await;
    assert_eq!(ws_next(&mut socket).await["type"], "authenticated");

    server
        .put_item(
            &phone.access_token,
            &vault_id,
            &new_id(),
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(ws_next(&mut socket).await["type"], "vault-changed");

    // Another device's token can't take over the connection.
    ws_send_auth(&mut socket, &phone.access_token).await;
    assert_eq!(ws_close_code(&mut socket).await, 4400);

    // The old token no longer authenticates anything.
    let mut stale = ws_connect(addr).await;
    ws_send_auth(&mut stale, &laptop.access_token).await;
    assert_eq!(ws_close_code(&mut stale).await, 4401);
}

#[tokio::test]
async fn remote_sign_out_revokes_the_session() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    let mut phone_socket = ws_auth(addr, &phone.access_token).await;
    let mut laptop_socket = ws_auth(addr, &laptop.access_token).await;

    let phone_id = device_id(&server, &laptop, "Phone").await;
    let removed = server
        .call(
            Method::DELETE,
            &format!("/v1/devices/{phone_id}"),
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(
        ws_next(&mut phone_socket).await,
        json!({ "type": "session-revoked" })
    );
    assert_eq!(ws_close_code(&mut phone_socket).await, 4401);

    // The laptop stays connected: its next message is about its own sign-out.
    server
        .call(
            Method::POST,
            "/v1/auth/logout",
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(ws_next(&mut laptop_socket).await["type"], "session-revoked");
}

#[tokio::test]
async fn a_reused_refresh_token_revokes_the_session() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let mut socket = ws_auth(addr, &laptop.access_token).await;

    let refresh = json!({ "refreshToken": laptop.refresh_token });
    server.post("/v1/auth/refresh", refresh.clone()).await;
    let reused = server.post("/v1/auth/refresh", refresh).await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(ws_next(&mut socket).await["type"], "session-revoked");
}

#[tokio::test]
async fn announces_account_deletion() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    let mut phone_socket = ws_auth(addr, &phone.access_token).await;

    let token = reauth_token(&server, &laptop).await;
    let deleted = delete_account(&server, &laptop, Some(&token), EMAIL).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        ws_next(&mut phone_socket).await,
        json!({ "type": "account-deleted" })
    );
    assert_eq!(ws_close_code(&mut phone_socket).await, 4401);

    // Connecting later with a token of the deleted account says so too.
    let mut late = ws_connect(addr).await;
    ws_send_auth(&mut late, &phone.access_token).await;
    assert_eq!(ws_next(&mut late).await["type"], "account-deleted");
    assert_eq!(ws_close_code(&mut late).await, 4401);
}

#[tokio::test]
async fn pings_and_drops_silent_clients() {
    let server = TestServer::with_config(|config| {
        config.ws_heartbeat = Duration::from_millis(100);
    })
    .await;
    let addr = server.listen().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let mut socket = ws_auth(addr, &device.access_token).await;

    // Reading lets tungstenite answer each ping, so the connection stays up.
    for _ in 0..3 {
        assert!(matches!(ws_frame(&mut socket).await, WsMessage::Ping(_)));
    }
    // A client that stops reading never pongs and is dropped.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let closed = loop {
        match tokio::time::timeout(Duration::from_secs(2), socket.next()).await {
            Ok(Some(Ok(WsMessage::Ping(_)))) => continue,
            Ok(_) => break true,
            Err(_) => break false,
        }
    };
    assert!(closed, "the server should have dropped the connection");
}
