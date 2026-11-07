//! The main flow: register → login → refresh → sync → create/update/conflict →
//! delete/restore → logout.

use crate::common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

const EMAIL: &str = "alice@example.com";

#[tokio::test]
async fn server_info_and_health() {
    let server = TestServer::new().await;
    for path in ["/healthz", "/readyz"] {
        assert_eq!(
            server.call(Method::GET, path, None, &[], None).await.status,
            StatusCode::OK
        );
    }
    let info = server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.body["name"], "Octa Pass");
    assert_eq!(info.body["apiVersion"], 1);
    assert_eq!(info.body["signups"], "open");
    assert_eq!(info.body["pushRelay"], false);
}

#[tokio::test]
async fn full_sync_flow() {
    let server = TestServer::new().await;
    let vault_id = server.register("  Alice@Example.com ").await;

    let laptop = server.login(EMAIL, "Laptop").await;
    assert_eq!(laptop.account["email"], EMAIL);
    assert!(laptop.account["accountId"].is_string());
    let account = server.get("/v1/account", &laptop.access_token).await;
    assert_eq!(account.status, StatusCode::OK);
    assert_eq!(account.body, laptop.account);

    // A fresh account has its personal vault and nothing else.
    let sync = server.get("/v1/sync", &laptop.access_token).await;
    assert_eq!(sync.status, StatusCode::OK);
    assert_eq!(sync.body["vaults"].as_array().unwrap().len(), 1);
    assert_eq!(sync.body["vaults"][0]["id"], vault_id.as_str());
    assert_eq!(sync.body["vaults"][0]["type"], "personal");
    assert_eq!(sync.body["vaults"][0]["role"], "owner");
    assert_eq!(sync.body["vaults"][0]["revision"], 0);
    assert_eq!(sync.body["items"], json!([]));

    // Create.
    let item_id = new_id();
    let created = server
        .put_item(
            &laptop.access_token,
            &vault_id,
            &item_id,
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
    assert_eq!(created.body["revision"], 1);
    assert_eq!(created.headers["etag"], "\"1\"");

    // Creating the same id again is a conflict that returns the stored item.
    let again = server
        .put_item(
            &laptop.access_token,
            &vault_id,
            &item_id,
            ("if-none-match", "*"),
            9,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert!(again.is_problem("conflict"));
    assert_eq!(again.body["current"]["revision"], 1);
    assert_eq!(unb64(&again.body["current"]["details"]).last(), Some(&1));

    // Update with the right revision.
    let updated = server
        .put_item(
            &laptop.access_token,
            &vault_id,
            &item_id,
            ("if-match", "\"1\""),
            2,
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{:?}", updated.body);
    assert_eq!(updated.body["revision"], 2);

    // A second device syncs from scratch and sees the latest version.
    let phone = server.login(EMAIL, "Phone").await;
    let phone_sync = server.get("/v1/sync", &phone.access_token).await;
    let items = phone_sync.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], item_id.as_str());
    assert_eq!(items[0]["vaultId"], vault_id.as_str());
    assert_eq!(items[0]["revision"], 2);
    assert_eq!(unb64(&items[0]["details"]).last(), Some(&2));
    assert!(items[0]["updatedAt"].as_str().unwrap().ends_with('Z'));
    assert!(items[0].get("deletedAt").is_none());

    // The phone's stale write conflicts and gets the server version back.
    let stale = server
        .put_item(
            &phone.access_token,
            &vault_id,
            &item_id,
            ("if-match", "\"1\""),
            3,
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["current"]["revision"], 2);
    assert_eq!(unb64(&stale.body["current"]["details"]).last(), Some(&2));

    // Incremental sync only returns what changed.
    let unchanged = server
        .get(&format!("/v1/sync?since={vault_id}:2"), &phone.access_token)
        .await;
    assert_eq!(unchanged.body["items"], json!([]));
    assert_eq!(unchanged.body["vaults"][0]["revision"], 2);

    // Delete moves the item to the trash.
    let path = format!("/v1/vaults/{vault_id}/items/{item_id}");
    let deleted = server
        .call(
            Method::DELETE,
            &path,
            Some(&laptop.access_token),
            &[("if-match", "\"2\"")],
            None,
        )
        .await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.body);
    assert_eq!(deleted.body["revision"], 3);
    let trash = server
        .get(&format!("/v1/sync?since={vault_id}:2"), &phone.access_token)
        .await;
    assert_eq!(trash.body["items"][0]["revision"], 3);
    assert!(trash.body["items"][0]["deletedAt"].is_string());

    // Deleting needs the current revision.
    let no_match = server
        .call(Method::DELETE, &path, Some(&laptop.access_token), &[], None)
        .await;
    assert_eq!(no_match.status, StatusCode::PRECONDITION_REQUIRED);

    // Restore brings it back.
    let restored = server
        .call(
            Method::POST,
            &format!("{path}/restore"),
            Some(&phone.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(restored.status, StatusCode::OK, "{:?}", restored.body);
    assert_eq!(restored.body["revision"], 4);
    let back = server
        .get(
            &format!("/v1/sync?since={vault_id}:3"),
            &laptop.access_token,
        )
        .await;
    assert_eq!(back.body["items"][0]["revision"], 4);
    assert!(back.body["items"][0].get("deletedAt").is_none());
    assert_eq!(back.body["deleted"], json!([]));

    // Refresh rotates both tokens.
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": laptop.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert_eq!(refreshed.body["expiresIn"], 900);
    let new_access = refreshed.body["accessToken"].as_str().unwrap();
    assert_ne!(new_access, laptop.access_token);
    assert_eq!(
        server.get("/v1/account", &laptop.access_token).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.get("/v1/account", new_access).await.status,
        StatusCode::OK
    );

    // Reusing the old refresh token revokes the whole session.
    let reused = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": laptop.refresh_token }),
        )
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert!(reused.is_problem("unauthorized"));
    assert_eq!(
        server.get("/v1/account", new_access).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Logout revokes this device only.
    let logout = server
        .call(
            Method::POST,
            "/v1/auth/logout",
            Some(&phone.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let after = server.get("/v1/sync", &phone.access_token).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert!(after.is_problem("unauthorized"));
    let refresh_after = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": phone.refresh_token }),
        )
        .await;
    assert_eq!(refresh_after.status, StatusCode::UNAUTHORIZED);
    let tablet = server.login(EMAIL, "Tablet").await;
    assert_eq!(
        server.get("/v1/account", &tablet.access_token).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn items_are_scoped_to_the_account() {
    let server = TestServer::new().await;
    let alice_vault = server.register(EMAIL).await;
    server.register("bob@example.com").await;
    let alice = server.login(EMAIL, "Laptop").await;
    let bob = server.login("bob@example.com", "Laptop").await;

    let item_id = new_id();
    let created = server
        .put_item(
            &alice.access_token,
            &alice_vault,
            &item_id,
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(created.status, StatusCode::OK);

    // Bob can't see, write or restore anything in Alice's vault.
    let write = server
        .put_item(
            &bob.access_token,
            &alice_vault,
            &new_id(),
            ("if-none-match", "*"),
            1,
        )
        .await;
    assert_eq!(write.status, StatusCode::NOT_FOUND);
    assert!(write.is_problem("not-found"));
    let path = format!("/v1/vaults/{alice_vault}/items/{item_id}");
    let delete = server
        .call(
            Method::DELETE,
            &path,
            Some(&bob.access_token),
            &[("if-match", "\"1\"")],
            None,
        )
        .await;
    assert_eq!(delete.status, StatusCode::NOT_FOUND);
    let restore = server
        .call(
            Method::POST,
            &format!("{path}/restore"),
            Some(&bob.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(restore.status, StatusCode::NOT_FOUND);
    let sync = server
        .get(
            &format!("/v1/sync?since={alice_vault}:0"),
            &bob.access_token,
        )
        .await;
    assert_eq!(sync.body["items"], json!([]));
    assert_ne!(sync.body["vaults"][0]["id"], alice_vault.as_str());
}

#[tokio::test]
async fn item_writes_are_validated() {
    let server = TestServer::new().await;
    let vault_id = server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = Some(device.access_token.as_str());
    let item_path = format!("/v1/vaults/{vault_id}/items/{}", new_id());

    let missing = server
        .call(Method::PUT, &item_path, token, &[], Some(item_body(1)))
        .await;
    assert_eq!(missing.status, StatusCode::PRECONDITION_REQUIRED);
    assert!(missing.is_problem("precondition-required"));

    let not_ciphertext = json!({ "encryptedItemKey": envelope(48), "overview": b64(b"{\"title\":\"plain\"}"), "details": envelope(10) });
    let plain = server
        .call(
            Method::PUT,
            &item_path,
            token,
            &[("if-none-match", "*")],
            Some(not_ciphertext),
        )
        .await;
    assert_eq!(plain.status, StatusCode::BAD_REQUEST);
    assert!(plain.is_problem("invalid-request"));

    let bad_id = server
        .call(
            Method::PUT,
            &format!("/v1/vaults/{vault_id}/items/item_123"),
            token,
            &[("if-none-match", "*")],
            Some(item_body(1)),
        )
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);

    let bad_tag = server
        .call(
            Method::PUT,
            &item_path,
            token,
            &[("if-match", "1")],
            Some(item_body(1)),
        )
        .await;
    assert_eq!(bad_tag.status, StatusCode::BAD_REQUEST);

    let unknown = server
        .call(
            Method::PUT,
            &item_path,
            token,
            &[("if-match", "\"1\"")],
            Some(item_body(1)),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let malformed = server
        .call(
            Method::PUT,
            &item_path,
            token,
            &[("if-none-match", "*")],
            Some(json!({ "overview": 1 })),
        )
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert!(malformed.is_problem("invalid-request"));

    let huge = json!({ "encryptedItemKey": envelope(48), "overview": envelope(100), "details": envelope(2 * 1024 * 1024) });
    let too_large = server
        .call(
            Method::PUT,
            &item_path,
            token,
            &[("if-none-match", "*")],
            Some(huge),
        )
        .await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(too_large.is_problem("payload-too-large"));

    let bad_since = server
        .get("/v1/sync?since=nonsense", &device.access_token)
        .await;
    assert_eq!(bad_since.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_routes_and_missing_tokens_are_problems() {
    let server = TestServer::new().await;
    let missing = server.call(Method::GET, "/v1/nope", None, &[], None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.is_problem("not-found"));

    let method = server
        .call(Method::DELETE, "/v1/sync", None, &[], None)
        .await;
    assert_eq!(method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(method.is_problem("method-not-allowed"));

    let anonymous = server.call(Method::GET, "/v1/sync", None, &[], None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert!(anonymous.is_problem("unauthorized"));
    let forged = server.get("/v1/sync", "not-a-real-token").await;
    assert!(forged.is_problem("unauthorized"));
}

#[tokio::test]
async fn openapi_document_is_served_and_checked_in() {
    let server = TestServer::new().await;
    let served = server
        .call(Method::GET, "/v1/openapi.json", None, &[], None)
        .await;
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.body["openapi"].as_str().unwrap().starts_with("3.1"));
    for path in [
        "/v1/auth/prelogin",
        "/v1/auth/reauth/finish",
        "/v1/sync",
        "/v1/vaults/{vaultId}/items/{itemId}",
    ] {
        assert!(
            served.body["paths"][path].is_object(),
            "{path} missing from the OpenAPI document"
        );
    }

    let checked_in_path = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json");
    let generated = octapass_server::openapi::json();
    if std::env::var_os("OCTAPASS_UPDATE_OPENAPI").is_some() {
        std::fs::write(checked_in_path, &generated).unwrap();
    }
    let checked_in = std::fs::read_to_string(checked_in_path).unwrap_or_default();
    assert!(
        checked_in == generated,
        "apps/server/openapi.json is out of date: run OCTAPASS_UPDATE_OPENAPI=1 cargo test -p octapass-server --test integration api::"
    );
}
