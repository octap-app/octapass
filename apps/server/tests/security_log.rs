//! "Vault exported" entries in the security log: what clients send after an export, and what the
//! log shows (the device, the format, whether the attachments went with it).

use crate::common;

use axum::http::{Method, StatusCode};
use common::{Device, TestServer};
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";

async fn exported(server: &TestServer, device: &Device, body: Value) -> StatusCode {
    server
        .call(
            Method::POST,
            "/v1/security-log/exports",
            Some(&device.access_token),
            &[],
            Some(body),
        )
        .await
        .status
}

async fn log(server: &TestServer, device: &Device) -> Vec<Value> {
    let response = server.get("/v1/security-log", &device.access_token).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body["events"].as_array().unwrap().clone()
}

#[tokio::test]
async fn an_export_names_the_device_format_and_attachments() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Ada’s laptop").await;
    let phone = server.login(EMAIL, "Ada’s phone").await;

    let body = json!({ "format": "encrypted", "attachments": true });
    assert_eq!(
        exported(&server, &laptop, body).await,
        StatusCode::NO_CONTENT
    );
    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(60));
    let body = json!({ "format": "csv", "attachments": false });
    assert_eq!(
        exported(&server, &phone, body).await,
        StatusCode::NO_CONTENT
    );

    let events = log(&server, &laptop).await;
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["type"], "vault-exported");
    assert_eq!(events[0]["deviceName"], "Ada’s phone");
    assert_eq!(events[0]["devicePlatform"], "test");
    assert_eq!(events[0]["exportFormat"], "csv");
    assert_eq!(events[0]["exportAttachments"], false);
    assert_eq!(events[1]["deviceName"], "Ada’s laptop");
    assert_eq!(events[1]["exportFormat"], "encrypted");
    assert_eq!(events[1]["exportAttachments"], true);
    assert!(events[1]["createdAt"].as_str().unwrap().ends_with('Z'));
    // Entries of other kinds don't carry the export's members.
    assert!(events[0].get("otherAccountEmail").is_none());

    // The entry still names the phone after it signs out.
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
    assert_eq!(log(&server, &laptop).await[0]["deviceName"], "Ada’s phone");
}

#[tokio::test]
async fn only_the_account_sees_its_exports() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    server.register("bob@example.com").await;
    let ada = server.login(EMAIL, "laptop").await;
    let bob = server.login("bob@example.com", "laptop").await;
    let body = json!({ "format": "json", "attachments": false });
    assert_eq!(exported(&server, &ada, body).await, StatusCode::NO_CONTENT);
    assert_eq!(log(&server, &ada).await.len(), 1);
    assert!(log(&server, &bob).await.is_empty());
}

#[tokio::test]
async fn bad_reports_are_refused() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;

    // Only the encrypted export holds attachments.
    let body = json!({ "format": "cxf", "attachments": true });
    assert_eq!(
        exported(&server, &laptop, body).await,
        StatusCode::BAD_REQUEST
    );
    let body = json!({ "format": "pdf", "attachments": false });
    assert!(exported(&server, &laptop, body).await.is_client_error());
    let body = json!({ "format": "json" });
    assert!(exported(&server, &laptop, body).await.is_client_error());
    assert!(log(&server, &laptop).await.is_empty());

    let anonymous = server
        .call(
            Method::POST,
            "/v1/security-log/exports",
            None,
            &[],
            Some(json!({ "format": "json", "attachments": false })),
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}
