//! Email breach alerts through a local stand-in for Have I Been Pwned. Nothing here reaches HIBP.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::Method;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use common::{Device, TestServer};
use octapass_server::config::{Bucket, Hibp};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

/// The address, query and headers of a request to the stand-in.
type Call = (String, HashMap<String, String>, HeaderMap);

#[derive(Default)]
struct Calls {
    seen: Mutex<Vec<Call>>,
}

async fn breached(
    State(calls): State<Arc<Calls>>,
    Path(account): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    calls
        .seen
        .lock()
        .unwrap()
        .push((account.clone(), query, headers));
    match account.as_str() {
        "pwned+tag@example.com" => (
            StatusCode::OK,
            axum::Json(json!([{
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "AddedDate": "2013-12-04T00:00:00Z",
                "Description": "<a href=\"https://evil.example\">HTML from the breach list</a>",
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": true
            }, {
                "Name": "NoDomain", "Title": "No domain", "Domain": "", "DataClasses": []
            }])),
        )
            .into_response(),
        "limited@example.com" => {
            (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "7")]).into_response()
        }
        "badkey@example.com" => StatusCode::UNAUTHORIZED.into_response(),
        "garbage@example.com" => (StatusCode::OK, "not json").into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn fake_hibp() -> (SocketAddr, Arc<Calls>) {
    let calls = Arc::new(Calls::default());
    let app = Router::new()
        .route("/api/v3/breachedaccount/{account}", get(breached))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, calls)
}

async fn server_with_hibp() -> (TestServer, Arc<Calls>) {
    let (addr, calls) = fake_hibp().await;
    let server = TestServer::with_config(|config| {
        config.hibp = Some(Hibp {
            api_key: "test-key".into(),
            base_url: format!("http://{addr}/api/v3"),
            requests_per_minute: 60_000,
        });
    })
    .await;
    (server, calls)
}

async fn lookup(server: &TestServer, token: &str, email: &str) -> common::Response {
    server
        .call(
            Method::POST,
            "/v1/health/breach-email",
            Some(token),
            &[],
            Some(json!({ "email": email })),
        )
        .await
}

async fn signed_in(server: &TestServer, email: &str) -> Device {
    server.register(email).await;
    server.login(email, "test device").await
}

async fn server_info(server: &TestServer) -> Value {
    server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await
        .body
}

#[tokio::test]
async fn off_by_default() {
    let server = TestServer::new().await;
    assert_eq!(server_info(&server).await["emailBreachChecks"], false);
    let device = signed_in(&server, "a@example.com").await;
    let response = lookup(&server, &device.access_token, "a@example.com").await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn needs_a_signed_in_client() {
    let (server, calls) = server_with_hibp().await;
    let response = server
        .call(
            Method::POST,
            "/v1/health/breach-email",
            None,
            &[],
            Some(json!({ "email": "a@example.com" })),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(calls.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn proxies_a_lookup_and_passes_on_only_plain_fields() {
    let (server, calls) = server_with_hibp().await;
    assert_eq!(server_info(&server).await["emailBreachChecks"], true);
    let device = signed_in(&server, "a@example.com").await;

    let response = lookup(&server, &device.access_token, " Pwned+Tag@Example.com ").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers.get("cache-control").unwrap(), "no-store");
    let body = response.body;
    assert_eq!(
        body,
        json!({ "breaches": [
            { "name": "Adobe", "title": "Adobe", "domain": "adobe.com", "breachDate": "2013-10-04", "dataClasses": ["Email addresses", "Passwords"] },
            { "name": "NoDomain", "title": "No domain", "dataClasses": [] },
        ]})
    );
    assert!(!body.to_string().contains("evil.example"));

    let seen = calls.seen.lock().unwrap();
    let (account, query, headers) = &seen[0];
    assert_eq!(account, "pwned+tag@example.com");
    assert_eq!(query.get("truncateResponse").unwrap(), "false");
    assert_eq!(headers.get("hibp-api-key").unwrap(), "test-key");
    assert!(
        headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("Octa Pass server/")
    );
    assert!(headers.get("authorization").is_none() && headers.get("cookie").is_none());
}

#[tokio::test]
async fn an_unknown_address_is_no_breaches() {
    let (server, _) = server_with_hibp().await;
    let device = signed_in(&server, "a@example.com").await;
    let response = lookup(&server, &device.access_token, "clean@example.com").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, json!({ "breaches": [] }));
}

#[tokio::test]
async fn keeps_nothing_about_the_address() {
    let (server, _) = server_with_hibp().await;
    if server.is_postgres() {
        return;
    }
    let device = signed_in(&server, "a@example.com").await;
    let response = lookup(&server, &device.access_token, "alias-private@relay.example").await;
    assert_eq!(response.status, StatusCode::OK);

    // The database and its write-ahead log, and anything else in the data folder.
    let mut folders = vec![server.dir.path().to_path_buf()];
    let mut files = 0;
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else {
                files += 1;
                let bytes = std::fs::read(&path).unwrap();
                let found = bytes.windows(13).any(|window| window == b"alias-private");
                assert!(!found, "{}", path.display());
            }
        }
    }
    assert!(files > 0);
}

#[tokio::test]
async fn upstream_failures_become_a_retry_or_unavailable() {
    let (server, _) = server_with_hibp().await;
    let device = signed_in(&server, "a@example.com").await;

    let limited = lookup(&server, &device.access_token, "limited@example.com").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers.get("retry-after").unwrap(), "7");

    assert_eq!(
        lookup(&server, &device.access_token, "badkey@example.com")
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        lookup(&server, &device.access_token, "garbage@example.com")
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn rejects_a_bad_address_before_calling_out() {
    let (server, calls) = server_with_hibp().await;
    let device = signed_in(&server, "a@example.com").await;
    assert_eq!(
        lookup(&server, &device.access_token, "not an email")
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert!(calls.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn each_account_has_a_budget() {
    let (addr, calls) = fake_hibp().await;
    let server = TestServer::with_config(|config| {
        config.hibp = Some(Hibp {
            api_key: "k".into(),
            base_url: format!("http://{addr}/api/v3"),
            requests_per_minute: 60_000,
        });
        config.rate_limits.breach_email_per_account = Bucket {
            burst: 2,
            refill: Duration::from_secs(3600),
        };
    })
    .await;
    let one = signed_in(&server, "one@example.com").await;
    let two = signed_in(&server, "two@example.com").await;
    assert_eq!(
        lookup(&server, &one.access_token, "x@example.com")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        lookup(&server, &one.access_token, "y@example.com")
            .await
            .status,
        StatusCode::OK
    );
    let over = lookup(&server, &one.access_token, "z@example.com").await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(over.headers.get("retry-after").is_some());
    assert_eq!(calls.seen.lock().unwrap().len(), 2);
    assert_eq!(
        lookup(&server, &two.access_token, "z@example.com")
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_server_keeps_to_the_keys_limit() {
    let (addr, calls) = fake_hibp().await;
    let server = TestServer::with_config(|config| {
        config.hibp = Some(Hibp {
            api_key: "k".into(),
            base_url: format!("http://{addr}/api/v3"),
            requests_per_minute: 1,
        });
    })
    .await;
    let device = signed_in(&server, "a@example.com").await;
    assert_eq!(
        lookup(&server, &device.access_token, "x@example.com")
            .await
            .status,
        StatusCode::OK
    );
    // The next slot is a minute away, past what a request may wait.
    let refused = lookup(&server, &device.access_token, "y@example.com").await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(calls.seen.lock().unwrap().len(), 1);
}
