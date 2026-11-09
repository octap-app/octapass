//! `GET /v1/health/data` and the daily fetch from a local stand-in for the project's site.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::TestServer;
use ed25519_dalek::{Signer, SigningKey};
use octapass_core::health_data::{self, BUNDLED, Rejected};
use octapass_server::health_data::{FetchError, fetch};
use serde_json::{Value, json};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn signed_by(key: &SigningKey, version: u64, passkeys: &[&str]) -> String {
    let payload = json!({
        "format": 1,
        "version": version,
        "issuedAt": "2026-11-08T00:00:00.000Z",
        "passkeyDomains": passkeys,
        "twoFactorDomains": ["example.com"],
    })
    .to_string();
    let mut message = health_data::CONTEXT.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(payload.as_bytes());
    json!({
        "payload": STANDARD.encode(&payload),
        "signature": STANDARD.encode(key.sign(&message).to_bytes()),
    })
    .to_string()
}

/// The site's answer: a status and a body, changed between fetches.
type Answer = Arc<Mutex<(StatusCode, String)>>;

async fn site(answer: Answer) -> SocketAddr {
    async fn file(State(answer): State<Answer>) -> impl IntoResponse {
        let (status, body) = answer.lock().unwrap().clone();
        if status == StatusCode::FOUND {
            return (status, [("location", "/elsewhere")], body).into_response();
        }
        (status, body).into_response()
    }
    let app = Router::new()
        .route("/data/health-data.json", get(file))
        .with_state(answer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn served(server: &TestServer) -> Value {
    let response = server
        .call(Method::GET, "/v1/health/data", None, &[], None)
        .await;
    assert_eq!(response.status, StatusCode::OK);
    response.body
}

#[tokio::test]
async fn serves_the_bundled_file_to_anyone() {
    let server = TestServer::new().await;
    let body = served(&server).await;
    let bundled: Value = serde_json::from_str(BUNDLED).unwrap();
    assert_eq!(body, bundled);
    assert!(health_data::verify(&body.to_string(), 0).is_ok());
    // No URL set: nothing is fetched.
    assert!(!fetch(&server.state).await.unwrap());
}

#[tokio::test]
async fn keeps_a_newer_signed_file_and_refuses_the_rest() {
    let answer: Answer = Arc::new(Mutex::new((StatusCode::OK, String::new())));
    let addr = site(answer.clone()).await;
    let server = TestServer::with_config(|config| {
        config.health_data.url = Some(format!("http://{addr}/data/health-data.json"));
        config.health_data.key = key().verifying_key().to_bytes();
    })
    .await;
    let bundled = health_data::bundled().version;
    let set = |status: StatusCode, body: String| *answer.lock().unwrap() = (status, body);

    let newer = signed_by(&key(), bundled + 1, &["passkeys.example"]);
    set(StatusCode::OK, newer.clone());
    assert!(fetch(&server.state).await.unwrap());
    assert_eq!(
        served(&server).await,
        serde_json::from_str::<Value>(&newer).unwrap()
    );
    assert_eq!(server.state.health_data.version(), bundled + 1);

    // Each refusal leaves the newer file served.
    let other = SigningKey::from_bytes(&[4; 32]);
    set(StatusCode::OK, signed_by(&other, bundled + 2, &[]));
    assert!(matches!(
        fetch(&server.state).await,
        Err(FetchError::Rejected(Rejected::BadSignature))
    ));
    set(StatusCode::OK, signed_by(&key(), bundled, &[]));
    assert!(
        !fetch(&server.state).await.unwrap(),
        "an older file is a rollback"
    );
    set(StatusCode::OK, signed_by(&key(), bundled + 1, &[]));
    assert!(!fetch(&server.state).await.unwrap(), "the same version");
    set(StatusCode::OK, "{".into());
    assert!(matches!(
        fetch(&server.state).await,
        Err(FetchError::Rejected(Rejected::Malformed))
    ));
    set(StatusCode::OK, "x".repeat(health_data::MAX_BYTES + 1));
    assert!(matches!(
        fetch(&server.state).await,
        Err(FetchError::TooLarge)
    ));
    set(StatusCode::NOT_FOUND, String::new());
    assert!(matches!(
        fetch(&server.state).await,
        Err(FetchError::Status(404))
    ));
    set(StatusCode::FOUND, String::new());
    assert!(
        matches!(fetch(&server.state).await, Err(FetchError::Status(302))),
        "redirects aren't followed"
    );
    assert_eq!(
        served(&server).await,
        serde_json::from_str::<Value>(&newer).unwrap()
    );
}

#[tokio::test]
async fn trusts_only_the_pinned_key_by_default() {
    let answer: Answer = Arc::new(Mutex::new((StatusCode::OK, String::new())));
    let addr = site(answer.clone()).await;
    let server = TestServer::with_config(|config| {
        config.health_data.url = Some(format!("http://{addr}/data/health-data.json"));
    })
    .await;
    *answer.lock().unwrap() = (
        StatusCode::OK,
        signed_by(&key(), health_data::bundled().version + 1, &[]),
    );
    assert!(matches!(
        fetch(&server.state).await,
        Err(FetchError::Rejected(Rejected::BadSignature))
    ));
    assert_eq!(
        served(&server).await,
        serde_json::from_str::<Value>(BUNDLED).unwrap()
    );
}
