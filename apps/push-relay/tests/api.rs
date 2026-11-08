//! The relay against fake APNs and FCM endpoints on local ports: what it sends Apple and Google,
//! and what it tells the server back. No real credentials, no network beyond 127.0.0.1.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use octapass_push_relay::config::{ApnsConfig, FcmConfig, Limits};
use octapass_push_relay::{AppState, Config, router};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};
use tower::ServiceExt;

const RSA_PEM: &str = include_str!("fixtures/test-rsa.pem");
const APNS_TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const FCM_TOKEN: &str = "fcm-token:APA91b_test";

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    }
}

/// Answers every request with the status set for its path's first segment (`3` for APNs,
/// `token`, `v1` for FCM), and records it.
#[derive(Clone, Default)]
struct Fake {
    seen: Arc<Mutex<Vec<Seen>>>,
    answers: Arc<Mutex<Vec<(String, StatusCode, Value)>>>,
}

async fn answer(State(fake): State<Fake>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let path = parts.uri.path().to_owned();
    fake.seen.lock().unwrap().push(Seen {
        path: path.clone(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_owned()))
            .collect(),
        body,
    });
    let answers = fake.answers.lock().unwrap();
    let (_, status, body) = answers
        .iter()
        .find(|(prefix, ..)| path.starts_with(prefix.as_str()))
        .cloned()
        .unwrap_or((String::new(), StatusCode::OK, json!({})));
    (status, axum::Json(body)).into_response()
}

impl Fake {
    async fn start() -> (Self, String) {
        let fake = Self::default();
        let app = Router::new().fallback(answer).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (fake, url)
    }

    fn answer(&self, prefix: &str, status: StatusCode, body: Value) {
        self.answers
            .lock()
            .unwrap()
            .insert(0, (prefix.to_owned(), status, body));
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn p256_pem() -> String {
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .unwrap();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der.as_ref())
    )
}

struct Relay {
    router: Router,
    _dir: tempfile::TempDir,
}

async fn relay(fake_url: &str, limits: Limits) -> Relay {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}/relay.db", dir.path().display()),
        trust_proxy: false,
        apns: Some(ApnsConfig {
            key_pem: p256_pem(),
            key_id: "KEYID12345".into(),
            team_id: "TEAMID1234".into(),
            topic: "app.octap.ios".into(),
            production_url: format!("{fake_url}/apple"),
            sandbox_url: format!("{fake_url}/sandbox"),
        }),
        fcm: Some(FcmConfig {
            project_id: "octa-pass-test".into(),
            client_email: "push@octa-pass-test.iam.gserviceaccount.com".into(),
            private_key: RSA_PEM.into(),
            token_uri: format!("{fake_url}/token"),
            send_url: format!("{fake_url}/google"),
        }),
        limits,
    };
    let state = AppState::new(config).await.unwrap();
    Relay {
        router: router(state),
        _dir: dir,
    }
}

impl Relay {
    async fn call(&self, path: &str, key: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("authorization", format!("Bearer {key}"));
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        let peer: SocketAddr = "192.0.2.7:4000".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self) -> (String, String) {
        let (status, body) = self.call("/v1/installations", None, json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            body["installationId"].as_str().unwrap().to_owned(),
            body["installationKey"].as_str().unwrap().to_owned(),
        )
    }

    async fn push(&self, id: &str, key: &str, messages: Value) -> (StatusCode, Value) {
        self.call(
            "/v1/push",
            Some(key),
            json!({ "installationId": id, "messages": messages }),
        )
        .await
    }
}

#[tokio::test]
async fn passes_wakeups_to_apple_and_google() {
    let (fake, url) = Fake::start().await;
    fake.answer(
        "/token",
        StatusCode::OK,
        json!({ "access_token": "google-access", "expires_in": 3599, "token_type": "Bearer" }),
    );
    let relay = relay(&url, Limits::default()).await;
    let (id, key) = relay.register().await;

    let (status, body) = relay
        .push(
            &id,
            &key,
            json!([
                { "platform": "apns", "token": APNS_TOKEN, "kind": "sync" },
                { "platform": "apns", "token": APNS_TOKEN, "sandbox": true, "kind": "alert" },
                { "platform": "fcm", "token": FCM_TOKEN, "kind": "sync" },
                { "platform": "fcm", "token": FCM_TOKEN, "kind": "alert" },
            ]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "results": ["sent", "sent", "sent", "sent"] }));

    let seen = fake.seen();
    let apple: Vec<_> = seen
        .iter()
        .filter(|s| s.path.starts_with("/apple"))
        .collect();
    let sandbox: Vec<_> = seen
        .iter()
        .filter(|s| s.path.starts_with("/sandbox"))
        .collect();
    assert_eq!((apple.len(), sandbox.len()), (1, 1));
    let sync = apple[0];
    assert_eq!(sync.path, format!("/apple/3/device/{APNS_TOKEN}"));
    assert_eq!(sync.header("apns-topic"), "app.octap.ios");
    assert_eq!(sync.header("apns-push-type"), "background");
    assert_eq!(sync.header("apns-priority"), "5");
    assert!(sync.header("authorization").starts_with("bearer ey"));
    assert_eq!(
        serde_json::from_str::<Value>(&sync.body).unwrap(),
        json!({ "aps": { "content-available": 1 }, "octapass": "sync" })
    );
    assert_eq!(sandbox[0].header("apns-push-type"), "alert");
    assert_eq!(sandbox[0].header("apns-priority"), "10");

    // One access token for both FCM messages.
    let token_requests: Vec<_> = seen.iter().filter(|s| s.path == "/token").collect();
    assert_eq!(token_requests.len(), 1);
    assert!(token_requests[0].body.starts_with(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=ey"
    ));
    let google: Vec<_> = seen
        .iter()
        .filter(|s| s.path.starts_with("/google"))
        .collect();
    assert_eq!(google.len(), 2);
    assert_eq!(
        google[0].path,
        "/google/v1/projects/octa-pass-test/messages:send"
    );
    assert_eq!(google[0].header("authorization"), "Bearer google-access");
    let messages: Vec<Value> = google
        .iter()
        .map(|s| serde_json::from_str(&s.body).unwrap())
        .collect();
    for message in &messages {
        let data = message["message"]["data"].as_object().unwrap();
        assert_eq!(data.len(), 1, "only the kind: {message}");
        assert!(message["message"].get("notification").is_none());
    }

    // Nothing anywhere carries more than the token and the kind.
    for request in &seen {
        assert!(!request.body.contains("installation"), "{}", request.body);
    }
}

#[tokio::test]
async fn reports_dead_tokens() {
    let (fake, url) = Fake::start().await;
    fake.answer(
        "/token",
        StatusCode::OK,
        json!({ "access_token": "a", "expires_in": 3600 }),
    );
    fake.answer(
        "/apple",
        StatusCode::GONE,
        json!({ "reason": "Unregistered" }),
    );
    fake.answer(
        "/google",
        StatusCode::NOT_FOUND,
        json!({ "error": { "status": "NOT_FOUND", "details": [{ "errorCode": "UNREGISTERED" }] } }),
    );
    fake.answer("/sandbox", StatusCode::INTERNAL_SERVER_ERROR, json!({}));
    let relay = relay(&url, Limits::default()).await;
    let (id, key) = relay.register().await;
    let (status, body) = relay
        .push(
            &id,
            &key,
            json!([
                { "platform": "apns", "token": APNS_TOKEN, "kind": "sync" },
                { "platform": "fcm", "token": FCM_TOKEN, "kind": "sync" },
                { "platform": "apns", "token": APNS_TOKEN, "sandbox": true, "kind": "sync" },
                { "platform": "apns", "token": "not/hex", "kind": "sync" },
            ]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "results": ["unregistered", "unregistered", "failed", "unregistered"] })
    );
    assert!(
        !fake.seen().iter().any(|s| s.path.contains("not")),
        "a bad token never reaches Apple"
    );
}

#[tokio::test]
async fn a_refused_provider_token_is_made_again_once() {
    let (fake, url) = Fake::start().await;
    fake.answer(
        "/apple",
        StatusCode::FORBIDDEN,
        json!({ "reason": "ExpiredProviderToken" }),
    );
    let relay = relay(&url, Limits::default()).await;
    let (id, key) = relay.register().await;
    let (_, body) = relay
        .push(
            &id,
            &key,
            json!([{ "platform": "apns", "token": APNS_TOKEN, "kind": "sync" }]),
        )
        .await;
    assert_eq!(body, json!({ "results": ["failed"] }));
    assert_eq!(
        fake.seen().len(),
        2,
        "one retry with a fresh token, no more"
    );
}

#[tokio::test]
async fn only_registered_servers_send() {
    let (fake, url) = Fake::start().await;
    let relay = relay(&url, Limits::default()).await;
    let (id, key) = relay.register().await;
    let one = json!([{ "platform": "apns", "token": APNS_TOKEN, "kind": "sync" }]);

    assert_eq!(
        relay.push(&id, "wrong", one.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay.push("unknown", &key, one.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (other_id, _) = relay.register().await;
    assert_eq!(
        relay.push(&other_id, &key, one.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let no_auth = relay
        .call(
            "/v1/push",
            None,
            json!({ "installationId": id, "messages": one }),
        )
        .await;
    assert_eq!(no_auth.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        relay.push(&id, &key, json!([])).await.0,
        StatusCode::BAD_REQUEST
    );
    let too_many: Vec<Value> = (0..101).map(|_| one[0].clone()).collect();
    assert_eq!(
        relay.push(&id, &key, json!(too_many)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(fake.seen().is_empty());
}

/// The relay's database, through a second connection to the same file.
fn relay_db(relay: &Relay) -> std::path::PathBuf {
    relay._dir.path().join("relay.db")
}

#[tokio::test]
async fn a_revoked_installation_is_refused() {
    let (_fake, url) = Fake::start().await;
    let relay = relay(&url, Limits::default()).await;
    let (id, key) = relay.register().await;
    let db = octapass_push_relay::db::connect(&format!("sqlite://{}", relay_db(&relay).display()))
        .await
        .unwrap();
    assert!(octapass_push_relay::db::revoke(&db, &id, 1).await.unwrap());
    assert!(!octapass_push_relay::db::revoke(&db, &id, 2).await.unwrap());
    let one = json!([{ "platform": "fcm", "token": FCM_TOKEN, "kind": "sync" }]);
    let (status, body) = relay.push(&id, &key, one.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "revoked");
    // The wrong key still says nothing about whether the installation exists or was revoked.
    assert_eq!(
        relay.push(&id, "wrong", one).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn installations_are_rate_limited() {
    let (_fake, url) = Fake::start().await;
    let limits = Limits {
        pushes_per_minute: 3,
        registrations_per_hour: 2,
        max_batch: 100,
    };
    let relay = relay(&url, limits).await;
    let (id, key) = relay.register().await;
    relay.register().await;
    let (status, _) = relay.call("/v1/installations", None, json!({})).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "two an hour from one address"
    );

    let two = json!([
        { "platform": "apns", "token": APNS_TOKEN, "kind": "sync" },
        { "platform": "apns", "token": APNS_TOKEN, "kind": "sync" },
    ]);
    assert_eq!(relay.push(&id, &key, two.clone()).await.0, StatusCode::OK);
    let (status, body) = relay.push(&id, &key, two).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate-limited");
}
