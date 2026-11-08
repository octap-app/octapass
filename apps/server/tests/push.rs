//! Push sync end to end, all on 127.0.0.1: this server, the real push relay (`apps/push-relay`)
//! on a local port, and fake APNs and FCM endpoints behind it. Checks what each hop sees: the
//! relay gets tokens and one word, Apple and Google get the same, and nobody gets an account,
//! vault, item, email or name.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response as HttpResponse};
use base64::Engine;
use common::people::Person;
use common::*;
use http_body_util::BodyExt;
use octapass_core::sharing::Role;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_push_relay::config::{ApnsConfig, FcmConfig, Limits};
use octapass_server::config::PushRelay;
use rand_core::OsRng;
use serde_json::{Value, json};

const RSA_PEM: &str = include_str!("../../push-relay/tests/fixtures/test-rsa.pem");
const ALICE_PHONE: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
const ALICE_ANDROID: &str = "alice-android:APA91b_one";
const BOB_PHONE: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";

/// Everything that reached the fake Apple and Google endpoints, or the fake relay.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<(String, Value)>>>,
    gone: Arc<Mutex<Vec<String>>>,
    status: Arc<Mutex<Option<StatusCode>>>,
}

async fn record(State(recorder): State<Recorder>, request: Request) -> HttpResponse {
    let (parts, body) = request.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let path = parts.uri.path().to_owned();
    recorder.seen.lock().unwrap().push((path.clone(), body));
    if let Some(status) = *recorder.status.lock().unwrap() {
        return (status, axum::Json(json!({}))).into_response();
    }
    if path == "/token" {
        return axum::Json(json!({ "access_token": "google", "expires_in": 3600 })).into_response();
    }
    if path.starts_with("/v1/installations") {
        return (
            StatusCode::CREATED,
            axum::Json(json!({ "installationId": "fake", "installationKey": "key" })),
        )
            .into_response();
    }
    if path == "/v1/push" {
        let count = serde_json::from_slice::<Value>(&bytes).unwrap()["messages"]
            .as_array()
            .unwrap()
            .len();
        return axum::Json(json!({ "results": vec!["sent"; count] })).into_response();
    }
    let gone = recorder.gone.lock().unwrap();
    if gone.iter().any(|token| path.ends_with(token.as_str())) {
        return (
            StatusCode::GONE,
            axum::Json(json!({ "reason": "Unregistered" })),
        )
            .into_response();
    }
    axum::Json(json!({})).into_response()
}

impl Recorder {
    async fn start() -> (Self, String) {
        let recorder = Self::default();
        let app = Router::new().fallback(record).with_state(recorder.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (recorder, url)
    }

    fn take(&self) -> Vec<(String, Value)> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }

    /// Waits until something arrives, then a little longer for the rest of the round.
    async fn wait(&self) -> Vec<(String, Value)> {
        for _ in 0..200 {
            if !self.seen.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(150)).await;
                return self.take();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("nothing arrived");
    }

    /// Nothing more within a round's time.
    async fn quiet(&self) {
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(self.take(), vec![], "nothing should have been sent");
    }
}

fn p256_pem() -> String {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    let der = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let base64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    format!("-----BEGIN PRIVATE KEY-----\n{base64}\n-----END PRIVATE KEY-----\n")
}

/// The real relay on a local port, sending to `platforms` (the fake Apple and Google).
async fn start_relay(platforms: &str, dir: &std::path::Path) -> String {
    let config = octapass_push_relay::Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}/push-relay.db", dir.display()),
        trust_proxy: false,
        apns: Some(ApnsConfig {
            key_pem: p256_pem(),
            key_id: "KEYID12345".into(),
            team_id: "TEAMID1234".into(),
            topic: "app.octap.ios".into(),
            production_url: format!("{platforms}/apple"),
            sandbox_url: format!("{platforms}/sandbox"),
        }),
        fcm: Some(FcmConfig {
            project_id: "octa-pass-test".into(),
            client_email: "push@octa-pass-test.iam.gserviceaccount.com".into(),
            private_key: RSA_PEM.into(),
            token_uri: format!("{platforms}/token"),
            send_url: format!("{platforms}/google"),
        }),
        limits: Limits::default(),
    };
    let state = octapass_push_relay::AppState::new(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let service =
        octapass_push_relay::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
    url
}

async fn server_with_relay(relay_url: &str) -> TestServer {
    let url = relay_url.to_owned();
    let server = TestServer::with_config(move |config| {
        config.push = Some(PushRelay {
            url,
            batch_delay: Duration::from_millis(50),
        });
    })
    .await;
    // Registration runs in the background at startup.
    for _ in 0..200 {
        let info = server.post_get("/v1/server-info").await;
        if info.body["pushRelay"] == true {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the server never registered with the relay");
}

impl TestServer {
    async fn post_get(&self, path: &str) -> Response {
        self.call(Method::GET, path, None, &[], None).await
    }
}

async fn put_token(server: &TestServer, token: &str, body: Value) -> Response {
    server
        .call(
            Method::PUT,
            "/v1/devices/current/push",
            Some(token),
            &[],
            Some(body),
        )
        .await
}

async fn phone(server: &TestServer, person: &Person, name: &str, push: Value) -> Device {
    let device = server.login(&person.email, name).await;
    let saved = put_token(server, &device.access_token, push).await;
    assert_eq!(saved.status, StatusCode::NO_CONTENT, "{:?}", saved.body);
    device
}

/// What Apple got, by device token, and what Google got, by token.
fn deliveries(seen: &[(String, Value)]) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = seen
        .iter()
        .filter_map(|(path, body)| {
            let apple = path
                .strip_prefix("/apple/3/device/")
                .or_else(|| path.strip_prefix("/sandbox/3/device/"));
            if let Some(token) = apple {
                Some((token.to_owned(), body["octapass"].as_str()?.to_owned()))
            } else if path.starts_with("/google/") {
                let message = &body["message"];
                Some((
                    message["token"].as_str()?.to_owned(),
                    message["data"]["octapass"].as_str()?.to_owned(),
                ))
            } else {
                None
            }
        })
        .collect();
    found.sort();
    found
}

fn assert_says_nothing(seen: &[(String, Value)], people: &[&Person]) {
    for (path, body) in seen {
        let text = format!("{path} {body}");
        for person in people {
            for secret in [&person.email, &person.account_id, &person.personal_vault] {
                assert!(!text.contains(secret.as_str()), "{text} names {secret}");
            }
        }
    }
}

#[tokio::test]
async fn push_is_off_until_turned_on() {
    let server = TestServer::new().await;
    let info = server.post_get("/v1/server-info").await;
    assert_eq!(info.body["pushRelay"], false);
    server.register("alice@example.com").await;
    let alice = server.login("alice@example.com", "Phone").await;
    let saved = put_token(
        &server,
        &alice.access_token,
        json!({ "platform": "apns", "token": ALICE_PHONE }),
    )
    .await;
    assert_eq!(saved.status, StatusCode::NOT_FOUND);
    assert!(saved.is_problem("push-off"));
    let removed = server
        .call(
            Method::DELETE,
            "/v1/devices/current/push",
            Some(&alice.access_token),
            &[],
            None,
        )
        .await;
    assert!(removed.is_problem("push-off"));
}

#[tokio::test]
async fn vault_changes_wake_the_accounts_phones_through_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (platforms, platforms_url) = Recorder::start().await;
    let relay = start_relay(&platforms_url, dir.path()).await;
    let server = server_with_relay(&relay).await;
    let mut alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    phone(
        &server,
        &alice,
        "iPhone",
        json!({ "platform": "apns", "token": ALICE_PHONE.to_uppercase() }),
    )
    .await;
    phone(
        &server,
        &alice,
        "Pixel",
        json!({ "platform": "fcm", "token": ALICE_ANDROID }),
    )
    .await;
    phone(
        &server,
        &bob,
        "Bob's iPhone",
        json!({ "platform": "apns", "token": BOB_PHONE, "sandbox": true }),
    )
    .await;

    // A burst of writes is one push per device.
    for title in ["one", "two", "three"] {
        let saved = server
            .put_new_item(&alice, &alice.personal_vault, title)
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    }
    let seen = platforms.wait().await;
    let mut expected = vec![
        (ALICE_PHONE.to_owned(), "sync".to_owned()),
        (ALICE_ANDROID.to_owned(), "sync".to_owned()),
    ];
    expected.sort();
    assert_eq!(
        deliveries(&seen),
        expected,
        "the token was stored in lowercase"
    );
    assert_says_nothing(&seen, &[&alice, &bob]);
    let apple = seen
        .iter()
        .find(|(path, _)| path.starts_with("/apple/"))
        .unwrap();
    assert_eq!(
        apple.1,
        json!({ "aps": { "content-available": 1 }, "octapass": "sync" })
    );

    // Sharing a vault with Bob is a notice for him, and a sync for Alice.
    let vault_id = server.shared_vault(&mut alice).await;
    platforms.wait().await;
    let invited = server.invite(&alice, &vault_id, &bob, Role::Write).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
    let seen = platforms.wait().await;
    let mut got = deliveries(&seen);
    got.retain(|(token, _)| token == BOB_PHONE);
    assert_eq!(got, [(BOB_PHONE.to_owned(), "alert".to_owned())]);
    let bob_push = seen
        .iter()
        .find(|(path, _)| path.starts_with("/sandbox/"))
        .unwrap();
    assert_eq!(
        bob_push.1["aps"]["alert"]["loc-key"],
        "phone.native.pushAlertBody"
    );
    assert_says_nothing(&seen, &[&alice, &bob]);
}

#[tokio::test]
async fn emergency_access_alerts_both_sides() {
    let dir = tempfile::tempdir().unwrap();
    let (platforms, platforms_url) = Recorder::start().await;
    let relay = start_relay(&platforms_url, dir.path()).await;
    let server = server_with_relay(&relay).await;
    let alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    phone(
        &server,
        &alice,
        "iPhone",
        json!({ "platform": "apns", "token": ALICE_PHONE }),
    )
    .await;
    phone(
        &server,
        &bob,
        "Bob's Pixel",
        json!({ "platform": "fcm", "token": "bob-android:x" }),
    )
    .await;

    let scope = EmergencyScope::Account;
    let sealed = alice
        .session
        .seal_for_emergency_contact(
            &bob.account_id,
            &bob.session.key_pairs().public_enc_key(),
            None,
            &scope,
            &mut OsRng,
        )
        .unwrap();
    let created = server
        .send_as(
            &alice,
            Method::POST,
            "/v1/emergency-contacts",
            Some(json!({
                "contactAccountId": bob.account_id,
                "sealedKey": sealed,
                "scope": scope,
                "accessLevel": "view",
                "waitDays": 2,
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let seen = platforms.wait().await;
    assert_eq!(
        deliveries(&seen),
        [("bob-android:x".to_owned(), "alert".to_owned())]
    );
    let google = seen
        .iter()
        .find(|(path, _)| path.starts_with("/google/"))
        .unwrap();
    assert_eq!(google.1["message"]["data"], json!({ "octapass": "alert" }));
    assert_eq!(google.1["message"]["android"]["priority"], "HIGH");

    let id = created.body["id"].as_str().unwrap();
    let requested = server
        .send_as(
            &bob,
            Method::POST,
            &format!("/v1/emergency-contacts/{id}/request"),
            None,
        )
        .await;
    assert_eq!(requested.status, StatusCode::OK, "{:?}", requested.body);
    let seen = platforms.wait().await;
    assert_eq!(
        deliveries(&seen),
        [(ALICE_PHONE.to_owned(), "alert".to_owned())]
    );

    let denied = server
        .send_as(
            &alice,
            Method::POST,
            &format!("/v1/emergency-contacts/{id}/deny"),
            None,
        )
        .await;
    assert_eq!(denied.status, StatusCode::OK);
    let seen = platforms.wait().await;
    assert_eq!(
        deliveries(&seen),
        [("bob-android:x".to_owned(), "alert".to_owned())]
    );
    assert_says_nothing(&seen, &[&alice, &bob]);
}

#[tokio::test]
async fn dead_and_signed_out_devices_get_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (platforms, platforms_url) = Recorder::start().await;
    let relay = start_relay(&platforms_url, dir.path()).await;
    let server = server_with_relay(&relay).await;
    let alice = server.person("alice@example.com").await;
    let old = "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33";
    phone(
        &server,
        &alice,
        "Old iPhone",
        json!({ "platform": "apns", "token": old }),
    )
    .await;
    let pixel = phone(
        &server,
        &alice,
        "Pixel",
        json!({ "platform": "fcm", "token": ALICE_ANDROID }),
    )
    .await;
    let ipad = phone(
        &server,
        &alice,
        "iPad",
        json!({ "platform": "apns", "token": ALICE_PHONE }),
    )
    .await;

    // Apple says the old iPhone's token is gone: the server forgets it.
    platforms.gone.lock().unwrap().push(old.to_owned());
    server
        .put_new_item(&alice, &alice.personal_vault, "one")
        .await;
    assert_eq!(deliveries(&platforms.wait().await).len(), 3);
    platforms.gone.lock().unwrap().clear();

    // The Pixel signs out; the iPad turns pushes off.
    let out = server
        .call(
            Method::POST,
            "/v1/auth/logout",
            Some(&pixel.access_token),
            &[],
            None,
        )
        .await;
    assert!(out.status.is_success(), "{:?}", out.body);
    let off = server
        .call(
            Method::DELETE,
            "/v1/devices/current/push",
            Some(&ipad.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(off.status, StatusCode::NO_CONTENT);
    server
        .put_new_item(&alice, &alice.personal_vault, "two")
        .await;
    platforms.quiet().await;

    // A token another device had moves to the one that registers it now.
    let laptop_token = server
        .login(&alice.email, "Another iPad")
        .await
        .access_token;
    let moved = put_token(
        &server,
        &laptop_token,
        json!({ "platform": "apns", "token": old }),
    )
    .await;
    assert_eq!(moved.status, StatusCode::NO_CONTENT);
    server
        .put_new_item(&alice, &alice.personal_vault, "three")
        .await;
    assert_eq!(
        deliveries(&platforms.wait().await),
        [(old.to_owned(), "sync".to_owned())]
    );
}

#[tokio::test]
async fn tokens_are_checked() {
    let (_relay, relay_url) = Recorder::start().await;
    let server = server_with_relay(&relay_url).await;
    server.register("alice@example.com").await;
    let alice = server.login("alice@example.com", "Phone").await;
    for body in [
        json!({ "platform": "apns", "token": "not hex" }),
        json!({ "platform": "apns", "token": "" }),
        json!({ "platform": "fcm", "token": "a/b" }),
        json!({ "platform": "fcm", "token": "a".repeat(4097) }),
        json!({ "platform": "webpush", "token": "abc" }),
    ] {
        let saved = put_token(&server, &alice.access_token, body.clone()).await;
        assert_eq!(saved.status, StatusCode::BAD_REQUEST, "{body}");
    }
    let unauthenticated = server
        .call(
            Method::PUT,
            "/v1/devices/current/push",
            None,
            &[],
            Some(json!({ "platform": "fcm", "token": "abc" })),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refused_installation_registers_again() {
    let (relay, relay_url) = Recorder::start().await;
    let server = server_with_relay(&relay_url).await;
    let mut alice = server.person("alice@example.com").await;
    phone(
        &server,
        &alice,
        "Pixel",
        json!({ "platform": "fcm", "token": ALICE_ANDROID }),
    )
    .await;
    let registrations = |seen: &[(String, Value)]| {
        seen.iter()
            .filter(|(path, _)| path == "/v1/installations")
            .count()
    };
    assert_eq!(registrations(&relay.take()), 1);

    // The relay revoked this server: it stops, forgets the installation, and registers anew.
    *relay.status.lock().unwrap() = Some(StatusCode::UNAUTHORIZED);
    server
        .put_new_item(&alice, &alice.personal_vault, "one")
        .await;
    let seen = relay.wait().await;
    assert_eq!(seen.len(), 1, "one refused push, nothing more: {seen:?}");
    assert_eq!(
        server.post_get("/v1/server-info").await.body["pushRelay"],
        false
    );
    *relay.status.lock().unwrap() = None;
    server.state.run_maintenance().await.unwrap();
    let again = relay.wait().await;
    assert_eq!(registrations(&again), 1);
    assert_eq!(
        server.post_get("/v1/server-info").await.body["pushRelay"],
        true
    );

    // The relay's request: the installation, the token, the kind. Nothing else.
    let _ = server.shared_vault(&mut alice).await;
    let seen = relay.wait().await;
    let (_, body) = seen.iter().find(|(path, _)| path == "/v1/push").unwrap();
    assert_eq!(
        body,
        &json!({
            "installationId": "fake",
            "messages": [{ "platform": "fcm", "token": ALICE_ANDROID, "sandbox": false, "kind": "sync" }],
        })
    );
    // Revoked (403) is final: the server stops and doesn't register again by itself.
    *relay.status.lock().unwrap() = Some(StatusCode::FORBIDDEN);
    server
        .put_new_item(&alice, &alice.personal_vault, "two")
        .await;
    assert_eq!(relay.wait().await.len(), 1);
    *relay.status.lock().unwrap() = None;
    assert_eq!(
        server.post_get("/v1/server-info").await.body["pushRelay"],
        false
    );
    server.state.run_maintenance().await.unwrap();
    server
        .put_new_item(&alice, &alice.personal_vault, "three")
        .await;
    relay.quiet().await;
}
