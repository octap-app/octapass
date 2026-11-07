//! The masked email routes against a fake relay: what the server passes on, and what it does with
//! the answers. The relay itself has its own tests in `apps/relay`.

use crate::common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response as HttpResponse};
use common::*;
use http_body_util::BodyExt;
use octapass_server::Config;
use octapass_server::config::Relay;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";
const TOKEN: &str = "a-relay-token";
const ALIAS: &str = "/v1/masked-email/aliases/abcdefghijkl";
const LIST: &str = "/v1/masked-email/aliases";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorization: String,
    body: Value,
}

#[derive(Clone)]
struct FakeRelay {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<(StatusCode, Value)>>,
}

async fn answer(State(relay): State<FakeRelay>, request: Request) -> HttpResponse {
    let (parts, body) = request.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    relay.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        authorization: parts
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default(),
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    });
    let (status, body) = relay.answer.lock().unwrap().clone();
    (status, axum::Json(body)).into_response()
}

impl FakeRelay {
    /// Starts on a local port; returns the relay and its URL.
    async fn start() -> (Self, String) {
        let relay = Self {
            seen: Arc::default(),
            answer: Arc::new(Mutex::new((StatusCode::OK, json!({})))),
        };
        let router = Router::new().fallback(answer).with_state(relay.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (relay, url)
    }

    fn reply(&self, status: StatusCode, body: Value) {
        *self.answer.lock().unwrap() = (status, body);
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn alias() -> Value {
    json!({
        "id": "abcdefghijkl",
        "address": "abcdefghijkl@relay.example",
        "enabled": true,
        "paused": false,
        "forwarded": 2,
        "blocked": 0,
        "replied": 1,
        "createdAt": "2026-11-02T10:00:00Z",
    })
}

async fn with_relay() -> (TestServer, FakeRelay, Device) {
    let (relay, url) = FakeRelay::start().await;
    let server = TestServer::with_config(|config: &mut Config| {
        config.relay = Some(Relay {
            url,
            token: TOKEN.into(),
        });
    })
    .await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    (server, relay, device)
}

async fn delete_account(server: &TestServer, device: &Device) {
    let reauth = reauth_token(server, device).await;
    let response = server
        .call(
            Method::DELETE,
            "/v1/account",
            Some(&device.access_token),
            &[("x-reauth-token", reauth.as_str())],
            Some(json!({ "confirmEmail": EMAIL })),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        response.body
    );
}

async fn queued(server: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM relay_deletions")
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

async fn eventually(check: impl AsyncFn() -> bool) {
    for _ in 0..500 {
        if check().await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("it never happened");
}

#[tokio::test]
async fn without_a_relay_nothing_is_there() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = Some(device.access_token.as_str());

    let info = server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    assert_eq!(info.body["maskedEmailRelay"], false);

    for (method, path, body) in [
        (Method::GET, LIST, None),
        (Method::POST, LIST, None),
        (Method::PATCH, ALIAS, Some(json!({ "enabled": false }))),
        (Method::DELETE, ALIAS, None),
        (
            Method::POST,
            "/v1/masked-email/aliases/abcdefghijkl/block",
            Some(json!({ "sender": "a@b.example" })),
        ),
    ] {
        let response = server.call(method.clone(), path, token, &[], body).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(
            response.is_problem("masked-email-off"),
            "{:?}",
            response.body
        );
    }
}

#[tokio::test]
async fn half_a_configuration_is_an_error() {
    let lookup = |pairs: &'static [(&str, &str)]| {
        Config::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    };
    assert!(lookup(&[("OCTAPASS_RELAY_API_URL", "http://127.0.0.1:8025")]).is_err());
    assert!(
        lookup(&[
            ("OCTAPASS_RELAY_API_URL", "ftp://relay"),
            ("OCTAPASS_RELAY_API_TOKEN", "t"),
        ])
        .is_err()
    );
    let config = lookup(&[
        ("OCTAPASS_RELAY_API_URL", "http://127.0.0.1:8025/"),
        ("OCTAPASS_RELAY_API_TOKEN", "secret-token"),
    ])
    .unwrap();
    let relay = config.relay.unwrap();
    assert_eq!(relay.url, "http://127.0.0.1:8025");
    assert!(!format!("{relay:?}").contains("secret-token"));
    assert!(lookup(&[]).unwrap().relay.is_none());
}

#[tokio::test]
async fn the_routes_need_a_session() {
    let (server, relay, _) = with_relay().await;
    let response = server.call(Method::GET, LIST, None, &[], None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(relay.seen().is_empty());
}

#[tokio::test]
async fn calls_carry_the_account_and_its_verified_email_and_no_one_elses() {
    let (server, relay, device) = with_relay().await;
    let token = Some(device.access_token.as_str());
    let info = server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    assert_eq!(info.body["maskedEmailRelay"], true);

    relay.reply(
        StatusCode::OK,
        json!({ "aliases": [alias()], "maxAliases": 200, "domain": "relay.example" }),
    );
    let list = server.call(Method::GET, LIST, token, &[], None).await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    assert_eq!(
        list.body["aliases"][0]["address"],
        "abcdefghijkl@relay.example"
    );
    assert_eq!(list.body["maxAliases"], 200);

    let seen = relay.seen();
    assert_eq!(seen[0].method, "PUT");
    assert!(
        seen[0].path.starts_with("/internal/accounts/"),
        "{}",
        seen[0].path
    );
    assert_eq!(seen[0].authorization, format!("Bearer {TOKEN}"));
    assert_eq!(seen[0].body, json!({ "email": EMAIL }));
    let account = seen[0]
        .path
        .trim_start_matches("/internal/accounts/")
        .to_owned();

    relay.reply(StatusCode::CREATED, alias());
    // A body can't choose where mail goes: the email comes from the session's account.
    let created = server
        .call(
            Method::POST,
            LIST,
            token,
            &[],
            Some(json!({ "email": "attacker@evil.example" })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["id"], "abcdefghijkl");
    let seen = relay.seen();
    assert_eq!(
        seen[1].path,
        format!("/internal/accounts/{account}/aliases")
    );
    assert_eq!(seen[1].body, json!({ "email": EMAIL }));

    relay.reply(StatusCode::OK, alias());
    let changed = server
        .call(
            Method::PATCH,
            ALIAS,
            token,
            &[],
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK);
    let seen = relay.seen();
    assert_eq!(seen[2].method, "PATCH");
    assert_eq!(
        seen[2].path,
        format!("/internal/accounts/{account}/aliases/abcdefghijkl")
    );
    assert_eq!(seen[2].body, json!({ "enabled": false }));

    for action in ["block", "unblock"] {
        relay.reply(StatusCode::NO_CONTENT, Value::Null);
        let path = format!("{ALIAS}/{action}");
        let body = Some(json!({ "sender": "spam@sender.example" }));
        let response = server.call(Method::POST, &path, token, &[], body).await;
        assert_eq!(response.status, StatusCode::NO_CONTENT, "{action}");
        let last = relay.seen().pop().unwrap();
        assert!(
            last.path
                .ends_with(&format!("/aliases/abcdefghijkl/{action}"))
        );
        assert_eq!(last.body, json!({ "sender": "spam@sender.example" }));
    }

    let deleted = server.call(Method::DELETE, ALIAS, token, &[], None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(relay.seen().pop().unwrap().method, "DELETE");
}

#[tokio::test]
async fn ids_that_could_not_exist_never_reach_the_relay() {
    let (server, relay, device) = with_relay().await;
    let token = Some(device.access_token.as_str());
    for id in [
        "short",
        "ABCDEFGHIJKL",
        "abcdefghijk1",
        "..%2f..%2fadmin",
        "abcdefghijkl%2f..",
        "r-abcdefghijkl",
    ] {
        let path = format!("/v1/masked-email/aliases/{id}");
        let response = server.call(Method::DELETE, &path, token, &[], None).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{id}");
    }
    assert!(relay.seen().is_empty());
}

#[tokio::test]
async fn the_relay_refusals_become_this_api_errors() {
    let (server, relay, device) = with_relay().await;
    let token = Some(device.access_token.as_str());
    let create = async || server.call(Method::POST, LIST, token, &[], None).await;

    relay.reply(StatusCode::CONFLICT, json!({ "error": "alias-limit" }));
    let response = create().await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(
        response.is_problem("masked-email-limit"),
        "{:?}",
        response.body
    );

    relay.reply(
        StatusCode::TOO_MANY_REQUESTS,
        json!({ "error": "alias-daily-limit" }),
    );
    assert_eq!(create().await.status, StatusCode::TOO_MANY_REQUESTS);

    relay.reply(
        StatusCode::BAD_REQUEST,
        json!({ "error": "bad-destination" }),
    );
    assert_eq!(create().await.status, StatusCode::BAD_REQUEST);

    relay.reply(StatusCode::NOT_FOUND, json!({ "error": "not-found" }));
    let response = server.call(Method::DELETE, ALIAS, token, &[], None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);

    relay.reply(StatusCode::UNAUTHORIZED, json!({}));
    assert_eq!(create().await.status, StatusCode::SERVICE_UNAVAILABLE);

    relay.reply(StatusCode::OK, json!("not an alias"));
    assert_eq!(create().await.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn deleting_an_account_tells_the_relay() {
    let (server, relay, device) = with_relay().await;
    relay.reply(StatusCode::NO_CONTENT, Value::Null);
    delete_account(&server, &device).await;
    eventually(async || relay.seen().iter().any(|s| s.method == "DELETE")).await;
    let seen = relay.seen();
    let call = seen.iter().find(|s| s.method == "DELETE").unwrap();
    assert!(
        call.path.starts_with("/internal/accounts/"),
        "{}",
        call.path
    );
    assert!(!call.path.contains("aliases"));
    assert_eq!(call.authorization, format!("Bearer {TOKEN}"));
    eventually(async || queued(&server).await == 0).await;
}

#[tokio::test]
async fn a_deletion_outlives_a_relay_that_is_down() {
    let (server, relay, device) = with_relay().await;
    relay.reply(StatusCode::SERVICE_UNAVAILABLE, json!({}));
    delete_account(&server, &device).await;
    let attempts = async || -> Option<i64> {
        sqlx::query_scalar("SELECT attempts FROM relay_deletions")
            .fetch_optional(&server.state.db)
            .await
            .unwrap()
    };
    eventually(async || attempts().await == Some(1)).await;

    // Later, with the relay back and the retry due.
    relay.reply(StatusCode::NO_CONTENT, Value::Null);
    sqlx::query("UPDATE relay_deletions SET next_attempt_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
    server.state.run_maintenance().await.unwrap();
    assert_eq!(queued(&server).await, 0);
}

#[tokio::test]
async fn without_a_relay_deleting_an_account_queues_nothing() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    delete_account(&server, &device).await;
    assert_eq!(queued(&server).await, 0);
}
