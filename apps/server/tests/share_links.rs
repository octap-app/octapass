//! One-time share links: ciphertext from octapass-core opened with the link
//! key that never reaches the server, view limits, expiry on the server's
//! clock, strict per-IP limits, and deletion by the creator.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::people::Person;
use common::*;
use octapass_core::item::Item;
use octapass_core::sharing::share_link;
use rand_core::OsRng;
use serde_json::{Value, json};

fn item() -> Item {
    Item::from_json(
        r#"{"overview":{"title":"Guest Wi-Fi","type":"password"},"details":{"password":"correct horse"}}"#,
    )
    .unwrap()
}

fn expires_in(server: &TestServer, ms: i64) -> String {
    let at = server.state.clock.now() + ms;
    let nanos = i128::from(at) * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

const HOUR: i64 = 60 * 60 * 1000;

async fn create(server: &TestServer, person: &Person, body: Value) -> Response {
    server
        .send_as(person, Method::POST, "/v1/share-links", Some(body))
        .await
}

/// Views a link anonymously, from `ip`.
async fn view(server: &TestServer, id: &str, ip: &str) -> Response {
    server
        .call_from(
            ip,
            Method::GET,
            &format!("/v1/share-links/{id}"),
            None,
            &[],
            None,
        )
        .await
}

#[tokio::test]
async fn a_link_opens_with_its_fragment_and_counts_views() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let link = share_link::create(&item(), None, &mut OsRng).unwrap();
    let created = create(
        &server,
        &alice,
        json!({
            "ciphertext": link.ciphertext,
            "expiresAt": expires_in(&server, 24 * HOUR),
            "maxViews": 2,
            "passphraseRequired": false,
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let id = created.body["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 22);

    let first = view(&server, &id, "198.51.100.7").await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.headers["cache-control"], "no-store");
    assert_eq!(first.body["viewsLeft"], 1);
    assert_eq!(first.body["passphraseRequired"], false);
    // The server returns what it stored; only the fragment opens it.
    let ciphertext = first.body["ciphertext"].as_str().unwrap();
    assert_eq!(
        share_link::open(ciphertext, &link.key, None).unwrap(),
        item()
    );

    let listed = server.get_as(&alice, "/v1/share-links").await;
    assert_eq!(listed.body["links"][0]["views"], 1);
    assert_eq!(listed.body["links"][0]["maxViews"], 2);
    assert!(listed.body["links"][0].get("ciphertext").is_none());

    let last = view(&server, &id, "198.51.100.7").await;
    assert_eq!(last.body["viewsLeft"], 0);
    let gone = view(&server, &id, "198.51.100.7").await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    let listed = server.get_as(&alice, "/v1/share-links").await;
    assert_eq!(listed.body["links"], json!([]));
}

#[tokio::test]
async fn links_expire_on_the_servers_clock() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let link = share_link::create(&item(), Some("hunter2"), &mut OsRng).unwrap();
    let body = |expires_at: String| {
        json!({
            "ciphertext": link.ciphertext,
            "expiresAt": expires_at,
            "maxViews": 100,
            "passphraseRequired": true,
        })
    };
    let created = create(&server, &alice, body(expires_in(&server, 2 * HOUR))).await;
    let id = created.body["id"].as_str().unwrap().to_owned();
    let kept = create(&server, &alice, body(expires_in(&server, 3 * HOUR))).await;
    let kept_id = kept.body["id"].as_str().unwrap().to_owned();

    let viewed = view(&server, &id, "198.51.100.7").await;
    assert_eq!(viewed.body["passphraseRequired"], true);
    let ciphertext = viewed.body["ciphertext"].as_str().unwrap();
    assert!(share_link::needs_passphrase(ciphertext).unwrap());
    assert_eq!(
        share_link::open(ciphertext, &link.key, Some("hunter2")).unwrap(),
        item()
    );

    server
        .state
        .clock
        .advance(Duration::from_secs(2 * 60 * 60 + 1));
    assert_eq!(
        view(&server, &id, "198.51.100.7").await.status,
        StatusCode::NOT_FOUND
    );
    server.state.run_maintenance().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM share_links")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(left, 1, "maintenance keeps unexpired links");
    assert_eq!(
        view(&server, &kept_id, "198.51.100.7").await.status,
        StatusCode::OK
    );
    server.state.clock.advance(Duration::from_secs(60 * 60));
    server.state.run_maintenance().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM share_links")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn only_sane_links_are_accepted() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let ciphertext = share_link::create(&item(), None, &mut OsRng)
        .unwrap()
        .ciphertext;
    let body = |expires: i64, max_views: u32| {
        json!({
            "ciphertext": ciphertext,
            "expiresAt": expires_in(&server, expires),
            "maxViews": max_views,
            "passphraseRequired": false,
        })
    };
    for bad in [
        body(30 * 60 * 1000, 1),
        body(31 * 24 * HOUR, 1),
        body(HOUR, 0),
        body(HOUR, 101),
        json!({ "ciphertext": "AQ", "expiresAt": expires_in(&server, HOUR), "maxViews": 1, "passphraseRequired": false }),
        json!({ "ciphertext": ciphertext, "expiresAt": "tomorrow", "maxViews": 1, "passphraseRequired": false }),
    ] {
        let refused = create(&server, &alice, bad).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.body
        );
    }
    for good in [body(HOUR, 1), body(30 * 24 * HOUR, 100)] {
        assert_eq!(
            create(&server, &alice, good).await.status,
            StatusCode::CREATED
        );
    }
    let anonymous = server
        .call(
            Method::POST,
            "/v1/share-links",
            None,
            &[],
            Some(body(HOUR, 1)),
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_the_creator_deletes_a_link() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    let link = share_link::create(&item(), None, &mut OsRng).unwrap();
    let created = create(
        &server,
        &alice,
        json!({ "ciphertext": link.ciphertext, "expiresAt": expires_in(&server, HOUR), "maxViews": 5, "passphraseRequired": false }),
    )
    .await;
    let path = format!("/v1/share-links/{}", created.body["id"].as_str().unwrap());
    let refused = server.send_as(&bob, Method::DELETE, &path, None).await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
    let deleted = server.send_as(&alice, Method::DELETE, &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = server.call(Method::GET, &path, None, &[], None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn viewing_is_rate_limited_per_ip() {
    let server = TestServer::with_config(|config| {
        config.rate_limits.share_link_per_ip.burst = 3;
    })
    .await;
    let id = "AAAAAAAAAAAAAAAAAAAAAA";
    for _ in 0..3 {
        assert_eq!(
            view(&server, id, "198.51.100.7").await.status,
            StatusCode::NOT_FOUND
        );
    }
    let limited = view(&server, id, "198.51.100.7").await;
    assert!(limited.is_problem("rate-limited"));
    assert!(limited.headers.contains_key("retry-after"));
    assert_eq!(
        view(&server, id, "198.51.100.8").await.status,
        StatusCode::NOT_FOUND,
        "other addresses have their own budget"
    );
}
