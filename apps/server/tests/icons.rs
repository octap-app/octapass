//! `GET /v1/icons/{domain}` end to end: a local test site plays the websites; the server must
//! fetch from it, cache, rate limit, refuse bad names and inward addresses, and never need an
//! account.

use crate::common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use common::*;
use octapass_server::config::Bucket;
use octapass_server::icons::TestNetwork;

/// 32 × 32 pixels of one colour, as an RGB PNG (the server's are RGBA).
fn png() -> Vec<u8> {
    let image = image::RgbImage::from_pixel(32, 32, image::Rgb([16, 183, 127]));
    let mut out = std::io::Cursor::new(vec![]);
    image.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

struct Site {
    hits: AtomicUsize,
    internal_hits: AtomicUsize,
}

async fn serve(State(site): State<Arc<Site>>, request: Request) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if host == "inside.example.com" {
        site.internal_hits.fetch_add(1, Ordering::SeqCst);
    } else {
        site.hits.fetch_add(1, Ordering::SeqCst);
    }
    match (host.as_str(), request.uri().path()) {
        ("shop.example.com" | "inside.example.com", "/favicon.ico") => {
            ([(header::CONTENT_TYPE, "image/x-icon")], png()).into_response()
        }
        ("redirect.example.com", "/") => (
            StatusCode::FOUND,
            [(header::LOCATION, "http://inside.example.com/")],
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, Body::empty()).into_response(),
    }
}

/// A test site on two addresses: one the fetcher may reach, and an "internal" one it must not.
async fn server_with_site(
    adjust: impl FnOnce(&mut octapass_server::Config) + Send,
) -> (TestServer, Arc<Site>) {
    let site = Arc::new(Site {
        hits: AtomicUsize::new(0),
        internal_hits: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new().fallback(serve).with_state(site.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // The same server under another loopback address, which isn't on the reachable list.
    let inside: SocketAddr = format!("127.0.0.2:{}", addr.port()).parse().unwrap();
    let network = TestNetwork {
        hosts: HashMap::from([
            ("shop.example.com".into(), vec![addr]),
            ("www.shop.example.com".into(), vec![addr]),
            ("empty.example.com".into(), vec![addr]),
            ("redirect.example.com".into(), vec![addr]),
            ("inside.example.com".into(), vec![inside]),
        ]),
        reachable: vec![addr],
    };
    let server = TestServer::with_config(|config| {
        config.icons.test_network = Some(Arc::new(network));
        config.icons.limits.request = Duration::from_secs(2);
        adjust(config);
    })
    .await;
    (server, site)
}

async fn icon(
    server: &TestServer,
    domain: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/icons/{domain}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    server.send_raw(builder.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn serves_icons_without_an_account() {
    let (server, site) = server_with_site(|_| {}).await;
    // A token or cookie, if a client sent one, changes nothing.
    let (status, headers, body) = icon(
        &server,
        "Shop.Example.com",
        &[("authorization", "Bearer nonsense"), ("cookie", "a=b")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "image/png");
    assert_eq!(headers["cache-control"], "public, max-age=604800");
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert!(headers.get("set-cookie").is_none());
    assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_ne!(body, png(), "encoded again by the server");

    // From the cache the second time.
    let hits = site.hits.load(Ordering::SeqCst);
    let (status, _, again) = icon(&server, "shop.example.com", &[]).await;
    assert_eq!((status, again), (StatusCode::OK, body));
    assert_eq!(site.hits.load(Ordering::SeqCst), hits);
}

#[tokio::test]
async fn sites_without_icons_and_bad_names() {
    let (server, site) = server_with_site(|_| {}).await;
    let (status, headers, body) = icon(&server, "empty.example.com", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["cache-control"], "public, max-age=86400");
    assert_eq!(headers["access-control-allow-origin"], "*");
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        problem["type"],
        "https://octap.app/problems/not-found"
    );

    let before = site.hits.load(Ordering::SeqCst);
    for bad in [
        "127.0.0.1",
        "localhost",
        "example.com:8080",
        "%5B::1%5D",
        "printer.local",
        "com",
        "a%2Fb.com",
    ] {
        let (status, _, _) = icon(&server, bad, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(
        site.hits.load(Ordering::SeqCst),
        before,
        "nothing fetched for bad names"
    );

    // A site redirecting into the server's network gets nothing from there.
    let (status, _, _) = icon(&server, "redirect.example.com", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = icon(&server, "inside.example.com", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(site.internal_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rate_limited_per_ip() {
    let (server, _) = server_with_site(|config| {
        config.rate_limits.icons_per_ip = Bucket {
            burst: 2,
            refill: Duration::from_secs(60),
        };
    })
    .await;
    for _ in 0..2 {
        assert_eq!(
            icon(&server, "shop.example.com", &[]).await.0,
            StatusCode::OK
        );
    }
    let (status, headers, _) = icon(&server, "shop.example.com", &[]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
    assert_eq!(headers["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn the_proxy_can_be_turned_off() {
    let (server, site) = server_with_site(|config| config.icons.enabled = false).await;
    let (status, _, body) = icon(&server, "shop.example.com", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        problem["type"],
        "https://octap.app/problems/icons-off"
    );
    assert_eq!(site.hits.load(Ordering::SeqCst), 0);
    assert!(!server.dir.path().join("icons").exists());
}
