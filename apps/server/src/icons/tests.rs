//! The fetcher and cache against a local test site that plays many sites at once (by `Host`),
//! with the SSRF cases: names that resolve inward, redirects inward, links to metadata addresses.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::image::tests::{ico, png};
use super::*;

#[derive(Clone)]
struct Page {
    status: StatusCode,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    delay: Duration,
}

fn page(body: impl Into<Vec<u8>>) -> Page {
    Page {
        status: StatusCode::OK,
        headers: vec![],
        body: body.into(),
        delay: Duration::ZERO,
    }
}

fn html(head: &str) -> Page {
    page(format!(
        "<!doctype html><html><head>{head}</head><body>Hello</body></html>"
    ))
}

fn redirect(to: &str) -> Page {
    Page {
        status: StatusCode::MOVED_PERMANENTLY,
        headers: vec![("location", to.to_owned())],
        body: vec![],
        delay: Duration::ZERO,
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[derive(Default)]
struct Site {
    pages: Mutex<HashMap<(String, String), Page>>,
    hits: Mutex<Vec<(String, String)>>,
}

impl Site {
    fn add(&self, host: &str, path: &str, page: Page) {
        self.pages
            .lock()
            .unwrap()
            .insert((host.to_owned(), path.to_owned()), page);
    }

    fn hits(&self, host: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, _)| h == host)
            .count()
    }
}

async fn serve(State(site): State<Arc<Site>>, request: Request) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    site.hits.lock().unwrap().push((host.clone(), path.clone()));
    let found = site.pages.lock().unwrap().get(&(host, path)).cloned();
    let Some(page) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokio::time::sleep(page.delay).await;
    let mut response = Response::new(Body::from(page.body));
    *response.status_mut() = page.status;
    for (name, value) in page.headers {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_str(&value).unwrap());
    }
    response
}

async fn start(site: Arc<Site>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(serve).with_state(site);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A public test site and an "internal" one (the server's own network) that must never be hit.
struct World {
    site: Arc<Site>,
    internal: Arc<Site>,
    network: Arc<TestNetwork>,
    limits: Limits,
}

const SITES: [&str; 12] = [
    "links.example.com",
    "fallback.example.com",
    "touch.example.com",
    "svg.example.com",
    "moved.example.com",
    "www.moved.example.com",
    "loop.example.com",
    "big.example.com",
    "zip.example.com",
    "slow.example.com",
    "cdn.example.net",
    "evil.example.com",
];

async fn world() -> World {
    let site = Arc::new(Site::default());
    let internal = Arc::new(Site::default());
    let site_addr = start(site.clone()).await;
    let internal_addr = start(internal.clone()).await;
    let mut hosts: HashMap<String, Vec<SocketAddr>> = SITES
        .iter()
        .map(|host| (host.to_string(), vec![site_addr]))
        .collect();
    // Names that point inward, as an attacker's DNS would.
    hosts.insert("internal.example.com".into(), vec![internal_addr]);
    hosts.insert(
        "rebind.example.com".into(),
        vec![
            "10.0.0.7:0".parse().unwrap(),
            "169.254.169.254:0".parse().unwrap(),
        ],
    );
    internal.add("internal.example.com", "/favicon.ico", page(ico(64)));
    let limits = Limits {
        connect: Duration::from_millis(500),
        request: Duration::from_millis(800),
        total: Duration::from_secs(5),
        ..Limits::default()
    };
    World {
        site,
        internal,
        network: Arc::new(TestNetwork {
            hosts,
            reachable: vec![site_addr],
        }),
        limits,
    }
}

impl World {
    fn fetcher(&self) -> fetch::Fetcher {
        fetch::Fetcher::new(Some(self.network.clone()), self.limits)
    }

    async fn icon(&self, domain: &str) -> Option<(u32, u32)> {
        let png = self.fetcher().icon(domain).await?;
        let image = ::image::load_from_memory_with_format(&png, ::image::ImageFormat::Png).unwrap();
        Some((image.width(), image.height()))
    }
}

#[tokio::test]
async fn picks_the_best_linked_icon() {
    let w = world().await;
    w.site.add(
        "links.example.com",
        "/",
        html(r#"<link rel="icon" sizes="16x16" href="/16.png"><link rel="icon" sizes="96x96" href="/img/96.png"><link rel="apple-touch-icon" href="http://cdn.example.net/touch.png">"#),
    );
    w.site.add("links.example.com", "/16.png", page(png(16)));
    w.site
        .add("links.example.com", "/img/96.png", page(png(96)));
    assert_eq!(w.icon("links.example.com").await, Some((96, 96)));
    assert_eq!(
        w.site.hits("links.example.com"),
        2,
        "the page and the 96 px icon"
    );

    // A broken best choice falls through to the next one, here on the site's CDN.
    w.site.add(
        "links.example.com",
        "/img/96.png",
        page("<html>gone</html>"),
    );
    w.site.add("cdn.example.net", "/touch.png", page(png(180)));
    assert_eq!(w.icon("links.example.com").await, Some((128, 128)));
}

#[tokio::test]
async fn falls_back_to_well_known_paths() {
    let w = world().await;
    w.site.add(
        "fallback.example.com",
        "/",
        html("<title>No icons here</title>"),
    );
    w.site
        .add("fallback.example.com", "/favicon.ico", page(ico(32)));
    assert_eq!(w.icon("fallback.example.com").await, Some((32, 32)));

    w.site
        .add("touch.example.com", "/apple-touch-icon.png", page(png(180)));
    assert_eq!(
        w.icon("touch.example.com").await,
        Some((128, 128)),
        "even without a home page"
    );

    assert_eq!(w.icon("svg.example.com").await, None, "nothing anywhere");
}

#[tokio::test]
async fn draws_svg_icons_and_reads_inline_ones() {
    let w = world().await;
    w.site.add(
        "svg.example.com",
        "/",
        html(r#"<link rel="icon" href="/icon.svg">"#),
    );
    w.site.add(
        "svg.example.com",
        "/icon.svg",
        page(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><script>alert(1)</script><circle cx="5" cy="5" r="5"/></svg>"#),
    );
    assert_eq!(w.icon("svg.example.com").await, Some((128, 128)));

    use base64::Engine;
    let inline = base64::engine::general_purpose::STANDARD.encode(png(64));
    w.site.add(
        "links.example.com",
        "/",
        html(&format!(
            r#"<link rel="icon" href="data:image/png;base64,{inline}">"#
        )),
    );
    assert_eq!(w.icon("links.example.com").await, Some((64, 64)));
}

#[tokio::test]
async fn follows_up_to_three_redirects() {
    let w = world().await;
    w.site.add(
        "moved.example.com",
        "/",
        redirect("http://www.moved.example.com/home/"),
    );
    w.site.add(
        "www.moved.example.com",
        "/home/",
        html(r#"<link rel="icon" href="icon.png">"#),
    );
    w.site.add(
        "www.moved.example.com",
        "/home/icon.png",
        redirect("/static/icon.png"),
    );
    w.site
        .add("www.moved.example.com", "/static/icon.png", page(png(64)));
    assert_eq!(w.icon("moved.example.com").await, Some((64, 64)));

    for (from, to) in [("/", "/1"), ("/1", "/2"), ("/2", "/3"), ("/3", "/4")] {
        w.site.add("loop.example.com", from, redirect(to));
    }
    w.site.add(
        "loop.example.com",
        "/4",
        html(r#"<link rel="icon" href="/icon.png">"#),
    );
    w.site.add("loop.example.com", "/icon.png", page(png(64)));
    assert_eq!(
        w.icon("loop.example.com").await,
        None,
        "four redirects is one too many"
    );
    assert_eq!(
        w.site
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p == "/4")
            .count(),
        0
    );
}

#[tokio::test]
async fn never_reaches_inward() {
    let w = world().await;
    // A site redirecting to the server's network, by name and by address.
    w.site.add(
        "evil.example.com",
        "/",
        redirect("http://internal.example.com/"),
    );
    w.site.add(
        "evil.example.com",
        "/apple-touch-icon.png",
        redirect("http://127.0.0.1/favicon.ico"),
    );
    w.site.add(
        "evil.example.com",
        "/favicon.ico",
        redirect("http://[::1]/favicon.ico"),
    );
    assert_eq!(w.icon("evil.example.com").await, None);

    // Icon links to metadata services and other ports.
    w.site.add(
        "evil.example.com",
        "/",
        html(r#"<link rel="icon" sizes="64x64" href="http://169.254.169.254/latest/meta-data"><link rel="icon" href="http://internal.example.com/favicon.ico"><link rel="icon" href="http://evil.example.com:6379/x.png"><link rel="icon" href="file:///etc/passwd"><link rel="icon" href="gopher://evil.example.com/">"#),
    );
    assert_eq!(w.icon("evil.example.com").await, None);

    // Names that resolve inward are never connected to.
    assert_eq!(w.icon("internal.example.com").await, None);
    assert_eq!(w.icon("rebind.example.com").await, None);
    assert_eq!(
        w.internal.hits.lock().unwrap().len(),
        0,
        "{:?}",
        w.internal.hits.lock().unwrap()
    );
    assert_eq!(
        w.site
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path == "/x.png")
            .count(),
        0,
        "other ports are refused before connecting"
    );
}

#[tokio::test]
async fn caps_sizes_even_compressed() {
    let w = world().await;
    // The home page is read up to 512 KB: an icon linked after that is never seen.
    let padding = "x".repeat(600 * 1024);
    w.site.add(
        "big.example.com",
        "/",
        page(format!(
            r#"<html><head><!-- {padding} --><link rel="icon" href="/late.png"></head></html>"#
        )),
    );
    w.site.add("big.example.com", "/late.png", page(png(64)));
    // A 300 KB icon is refused, whatever it holds.
    let mut huge = png(64);
    huge.extend(vec![0; 300 * 1024]);
    w.site.add("big.example.com", "/favicon.ico", page(huge));
    assert_eq!(w.icon("big.example.com").await, None);
    assert_eq!(
        w.site
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p == "/late.png")
            .count(),
        0
    );

    // Compressed responses work, and a gzip bomb stops at the cap after inflating.
    let mut zipped = page(gzip(&png(64)));
    zipped.headers.push(("content-encoding", "gzip".into()));
    w.site
        .add("zip.example.com", "/apple-touch-icon.png", zipped);
    assert_eq!(w.icon("zip.example.com").await, Some((64, 64)));
    let mut bomb = page(gzip(&vec![0; 50 * 1024 * 1024]));
    assert!(bomb.body.len() < 256 * 1024);
    bomb.headers.push(("content-encoding", "gzip".into()));
    w.site.add("zip.example.com", "/apple-touch-icon.png", bomb);
    assert_eq!(w.icon("zip.example.com").await, None);
}

#[tokio::test]
async fn sniffs_content_and_gives_up_on_slow_sites() {
    let w = world().await;
    let mut lying = page(png(48));
    lying.headers.push(("content-type", "text/html".into()));
    w.site.add("fallback.example.com", "/favicon.ico", lying);
    assert_eq!(
        w.icon("fallback.example.com").await,
        Some((48, 48)),
        "the bytes decide, not the type"
    );
    let mut page_as_image = page("<!doctype html><title>Not found</title>");
    page_as_image
        .headers
        .push(("content-type", "image/png".into()));
    w.site
        .add("fallback.example.com", "/favicon.ico", page_as_image);
    assert_eq!(w.icon("fallback.example.com").await, None);

    let mut slow = page(png(64));
    slow.delay = Duration::from_secs(30);
    w.site.add("slow.example.com", "/favicon.ico", slow);
    let started = std::time::Instant::now();
    assert_eq!(w.icon("slow.example.com").await, None);
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn caches_icons_and_misses() {
    let w = world().await;
    let dir = tempfile::tempdir().unwrap();
    let icons = Arc::new(
        Icons::new(
            dir.path().join("icons"),
            [7; 32],
            Some(w.network.clone()),
            w.limits,
        )
        .unwrap(),
    );
    w.site
        .add("fallback.example.com", "/favicon.ico", page(ico(32)));
    let now = 1_000_000;

    // Many askers at once: one fetch.
    let asks: Vec<_> = (0..10)
        .map(|_| {
            let icons = icons.clone();
            tokio::spawn(async move { icons.get("fallback.example.com", now).await })
        })
        .collect();
    for ask in asks {
        assert!(ask.await.unwrap().is_some());
    }
    let fetched = w.site.hits("fallback.example.com");
    assert!(
        icons
            .get("fallback.example.com", now + ICON_TTL_MS - 1)
            .await
            .is_some()
    );
    assert_eq!(
        w.site.hits("fallback.example.com"),
        fetched,
        "served from the cache"
    );
    assert!(icons.in_flight.lock().unwrap().is_empty());

    // The file names don't give the site away.
    let names: Vec<String> = std::fs::read_dir(dir.path().join("icons"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(!names[0].contains("example"));

    // Misses are remembered for a day.
    assert!(icons.get("touch.example.com", now).await.is_none());
    let missed = w.site.hits("touch.example.com");
    assert!(
        icons
            .get("touch.example.com", now + MISS_TTL_MS - 1)
            .await
            .is_none()
    );
    assert_eq!(w.site.hits("touch.example.com"), missed);
    w.site
        .add("touch.example.com", "/favicon.ico", page(ico(32)));
    assert!(
        icons
            .get("touch.example.com", now + MISS_TTL_MS)
            .await
            .is_some(),
        "asked again after a day"
    );

    // Expired entries are purged.
    icons.purge(now + ICON_TTL_MS + MISS_TTL_MS);
    assert_eq!(
        std::fs::read_dir(dir.path().join("icons")).unwrap().count(),
        0
    );
}
