//! The service over a real socket and a real loopback port, with a stand-in backend: what a tool
//! sees, and what's refused before a backend is ever asked.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use octapass_connect::client::{ClientError, ConnectClient, Endpoint};
use octapass_connect::clients::{Client, Clients};
use octapass_connect::server::{self, Approval, Backend, BoxFuture, ConnectError, ItemRef, Secret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

#[derive(Default)]
struct Fake {
    approve: AtomicBool,
    locked: AtomicBool,
    asked: AtomicUsize,
    reads: AtomicUsize,
    last_program: std::sync::Mutex<Option<String>>,
    gate: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

impl Backend for Fake {
    fn unlocked(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { !self.locked.load(Ordering::SeqCst) })
    }

    fn approve(&self, request: Approval) -> BoxFuture<'_, bool> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last_program.lock().unwrap() = request.peer.program;
        let gate = self.gate.lock().unwrap().take();
        Box::pin(async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            self.approve.load(Ordering::SeqCst)
        })
    }

    fn items(&self, _: Client) -> BoxFuture<'_, Result<Vec<ItemRef>, ConnectError>> {
        Box::pin(async {
            Ok(vec![ItemRef {
                vault: "Work".into(),
                vault_id: "v".into(),
                item: "Stripe".into(),
                item_id: "1".into(),
                item_type: "login".into(),
                fields: Vec::new(),
            }])
        })
    }

    fn read(
        &self,
        client: Client,
        references: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<Secret>, ConnectError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.locked.load(Ordering::SeqCst) {
                return Err(ConnectError::locked());
            }
            Ok(references
                .into_iter()
                .map(|reference| Secret {
                    value: Some(format!("value for {}", client.name)),
                    reference,
                    error: None,
                })
                .collect())
        })
    }
}

#[cfg(unix)]
async fn socket(folder: &Path) -> (Arc<Fake>, Endpoint) {
    let fake = Arc::new(Fake::default());
    fake.approve.store(true, Ordering::SeqCst);
    let listener = server::bind_socket(folder).await.unwrap();
    let (backend, dir) = (fake.clone() as Arc<dyn Backend>, folder.to_owned());
    tokio::spawn(async move {
        server::serve_socket(listener, &dir, backend, std::future::pending())
            .await
            .unwrap();
    });
    (fake, Endpoint::Socket(server::socket_path(folder)))
}

async fn loopback(folder: &Path) -> (Arc<Fake>, String) {
    let fake = Arc::new(Fake::default());
    fake.approve.store(true, Ordering::SeqCst);
    let listener = server::bind_loopback(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (backend, dir) = (fake.clone() as Arc<dyn Backend>, folder.to_owned());
    tokio::spawn(async move {
        server::serve_loopback(listener, &dir, backend, std::future::pending())
            .await
            .unwrap();
    });
    // The port file is written once serving starts.
    while !server::port_path(folder).exists() {
        tokio::task::yield_now().await;
    }
    (fake, format!("127.0.0.1:{port}"))
}

fn refused(error: ClientError) -> (u16, String) {
    match error {
        ClientError::Refused { status, code, .. } => (status, code),
        other => panic!("{other}"),
    }
}

/// A raw request, as a browser or a port scanner would send it.
async fn raw(address: &str, request: String) -> String {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[cfg(unix)]
#[tokio::test]
async fn a_tool_pairs_and_reads_over_the_socket() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (fake, endpoint) = socket(dir.path()).await;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&server::socket_path(dir.path())), 0o600);
    assert_eq!(mode(dir.path()), 0o700);

    let anonymous = ConnectClient::new(endpoint.clone(), None);
    assert_eq!(anonymous.status().await.unwrap()["unlocked"], true);
    assert_eq!(
        refused(anonymous.items().await.unwrap_err()),
        (401, "unauthorized".into())
    );
    assert_eq!(fake.reads.load(Ordering::SeqCst), 0);

    let paired = anonymous.pair("My tool").await.unwrap();
    assert!(paired.token.starts_with("opc1_"));
    // The real program behind the socket is this test binary.
    let program = fake.last_program.lock().unwrap().clone().unwrap();
    assert!(program.contains("server"), "{program}");

    let client = ConnectClient::new(endpoint, Some(paired.token.clone()));
    assert_eq!(client.items().await.unwrap()[0].item, "Stripe");
    let secrets = client.read(vec!["octapass://a/b/c".into()]).await.unwrap();
    assert_eq!(secrets[0].value.as_deref(), Some("value for My tool"));

    // Only a hash on disk.
    let stored = std::fs::read_to_string(Clients::path(dir.path())).unwrap();
    assert!(!stored.contains(&paired.token));
}

#[cfg(unix)]
#[tokio::test]
async fn a_token_from_another_program_is_refused() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (_, endpoint) = socket(dir.path()).await;
    let now = time::OffsetDateTime::now_utc()
        .unix_timestamp()
        .unsigned_abs();
    let (_, token) = Clients::open(dir.path())
        .approve("Elsewhere", Some("/some/other/program".into()), now)
        .unwrap();
    let client = ConnectClient::new(endpoint, Some(token.to_string()));
    assert_eq!(
        refused(client.items().await.unwrap_err()),
        (401, "unauthorized".into())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn refusing_gives_no_token_and_a_locked_vault_gives_no_secret() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (fake, endpoint) = socket(dir.path()).await;
    let anonymous = ConnectClient::new(endpoint.clone(), None);
    let paired = anonymous.pair("Fine").await.unwrap();

    fake.approve.store(false, Ordering::SeqCst);
    assert_eq!(
        refused(anonymous.pair("Nope").await.unwrap_err()),
        (403, "denied".into())
    );
    assert_eq!(Clients::open(dir.path()).list().len(), 1);

    fake.locked.store(true, Ordering::SeqCst);
    let client = ConnectClient::new(endpoint, Some(paired.token));
    assert_eq!(
        refused(
            client
                .read(vec!["octapass://a/b/c".into()])
                .await
                .unwrap_err()
        ),
        (423, "locked".into())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn one_prompt_at_a_time() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (fake, endpoint) = socket(dir.path()).await;
    let (release, gate) = oneshot::channel();
    *fake.gate.lock().unwrap() = Some(gate);
    let first = ConnectClient::new(endpoint.clone(), None);
    let waiting = tokio::spawn(async move { first.pair("First").await });
    while fake.asked.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let second = ConnectClient::new(endpoint, None);
    assert_eq!(
        refused(second.pair("Second").await.unwrap_err()),
        (429, "busy".into())
    );
    assert_eq!(fake.asked.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    assert!(waiting.await.unwrap().is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn a_second_service_is_refused_and_a_dead_socket_is_replaced() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (_, _endpoint) = socket(dir.path()).await;
    let error = server::bind_socket(dir.path()).await.err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);

    let other = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    // A socket nothing listens on, left by a process that died.
    let dead = std::os::unix::net::UnixListener::bind(server::socket_path(other.path())).unwrap();
    drop(dead);
    assert!(server::bind_socket(other.path()).await.is_ok());
}

#[tokio::test]
async fn loopback_works_for_local_programs_and_writes_its_port() {
    let dir = tempfile::tempdir().unwrap();
    let (_, address) = loopback(dir.path()).await;
    let port = std::fs::read_to_string(server::port_path(dir.path())).unwrap();
    assert!(address.ends_with(&port));
    let endpoint = Endpoint::find(None, dir.path()).unwrap();
    assert_eq!(endpoint, Endpoint::Loopback(address));
    let client = ConnectClient::new(endpoint.clone(), None);
    let paired = client.pair("Tool").await.unwrap();
    let client = ConnectClient::new(endpoint, Some(paired.token));
    assert_eq!(client.items().await.unwrap().len(), 1);
}

#[tokio::test]
async fn web_pages_cant_reach_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let (fake, address) = loopback(dir.path()).await;
    let body = r#"{"name":"evil"}"#;
    let post = |headers: &str| {
        format!(
            "POST /v1/clients HTTP/1.1\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    // A cross-origin fetch carries Origin.
    let response = raw(
        &address,
        post(&format!(
            "Host: {address}\r\nOrigin: https://evil.example\r\n"
        )),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    // DNS rebinding keeps the attacker's name in Host.
    let response = raw(&address, post("Host: evil.example\r\n")).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(fake.asked.load(Ordering::SeqCst), 0, "no prompt for either");

    // A form post can't send JSON's content type.
    let form = format!(
        "POST /v1/clients HTTP/1.1\r\nHost: {address}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = raw(&address, form).await;
    assert!(response.starts_with("HTTP/1.1 415"), "{response}");
    assert!(response.contains("\"code\":\"bad-request\""), "{response}");
    assert_eq!(fake.asked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_error_has_the_documented_body() {
    let dir = tempfile::tempdir().unwrap();
    let (_, address) = loopback(dir.path()).await;
    let response = raw(
        &address,
        format!("GET /nope HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    assert!(response.contains("\"code\":\"not-found\""), "{response}");
    let bad = "not json";
    let response = raw(
        &address,
        format!(
            "POST /v1/clients HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bad}",
            bad.len()
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("\"code\":\"bad-request\""), "{response}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_client_that_gives_up_frees_the_prompt_and_gets_no_approval() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let (fake, endpoint) = socket(dir.path()).await;
    let (release, gate) = oneshot::channel();
    *fake.gate.lock().unwrap() = Some(gate);
    let first = ConnectClient::new(endpoint.clone(), None);
    let waiting = tokio::spawn(async move { first.pair("Gave up").await });
    while fake.asked.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    waiting.abort();
    let _ = waiting.await;
    let _ = release.send(());
    let second = ConnectClient::new(endpoint, None);
    let mut paired = second.pair("Next").await;
    for _ in 0..200 {
        if paired.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        paired = second.pair("Next").await;
    }
    assert!(paired.is_ok());
    let names: Vec<String> = Clients::open(dir.path())
        .list()
        .into_iter()
        .map(|client| client.name)
        .collect();
    assert_eq!(names, ["Next"]);
}

#[cfg(unix)]
#[tokio::test]
async fn a_dead_socket_doesnt_hide_a_live_port() {
    let dir = tempfile::Builder::new()
        .prefix("c")
        .tempdir_in("/tmp")
        .unwrap();
    let dead = std::os::unix::net::UnixListener::bind(server::socket_path(dir.path())).unwrap();
    drop(dead);
    std::fs::write(server::port_path(dir.path()), "4242").unwrap();
    assert_eq!(
        Endpoint::find(None, dir.path()),
        Some(Endpoint::Loopback("127.0.0.1:4242".into()))
    );
}

#[tokio::test]
async fn limits_on_names_and_references() {
    let dir = tempfile::tempdir().unwrap();
    let (_, address) = loopback(dir.path()).await;
    let client = ConnectClient::new(Endpoint::Loopback(address.clone()), None);
    assert_eq!(
        refused(client.pair(&"x".repeat(65)).await.unwrap_err()),
        (400, "bad-request".into())
    );
    assert_eq!(
        refused(client.pair(" \n ").await.unwrap_err()),
        (400, "bad-request".into())
    );
    let paired = client.pair("Tool").await.unwrap();
    let client = ConnectClient::new(Endpoint::Loopback(address), Some(paired.token));
    assert_eq!(
        refused(client.read(Vec::new()).await.unwrap_err()),
        (400, "bad-request".into())
    );
    assert_eq!(
        refused(client.read(vec!["x".into(); 101]).await.unwrap_err()),
        (400, "bad-request".into())
    );
}

#[test]
fn endpoints_are_found_in_order() {
    assert_eq!(
        Endpoint::parse("unix:/tmp/x.sock"),
        Some(Endpoint::Socket("/tmp/x.sock".into()))
    );
    assert_eq!(
        Endpoint::parse("http://127.0.0.1:9/"),
        Some(Endpoint::Loopback("127.0.0.1:9".into()))
    );
    // Connect is local only: a client won't send tokens anywhere else.
    assert_eq!(Endpoint::parse("http://example.com:9"), None);
    assert_eq!(Endpoint::parse("https://127.0.0.1:9"), None);
    assert_eq!(Endpoint::parse("http://127.0.0.1.evil.example:9"), None);
    assert_eq!(Endpoint::parse("http://127.0.0.1:80@example.com"), None);
    assert_eq!(Endpoint::parse("http://localhost:80/path"), None);
    assert_eq!(
        Endpoint::parse("http://localhost:9"),
        Some(Endpoint::Loopback("localhost:9".into()))
    );
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(Endpoint::find(None, dir.path()), None);
    assert_eq!(
        Endpoint::find(Some("unix:/a"), dir.path()),
        Some(Endpoint::Socket("/a".into()))
    );
}
