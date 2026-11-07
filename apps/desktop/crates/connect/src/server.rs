//! The local service. HTTP over a Unix socket, or over `127.0.0.1` where sockets aren't an option,
//! so that any tool with an HTTP client can use it (`curl --unix-socket`, a script, an IDE).
//!
//! ```text
//! GET  /v1/status                       no token. Whether the vault is unlocked.
//! POST /v1/clients   { name }           asks the person; answers { id, token, expiresAt }
//! GET  /v1/items                        names of vaults, items and fields, never values
//! POST /v1/read      { references: [] } values; each one recorded first
//! DELETE /v1/clients/self               the client gives its token up
//! ```

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::connect_info::Connected;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::clients::{Client, Clients, MAX_NAME_CHARS};
use crate::reference::FieldName;

/// How long a person gets to answer a prompt.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REFERENCES: usize = 100;
const MAX_BODY: usize = 64 * 1024;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct ConnectError {
    #[serde(skip)]
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ConnectError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn locked() -> Self {
        Self::new(
            423,
            "locked",
            "Octa Pass is locked. Unlock it, then try again.",
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "not-found", message)
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(500, "failed", message)
    }

    fn unauthorized() -> Self {
        Self::new(401, "unauthorized", "Missing or unknown client token.")
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a ConnectError,
}

/// A body that isn't JSON, is too large, or has the wrong type, in the same shape as other errors.
fn bad_body(rejection: JsonRejection) -> ConnectError {
    ConnectError::new(
        rejection.status().as_u16(),
        "bad-request",
        rejection.body_text(),
    )
}

impl IntoResponse for ConnectError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ErrorBody { error: &self })).into_response()
    }
}

/// Who connected, as far as the OS can say. Over loopback it can't, so only the token counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
    pub program: Option<String>,
    /// Came over TCP: the Host and Origin checks apply.
    pub loopback: bool,
}

/// What the person is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// What the client calls itself. Only a claim.
    pub name: String,
    pub peer: Peer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRef {
    pub vault: String,
    /// For references to a vault whose name isn't unique.
    pub vault_id: String,
    pub item: String,
    pub item_id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub fields: Vec<FieldName>,
}

/// One answer of `POST /v1/read`: a value, or why this reference has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What each app plugs in.
pub trait Backend: Send + Sync + 'static {
    /// Whether the vault can be read right now.
    fn unlocked(&self) -> BoxFuture<'_, bool>;
    /// Asks the person. `false` also for no answer.
    fn approve(&self, request: Approval) -> BoxFuture<'_, bool>;
    fn items(&self, client: Client) -> BoxFuture<'_, Result<Vec<ItemRef>, ConnectError>>;
    /// Resolves references. Must record each one before returning its value.
    fn read(
        &self,
        client: Client,
        references: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<Secret>, ConnectError>>;
}

struct Shared {
    backend: Arc<dyn Backend>,
    clients: Mutex<Clients>,
    /// One prompt at a time, so a client can't bury the person in them.
    prompt: Semaphore,
    uid: Option<u32>,
    /// Over loopback: the only `Host` values accepted.
    hosts: Vec<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn authenticate(shared: &Shared, peer: &Peer, headers: &HeaderMap) -> Result<Client, ConnectError> {
    let token = token(headers).ok_or_else(ConnectError::unauthorized)?;
    shared
        .clients
        .lock()
        .expect("clients lock")
        .authenticate(token, peer.program.as_deref(), now())
        .ok_or_else(ConnectError::unauthorized)
}

/// Websites can make a browser talk to loopback. They can't set `Host` under DNS rebinding without
/// it naming their own domain, and every request a page makes across origins carries `Origin`.
/// Nothing but a local program has a reason to come here, so both end the request.
async fn guard(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request,
    next: Next,
) -> Response {
    if let (Some(expected), Some(actual)) = (shared.uid, peer.uid)
        && expected != actual
    {
        return ConnectError::new(403, "forbidden", "Another user's program.").into_response();
    }
    if peer.loopback {
        let headers = request.headers();
        let host = headers.get(HOST).and_then(|value| value.to_str().ok());
        if headers.contains_key(ORIGIN)
            || !host.is_some_and(|host| shared.hosts.iter().any(|allowed| allowed == host))
        {
            return ConnectError::new(403, "forbidden", "Local programs only.").into_response();
        }
    }
    next.run(request).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    unlocked: bool,
}

async fn status(State(shared): State<Arc<Shared>>) -> Json<Status> {
    Json(Status {
        unlocked: shared.backend.unlocked().await,
    })
}

#[derive(Deserialize)]
struct PairRequest {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResponse {
    pub id: String,
    pub token: String,
    /// Unix seconds.
    pub expires_at: u64,
}

async fn pair(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Result<Json<PairRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<PairResponse>), ConnectError> {
    let Json(request) = request.map_err(bad_body)?;
    let name: String = request
        .name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(ConnectError::new(
            400,
            "bad-request",
            format!("A client's name is 1 to {MAX_NAME_CHARS} characters."),
        ));
    }
    let Ok(_prompt) = shared.prompt.try_acquire() else {
        return Err(ConnectError::new(
            429,
            "busy",
            "Another client is waiting for approval.",
        ));
    };
    let approval = Approval {
        name: name.clone(),
        peer: peer.clone(),
    };
    let approved = tokio::time::timeout(APPROVAL_TIMEOUT, shared.backend.approve(approval))
        .await
        .unwrap_or(false);
    if !approved {
        return Err(ConnectError::new(
            403,
            "denied",
            "The request wasn't approved.",
        ));
    }
    let (client, token) = shared
        .clients
        .lock()
        .expect("clients lock")
        .approve(&name, peer.program, now())
        .map_err(|error| ConnectError::failed(format!("Can't save the approval: {error}")))?;
    Ok((
        StatusCode::CREATED,
        Json(PairResponse {
            id: client.id,
            token: token.to_string(),
            expires_at: client.expires_at,
        }),
    ))
}

async fn forget(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Result<StatusCode, ConnectError> {
    let client = authenticate(&shared, &peer, &headers)?;
    shared
        .clients
        .lock()
        .expect("clients lock")
        .revoke(&client.id)
        .map_err(|error| ConnectError::failed(error.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, Deserialize)]
pub struct ItemsResponse {
    pub items: Vec<ItemRef>,
}

async fn items(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Result<Json<ItemsResponse>, ConnectError> {
    let client = authenticate(&shared, &peer, &headers)?;
    Ok(Json(ItemsResponse {
        items: shared.backend.items(client).await?,
    }))
}

#[derive(Serialize, Deserialize)]
pub struct ReadRequest {
    pub references: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ReadResponse {
    pub secrets: Vec<Secret>,
}

async fn read(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    request: Result<Json<ReadRequest>, JsonRejection>,
) -> Result<Json<ReadResponse>, ConnectError> {
    let client = authenticate(&shared, &peer, &headers)?;
    let Json(request) = request.map_err(bad_body)?;
    if request.references.is_empty() || request.references.len() > MAX_REFERENCES {
        return Err(ConnectError::new(
            400,
            "bad-request",
            format!("Ask for 1 to {MAX_REFERENCES} references."),
        ));
    }
    Ok(Json(ReadResponse {
        secrets: shared.backend.read(client, request.references).await?,
    }))
}

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/clients", post(pair))
        .route("/v1/clients/self", delete(forget))
        .route("/v1/items", get(items))
        .route("/v1/read", post(read))
        .fallback(|| async { ConnectError::not_found("No such path.") })
        .method_not_allowed_fallback(|| async {
            ConnectError::new(405, "bad-request", "Wrong method.")
        })
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(shared.clone(), guard))
        .with_state(shared)
}

#[cfg(unix)]
fn program_of(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.display().to_string())
    }
    #[cfg(target_os = "macos")]
    {
        // PROC_PIDPATHINFO_MAXSIZE
        let mut buffer = vec![0u8; 4096];
        let pid = i32::try_from(pid).ok()?;
        // SAFETY: the buffer outlives the call and its length is passed with it.
        let written = unsafe {
            libc::proc_pidpath(
                pid,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).ok()?,
            )
        };
        let written = usize::try_from(written).ok().filter(|len| *len > 0)?;
        buffer.truncate(written);
        String::from_utf8(buffer).ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(unix)]
impl Connected<IncomingStream<'_, tokio::net::UnixListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        let credentials = stream.io().peer_cred().ok();
        let pid = credentials
            .as_ref()
            .and_then(tokio::net::unix::UCred::pid)
            .and_then(|pid| u32::try_from(pid).ok());
        Self {
            uid: credentials.as_ref().map(tokio::net::unix::UCred::uid),
            pid,
            program: pid.and_then(program_of),
            loopback: false,
        }
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(_: IncomingStream<'_, TcpListener>) -> Self {
        Self {
            loopback: true,
            ..Self::default()
        }
    }
}

fn shared(backend: Arc<dyn Backend>, folder: &Path, hosts: Vec<String>) -> Arc<Shared> {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and can't fail.
    let uid = Some(unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let uid = None;
    Arc::new(Shared {
        backend,
        clients: Mutex::new(Clients::open(folder)),
        prompt: Semaphore::new(1),
        uid,
        hosts,
    })
}

/// Makes `folder` private to this user.
pub fn private_folder(folder: &Path) -> io::Result<()> {
    std::fs::create_dir_all(folder)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn socket_path(folder: &Path) -> std::path::PathBuf {
    folder.join("connect.sock")
}

/// A listener bound to this user's socket, which only they can reach. A socket left by a process
/// that died is replaced; a live one is an error, so two services can't fight over clients.
#[cfg(unix)]
pub async fn bind_socket(folder: &Path) -> io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    private_folder(folder)?;
    let path = socket_path(folder);
    if path.exists() {
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Octa Pass Connect is already running",
            ));
        }
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves on a Unix socket until `stop` finishes. The socket goes with it.
#[cfg(unix)]
pub async fn serve_socket(
    listener: tokio::net::UnixListener,
    folder: &Path,
    backend: Arc<dyn Backend>,
    stop: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let app = router(shared(backend, folder, Vec::new()));
    let result = axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
        .with_graceful_shutdown(stop)
        .await;
    let _ = std::fs::remove_file(socket_path(folder));
    result
}

pub fn port_path(folder: &Path) -> std::path::PathBuf {
    folder.join("connect.port")
}

/// A loopback listener on a port the OS picks, or `port`. Never another address.
pub async fn bind_loopback(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await
}

/// Serves on loopback until `stop` finishes, with the port in a file only this user can read.
pub async fn serve_loopback(
    listener: TcpListener,
    folder: &Path,
    backend: Arc<dyn Backend>,
    stop: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    private_folder(folder)?;
    let port = listener.local_addr()?.port();
    std::fs::write(port_path(folder), port.to_string())?;
    let hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let app = router(shared(backend, folder, hosts));
    let result = axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
        .with_graceful_shutdown(stop)
        .await;
    let _ = std::fs::remove_file(port_path(folder));
    result
}
