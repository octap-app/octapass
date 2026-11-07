//! Test harness: the real router on a temporary database, driven by an OPAQUE
//! client built from opaque-ke with the contract's ciphersuite.
//!
//! The database is SQLite, or, when `OCTAPASS_TEST_POSTGRES_URL` points at a
//! PostgreSQL server, a fresh database there for each test, dropped after it.

#![allow(dead_code)] // Each test binary uses a different subset.

pub mod fake_s3;
pub mod people;
pub mod two_step;

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use octapass_server::{AppState, Config};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sqlx::{Connection, Executor, PgConnection};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tower::ServiceExt;

pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

pub const PASSWORD: &[u8] = b"auth_secret derived on the client";

pub struct TestServer {
    pub state: AppState,
    router: Router,
    pub dir: tempfile::TempDir,
    postgres: Option<TestDatabase>,
}

/// A database created for one test on the server at `OCTAPASS_TEST_POSTGRES_URL`.
struct TestDatabase {
    admin_url: String,
    name: String,
}

impl TestDatabase {
    async fn create() -> Option<Self> {
        let admin_url = std::env::var("OCTAPASS_TEST_POSTGRES_URL").ok()?;
        let name = format!("octapass_test_{}", uuid::Uuid::now_v7().simple());
        let mut conn = PgConnection::connect(&admin_url).await.unwrap();
        conn.execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .await
            .unwrap();
        Some(Self { admin_url, name })
    }

    fn url(&self) -> String {
        let mut url = url::Url::parse(&self.admin_url).unwrap();
        url.set_path(&self.name);
        url.to_string()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let (admin_url, name) = (self.admin_url.clone(), self.name.clone());
        // Drop can't await, and the test's runtime may be shutting down.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut conn = PgConnection::connect(&admin_url).await.unwrap();
                let drop = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
                conn.execute(sqlx::AssertSqlSafe(drop)).await.unwrap();
            });
        })
        .join()
        .unwrap();
    }
}

pub type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Response {
    pub fn problem_type(&self) -> &str {
        self.body["type"].as_str().unwrap_or_default()
    }

    pub fn is_problem(&self, slug: &str) -> bool {
        self.headers["content-type"] == "application/problem+json"
            && self.problem_type() == format!("https://octap.app/problems/{slug}")
    }
}

/// A signed-in device.
pub struct Device {
    pub access_token: String,
    pub refresh_token: String,
    pub account: Value,
    pub trusted_device_token: Option<String>,
}

impl Device {
    pub fn from_login(body: &Value) -> Self {
        Device {
            access_token: body["accessToken"].as_str().unwrap().to_owned(),
            refresh_token: body["refreshToken"].as_str().unwrap().to_owned(),
            account: body["account"].clone(),
            trusted_device_token: body["trustedDeviceToken"].as_str().map(str::to_owned),
        }
    }
}

impl TestServer {
    pub async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    pub async fn with_config(adjust: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap().to_owned();
        let mut config = Config::from_lookup(|name| match name {
            "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
            "OCTAPASS_DEV_MODE" => Some("true".into()),
            _ => None,
        })
        .unwrap();
        let postgres = TestDatabase::create().await;
        if let Some(database) = &postgres {
            config.database_url = database.url();
        }
        adjust(&mut config);
        let state = AppState::new(config).await.unwrap();
        Self {
            router: octapass_server::router(state.clone()),
            state,
            dir,
            postgres,
        }
    }

    pub fn is_postgres(&self) -> bool {
        self.postgres.is_some()
    }

    /// The server clock, in Unix milliseconds (tests move it forward).
    pub fn state_now(&self) -> i64 {
        self.state.clock.now()
    }

    /// Serves the router on a local port, for clients that need a real
    /// connection such as WebSockets.
    pub async fn listen(&self) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service = self
            .router
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
        addr
    }

    pub async fn send(&self, request: Request<Body>) -> Response {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        Response {
            status,
            headers,
            body,
        }
    }

    /// Sends a request and returns the raw response body.
    pub async fn send_raw(&self, mut request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let addr = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        request.extensions_mut().insert(ConnectInfo(addr));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, bytes.to_vec())
    }

    /// Sends a request from 192.0.2.1 with optional bearer token, headers and JSON body.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Response {
        self.call_from("192.0.2.1", method, path, token, headers, body)
            .await
    }

    pub async fn call_from(
        &self,
        ip: &str,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Response {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(json) => {
                builder = builder.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let mut request = builder.body(body).unwrap();
        let addr = SocketAddr::new(ip.parse().unwrap(), 40000);
        request.extensions_mut().insert(ConnectInfo(addr));
        self.send(request).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Response {
        self.call(Method::POST, path, None, &[], Some(body)).await
    }

    pub async fn get(&self, path: &str, token: &str) -> Response {
        self.call(Method::GET, path, Some(token), &[], None).await
    }

    /// Signs up through register/start and register/finish. Returns the
    /// personal vault id.
    pub async fn register(&self, email: &str) -> String {
        let vault_id = new_id();
        self.register_with(email, |code, upload| {
            register_finish_body(email, code, upload, &vault_id)
        })
        .await;
        vault_id
    }

    /// Signs up with the register/finish body `finish_body(code, upload)` makes.
    pub async fn register_with(&self, email: &str, finish_body: impl FnOnce(&str, &str) -> Value) {
        let start = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
        let started = self
            .post(
                "/v1/auth/register/start",
                json!({ "email": email, "registrationRequest": b64(start.message.serialize()) }),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
        let code = started.body["devVerificationCode"]
            .as_str()
            .unwrap()
            .to_owned();
        let response = RegistrationResponse::<Suite>::deserialize(&unb64(
            &started.body["registrationResponse"],
        ))
        .unwrap();
        let finish = start
            .state
            .finish(
                &mut OsRng,
                PASSWORD,
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();

        let finished = self
            .post(
                "/v1/auth/register/finish",
                finish_body(&code, &b64(finish.message.serialize())),
            )
            .await;
        assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    }

    /// Runs login/start and login/finish with `password`. Returns the raw
    /// finish response.
    pub async fn login_with(&self, email: &str, password: &[u8], device: &str) -> Response {
        self.login_from("192.0.2.1", email, password, device)
            .await
            .expect("login/start succeeds")
    }

    /// Like `login_with`, from `ip`. Returns the login/start response instead
    /// when that fails.
    pub async fn login_from(
        &self,
        ip: &str,
        email: &str,
        password: &[u8],
        device: &str,
    ) -> Result<Response, Box<Response>> {
        self.login_trusted(ip, email, password, device, None).await
    }

    /// Like `login_from`, sending a trusted-device token.
    pub async fn login_trusted(
        &self,
        ip: &str,
        email: &str,
        password: &[u8],
        device: &str,
        trusted_device_token: Option<&str>,
    ) -> Result<Response, Box<Response>> {
        let start = ClientLogin::<Suite>::start(&mut OsRng, password).unwrap();
        let body = json!({ "email": email, "credentialRequest": b64(start.message.serialize()) });
        let started = self
            .call_from(
                ip,
                Method::POST,
                "/v1/auth/login/start",
                None,
                &[],
                Some(body),
            )
            .await;
        if started.status != StatusCode::OK {
            return Err(Box::new(started));
        }
        let finalization =
            client_finish(start.state, password, &started.body["credentialResponse"]);
        let mut body = json!({
            "loginId": started.body["loginId"],
            "credentialFinalization": finalization,
            "device": { "name": device, "platform": "test" }
        });
        if let Some(token) = trusted_device_token {
            body["trustedDeviceToken"] = json!(token);
        }
        Ok(self
            .call_from(
                ip,
                Method::POST,
                "/v1/auth/login/finish",
                None,
                &[],
                Some(body),
            )
            .await)
    }

    pub async fn login(&self, email: &str, device: &str) -> Device {
        let response = self.login_with(email, PASSWORD, device).await;
        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
        Device::from_login(&response.body)
    }

    /// Runs reauth/start and reauth/finish. Returns the raw finish response.
    pub async fn reauth_with(&self, token: &str, password: &[u8]) -> Response {
        self.reauth_for(token, password, "delete-account").await
    }

    /// Like `reauth_with`, for another purpose.
    pub async fn reauth_for(&self, token: &str, password: &[u8], purpose: &str) -> Response {
        let start = ClientLogin::<Suite>::start(&mut OsRng, password).unwrap();
        let started = self
            .call(
                Method::POST,
                "/v1/auth/reauth/start",
                Some(token),
                &[],
                Some(json!({ "credentialRequest": b64(start.message.serialize()) })),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
        let finalization =
            client_finish(start.state, password, &started.body["credentialResponse"]);
        self.call(
            Method::POST,
            "/v1/auth/reauth/finish",
            Some(token),
            &[],
            Some(json!({
                "reauthId": started.body["reauthId"],
                "credentialFinalization": finalization,
                "purpose": purpose
            })),
        )
        .await
    }

    pub async fn put_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
        precondition: (&str, &str),
        label: u8,
    ) -> Response {
        self.call(
            Method::PUT,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(token),
            &[precondition],
            Some(item_body(label)),
        )
        .await
    }
}

/// `DELETE /v1/account` with an optional reauth token.
pub async fn delete_account(
    server: &TestServer,
    device: &Device,
    reauth_token: Option<&str>,
    confirm_email: &str,
) -> Response {
    let headers: Vec<(&str, &str)> = reauth_token
        .map(|token| ("x-reauth-token", token))
        .into_iter()
        .collect();
    server
        .call(
            Method::DELETE,
            "/v1/account",
            Some(&device.access_token),
            &headers,
            Some(json!({ "confirmEmail": confirm_email })),
        )
        .await
}

/// A fresh delete-account reauth token.
pub async fn reauth_token(server: &TestServer, device: &Device) -> String {
    let response = server.reauth_with(&device.access_token, PASSWORD).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(response.body["expiresIn"], 300);
    response.body["reauthToken"].as_str().unwrap().to_owned()
}

/// Opens `/v1/ws` on a server started with `listen`.
pub async fn ws_connect(addr: SocketAddr) -> Socket {
    tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .unwrap()
        .0
}

/// Connects and authenticates, returning the socket after `authenticated`.
pub async fn ws_auth(addr: SocketAddr, token: &str) -> Socket {
    let mut socket = ws_connect(addr).await;
    ws_send_auth(&mut socket, token).await;
    let reply = ws_next(&mut socket).await;
    assert_eq!(reply["type"], "authenticated", "{reply:?}");
    socket
}

pub async fn ws_send_auth(socket: &mut Socket, token: &str) {
    use futures_util::SinkExt;
    let auth = json!({ "type": "auth", "accessToken": token }).to_string();
    socket.send(WsMessage::Text(auth.into())).await.unwrap();
}

/// The next JSON message, skipping pings. Fails after five seconds.
pub async fn ws_next(socket: &mut Socket) -> Value {
    loop {
        match ws_frame(socket).await {
            WsMessage::Text(text) => return serde_json::from_str(&text).unwrap(),
            WsMessage::Ping(_) | WsMessage::Pong(_) => {}
            other => panic!("expected a text message, got {other:?}"),
        }
    }
}

/// The close code the server ends with, skipping anything sent before it.
pub async fn ws_close_code(socket: &mut Socket) -> u16 {
    loop {
        if let WsMessage::Close(frame) = ws_frame(socket).await {
            return frame.map_or(1005, |f| f.code.into());
        }
    }
}

pub async fn ws_frame(socket: &mut Socket) -> WsMessage {
    use futures_util::StreamExt;
    tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("a WebSocket frame within five seconds")
        .expect("the socket is open")
        .expect("a valid frame")
}

/// Finishes the client side of an OPAQUE login. A wrong password makes
/// opaque-ke fail on the client; the test then sends garbage, which is what a
/// server sees from a client that can't produce a valid finalization.
pub fn client_finish(
    state: ClientLogin<Suite>,
    password: &[u8],
    credential_response: &Value,
) -> String {
    let response = CredentialResponse::<Suite>::deserialize(&unb64(credential_response)).unwrap();
    match state.finish(
        &mut OsRng,
        password,
        response,
        ClientLoginFinishParameters::default(),
    ) {
        Ok(finished) => b64(finished.message.serialize()),
        Err(_) => b64(random_bytes(64)),
    }
}

pub fn register_finish_body(email: &str, code: &str, upload: &str, vault_id: &str) -> Value {
    json!({
        "email": email,
        "verificationCode": code,
        "registrationUpload": upload,
        "account": {
            "email": email,
            "kdf": { "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1 },
            "accountSalt": b64(random_bytes(16)),
            "wrappedAsk": envelope(48),
            "publicEncKey": b64(random_bytes(32)),
            "publicSignKey": b64(random_bytes(32)),
            "wrappedPrivateKeys": envelope(80),
            "recoveryWrappedAsk": envelope(48)
        },
        "personalVault": { "id": vault_id, "wrappedVaultKey": envelope(48) }
    })
}

/// A body whose ciphertexts carry `label` in their last byte, so tests can
/// tell versions apart.
pub fn item_body(label: u8) -> Value {
    let labelled = |len: usize| {
        let mut bytes = envelope_bytes(len);
        *bytes.last_mut().unwrap() = label;
        b64(bytes)
    };
    json!({ "encryptedItemKey": labelled(48), "overview": labelled(100), "details": labelled(300) })
}

/// A well-formed ciphertext envelope: version 1, key id, nonce, then `ciphertext_len` bytes.
pub fn envelope(ciphertext_len: usize) -> String {
    b64(envelope_bytes(ciphertext_len))
}

fn envelope_bytes(ciphertext_len: usize) -> Vec<u8> {
    let mut bytes = random_bytes(1 + 16 + 24 + ciphertext_len);
    bytes[0] = 1;
    bytes
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64url string"))
        .expect("valid base64url")
}
