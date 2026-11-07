//! A small Connect client: one HTTP/1.1 request per connection, over a Unix socket or loopback.
//! `octapass connect read` uses it, and its tests stand in for any other tool's HTTP client.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ENDPOINT_ENV;
use crate::server::{
    ItemRef, ItemsResponse, PairResponse, ReadRequest, ReadResponse, Secret, port_path, socket_path,
};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Socket(PathBuf),
    /// `host:port` on loopback.
    Loopback(String),
}

impl Endpoint {
    /// `unix:/path` or `http://127.0.0.1:port`.
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(path) = text.strip_prefix("unix:") {
            return Some(Self::Socket(PathBuf::from(path)));
        }
        let host = text
            .strip_prefix("http://")?
            .strip_suffix('/')
            .unwrap_or(&text[7..]);
        let (name, port) = host.split_once(':')?;
        // The whole of it: `127.0.0.1:80@example.com` is a host elsewhere with a password.
        (matches!(name, "127.0.0.1" | "localhost") && port.parse::<u16>().is_ok())
            .then(|| Self::Loopback(host.to_owned()))
    }

    /// `OCTAPASS_CONNECT`, then the socket or port file in this user's Connect folder.
    pub fn find(env: Option<&str>, folder: &Path) -> Option<Self> {
        if let Some(text) = env.filter(|text| !text.is_empty()) {
            return Self::parse(text);
        }
        let socket = socket_path(folder);
        if socket_answers(&socket) {
            return Some(Self::Socket(socket));
        }
        let port = std::fs::read_to_string(port_path(folder)).ok()?;
        Some(Self::Loopback(format!("127.0.0.1:{}", port.trim())))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(
        "Octa Pass Connect isn't running. Start it with `octapass connect serve`, or turn it on in the desktop app. Set {ENDPOINT_ENV} if it's elsewhere. ({0})"
    )]
    Unreachable(String),
    #[error("{message}")]
    Refused {
        status: u16,
        code: String,
        message: String,
    },
    #[error("Connect sent an answer this version can't read.")]
    BadResponse,
}

pub struct ConnectClient {
    endpoint: Endpoint,
    token: Option<String>,
}

impl ConnectClient {
    pub fn new(endpoint: Endpoint, token: Option<String>) -> Self {
        Self { endpoint, token }
    }

    pub async fn pair(&self, name: &str) -> Result<PairResponse, ClientError> {
        let body = serde_json::json!({ "name": name });
        self.call("POST", "/v1/clients", Some(&body)).await
    }

    pub async fn status(&self) -> Result<Value, ClientError> {
        self.call::<Value, ()>("GET", "/v1/status", None).await
    }

    pub async fn items(&self) -> Result<Vec<ItemRef>, ClientError> {
        let response: ItemsResponse = self.call::<_, ()>("GET", "/v1/items", None).await?;
        Ok(response.items)
    }

    pub async fn read(&self, references: Vec<String>) -> Result<Vec<Secret>, ClientError> {
        let response: ReadResponse = self
            .call("POST", "/v1/read", Some(&ReadRequest { references }))
            .await?;
        Ok(response.secrets)
    }

    async fn call<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, ClientError> {
        let body = body.map_or_else(Vec::new, |body| {
            serde_json::to_vec(body).expect("requests serialize")
        });
        let bytes = match &self.endpoint {
            Endpoint::Socket(socket) => {
                let request = self.request(method, path, "localhost", &body);
                exchange(connect_socket(socket).await?, request).await?
            }
            Endpoint::Loopback(host) => {
                let stream = tokio::net::TcpStream::connect(host)
                    .await
                    .map_err(|error| ClientError::Unreachable(error.to_string()))?;
                exchange(stream, self.request(method, path, host, &body)).await?
            }
        };
        parse(&bytes)
    }

    fn request(&self, method: &str, path: &str, host: &str, body: &[u8]) -> Vec<u8> {
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if let Some(token) = &self.token {
            head += &format!("Authorization: Bearer {token}\r\n");
        }
        if !body.is_empty() {
            head += &format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
        }
        head += "\r\n";
        let mut request = head.into_bytes();
        request.extend_from_slice(body);
        request
    }
}

/// A socket left by a process that died doesn't count, so it can't hide a live port.
#[cfg(unix)]
fn socket_answers(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn socket_answers(_: &Path) -> bool {
    false
}

#[cfg(unix)]
async fn connect_socket(path: &Path) -> Result<tokio::net::UnixStream, ClientError> {
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(|error| ClientError::Unreachable(error.to_string()))
}

#[cfg(not(unix))]
async fn connect_socket(_: &Path) -> Result<tokio::net::TcpStream, ClientError> {
    Err(ClientError::Unreachable("no sockets here".into()))
}

async fn exchange(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    stream
        .write_all(&request)
        .await
        .map_err(|error| ClientError::Unreachable(error.to_string()))?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|error| ClientError::Unreachable(error.to_string()))?;
    Ok(response)
}

fn parse<T: DeserializeOwned>(response: &[u8]) -> Result<T, ClientError> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ClientError::BadResponse)?;
    let head = std::str::from_utf8(&response[..split]).map_err(|_| ClientError::BadResponse)?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or(ClientError::BadResponse)?;
    let body = &response[split + 4..];
    if (200..300).contains(&status) {
        let empty: &[u8] = b"null";
        return serde_json::from_slice(if body.is_empty() { empty } else { body })
            .map_err(|_| ClientError::BadResponse);
    }
    let error: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let text = |key: &str| error["error"][key].as_str().unwrap_or_default().to_owned();
    Err(ClientError::Refused {
        status,
        code: text("code"),
        message: text("message"),
    })
}
