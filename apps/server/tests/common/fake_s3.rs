//! An in-memory S3-compatible server for the object storage backend. It
//! checks that requests are signed for the test credentials and that uploads
//! match their signed payload hash; the signature itself is checked against
//! the AWS example in the unit tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use sha2::{Digest, Sha256};

pub const BUCKET: &str = "files";
pub const ACCESS_KEY_ID: &str = "test-key";
pub const SECRET_ACCESS_KEY: &str = "test-secret";

#[derive(Clone, Default)]
pub struct FakeS3 {
    pub objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Answer 503 to everything, like an unreachable provider.
    pub down: Arc<Mutex<bool>>,
}

impl FakeS3 {
    /// Serves on a local port; returns the endpoint URL.
    pub async fn start(&self) -> String {
        let app = Router::new()
            .route("/{*path}", any(handle))
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    pub fn set_down(&self, down: bool) {
        *self.down.lock().unwrap() = down;
    }

    pub fn len(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
}

async fn handle(
    State(fake): State<FakeS3>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if *fake.down.lock().unwrap() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let credential = format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY_ID}/");
    let payload: String = Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !header("authorization").starts_with(&credential)
        || header("x-amz-content-sha256") != payload
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(key) = path.strip_prefix(&format!("{BUCKET}/")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut objects = fake.objects.lock().unwrap();
    match method {
        Method::HEAD if key.is_empty() => StatusCode::OK.into_response(),
        Method::PUT => {
            objects.insert(key.to_owned(), body.to_vec());
            StatusCode::OK.into_response()
        }
        Method::GET => match objects.get(key) {
            Some(bytes) => bytes.clone().into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        Method::DELETE => {
            objects.remove(key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
