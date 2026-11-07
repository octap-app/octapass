//! The built web vault, served from `OCTAPASS_WEB_DIR` on the API's own origin, so one port
//! carries both. Paths that look like pages (no file extension) and match no file get
//! `index.html`, so the vault's routes survive a reload; missing files and anything under `/v1`
//! get a 404.
//!
//! The pages get their own headers: a CSP that allows only this origin plus `wasm-unsafe-eval`
//! for the crypto core, cross-origin isolation, and long caching for the hashed `assets/`.

use std::convert::Infallible;
use std::path::Path;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::config::Config;
use crate::error::ApiError;

#[derive(Clone)]
pub struct Web {
    files: ServeDir,
    index: ServeFile,
    headers: HeaderMap,
}

impl Web {
    pub fn new(dir: &Path, config: &Config) -> Self {
        let mut headers = HeaderMap::new();
        let mut set = |name: HeaderName, value: &str| {
            headers.insert(name, HeaderValue::from_str(value).expect("valid header"));
        };
        set(
            header::CONTENT_SECURITY_POLICY,
            &content_security_policy(&config.public_url),
        );
        set(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        );
        set(
            HeaderName::from_static("cross-origin-embedder-policy"),
            "require-corp",
        );
        set(
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        );
        set(
            HeaderName::from_static("permissions-policy"),
            "camera=(self), microphone=(), geolocation=(), browsing-topics=()",
        );
        Self {
            files: ServeDir::new(dir).precompressed_gzip(),
            index: ServeFile::new(dir.join("index.html")).precompressed_gzip(),
            headers,
        }
    }

    pub async fn serve(self, request: Request) -> Response {
        let path = request.uri().path();
        if path == "/v1" || path.starts_with("/v1/") {
            return ApiError::NotFound.into_response();
        }
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return ApiError::MethodNotAllowed.into_response();
        }
        let is_page = !path.rsplit('/').next().unwrap_or_default().contains('.');
        let is_asset = path.starts_with("/assets/");
        let page_request = is_page.then(|| copy_for_index(&request));

        let mut response = unwrap(self.files.oneshot(request).await);
        if response.status() == StatusCode::NOT_FOUND
            && let Some(request) = page_request
        {
            response = unwrap(self.index.oneshot(request).await);
        }
        let mut response = response.map(Body::new);
        let cache = if is_asset && response.status().is_success() {
            // File names under assets/ carry a hash of their contents.
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        headers.extend(self.headers);
        response
    }
}

/// Only this origin, plus compiling the WASM core. `connect-src` names the WebSocket URL as well,
/// for browsers whose `'self'` doesn't cover `wss:`.
pub fn content_security_policy(public_url: &str) -> String {
    let origin = public_url.trim_end_matches('/');
    let websocket = origin
        .strip_prefix("https://")
        .map(|host| format!(" wss://{host}"))
        .or_else(|| {
            origin
                .strip_prefix("http://")
                .map(|host| format!(" ws://{host}"))
        })
        .unwrap_or_default();
    format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
         img-src 'self' data: blob:; font-src 'self'; connect-src 'self'{websocket}; \
         worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'; object-src 'none'"
    )
}

/// The parts of a request `ServeFile` looks at, for the second try.
fn copy_for_index(request: &Request) -> Request {
    let mut copy = Request::new(Body::empty());
    *copy.method_mut() = request.method().clone();
    *copy.headers_mut() = request.headers().clone();
    copy
}

fn unwrap<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_allows_the_websocket_on_the_same_host() {
        let csp = content_security_policy("https://pass.example.com/");
        assert!(
            csp.contains("connect-src 'self' wss://pass.example.com;"),
            "{csp}"
        );
        assert!(
            csp.contains("script-src 'self' 'wasm-unsafe-eval';"),
            "{csp}"
        );
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        let local = content_security_policy("http://127.0.0.1:8080");
        assert!(
            local.contains("connect-src 'self' ws://127.0.0.1:8080;"),
            "{local}"
        );
    }
}
