//! The core's `HttpClient` for the app's Rust side, plus the few calls the FFI doesn't make
//! (the trash, the device list, attachments, Pwned Passwords). Certificates are checked with the
//! platform's verifier, so the system's trust settings apply as they would in `URLSession`.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use octapass_ffi::{HttpClient, HttpMethod, HttpRequest, HttpResponse, OctaPassError};
use serde::de::DeserializeOwned;
use ureq::tls::{RootCerts, TlsConfig};

use crate::error::{ErrorCode, Result, VaultError};

/// A full sync of a large vault is a few megabytes; this is far above it.
const MAX_BODY: u64 = 64 << 20;
/// Attachments go up and down raw, for as long as the server allows (an hour), but a transfer
/// that stalls for a minute is given up.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const STALL_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    pub fn new(user_agent: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .user_agent(user_agent)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        Self { agent }
    }

    /// An authenticated JSON call; problems become the UI's error codes.
    pub fn json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: String,
        token: &str,
        headers: &[(&str, String)],
    ) -> std::result::Result<T, OctaPassError> {
        let mut all = HashMap::from([
            ("accept".to_owned(), "application/json".to_owned()),
            ("authorization".to_owned(), format!("Bearer {token}")),
        ]);
        all.extend(
            headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        );
        let response = self.send(HttpRequest {
            method,
            url,
            headers: all,
            body: None,
        })?;
        if !(200..300).contains(&response.status) {
            return Err(problem(&response));
        }
        serde_json::from_slice(&response.body).map_err(|_| OctaPassError::InvalidResponse)
    }

    /// An authenticated call whose answer has no body worth reading (`204 No Content`).
    pub fn call(
        &self,
        method: HttpMethod,
        url: String,
        token: &str,
    ) -> std::result::Result<(), OctaPassError> {
        let response = self.send(HttpRequest {
            method,
            url,
            headers: HashMap::from([("authorization".to_owned(), format!("Bearer {token}"))]),
            body: None,
        })?;
        if !(200..300).contains(&response.status) {
            return Err(problem(&response));
        }
        Ok(())
    }

    /// An authenticated POST of a JSON body, with a JSON answer.
    pub fn post_for_json<T: DeserializeOwned>(
        &self,
        url: String,
        token: &str,
        body: &impl serde::Serialize,
    ) -> std::result::Result<T, OctaPassError> {
        let body = serde_json::to_vec(body).map_err(|_| OctaPassError::InvalidResponse)?;
        let response = self.send(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: HashMap::from([
                ("accept".to_owned(), "application/json".to_owned()),
                ("authorization".to_owned(), format!("Bearer {token}")),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]),
            body: Some(body),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(problem(&response));
        }
        serde_json::from_slice(&response.body).map_err(|_| OctaPassError::InvalidResponse)
    }

    /// The server's own say on whether it has an HIBP key. False when it can't be read.
    pub fn email_breach_checks(&self, server_url: &str) -> bool {
        let answer = self.send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{}/v1/server-info", server_url.trim_end_matches('/')),
            headers: HashMap::from([("accept".to_owned(), "application/json".to_owned())]),
            body: None,
        });
        answer
            .ok()
            .filter(|response| (200..300).contains(&response.status))
            .and_then(|response| {
                serde_json::from_slice::<octapass_api::ServerInfo>(&response.body).ok()
            })
            .is_some_and(|info| info.email_breach_checks)
    }

    /// An authenticated POST of a JSON body whose answer has no body worth reading.
    pub fn post_json(
        &self,
        url: String,
        token: &str,
        body: &impl serde::Serialize,
    ) -> std::result::Result<(), OctaPassError> {
        let body = serde_json::to_vec(body).map_err(|_| OctaPassError::InvalidResponse)?;
        let response = self.send(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: HashMap::from([
                ("authorization".to_owned(), format!("Bearer {token}")),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]),
            body: Some(body),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(problem(&response));
        }
        Ok(())
    }

    /// An authenticated call of any method with a JSON body and no answer worth reading.
    pub fn send_json(
        &self,
        method: HttpMethod,
        url: String,
        token: &str,
        body: &impl serde::Serialize,
    ) -> std::result::Result<(), OctaPassError> {
        let body = serde_json::to_vec(body).map_err(|_| OctaPassError::InvalidResponse)?;
        let response = self.send(HttpRequest {
            method,
            url,
            headers: HashMap::from([
                ("authorization".to_owned(), format!("Bearer {token}")),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]),
            body: Some(body),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(problem(&response));
        }
        Ok(())
    }

    /// Uploads a file from disk as the raw request body (an encrypted attachment).
    pub fn upload_file(
        &self,
        url: String,
        token: &str,
        path: &Path,
    ) -> std::result::Result<(), OctaPassError> {
        let network = |error: &dyn std::fmt::Display| OctaPassError::Network {
            reason: error.to_string(),
        };
        let file = std::fs::File::open(path).map_err(|error| network(&error))?;
        let len = file.metadata().map_err(|error| network(&error))?.len();
        let request = ureq::http::Request::builder()
            .method("PUT")
            .uri(&url)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .header("content-length", len)
            .body(file)
            .map_err(|error| network(&error))?;
        let response = self
            .agent
            .run(self.transfer(request))
            .map_err(|error| network(&error))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(());
        }
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|error| network(&error))?;
        Err(problem(&HttpResponse { status, body }))
    }

    /// A raw response body to read in pieces (an encrypted attachment).
    pub fn download(
        &self,
        url: String,
        token: &str,
    ) -> std::result::Result<impl Read + use<>, OctaPassError> {
        let network = |error: &dyn std::fmt::Display| OctaPassError::Network {
            reason: error.to_string(),
        };
        let request = ureq::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .map_err(|error| network(&error))?;
        let response = self
            .agent
            .run(self.transfer(request))
            .map_err(|error| network(&error))?;
        let status = response.status().as_u16();
        let body = response.into_body();
        if !(200..300).contains(&status) {
            let body = body
                .into_with_config()
                .limit(MAX_BODY)
                .read_to_vec()
                .map_err(|error| network(&error))?;
            return Err(problem(&HttpResponse { status, body }));
        }
        Ok(body.into_with_config().limit(u64::MAX).reader())
    }

    /// A request with the attachment timeouts instead of the usual 30 seconds.
    fn transfer<B: ureq::AsSendBody>(
        &self,
        request: ureq::http::Request<B>,
    ) -> ureq::http::Request<B> {
        self.agent
            .configure_request(request)
            .timeout_global(Some(TRANSFER_TIMEOUT))
            .timeout_per_read(Some(STALL_TIMEOUT))
            .timeout_per_write(Some(STALL_TIMEOUT))
            .build()
    }

    /// One Pwned Passwords range, padded (`Add-Padding`) so its size says nothing about the
    /// prefix.
    pub fn pwned_range(&self, base: &str, prefix: &str) -> Result<String> {
        let response = self
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: format!("{}/range/{prefix}", base.trim_end_matches('/')),
                headers: HashMap::from([("add-padding".to_owned(), "true".to_owned())]),
                body: None,
            })
            .map_err(VaultError::from)?;
        if response.status != 200 {
            return Err(VaultError::new(
                ErrorCode::ServerUnreachable,
                format!("Pwned Passwords answered {}", response.status),
            ));
        }
        String::from_utf8(response.body).map_err(|_| ErrorCode::ServerError.into())
    }
}

impl Http {
    /// The server's public icon endpoint: no token. Network failures come back as status 0.
    pub fn site_icon(&self, url: &str) -> crate::site_icons::IconResponse {
        let Ok(request) = ureq::http::Request::builder()
            .method("GET")
            .uri(url)
            .header("accept", "image/png")
            .body(())
        else {
            return Default::default();
        };
        let Ok(response) = self.agent.run(request) else {
            return Default::default();
        };
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (status, content_type, retry_after) = (
            response.status().as_u16(),
            header("content-type").unwrap_or_default(),
            header("retry-after"),
        );
        // Icons are at most 128 px PNGs; the server refuses larger sources.
        match response
            .into_body()
            .with_config()
            .limit(256 * 1024)
            .read_to_vec()
        {
            Ok(body) => crate::site_icons::IconResponse {
                status,
                content_type,
                retry_after,
                body,
            },
            Err(_) => Default::default(),
        }
    }
}

impl HttpClient for Http {
    fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, OctaPassError> {
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        };
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let network = |error: &dyn std::fmt::Display| OctaPassError::Network {
            reason: error.to_string(),
        };
        let built = builder
            .body(request.body.unwrap_or_default())
            .map_err(|error| network(&error))?;
        let response = self.agent.run(built).map_err(|error| network(&error))?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|error| network(&error))?;
        Ok(HttpResponse { status, body })
    }
}

/// The FFI's mapping for the calls made here: the last segment of the problem type.
fn problem(response: &HttpResponse) -> OctaPassError {
    let problem: Option<octapass_api::Problem> = serde_json::from_slice(&response.body).ok();
    let name = problem
        .as_ref()
        .and_then(|problem| problem.problem_type.rsplit('/').next())
        .unwrap_or_default();
    match name {
        "unauthorized" => OctaPassError::Unauthorized,
        "account-deleted" => OctaPassError::AccountDeleted,
        name => OctaPassError::Server {
            status: response.status,
            problem_type: name.to_owned(),
            detail: problem.and_then(|problem| problem.detail),
        },
    }
}
