//! JSON calls to the sync API for what the mobile vault doesn't do itself: sharing, families,
//! share links, emergency access, devices and the security log (`docs/developers/sync-api.md`).
//! Certificates are checked with the platform's verifier, as in the vault crate. The access
//! token comes from the vault, which refreshes it.

use std::io::Read;
use std::time::Duration;

use octapass_api::Problem;
use octapass_ffi::OctaPassError;
use octapass_mobile_vault::vault::Access;
use serde::Serialize;
use serde::de::DeserializeOwned;
use ureq::tls::{RootCerts, TlsConfig};

use crate::error::{ErrorCode, Result, VaultError};

/// Answers are a few hundred kilobytes at most (an emergency sync page).
const MAX_BODY: u64 = 64 << 20;

pub(crate) struct Api {
    agent: ureq::Agent,
}

#[derive(Clone, Copy)]
pub(crate) enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

fn network(error: &dyn std::fmt::Display) -> OctaPassError {
    OctaPassError::Network {
        reason: error.to_string(),
    }
}

/// The problem's type, as the FFI reports the calls it makes: its last path segment.
fn problem(status: u16, body: &[u8]) -> OctaPassError {
    let problem: Option<Problem> = serde_json::from_slice(body).ok();
    let name = problem
        .as_ref()
        .and_then(|problem| problem.problem_type.rsplit('/').next())
        .unwrap_or_default();
    match name {
        "unauthorized" => OctaPassError::Unauthorized,
        "account-deleted" => OctaPassError::AccountDeleted,
        name => OctaPassError::Server {
            status,
            problem_type: name.to_owned(),
            detail: problem.and_then(|problem| problem.detail),
        },
    }
}

/// `https`, or `http` to this device, for development.
pub(crate) fn secure_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match parsed.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return None,
    }
    Some(parsed.origin().ascii_serialization())
}

impl Api {
    pub fn new(user_agent: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(0)
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

    fn send(
        &self,
        method: Method,
        url: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> std::result::Result<ureq::http::Response<ureq::Body>, OctaPassError> {
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url)
            .header("accept", "application/json, application/problem+json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = match body {
            Some(body) => {
                let request = builder
                    .header("content-type", "application/json")
                    .body(body)
                    .map_err(|error| network(&error))?;
                self.agent.run(request)
            }
            None => {
                let request = builder.body(()).map_err(|error| network(&error))?;
                self.agent.run(request)
            }
        };
        response.map_err(|error| network(&error))
    }

    /// One call. `token` is `None` for the public ones (a share link). An empty answer reads as
    /// JSON `null`, which is what `()` expects.
    pub fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        token: Option<&str>,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> std::result::Result<T, OctaPassError> {
        self.json_with(method, url, token, &[], body)
    }

    /// `json` with more headers (a reauth token).
    pub fn json_with<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> std::result::Result<T, OctaPassError> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| OctaPassError::InvalidResponse)?;
        let response = self.send(method, url, token, headers, body)?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|error| network(&error))?;
        if !(200..300).contains(&status) {
            return Err(problem(status, &bytes));
        }
        let bytes = if bytes.is_empty() {
            b"null".to_vec()
        } else {
            bytes
        };
        serde_json::from_slice(&bytes).map_err(|_| OctaPassError::InvalidResponse)
    }

    /// A raw answer to read in pieces (one of an emergency grantor's encrypted files).
    pub fn download(
        &self,
        url: &str,
        token: &str,
    ) -> std::result::Result<impl Read + use<>, OctaPassError> {
        let response = self.send(Method::Get, url, Some(token), &[], None)?;
        let status = response.status().as_u16();
        let body = response.into_body();
        if !(200..300).contains(&status) {
            let bytes = body
                .into_with_config()
                .limit(MAX_BODY)
                .read_to_vec()
                .map_err(|error| network(&error))?;
            return Err(problem(status, &bytes));
        }
        Ok(body.into_with_config().limit(u64::MAX).reader())
    }
}

/// The signed-in account's server, through the vault's access token.
pub(crate) struct Server<'a> {
    pub api: &'a Api,
    pub access: &'a Access<'a>,
}

impl Server<'_> {
    pub fn url(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.access.server_url(),
            path.trim_start_matches('/')
        )
    }

    /// The call's answer, or the server's problem as it stands: the vault would turn problems
    /// it doesn't know (`already-exists`, `family-full`) into `unexpected`.
    fn exchange<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<std::result::Result<T, OctaPassError>> {
        self.exchange_with(method, path, &[], body)
    }

    fn exchange_with<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<std::result::Result<T, OctaPassError>> {
        let url = self.url(path);
        Ok(self.access.authorized(|token| {
            match self.api.json_with(method, &url, Some(token), headers, body) {
                Err(error @ OctaPassError::Server { .. }) => Ok(Err(error)),
                other => other.map(Ok),
            }
        })?)
    }

    pub fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<T> {
        Ok(self.exchange(method, path, body)??)
    }

    /// Like `call`, but the server's `problem` (say `vault-changed`) comes back as `Ok(Err)`
    /// for the caller to handle, instead of an error.
    pub fn call_unless<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
        problem: &str,
    ) -> Result<std::result::Result<T, Refused>> {
        match self.exchange(method, path, body)? {
            Ok(answer) => Ok(Ok(answer)),
            Err(OctaPassError::Server { problem_type, .. }) if problem_type == problem => {
                Ok(Err(Refused))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// A call that needs a reauth token (`Access::reauth`), such as deleting an organisation.
    pub fn call_reauthed<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        reauth_token: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<T> {
        let headers = [(octapass_api::REAUTH_TOKEN_HEADER, reauth_token)];
        Ok(self.exchange_with(method, path, &headers, body)??)
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.call(Method::Get, path, None::<&()>)
    }

    pub fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &(impl Serialize + ?Sized),
    ) -> Result<T> {
        self.call(Method::Post, path, Some(body))
    }

    pub fn delete(&self, path: &str) -> Result<()> {
        self.call(Method::Delete, path, None::<&()>)
    }
}

/// A path segment from an id the server or the UI gave.
pub(crate) fn segment(id: &str) -> String {
    url::form_urlencoded::byte_serialize(id.as_bytes()).collect()
}

/// The server refused a call with the problem the caller expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refused;

pub(crate) fn not_found(error: &VaultError) -> bool {
    error.code() == ErrorCode::NotFound
}
