//! The sync API (plan 11) over an HTTP client the app implements natively (`URLSession`,
//! OkHttp), so TLS, proxies and certificate handling stay the platform's.

use std::collections::HashMap;
use std::sync::Arc;

use octapass_api::Problem;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::error::{OctaPassError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Implemented by the app. `send` returns every response the server gave, whatever its status,
/// and throws (`OctaPassError.Network`) only when there is none. It's called on the thread that
/// called into the core, never the main thread, so it may block.
#[uniffi::export(with_foreign)]
pub trait HttpClient: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse>;
}

/// JSON calls to one server.
#[derive(Clone)]
pub(crate) struct Api {
    base: Url,
    http: Arc<dyn HttpClient>,
}

/// A response the caller handles itself instead of turning it into an error.
pub(crate) enum Reply<T> {
    Ok(T),
    Problem(u16, Box<Problem>),
}

impl Api {
    /// `https` only, except `http://localhost` and loopback addresses for development.
    pub fn new(base_url: &str, http: Arc<dyn HttpClient>) -> Result<Self> {
        let mut base = Url::parse(base_url.trim()).map_err(|_| OctaPassError::InvalidUrl)?;
        let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(base.scheme() == "https" || base.scheme() == "http" && local)
            || base.cannot_be_a_base()
            || base.query().is_some()
        {
            return Err(OctaPassError::InvalidUrl);
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        Ok(Self { base, http })
    }

    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str, token: Option<&str>) -> Result<T> {
        self.call(HttpMethod::Get, path, token, &[], None::<&()>)?
            .into_result()
    }

    pub fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &impl Serialize,
    ) -> Result<T> {
        self.call(HttpMethod::Post, path, token, &[], Some(body))?
            .into_result()
    }

    /// Sends one request. 2xx bodies are parsed as `T` (`()` accepts an empty body); problems are
    /// returned for the caller to map.
    pub fn call<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: Option<&impl Serialize>,
    ) -> Result<Reply<T>> {
        let url = self
            .base
            .join(path)
            .map_err(|_| OctaPassError::InvalidUrl)?;
        let mut all_headers = HashMap::from([("accept".to_owned(), "application/json".to_owned())]);
        if let Some(token) = token {
            all_headers.insert("authorization".into(), format!("Bearer {token}"));
        }
        let body = body
            .map(|body| {
                all_headers.insert("content-type".into(), "application/json".into());
                serde_json::to_vec(body).map_err(|_| OctaPassError::InvalidResponse)
            })
            .transpose()?;
        for (name, value) in headers {
            all_headers.insert((*name).to_owned(), value.clone());
        }
        let response = self.http.send(HttpRequest {
            method,
            url: url.into(),
            headers: all_headers,
            body,
        })?;
        if (200..300).contains(&response.status) {
            let body: &[u8] = match response.body.as_slice() {
                b"" => b"null",
                body => body,
            };
            return serde_json::from_slice(body)
                .map(Reply::Ok)
                .map_err(|_| OctaPassError::InvalidResponse);
        }
        Ok(Reply::Problem(
            response.status,
            Box::new(
                serde_json::from_slice(&response.body).unwrap_or_else(|_| Problem {
                    problem_type: String::new(),
                    title: String::new(),
                    status: response.status,
                    detail: None,
                    current: None,
                    second_factor: None,
                    sso: None,
                    vault_ids: Vec::new(),
                }),
            ),
        ))
    }
}

impl<T> Reply<T> {
    pub fn into_result(self) -> Result<T> {
        match self {
            Reply::Ok(value) => Ok(value),
            Reply::Problem(status, problem) => Err(problem_error(status, *problem)),
        }
    }
}

/// The last segment of a problem `type` URI (`…/problems/rate-limited` → `rate-limited`), so
/// clients don't depend on the server's domain.
pub(crate) fn problem_name(problem: &Problem) -> &str {
    problem.problem_type.rsplit('/').next().unwrap_or_default()
}

fn problem_error(status: u16, problem: Problem) -> OctaPassError {
    match problem_name(&problem) {
        "login-failed" => OctaPassError::LoginFailed,
        "unauthorized" => OctaPassError::Unauthorized,
        "account-deleted" => OctaPassError::AccountDeleted,
        "account-exists" => OctaPassError::AccountExists,
        "invalid-verification-code" => OctaPassError::InvalidVerificationCode,
        name => OctaPassError::Server {
            status,
            problem_type: name.to_owned(),
            detail: problem.detail,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Answers every request with one canned response and remembers the request.
    struct Canned {
        response: HttpResponse,
        seen: Mutex<Option<HttpRequest>>,
    }

    impl HttpClient for Canned {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
            *self.seen.lock().unwrap() = Some(request);
            Ok(self.response.clone())
        }
    }

    fn api(base: &str, status: u16, body: &str) -> (Api, Arc<Canned>) {
        let http = Arc::new(Canned {
            response: HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            },
            seen: Mutex::new(None),
        });
        (Api::new(base, http.clone()).unwrap(), http)
    }

    #[test]
    fn only_https_or_local_development_servers() {
        let (_, http) = api("https://example.com", 200, "");
        for good in [
            "https://vault.example.com",
            "https://example.com/octapass",
            "http://localhost:8080",
            "http://127.0.0.1:3000/",
        ] {
            assert!(Api::new(good, http.clone()).is_ok(), "{good}");
        }
        for bad in [
            "http://example.com",
            "ftp://example.com",
            "example.com",
            "https://example.com/?x=1",
            "mailto:a@example.com",
        ] {
            assert_eq!(
                Api::new(bad, http.clone()).err(),
                Some(OctaPassError::InvalidUrl),
                "{bad}"
            );
        }
    }

    #[test]
    fn requests_carry_json_and_the_token_under_the_base_path() {
        let (api, http) = api("https://example.com/octapass", 200, r#"{"revision":3}"#);
        let reply: octapass_api::RevisionResponse = api
            .post(
                "v1/auth/prelogin",
                Some("tok"),
                &serde_json::json!({ "a": 1 }),
            )
            .unwrap();
        assert_eq!(reply.revision, 3);
        let request = http.seen.lock().unwrap().take().unwrap();
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.url, "https://example.com/octapass/v1/auth/prelogin");
        assert_eq!(request.headers["authorization"], "Bearer tok");
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(request.body.unwrap(), br#"{"a":1}"#);
    }

    #[test]
    fn problems_map_to_typed_errors() {
        let problem = |name: &str, status: u16| {
            format!(
                r#"{{"type":"https://octap.app/problems/{name}","title":"t","status":{status},"detail":"d"}}"#
            )
        };
        let error = |status: u16, body: &str| {
            let (api, _) = api("https://example.com", status, body);
            api.get::<()>("v1/account", None).unwrap_err()
        };
        assert_eq!(
            error(401, &problem("account-deleted", 401)),
            OctaPassError::AccountDeleted
        );
        assert_eq!(
            error(401, &problem("unauthorized", 401)),
            OctaPassError::Unauthorized
        );
        assert_eq!(
            error(429, &problem("rate-limited", 429)),
            OctaPassError::Server {
                status: 429,
                problem_type: "rate-limited".into(),
                detail: Some("d".into())
            }
        );
        assert_eq!(
            error(502, "<html>bad gateway</html>"),
            OctaPassError::Server {
                status: 502,
                problem_type: String::new(),
                detail: None
            }
        );
    }

    #[test]
    fn a_2xx_that_isnt_json_is_an_invalid_response() {
        let (api, _) = api("https://example.com", 200, "<html>captive portal</html>");
        assert_eq!(
            api.get::<octapass_api::ServerInfo>("v1/server-info", None)
                .unwrap_err(),
            OctaPassError::InvalidResponse
        );
    }
}
