//! Masked email calls the web view can't make: Firefox Relay and DuckDuckGo don't answer CORS.
//! Only HTTPS to the providers' own API hosts; the request is the UI's, the token comes with it.

use std::collections::HashMap;
use std::time::Duration;

use octapass_core::tools::masked_email::is_provider_api;
use serde::{Deserialize, Serialize};
use ureq::tls::{RootCerts, TlsConfig};

use crate::error::{ErrorCode, Result, VaultError};
use crate::vault::Vault;

/// Provider answers are a few hundred bytes.
const MAX_BODY: u64 = 1 << 20;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderResponse {
    pub status: u16,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Vault {
    pub fn masked_email_request(&self, request: ProviderRequest) -> Result<ProviderResponse> {
        if !is_provider_api(&request.url) {
            return Err(VaultError::unexpected("Not a masked email provider's API"));
        }
        if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&request.method.as_str()) {
            return Err(VaultError::unexpected("Unsupported method"));
        }
        let network = |error: &dyn std::fmt::Display| {
            VaultError::new(ErrorCode::ServerUnreachable, error.to_string())
        };
        // Its own agent: no redirects, so a custom auth header (SimpleLogin's) can't follow one to
        // another host.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(0)
            .https_only(true)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        let mut builder = ureq::http::Request::builder()
            .method(request.method.as_str())
            .uri(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let built = builder
            .body(request.body.unwrap_or_default())
            .map_err(|error| network(&error))?;
        let response = agent.run(built).map_err(|error| network(&error))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect();
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(|error| network(&error))?;
        Ok(ProviderResponse {
            status,
            headers,
            body,
        })
    }
}
