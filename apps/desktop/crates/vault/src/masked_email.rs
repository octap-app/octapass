//! Masked email calls the web view can't make: Firefox Relay and DuckDuckGo don't answer CORS.
//! Only HTTPS to the providers' own API hosts; the request is the UI's, the token comes with it.

use std::collections::HashMap;
use std::time::Duration;

use octapass_core::tools::masked_email::is_provider_api;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, VaultError};
use crate::vault::Vault;

/// Provider answers are a few hundred bytes.
const MAX_BODY: usize = 1 << 20;

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
    pub async fn masked_email_request(&self, request: ProviderRequest) -> Result<ProviderResponse> {
        if !is_provider_api(&request.url) {
            return Err(VaultError::unexpected("Not a masked email provider's API"));
        }
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            _ => return Err(VaultError::unexpected("Unsupported method")),
        };
        let network = |error: reqwest::Error| {
            VaultError::new(
                ErrorCode::ServerUnreachable,
                error.without_url().to_string(),
            )
        };
        // Its own client: no redirects, so a custom auth header (SimpleLogin's) can't follow one
        // to another host.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(network)?;
        let mut builder = client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder.send().await.map_err(network)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect();
        let bytes = response.bytes().await.map_err(network)?;
        if bytes.len() > MAX_BODY {
            return Err(VaultError::unexpected("The provider's answer is too large"));
        }
        Ok(ProviderResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }
}
