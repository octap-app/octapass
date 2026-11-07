//! Fetches a JWKS: the one thing the JWT tool needs from the network, and only when pointed at a URL.

use std::time::Duration;

use serde_json::Value;

use crate::{NetError, Result, check_url};

const MAX_BODY: u64 = 1 << 20;

/// A shared agent for this crate's HTTP: short timeouts, status codes as values, no cookies.
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(concat!("openpass/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

/// The JWKS at `url`, as text. Fails unless it has a `keys` array.
pub fn jwks(url: &str) -> Result<String> {
    check_url(url)?;
    let mut response = agent()
        .get(url)
        .call()
        .map_err(|error| NetError::Network(format!("Can't fetch {url}: {error}")))?;
    if !response.status().is_success() {
        return Err(NetError::Network(format!(
            "{url} answered {}.",
            response.status()
        )));
    }
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_string()
        .map_err(|error| NetError::Network(format!("Can't read {url}: {error}")))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| NetError::Network(format!("{url} didn't return JSON.")))?;
    if value.get("keys").and_then(Value::as_array).is_none() {
        return Err(NetError::Network(format!("{url} isn't a JWKS.")));
    }
    Ok(text)
}
