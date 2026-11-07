//! Website icons for the web view, whose content security policy only lets it talk to the app:
//! a plain GET of the server's public icon endpoint, with no token and no cookies. The web view
//! reads the answer and keeps the icon in its own cache (`siteIcons.ts`).

use std::time::Duration;

use serde::Serialize;

use crate::error::{ErrorCode, Result};
use crate::vault::{Vault, normalize_server_url};

/// Icons are at most 128 px PNGs; the server refuses larger sources.
const MAX_BODY: usize = 256 * 1024;

/// The server's answer, for `iconAnswer` in the web view. Status 0: the server couldn't be reached.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IconResponse {
    pub status: u16,
    pub content_type: String,
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// `{server}/v1/icons/{domain}`, for an HTTPS server (or this computer) and a plain domain name.
pub fn icon_url(server_url: &str, domain: &str) -> Result<String> {
    let origin = normalize_server_url(server_url)?;
    let plain = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if !plain {
        return Err(ErrorCode::NotFound.into());
    }
    Ok(format!("{origin}/v1/icons/{domain}"))
}

impl Vault {
    pub async fn site_icon(&self, server_url: &str, domain: &str) -> Result<IconResponse> {
        let url = icon_url(server_url, domain)?;
        let Ok(response) = self
            .http
            .get(url)
            .header("accept", "image/png")
            .timeout(Duration::from_secs(20))
            .send()
            .await
        else {
            return Ok(IconResponse::default());
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
        match response.bytes().await {
            Ok(body) if body.len() <= MAX_BODY => Ok(IconResponse {
                status,
                content_type,
                retry_after,
                body: body.to_vec(),
            }),
            _ => Ok(IconResponse::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::icon_url;

    #[test]
    fn only_plain_domains_on_the_server() {
        assert_eq!(
            icon_url("https://vault.example.org/app", "bank.com").unwrap(),
            "https://vault.example.org/v1/icons/bank.com"
        );
        assert_eq!(
            icon_url("http://localhost:8080", "bbc.co.uk").unwrap(),
            "http://localhost:8080/v1/icons/bbc.co.uk"
        );
        assert!(icon_url("http://vault.example.org", "bank.com").is_err());
        for domain in [
            "",
            "localhost",
            "bank.com/../x",
            "a b.com",
            "Bank.com",
            "bank.com?x",
        ] {
            assert!(
                icon_url("https://vault.example.org", domain).is_err(),
                "{domain}"
            );
        }
    }
}
