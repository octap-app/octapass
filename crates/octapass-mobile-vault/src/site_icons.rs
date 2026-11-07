//! Website icons for the web view, whose content security policy only lets it talk to the app:
//! a plain GET of the server's public icon endpoint, with no token and no cookies. The web view
//! reads the answer and keeps the icon in its own cache (`siteIcons.ts`).

use serde::Serialize;

use crate::error::{ErrorCode, Result};
use crate::vault::Vault;

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
    let server = server_url.trim();
    let (scheme, rest) = server
        .split_once("://")
        .ok_or(ErrorCode::InsecureServerUrl)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    let secure = match scheme {
        "https" => !authority.is_empty(),
        "http" => matches!(host, "localhost" | "127.0.0.1" | "[::1]"),
        _ => false,
    };
    if !secure || authority.contains('@') {
        return Err(ErrorCode::InsecureServerUrl.into());
    }
    let plain = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if !plain {
        return Err(ErrorCode::NotFound.into());
    }
    Ok(format!("{scheme}://{authority}/v1/icons/{domain}"))
}

impl Vault {
    pub fn site_icon(&self, server_url: &str, domain: &str) -> Result<IconResponse> {
        Ok(self.http.site_icon(&icon_url(server_url, domain)?))
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
        assert!(icon_url("https://user@vault.example.org", "bank.com").is_err());
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
