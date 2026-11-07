//! Masked email providers (plan 06, Phase A). The apps' web view can't reach the providers that
//! don't answer CORS, so the apps make those calls natively, but only to the providers' API hosts.
//! The list matches `PROVIDER_API_HOSTS` in `packages/vault-client/src/maskedEmail/providers.ts`.

use url::Url;

pub const PROVIDER_API_HOSTS: [&str; 6] = [
    "app.simplelogin.io",
    "app.addy.io",
    "relay.firefox.com",
    "api.fastmail.com",
    "quack.duckduckgo.com",
    "api.forwardemail.net",
];

/// HTTPS on the default port to one of the providers' API hosts, with no user name or password in
/// the URL. Self-hosted servers go through the web view, under the browser's rules.
pub fn is_provider_api(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .is_some_and(|host| PROVIDER_API_HOSTS.contains(&host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_providers_apis_over_https() {
        for url in [
            "https://app.simplelogin.io/api/alias/random/new?hostname=a.com",
            "https://api.fastmail.com/jmap/api/",
            "https://quack.duckduckgo.com/api/email/addresses",
            "https://APP.ADDY.IO/api/v1/aliases",
        ] {
            assert!(is_provider_api(url), "{url}");
        }
        for url in [
            "http://app.simplelogin.io/api",
            "https://app.simplelogin.io:8443/api",
            "https://user:pw@app.addy.io/api",
            "https://app.simplelogin.io.evil.example/api",
            "https://evil.example/?u=https://app.addy.io",
            "https://localhost/api",
            "not a url",
        ] {
            assert!(!is_provider_api(url), "{url}");
        }
    }
}
