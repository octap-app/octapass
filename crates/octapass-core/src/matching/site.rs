//! Parsing a website address into what matching compares: the host in ASCII (IDNs as punycode)
//! and its registrable domain from the Public Suffix List.

use url::{Host, Url};

use crate::error::{Error, Result};

/// A parsed `http`/`https` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub url: Url,
    /// Lower case, IDNs as punycode, without a trailing dot. IPv6 addresses keep their brackets.
    pub host: String,
    /// The registrable domain (eTLD+1), e.g. `google.com` for `accounts.google.com`. `None` for IP
    /// addresses, single-label hosts and hosts that are themselves public suffixes (`github.io`).
    pub domain: Option<String>,
    /// False when the scheme was missing and `https` was assumed.
    pub explicit_scheme: bool,
}

impl Site {
    /// Parses an address as people save it: `https://github.com/login`, `github.com`, or
    /// `localhost:8080`. Only `http` and `https` are websites; anything else is [`Error::InvalidUrl`].
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let explicit_scheme = match scheme_end(text) {
            Some(end) if text[end..].starts_with("://") => true,
            // `localhost:8080`: a host and port, not a scheme.
            Some(end) if text[end + 1..].starts_with(|c: char| c.is_ascii_digit()) => false,
            // `mailto:`, `tel:`, `javascript:` …
            Some(_) => return Err(Error::InvalidUrl),
            None => false,
        };
        let url = if explicit_scheme {
            Url::parse(text)
        } else {
            Url::parse(&format!("https://{text}"))
        }
        .map_err(|_| Error::InvalidUrl)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::InvalidUrl);
        }
        let host = match url.host().ok_or(Error::InvalidUrl)? {
            Host::Domain(domain) => domain.trim_end_matches('.').to_string(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => format!("[{ip}]"),
        };
        if host.is_empty() {
            return Err(Error::InvalidUrl);
        }
        let domain = match url.host() {
            Some(Host::Domain(_)) => registrable_domain(&host),
            _ => None,
        };
        Ok(Self {
            url,
            host,
            domain,
            explicit_scheme,
        })
    }

    pub fn is_https(&self) -> bool {
        self.url.scheme() == "https"
    }

    /// The port, or the scheme's default.
    pub fn port(&self) -> Option<u16> {
        self.url.port_or_known_default()
    }

    /// Path plus `?query`, the part a "starts with" rule compares.
    pub fn path_and_query(&self) -> String {
        match self.url.query() {
            Some(query) => format!("{}?{query}", self.url.path()),
            None => self.url.path().to_string(),
        }
    }

    /// The host for display and titles: IDNs in Unicode, without a leading `www.`.
    pub fn display_host(&self) -> String {
        let host = self.host.strip_prefix("www.").unwrap_or(&self.host);
        match idna::domain_to_unicode(host) {
            (unicode, Ok(())) => unicode,
            _ => host.to_string(),
        }
    }
}

/// The index of the `:` after a leading `scheme`-shaped word, if there is one.
fn scheme_end(text: &str) -> Option<usize> {
    let end = text.find(':')?;
    let mut chars = text[..end].chars();
    (chars.next()?.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
    .then_some(end)
}

/// The registrable domain of an ASCII host, from the embedded Public Suffix List snapshot
/// (both its ICANN and private sections, so `alice.github.io` and `bob.github.io` differ).
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !host.contains('.') {
        return None;
    }
    super::psl::domain(&host).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(text: &str) -> Option<String> {
        Site::parse(text).unwrap().domain
    }

    #[test]
    fn registrable_domains_follow_the_public_suffix_list() {
        assert_eq!(
            domain("https://accounts.google.com/x").as_deref(),
            Some("google.com")
        );
        assert_eq!(domain("www.bbc.co.uk").as_deref(), Some("bbc.co.uk"));
        assert_eq!(
            domain("https://alice.github.io").as_deref(),
            Some("alice.github.io")
        );
        assert_eq!(domain("https://github.io"), None);
        assert_eq!(domain("https://co.uk"), None);
        assert_eq!(domain("http://localhost:8080"), None);
        assert_eq!(domain("http://192.168.1.1/admin"), None);
        assert_eq!(domain("https://[::1]:8443"), None);
        assert_eq!(
            domain("https://Example.COM.").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn hosts_are_ascii_lowercase_and_idns_are_punycode() {
        let site = Site::parse("https://BÜCHER.de/").unwrap();
        assert_eq!(site.host, "xn--bcher-kva.de");
        assert_eq!(site.domain.as_deref(), Some("xn--bcher-kva.de"));
        assert_eq!(
            Site::parse("https://xn--bcher-kva.de").unwrap().host,
            site.host
        );
        // A Cyrillic "а" makes a different domain, not paypal.com.
        let homograph = Site::parse("https://pаypal.com").unwrap();
        assert_ne!(homograph.domain.as_deref(), Some("paypal.com"));
        assert!(homograph.host.starts_with("xn--"));
    }

    #[test]
    fn missing_schemes_default_to_https() {
        let site = Site::parse(" github.com/login ").unwrap();
        assert!(!site.explicit_scheme && site.is_https());
        assert_eq!(site.path_and_query(), "/login");
        let local = Site::parse("localhost:8080").unwrap();
        assert_eq!(
            (local.host.as_str(), local.port()),
            ("localhost", Some(8080))
        );
        assert!(Site::parse("http://example.com").unwrap().explicit_scheme);
    }

    #[test]
    fn user_info_does_not_fool_the_host() {
        let site = Site::parse("https://paypal.com@evil.io/login").unwrap();
        assert_eq!(site.host, "evil.io");
    }

    #[test]
    fn only_websites_parse() {
        for bad in [
            "",
            "mailto:a@b.c",
            "ftp://example.com",
            "chrome://settings",
            "file:///etc/passwd",
            "androidapp://com.example",
            "https://",
            "http://exa mple.com",
        ] {
            assert_eq!(Site::parse(bad).unwrap_err(), Error::InvalidUrl, "{bad}");
        }
    }

    #[test]
    fn display_host_drops_www() {
        assert_eq!(
            Site::parse("https://www.example.com")
                .unwrap()
                .display_host(),
            "example.com"
        );
    }
}
