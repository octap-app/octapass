//! Fetches a site's icon from the site itself: the home page's icon links, then
//! `/apple-touch-icon.png` and `/favicon.ico`. Every request, redirects included, goes only to
//! public addresses on the default ports, within strict time and size limits.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use reqwest::header::{ACCEPT, LOCATION};
use reqwest::redirect::Policy;
use url::Url;

use super::html;
use super::image;
use super::net::{PublicResolver, TestNetwork};

/// Time and size limits. Tests shorten the timeouts.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub connect: Duration,
    /// One request, from sending it to the last byte.
    pub request: Duration,
    /// Everything for one site.
    pub total: Duration,
    /// The home page is read up to here; icon links are in its head.
    pub html_bytes: usize,
    /// Larger icons are refused.
    pub image_bytes: usize,
    pub redirects: usize,
    /// Icon links tried before the fallbacks.
    pub candidates: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(3),
            request: Duration::from_secs(5),
            total: Duration::from_secs(15),
            html_bytes: 512 * 1024,
            image_bytes: 256 * 1024,
            redirects: 3,
            candidates: 4,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("too many redirects")]
    Redirects,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("larger than allowed")]
    TooLarge,
    #[error("{0}")]
    Network(#[from] reqwest::Error),
}

pub struct Fetcher {
    client: reqwest::Client,
    resolver: Arc<PublicResolver>,
    limits: Limits,
}

const USER_AGENT: &str = concat!(
    "OctaPassIcons/",
    env!("CARGO_PKG_VERSION"),
    " (website icons for an Octa Pass server)"
);

impl Fetcher {
    pub fn new(test: Option<Arc<TestNetwork>>, limits: Limits) -> Self {
        let resolver = Arc::new(PublicResolver::new(test));
        let client = reqwest::Client::builder()
            // Redirects are followed by hand, so each hop is checked.
            .redirect(Policy::none())
            // A proxy would do its own DNS and skip the address checks.
            .no_proxy()
            .dns_resolver(resolver.clone())
            .connect_timeout(limits.connect)
            .timeout(limits.request)
            .user_agent(USER_AGENT)
            .referer(false)
            .pool_max_idle_per_host(1)
            .build()
            .expect("the icon HTTP client builds");
        Self {
            client,
            resolver,
            limits,
        }
    }

    /// The icon for `domain` as a PNG, or `None` when the site has no usable one.
    pub async fn icon(&self, domain: &str) -> Option<Vec<u8>> {
        match tokio::time::timeout(self.limits.total, self.find(domain)).await {
            Ok(icon) => icon,
            Err(_) => {
                tracing::debug!("icon fetch timed out");
                None
            }
        }
    }

    async fn find(&self, domain: &str) -> Option<Vec<u8>> {
        let (page_url, html) = self.home_page(domain).await;
        let mut tried = vec![];
        if let (Some(page_url), Some(html)) = (&page_url, html) {
            let (base, candidates) = html::icon_links(&String::from_utf8_lossy(&html));
            let base = base
                .and_then(|base| page_url.join(&base).ok())
                .unwrap_or_else(|| page_url.clone());
            for candidate in html::rank(candidates)
                .into_iter()
                .take(self.limits.candidates)
            {
                if let Some(png) = self.candidate(&base, &candidate.href, &mut tried).await {
                    return Some(png);
                }
            }
        }
        let origin = page_url
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_else(|| format!("https://{domain}"));
        for path in ["/apple-touch-icon.png", "/favicon.ico"] {
            if let Some(png) = self
                .candidate(&Url::parse(&origin).ok()?, path, &mut tried)
                .await
            {
                return Some(png);
            }
        }
        None
    }

    /// The home page over HTTPS, else plain HTTP; then the same for `www.`. The URL is where the
    /// redirects ended, even when the page itself failed (an icon may still be there).
    async fn home_page(&self, domain: &str) -> (Option<Url>, Option<Vec<u8>>) {
        let mut hosts = vec![domain.to_owned()];
        if !domain.starts_with("www.") {
            hosts.push(format!("www.{domain}"));
        }
        for host in hosts {
            for scheme in ["https", "http"] {
                let Ok(url) = Url::parse(&format!("{scheme}://{host}/")) else {
                    return (None, None);
                };
                match self.get(url.clone(), self.limits.html_bytes, true).await {
                    Ok((url, body)) => return (Some(url), Some(body)),
                    // The site answered: no need to try other ways in.
                    Err(FetchError::Status(_)) => return (Some(url), None),
                    Err(error) => tracing::debug!(%error, "home page unavailable"),
                }
            }
        }
        (None, None)
    }

    async fn candidate(&self, base: &Url, href: &str, tried: &mut Vec<Url>) -> Option<Vec<u8>> {
        if href.len() > 4096 {
            return None;
        }
        if let Some(data) = href.strip_prefix("data:") {
            return self.data_url(data);
        }
        let url = base.join(href).ok()?;
        if tried.contains(&url) {
            return None;
        }
        tried.push(url.clone());
        match self.get(url, self.limits.image_bytes, false).await {
            Ok((_, bytes)) => image::normalise(&bytes),
            Err(error) => {
                tracing::debug!(%error, "icon unavailable");
                None
            }
        }
    }

    /// An icon inlined in the page as `data:image/…;base64,…`.
    fn data_url(&self, data: &str) -> Option<Vec<u8>> {
        let (meta, payload) = data.split_once(',')?;
        if !meta.to_ascii_lowercase().ends_with(";base64")
            || payload.len() > self.limits.image_bytes * 4 / 3 + 4
        {
            return None;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload.trim())
            .ok()?;
        image::normalise(&bytes)
    }

    /// GETs `url`, following up to the redirect limit. Bodies over `cap` fail, or with
    /// `truncate` are cut there.
    async fn get(
        &self,
        mut url: Url,
        cap: usize,
        truncate: bool,
    ) -> Result<(Url, Vec<u8>), FetchError> {
        for _ in 0..=self.limits.redirects {
            self.check(&url)?;
            let accept = if truncate { "text/html" } else { "image/*" };
            let mut response = self
                .client
                .get(url.clone())
                .header(ACCEPT, accept)
                .send()
                .await?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(FetchError::Status(status.as_u16()))?;
                url = url
                    .join(location)
                    .map_err(|_| FetchError::Refused("bad redirect"))?;
                continue;
            }
            if !status.is_success() {
                return Err(FetchError::Status(status.as_u16()));
            }
            if !truncate
                && response
                    .content_length()
                    .is_some_and(|len| len > cap as u64)
            {
                return Err(FetchError::TooLarge);
            }
            // Counted after decompression, so a gzip bomb stops at the cap too.
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                body.extend_from_slice(&chunk);
                if body.len() > cap {
                    if !truncate {
                        return Err(FetchError::TooLarge);
                    }
                    body.truncate(cap);
                    break;
                }
            }
            return Ok((url, body));
        }
        Err(FetchError::Redirects)
    }

    /// Only http(s) on the default port, without credentials, to a name or a public address.
    /// Names are checked when they resolve (`PublicResolver`).
    fn check(&self, url: &Url) -> Result<(), FetchError> {
        if !matches!(url.scheme(), "https" | "http") {
            return Err(FetchError::Refused("not http or https"));
        }
        if url.port().is_some() {
            return Err(FetchError::Refused("not the default port"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchError::Refused("credentials in the URL"));
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let ip = match url.host() {
            Some(url::Host::Ipv4(ip)) => std::net::IpAddr::V4(ip),
            Some(url::Host::Ipv6(ip)) => std::net::IpAddr::V6(ip),
            Some(url::Host::Domain(_)) => return Ok(()),
            None => return Err(FetchError::Refused("no host")),
        };
        if self.resolver.allows((ip, port).into()) {
            Ok(())
        } else {
            Err(FetchError::Refused("not a public address"))
        }
    }
}
