//! The opt-in email breach proxy: asks Have I Been Pwned about one address for a signed-in client.
//!
//! Off unless `OCTAPASS_HIBP_API_KEY` is set. The address is used for the one outgoing request and
//! then dropped: it's never written to the database, the logs or a cache. It goes in the path of
//! the request to HIBP because that's the API, and in the body of the request to us so it stays out
//! of our own URLs and access logs.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use octapass_api::EmailBreach;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::config::Hibp;
use crate::error::{ApiError, ApiResult};

const USER_AGENT: &str = concat!("Octa Pass server/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest one request waits for its turn. Longer, and the client is told to come back.
const MAX_QUEUE: Duration = Duration::from_secs(15);
/// Far more than the largest answer: a few hundred breaches, about 300 bytes each.
const MAX_RESPONSE: usize = 4 << 20;

/// Spaces requests out for the whole server, because an HIBP key has one limit however many
/// accounts share it.
struct Pacer {
    interval: Duration,
    next: Mutex<Instant>,
}

impl Pacer {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next: Mutex::new(Instant::now()),
        }
    }

    /// Takes the next free slot and says how long to wait for it, or how long until asking again
    /// is worthwhile when the queue is full.
    fn reserve(&self, now: Instant) -> Result<Duration, Duration> {
        let mut next = self.next.lock().expect("pacer lock poisoned");
        let slot = (*next).max(now);
        let wait = slot - now;
        if wait > MAX_QUEUE {
            return Err(wait - MAX_QUEUE);
        }
        *next = slot + self.interval;
        Ok(wait)
    }
}

pub struct BreachClient {
    http: reqwest::Client,
    base_url: url::Url,
    api_key: String,
    pacer: Pacer,
}

/// The fields HIBP sends that we pass on. Its `Description` is HTML and stays behind.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HibpBreach {
    name: String,
    title: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    breach_date: Option<String>,
    #[serde(default)]
    data_classes: Vec<String>,
}

impl BreachClient {
    pub fn new(config: &Hibp) -> Result<Self, url::ParseError> {
        let base_url = url::Url::parse(config.base_url.trim_end_matches('/'))?;
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("the HTTP client builds with static settings");
        Ok(Self {
            http,
            base_url,
            api_key: config.api_key.clone(),
            pacer: Pacer::new(Duration::from_secs(60) / config.requests_per_minute.max(1)),
        })
    }

    /// The breaches an address is in; none when HIBP doesn't know it.
    pub async fn lookup(&self, email: &str) -> ApiResult<Vec<EmailBreach>> {
        let wait = self
            .pacer
            .reserve(Instant::now())
            .map_err(ApiError::RateLimited)?;
        tokio::time::sleep(wait).await;

        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| ApiError::Unavailable)?
            .pop_if_empty()
            .extend(["breachedaccount", email]);
        url.query_pairs_mut()
            .append_pair("truncateResponse", "false");
        // `error.without_url()`: a reqwest error prints its URL, and this one holds the address.
        let response = self
            .http
            .get(url)
            .header("hibp-api-key", &self.api_key)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = %error.without_url(), "HIBP unreachable");
                ApiError::Unavailable
            })?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(Vec::new()),
            StatusCode::TOO_MANY_REQUESTS => {
                let wait = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok()?.parse().ok())
                    .unwrap_or(60);
                return Err(ApiError::RateLimited(Duration::from_secs(wait)));
            }
            status => {
                tracing::warn!(%status, "HIBP refused a request: check OCTAPASS_HIBP_API_KEY");
                return Err(ApiError::Unavailable);
            }
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE as u64)
        {
            return Err(ApiError::Unavailable);
        }
        let body = response.bytes().await.map_err(|_| ApiError::Unavailable)?;
        if body.len() > MAX_RESPONSE {
            return Err(ApiError::Unavailable);
        }
        let breaches: Vec<HibpBreach> =
            serde_json::from_slice(&body).map_err(|_| ApiError::Unavailable)?;
        Ok(breaches
            .into_iter()
            .map(|breach| EmailBreach {
                name: breach.name,
                title: breach.title,
                domain: Some(breach.domain).filter(|domain| !domain.is_empty()),
                breach_date: breach.breach_date,
                data_classes: breach.data_classes,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pacer_spaces_requests_and_turns_away_a_long_queue() {
        let pacer = Pacer::new(Duration::from_secs(6));
        let start = Instant::now();
        assert_eq!(pacer.reserve(start), Ok(Duration::ZERO));
        assert_eq!(pacer.reserve(start), Ok(Duration::from_secs(6)));
        assert_eq!(pacer.reserve(start), Ok(Duration::from_secs(12)));
        assert_eq!(pacer.reserve(start), Err(Duration::from_secs(3)));
        // A refused request doesn't take a slot, and time frees them.
        let later = start + Duration::from_secs(60);
        assert_eq!(pacer.reserve(later), Ok(Duration::ZERO));
    }
}
