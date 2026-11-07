//! In-process token buckets keyed by client IP or email.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Bucket;

pub struct RateLimiter {
    config: Bucket,
    buckets: Mutex<HashMap<String, State>>,
}

struct State {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    pub fn new(config: Bucket) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `key`, or returns how long to wait for the next one.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now(), true)
    }

    /// Like `check`, but leaves the token in place: for limits that only
    /// count failures, checked before the attempt and charged after.
    pub fn peek(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now(), false)
    }

    /// Gives back a token taken with `check`, for limits charged before the
    /// attempt (so concurrent attempts can't all pass) that only count failures.
    pub fn refund(&self, key: &str) {
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        if let Some(state) = buckets.get_mut(key) {
            state.tokens = (state.tokens + 1.0).min(f64::from(self.config.burst));
        }
    }

    fn check_at(&self, key: &str, now: Instant, take: bool) -> Result<(), Duration> {
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        let burst = f64::from(self.config.burst);
        let Some(state) = buckets.get_mut(key) else {
            if take {
                let tokens = burst - 1.0;
                buckets.insert(
                    key.to_owned(),
                    State {
                        tokens,
                        updated: now,
                    },
                );
            }
            return Ok(());
        };
        state.tokens = (state.tokens + self.refilled(now - state.updated)).min(burst);
        state.updated = now;
        if state.tokens >= 1.0 {
            if take {
                state.tokens -= 1.0;
            }
            Ok(())
        } else {
            Err(self.config.refill.mul_f64(1.0 - state.tokens))
        }
    }

    /// Forgets buckets that have refilled completely, so memory stays bounded.
    pub fn prune(&self) {
        let now = Instant::now();
        let burst = f64::from(self.config.burst);
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        buckets.retain(|_, state| state.tokens + self.refilled(now - state.updated) < burst);
    }

    fn refilled(&self, elapsed: Duration) -> f64 {
        elapsed.as_secs_f64() / self.config.refill.as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        RateLimiter::new(Bucket {
            burst: 2,
            refill: Duration::from_secs(10),
        })
    }

    #[test]
    fn allows_a_burst_then_refills() {
        let limiter = limiter();
        let start = Instant::now();
        assert!(limiter.check_at("a", start, true).is_ok());
        assert!(limiter.check_at("a", start, true).is_ok());
        let wait = limiter.check_at("a", start, true).unwrap_err();
        assert_eq!(wait, Duration::from_secs(10));
        assert!(
            limiter.check_at("b", start, true).is_ok(),
            "keys are independent"
        );
        let later = start + Duration::from_secs(10);
        assert!(limiter.check_at("a", later, true).is_ok());
        assert!(limiter.check_at("a", later, true).is_err());
    }

    #[test]
    fn peeking_takes_nothing() {
        let limiter = limiter();
        let start = Instant::now();
        for _ in 0..5 {
            assert!(limiter.check_at("a", start, false).is_ok());
        }
        assert!(limiter.buckets.lock().unwrap().is_empty());
        limiter.check_at("a", start, true).unwrap();
        limiter.check_at("a", start, true).unwrap();
        assert!(limiter.check_at("a", start, false).is_err());
    }

    #[test]
    fn refunds_give_a_token_back_up_to_the_burst() {
        let limiter = limiter();
        let start = Instant::now();
        limiter.refund("a");
        assert!(limiter.buckets.lock().unwrap().is_empty());
        limiter.check_at("a", start, true).unwrap();
        limiter.check_at("a", start, true).unwrap();
        assert!(limiter.check_at("a", start, false).is_err());
        limiter.refund("a");
        assert!(limiter.check_at("a", start, true).is_ok());
        limiter.refund("a");
        limiter.refund("a");
        limiter.refund("a");
        assert_eq!(limiter.buckets.lock().unwrap()["a"].tokens, 2.0);
    }

    #[test]
    fn prune_keeps_only_partial_buckets() {
        let limiter = limiter();
        limiter.check("used").unwrap();
        limiter.prune();
        assert_eq!(limiter.buckets.lock().unwrap().len(), 1);
        limiter
            .buckets
            .lock()
            .unwrap()
            .get_mut("used")
            .unwrap()
            .updated -= Duration::from_secs(60);
        limiter.prune();
        assert!(limiter.buckets.lock().unwrap().is_empty());
    }
}
