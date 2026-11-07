//! In-process token buckets. One relay process owns its limits; running several would multiply
//! them, which is one reason the relay is a single instance (see the docs).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    pub burst: u32,
    pub refill: Duration,
}

impl Bucket {
    pub fn per_hour(burst: u32) -> Self {
        Self {
            burst,
            refill: Duration::from_secs(3600) / burst.max(1),
        }
    }

    pub fn per_minute(burst: u32) -> Self {
        Self {
            burst,
            refill: Duration::from_secs(60) / burst.max(1),
        }
    }
}

/// Past this many keys, full buckets are dropped: a key nobody is using is the same as a new one.
const MAX_KEYS: usize = 100_000;

pub struct Limiter {
    config: Bucket,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(config: Bucket) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes a token for `key`, or returns false.
    pub fn take(&self, key: &str) -> bool {
        self.take_at(key, Instant::now())
    }

    fn take_at(&self, key: &str, now: Instant) -> bool {
        let burst = f64::from(self.config.burst);
        let refill = self.config.refill.as_secs_f64().max(f64::MIN_POSITIVE);
        let mut buckets = self.buckets.lock().expect("limiter lock poisoned");
        if buckets.len() >= MAX_KEYS && !buckets.contains_key(key) {
            buckets.retain(|_, (tokens, updated)| {
                *tokens + now.duration_since(*updated).as_secs_f64() / refill < burst
            });
        }
        let (tokens, updated) = buckets.entry(key.to_owned()).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*updated).as_secs_f64() / refill).min(burst);
        *updated = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// IPv6 users usually control a whole /64, so that's the unit.
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spends_the_burst_then_refills() {
        let limiter = Limiter::new(Bucket {
            burst: 2,
            refill: Duration::from_secs(10),
        });
        let start = Instant::now();
        assert!(limiter.take_at("a", start));
        assert!(limiter.take_at("a", start));
        assert!(!limiter.take_at("a", start));
        assert!(limiter.take_at("b", start));
        assert!(limiter.take_at("a", start + Duration::from_secs(11)));
    }

    #[test]
    fn groups_ipv6_by_prefix() {
        let a = ip_key("2001:db8:1:2:aaaa::1".parse().unwrap());
        assert_eq!(a, ip_key("2001:db8:1:2:bbbb::2".parse().unwrap()));
        assert_eq!(ip_key("::ffff:192.0.2.1".parse().unwrap()), "192.0.2.1");
    }
}
