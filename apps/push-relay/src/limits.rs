//! Token buckets in memory, by installation and by client address.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Buckets {
    burst: u32,
    refill: Duration,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Buckets {
    pub fn new(burst: u32, refill: Duration) -> Self {
        Self {
            burst,
            refill,
            buckets: Mutex::default(),
        }
    }

    /// Takes `n` at once, or none and says how long until there are `n`.
    pub fn take(&self, key: &str, n: u32) -> Result<(), Duration> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let (tokens, at) = buckets
            .entry(key.to_owned())
            .or_insert((f64::from(self.burst), now));
        let earned = now.duration_since(*at).as_secs_f64() / self.refill.as_secs_f64();
        *tokens = (*tokens + earned).min(f64::from(self.burst));
        *at = now;
        let wanted = f64::from(n);
        if *tokens >= wanted {
            *tokens -= wanted;
            Ok(())
        } else {
            let missing = wanted - *tokens;
            Err(self.refill.mul_f64(missing))
        }
    }

    /// Forgets full buckets: they'd be full again anyway.
    pub fn prune(&self) {
        let now = Instant::now();
        let burst = f64::from(self.burst);
        let refill = self.refill.as_secs_f64();
        self.buckets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() / refill < burst
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_until_empty_then_says_how_long() {
        let buckets = Buckets::new(3, Duration::from_secs(10));
        assert!(buckets.take("a", 2).is_ok());
        let wait = buckets.take("a", 2).unwrap_err();
        assert!(wait > Duration::from_secs(9) && wait <= Duration::from_secs(10));
        assert!(buckets.take("a", 1).is_ok());
        assert!(buckets.take("b", 3).is_ok(), "buckets are per key");
        assert!(buckets.take("c", 4).is_err(), "never more than the burst");
        buckets.prune();
        assert_eq!(
            buckets.buckets.lock().unwrap().len(),
            2,
            "c is full and forgotten"
        );
    }
}
