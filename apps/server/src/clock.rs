//! The server's "now" for time-based rules: share-link expiry, the
//! emergency-access waiting period and authenticator codes. Tests move it
//! forward to cross those periods without sleeping; nothing else ever does.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use crate::db;

#[derive(Default)]
pub struct Clock {
    offset_ms: AtomicI64,
}

impl Clock {
    /// Unix milliseconds.
    pub fn now(&self) -> i64 {
        db::now() + self.offset_ms.load(Ordering::Relaxed)
    }

    pub fn advance(&self, by: Duration) {
        let by = i64::try_from(by.as_millis()).expect("test durations fit in i64");
        self.offset_ms.fetch_add(by, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances() {
        let clock = Clock::default();
        let before = clock.now();
        clock.advance(Duration::from_secs(86_400));
        assert!(clock.now() - before >= 86_400_000);
    }
}
