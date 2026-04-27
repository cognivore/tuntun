//! Real wall-clock + monotonic clock backing `tuntun_core::ClockPort`.

use std::time::{SystemTime, UNIX_EPOCH};

use tuntun_core::{ClockPort, Instant, Timestamp};

#[derive(Debug, Default)]
pub struct SystemClock;

impl ClockPort for SystemClock {
    fn now(&self) -> Timestamp {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp::from_seconds(i64::try_from(dur.as_secs()).unwrap_or(i64::MAX))
    }

    fn instant(&self) -> Instant {
        // Monotonic counter: just reuse SystemTime as a coarse approximation
        // for now. For finer-grained timing, swap to `std::time::Instant`
        // anchored at process start; we don't need that resolution here.
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Instant::from_nanos(dur.as_nanos())
    }
}
