//! Time value types used at the `ClockPort` boundary.
//!
//! `Timestamp` is wall-clock UNIX seconds. `Instant` is a monotonic, opaque
//! reference for measuring elapsed time. Library code must obtain both via
//! `ClockPort` — never via `std::time` directly.

use std::fmt;
use std::ops::{Add, Sub};

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp {
    /// UNIX seconds since 1970-01-01 UTC.
    pub seconds: i64,
}

impl Timestamp {
    pub const fn from_seconds(seconds: i64) -> Self {
        Self { seconds }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.seconds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    /// Whole seconds.
    pub seconds: i64,
}

impl Duration {
    pub const ZERO: Duration = Duration { seconds: 0 };

    pub const fn from_seconds(seconds: i64) -> Self {
        Self { seconds }
    }

    pub const fn from_minutes(minutes: i64) -> Self {
        Self {
            seconds: minutes * 60,
        }
    }

    pub const fn from_hours(hours: i64) -> Self {
        Self {
            seconds: hours * 3600,
        }
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;
    fn add(self, rhs: Duration) -> Self::Output {
        Timestamp {
            seconds: self.seconds.saturating_add(rhs.seconds),
        }
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Duration;
    fn sub(self, rhs: Timestamp) -> Self::Output {
        Duration {
            seconds: self.seconds.saturating_sub(rhs.seconds),
        }
    }
}

/// Monotonic time. The inner counter is opaque — only its delta is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    pub ticks_ns: u128,
}

impl Instant {
    pub const fn from_nanos(ticks_ns: u128) -> Self {
        Self { ticks_ns }
    }

    pub fn duration_since(self, earlier: Instant) -> Duration {
        let diff_ns = self.ticks_ns.saturating_sub(earlier.ticks_ns);
        let secs = (diff_ns / 1_000_000_000) as i64;
        Duration::from_seconds(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_arithmetic() {
        let t0 = Timestamp::from_seconds(1_000);
        let later = t0 + Duration::from_minutes(5);
        assert_eq!(later.seconds, 1_300);
        assert_eq!((later - t0).seconds, 300);
    }
}
