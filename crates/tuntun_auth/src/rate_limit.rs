//! Token-bucket rate limiter.
//!
//! Pure: state mutates in place; the clock comes from the caller's
//! `ClockPort`. Workspace defaults per CLAUDE.md rule 5: capacity 5,
//! refill 1 token per 30 seconds, cost 1 per attempt.
//!
//! Refill is computed as `(now - last_refill) * refill_per_second`, capped at
//! `capacity`. The `last_refill` field advances every time we either consume a
//! token or refuse to consume one — that is, each call advances the clock to
//! `now`. This avoids unbounded drift if a quiet caller polls infrequently.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tuntun_core::{Error as CoreError, Timestamp};

/// Workspace default capacity (tokens).
pub const DEFAULT_CAPACITY: f64 = 5.0;
/// Workspace default refill (tokens per second). 1 token per 30 seconds.
pub const DEFAULT_REFILL_PER_SECOND: f64 = 1.0 / 30.0;
/// Workspace default cost per login attempt.
pub const DEFAULT_COST_PER_ATTEMPT: f64 = 1.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimiterState {
    pub last_refill: Timestamp,
    pub tokens: f64,
    pub capacity: f64,
    pub refill_per_second: f64,
}

impl RateLimiterState {
    /// Construct a state at full capacity using workspace defaults.
    pub fn defaults_at(now: Timestamp) -> Self {
        Self {
            last_refill: now,
            tokens: DEFAULT_CAPACITY,
            capacity: DEFAULT_CAPACITY,
            refill_per_second: DEFAULT_REFILL_PER_SECOND,
        }
    }

    /// Construct a state with custom capacity and refill rate, full at `now`.
    pub fn new(now: Timestamp, capacity: f64, refill_per_second: f64) -> Self {
        Self {
            last_refill: now,
            tokens: capacity,
            capacity,
            refill_per_second,
        }
    }
}

#[derive(Debug, Error)]
#[error("rate limited: {tokens_available:.3} tokens available, {cost:.3} required, retry after {retry_after_seconds} s")]
pub struct RateLimitedError {
    pub tokens_available: f64,
    pub cost: f64,
    pub retry_after_seconds: i64,
}

impl From<RateLimitedError> for CoreError {
    fn from(value: RateLimitedError) -> Self {
        CoreError::auth(value.to_string())
    }
}

/// Try to consume `cost` tokens from the bucket at time `now`.
///
/// Updates the bucket in place: refills based on elapsed time since
/// `last_refill`, then either deducts `cost` (returning `Ok(())`) or refuses
/// (returning [`RateLimitedError`] with the suggested retry delay).
///
/// Even when the call is refused, `last_refill` is advanced to `now` so future
/// calls start their refill from a fresh, monotonic baseline. Token count is
/// preserved on refusal.
pub fn try_consume(
    state: &mut RateLimiterState,
    now: Timestamp,
    cost: f64,
) -> Result<(), RateLimitedError> {
    refill(state, now);
    if state.tokens + f64::EPSILON >= cost {
        state.tokens -= cost;
        if state.tokens < 0.0 {
            // Defensive clamp: never go below zero from float wobble.
            state.tokens = 0.0;
        }
        Ok(())
    } else {
        let deficit = cost - state.tokens;
        let retry_after = if state.refill_per_second > 0.0 {
            (deficit / state.refill_per_second).ceil() as i64
        } else {
            i64::MAX
        };
        Err(RateLimitedError {
            tokens_available: state.tokens,
            cost,
            retry_after_seconds: retry_after.max(0),
        })
    }
}

fn refill(state: &mut RateLimiterState, now: Timestamp) {
    let elapsed_seconds = now.seconds.saturating_sub(state.last_refill.seconds);
    if elapsed_seconds > 0 && state.refill_per_second > 0.0 {
        #[allow(clippy::cast_precision_loss)]
        let added = (elapsed_seconds as f64) * state.refill_per_second;
        state.tokens = (state.tokens + added).min(state.capacity);
    }
    // Advance even on zero/negative deltas: never let last_refill go backwards
    // unboundedly relative to a moving clock, and never let it stay frozen on
    // a refused attempt at the same instant.
    if now.seconds > state.last_refill.seconds {
        state.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: i64) -> Timestamp {
        Timestamp::from_seconds(s)
    }

    #[test]
    fn full_bucket_admits_up_to_capacity() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("admit");
        }
        let err = try_consume(&mut s, ts(0), 1.0).unwrap_err();
        assert!(err.tokens_available < 1.0);
        assert!(err.retry_after_seconds > 0);
    }

    #[test]
    fn defaults_match_workspace_policy() {
        let s = RateLimiterState::defaults_at(ts(0));
        assert!((s.capacity - 5.0).abs() < f64::EPSILON);
        // 1 token per 30 seconds
        assert!((s.refill_per_second - 1.0 / 30.0).abs() < 1e-12);
    }

    #[test]
    fn refill_replenishes_over_time() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("admit");
        }
        // 30s later: +1 token. Should admit one more.
        try_consume(&mut s, ts(30), 1.0).expect("post-refill");
        assert!(try_consume(&mut s, ts(30), 1.0).is_err());
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("admit");
        }
        // A long quiet period must not push us above capacity.
        try_consume(&mut s, ts(10_000), 1.0).expect("admit after quiet");
        // After consuming one token from a freshly-capped bucket of 5, we
        // should have ~4 left, not "5 + huge refill".
        assert!(s.tokens <= s.capacity);
        assert!(s.tokens >= 3.9);
    }

    #[test]
    fn retry_after_is_at_least_one_second_when_empty() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("admit");
        }
        let err = try_consume(&mut s, ts(0), 1.0).unwrap_err();
        // 1 token deficit at 1/30 tokens/sec => 30 seconds.
        assert_eq!(err.retry_after_seconds, 30);
    }

    #[test]
    fn cost_zero_is_always_admitted() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("drain");
        }
        try_consume(&mut s, ts(0), 0.0).expect("zero cost");
    }

    #[test]
    fn cost_greater_than_capacity_always_fails() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        let err = try_consume(&mut s, ts(0), 999.0).unwrap_err();
        assert!(err.cost > err.tokens_available);
    }

    #[test]
    fn last_refill_advances_on_success() {
        let mut s = RateLimiterState::defaults_at(ts(100));
        try_consume(&mut s, ts(150), 1.0).expect("admit");
        assert_eq!(s.last_refill.seconds, 150);
    }

    #[test]
    fn last_refill_advances_on_refusal() {
        let mut s = RateLimiterState::defaults_at(ts(100));
        for _ in 0..5 {
            try_consume(&mut s, ts(100), 1.0).expect("drain");
        }
        let _ = try_consume(&mut s, ts(120), 1.0); // expected to fail
        assert_eq!(s.last_refill.seconds, 120);
    }

    #[test]
    fn last_refill_does_not_go_backwards() {
        let mut s = RateLimiterState::defaults_at(ts(100));
        let _ = try_consume(&mut s, ts(50), 1.0); // earlier than last_refill
        assert!(s.last_refill.seconds >= 100);
    }

    #[test]
    fn zero_refill_rate_means_permanent_lockout_on_exhaustion() {
        let mut s = RateLimiterState::new(ts(0), 1.0, 0.0);
        try_consume(&mut s, ts(0), 1.0).expect("first");
        let err = try_consume(&mut s, ts(1_000_000), 1.0).unwrap_err();
        assert_eq!(err.retry_after_seconds, i64::MAX);
    }

    #[test]
    fn fractional_cost_works() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        try_consume(&mut s, ts(0), 0.5).expect("half");
        try_consume(&mut s, ts(0), 0.5).expect("half again");
        // We've consumed 1.0 total; 4.0 remain.
        assert!((s.tokens - 4.0).abs() < 1e-9);
    }

    #[test]
    fn full_lifecycle_exhaust_wait_resume() {
        let mut s = RateLimiterState::defaults_at(ts(0));
        // Burn through all 5 tokens at t=0.
        for _ in 0..5 {
            try_consume(&mut s, ts(0), 1.0).expect("admit");
        }
        // At t=29 we still can't refill a full token.
        assert!(try_consume(&mut s, ts(29), 1.0).is_err());
        // At t=30 we have exactly 1 token.
        try_consume(&mut s, ts(30), 1.0).expect("first refilled token");
        // And it's gone again until t=60.
        assert!(try_consume(&mut s, ts(30), 1.0).is_err());
        try_consume(&mut s, ts(60), 1.0).expect("second refilled token");
    }
}
