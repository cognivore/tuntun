//! Exponential backoff with full jitter for tunnel reconnection.
//!
//! Per CLAUDE.md rule 10: 200ms base, 30s cap, reset on a successful
//! handshake. The state lives here so it's testable without spinning a real
//! tunnel.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BackoffState {
    base_ms: u64,
    cap_ms: u64,
    attempt: u32,
}

impl Default for BackoffState {
    fn default() -> Self {
        Self::new()
    }
}

impl BackoffState {
    pub const BASE_MS: u64 = 200;
    pub const CAP_MS: u64 = 30_000;

    pub fn new() -> Self {
        Self {
            base_ms: Self::BASE_MS,
            cap_ms: Self::CAP_MS,
            attempt: 0,
        }
    }

    /// Compute the next sleep duration. Caller advances `attempt`.
    /// Pure function; jitter source is supplied via `rng_uniform_01`.
    pub fn next_delay<F: FnMut() -> f64>(&mut self, mut rng_uniform_01: F) -> Duration {
        // exponential backoff: base * 2^attempt, capped
        let exp = self
            .base_ms
            .saturating_mul(1u64 << self.attempt.min(20));
        let raw = exp.min(self.cap_ms);
        // full jitter: uniform in [0, raw]
        let jitter_factor = rng_uniform_01().clamp(0.0, 1.0);
        // Cap raw at f64-safe range; durations of seconds are well within
        // f64's exact integer range.
        let dur_ms = ((raw as f64) * jitter_factor) as u64;
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(dur_ms.max(1))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_is_within_base() {
        let mut state = BackoffState::new();
        let d = state.next_delay(|| 0.5);
        assert!(d.as_millis() <= u128::from(BackoffState::BASE_MS));
    }

    #[test]
    fn caps_at_max() {
        let mut state = BackoffState::new();
        for _ in 0..40 {
            let _ = state.next_delay(|| 1.0);
        }
        let d = state.next_delay(|| 1.0);
        assert!(d.as_millis() <= u128::from(BackoffState::CAP_MS));
    }

    #[test]
    fn reset_works() {
        let mut state = BackoffState::new();
        state.next_delay(|| 0.5);
        state.next_delay(|| 0.5);
        state.reset();
        assert_eq!(state.attempt, 0);
    }
}
