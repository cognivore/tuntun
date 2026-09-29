//! Heartbeat policy. The I/O owner supplies elapsed monotonic time.
use std::time::Duration;

use crate::PingFrame;

pub const PING_INTERVAL: Duration = Duration::from_secs(15);
pub const PONG_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("tunnel heartbeat lost after {missed} unanswered probes (last nonce {nonce})")]
pub struct HeartbeatTimeout {
    pub missed: u8,
    pub nonce: u64,
}

#[derive(Debug)]
pub struct Heartbeat {
    next_probe: Duration,
    pending: Option<(u64, Duration)>,
    nonce: u64,
    missed: u8,
}

impl Heartbeat {
    pub fn new(nonce: u64) -> Self {
        Self {
            next_probe: PING_INTERVAL,
            pending: None,
            nonce,
            missed: 0,
        }
    }

    pub fn deadline(&self) -> Duration {
        self.pending
            .map_or(self.next_probe, |(_, deadline)| deadline)
    }

    pub fn poll(&mut self, now: Duration) -> Result<Option<PingFrame>, HeartbeatTimeout> {
        if let Some((nonce, deadline)) = self.pending {
            if now < deadline {
                return Ok(None);
            }
            self.missed += 1;
            if self.missed >= 3 {
                return Err(HeartbeatTimeout {
                    missed: self.missed,
                    nonce,
                });
            }
            self.pending = None;
        }
        if now < self.next_probe {
            return Ok(None);
        }
        self.nonce = self.nonce.wrapping_add(1);
        self.pending = Some((self.nonce, now + PONG_TIMEOUT));
        self.next_probe = now + PING_INTERVAL;
        Ok(Some(PingFrame { nonce: self.nonce }))
    }

    pub fn on_pong(&mut self, nonce: u64) {
        if self.pending.is_some_and(|(expected, _)| expected == nonce) {
            self.pending = None;
            self.missed = 0;
        }
    }
}
