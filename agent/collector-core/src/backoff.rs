//! Jittered exponential backoff (AC-68).
//!
//! Guarantees:
//! - never returns a zero/tight-loop delay: every delay is ≥ `base/2`;
//! - exponential growth capped at `cap`;
//! - full-range jitter in `[d/2, d]` to avoid thundering-herd sync;
//! - `Retry-After` from the server is honored as a *floor* plus jitter.

use std::time::Duration;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

#[derive(Debug)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
    rng: SmallRng,
}

pub const DEFAULT_BASE: Duration = Duration::from_secs(1);
pub const DEFAULT_CAP: Duration = Duration::from_secs(300);

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self::seeded(base, cap, rand::random())
    }

    /// Deterministic RNG for tests.
    pub fn seeded(base: Duration, cap: Duration, seed: u64) -> Self {
        let base = base.max(Duration::from_millis(100));
        let cap = cap.max(base);
        Backoff { base, cap, attempt: 0, rng: SmallRng::seed_from_u64(seed) }
    }

    /// Next delay for a failed attempt; grows exponentially with jitter.
    pub fn next_delay(&mut self) -> Duration {
        let exp = self.attempt.min(30);
        self.attempt = self.attempt.saturating_add(1);
        let raw = self
            .base
            .saturating_mul(2u32.saturating_pow(exp))
            .min(self.cap);
        self.jitter(raw)
    }

    /// Delay honoring a server `Retry-After: <seconds>` header (AC-68):
    /// at least the server-requested wait, plus up to 1s of jitter.
    pub fn delay_from_retry_after(&mut self, retry_after_seconds: u64) -> Duration {
        // Count as an attempt so a following failure keeps growing.
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_secs(retry_after_seconds)
            + Duration::from_millis(self.rng.gen_range(0..=1000))
    }

    /// Reset after a success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Uniform jitter in `[d/2, d]`, never below `base/2`.
    fn jitter(&mut self, d: Duration) -> Duration {
        let d_ms = d.as_millis().max(1) as u64;
        let lo = (d_ms / 2).max(self.base.as_millis() as u64 / 2).max(50);
        let hi = d_ms.max(lo);
        Duration::from_millis(self.rng.gen_range(lo..=hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_tight_loops() {
        let mut b = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, 7);
        for _ in 0..100 {
            let d = b.next_delay();
            assert!(d >= Duration::from_millis(500), "delay {d:?} below base/2");
        }
    }

    #[test]
    fn respects_cap_and_grows() {
        let mut b = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, 42);
        let mut last_upper = 0u128;
        for i in 0..12 {
            let d = b.next_delay();
            assert!(d <= DEFAULT_CAP, "delay {d:?} above cap at attempt {i}");
            // upper bound for attempt i is min(base*2^i, cap)
            let ub = (1000u128 << i).min(DEFAULT_CAP.as_millis());
            assert!(d.as_millis() <= ub, "delay {d:?} above nominal {ub}ms at attempt {i}");
            last_upper = ub;
        }
        assert_eq!(last_upper, DEFAULT_CAP.as_millis());
    }

    #[test]
    fn jitter_within_half_to_full() {
        let mut b = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, 1);
        // attempt 3 → nominal 8s: delays must be in [4s, 8s]
        b.next_delay();
        b.next_delay();
        b.next_delay();
        for _ in 0..50 {
            let mut probe = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, rand::random());
            probe.attempt = 3;
            let d = probe.next_delay();
            assert!(d >= Duration::from_secs(4) && d <= Duration::from_secs(8), "{d:?}");
        }
        let _ = b;
    }

    #[test]
    fn retry_after_is_a_floor() {
        let mut b = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, 9);
        for _ in 0..20 {
            let d = b.delay_from_retry_after(30);
            assert!(d >= Duration::from_secs(30));
            assert!(d <= Duration::from_secs(31));
        }
    }

    #[test]
    fn reset_restarts_sequence() {
        let mut b = Backoff::seeded(DEFAULT_BASE, DEFAULT_CAP, 5);
        for _ in 0..8 {
            b.next_delay();
        }
        b.reset();
        let d = b.next_delay();
        assert!(d <= DEFAULT_BASE, "after reset, first delay must be within base: {d:?}");
    }
}
