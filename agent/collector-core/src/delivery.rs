//! Batch delivery to `POST /v1/agent/events` (api-contracts §6).
//!
//! - Batches ≤1,000 events AND ≤5 MB (AC-30 limits, enforced client-side).
//! - 202 → commit the batch in the buffer, reset backoff.
//! - 429 → honor `Retry-After` with jitter, never tight-loop (AC-68).
//! - 5xx / transport errors → jittered exponential backoff; events stay
//!   buffered (AC-66; fail-closed 503s are expected per SEC-10).
//! - 413 → halve the runtime batch cap and retry.
//! - 401 `DEVICE_REVOKED` → stop sending entirely (AC-59).
//! - 401 `DEVICE_IDENTITY_INVALID` → back off and keep trying (credential
//!   renewal may resolve a serial mismatch); logged loudly.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex, RwLock};
use tracing::{error, info, warn};

use crate::backoff::Backoff;
use crate::buffer::DiskBuffer;
use crate::http::ApiError;

pub const MAX_BATCH_EVENTS: usize = 1000;
pub const MAX_BATCH_BYTES: u64 = 5 * 1024 * 1024;
/// Margin subtracted from the 5 MB limit to cover the JSON wrapper.
const BODY_MARGIN_BYTES: u64 = 4096;

#[derive(Debug, Clone)]
pub struct DeliveryConfig {
    pub max_batch_events: usize,
    pub max_batch_bytes: u64,
    /// Idle poll interval when the buffer is empty.
    pub poll_interval: Duration,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        DeliveryConfig {
            max_batch_events: MAX_BATCH_EVENTS,
            max_batch_bytes: MAX_BATCH_BYTES,
            poll_interval: Duration::from_secs(1),
            backoff_base: crate::backoff::DEFAULT_BASE,
            backoff_cap: crate::backoff::DEFAULT_CAP,
        }
    }
}

/// Outcome of a single delivery attempt.
#[derive(Debug)]
pub enum DeliveryOutcome {
    /// Batch accepted (202) and committed.
    Delivered { accepted: usize },
    /// Nothing to send.
    Idle,
    /// Wait this long before the next attempt.
    Backoff(Duration),
    /// Device revoked: stop sending (AC-59).
    Revoked,
}

pub struct Deliverer {
    /// Swappable so credential renewal can rebuild the mTLS client.
    pub client: Arc<RwLock<reqwest::Client>>,
    pub ingest_url: String,
    cfg: DeliveryConfig,
    backoff: Backoff,
    /// Runtime-adaptive event cap (halved on 413).
    current_max_events: usize,
}

impl Deliverer {
    pub fn new(
        client: Arc<RwLock<reqwest::Client>>,
        ingest_url: String,
        cfg: DeliveryConfig,
    ) -> Self {
        let max_events = cfg.max_batch_events.clamp(1, MAX_BATCH_EVENTS);
        let backoff = Backoff::new(cfg.backoff_base, cfg.backoff_cap);
        Deliverer { client, ingest_url, cfg, backoff, current_max_events: max_events }
    }

    /// Attempt to deliver one batch from the buffer.
    pub async fn deliver_once(&mut self, buffer: &Mutex<DiskBuffer>) -> DeliveryOutcome {
        let max_events = self.current_max_events;
        let max_bytes = self
            .cfg
            .max_batch_bytes
            .min(MAX_BATCH_BYTES)
            .saturating_sub(BODY_MARGIN_BYTES);

        let batch = {
            let mut buf = buffer.lock().await;
            match buf.next_batch(max_events, max_bytes) {
                Ok(Some(b)) => b,
                Ok(None) => return DeliveryOutcome::Idle,
                Err(e) => {
                    error!("buffer read failed: {e}");
                    return DeliveryOutcome::Backoff(self.backoff.next_delay());
                }
            }
        };

        // Body: {"events":[<pre-serialized items>]} — no re-serialization.
        let mut body = String::with_capacity(batch.total_event_bytes as usize + 16);
        body.push_str("{\"events\":[");
        for (i, item) in batch.items.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push_str(item);
        }
        body.push_str("]}");

        let url = format!("{}/v1/agent/events", self.ingest_url.trim_end_matches('/'));
        let client = self.client.read().await.clone();
        let resp = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                let d = self.backoff.next_delay();
                warn!("delivery transport error ({e}); backing off {d:?}");
                return DeliveryOutcome::Backoff(d);
            }
        };

        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            let n = batch.len();
            buffer.lock().await.commit(&batch);
            self.backoff.reset();
            return DeliveryOutcome::Delivered { accepted: n };
        }

        let err = ApiError::from_response(resp).await;
        match (err.status, err.code.as_str()) {
            (401, "DEVICE_REVOKED") => {
                error!("device revoked by server; stopping all sending (AC-59)");
                DeliveryOutcome::Revoked
            }
            (401, _) => {
                let d = self.backoff.next_delay();
                error!(
                    code = err.code,
                    "device identity rejected; backing off {d:?} (renewal may recover)"
                );
                DeliveryOutcome::Backoff(d)
            }
            (413, _) => {
                let new_cap = (self.current_max_events / 2).max(1);
                warn!(
                    "server rejected batch as too large; reducing batch cap {} -> {}",
                    self.current_max_events, new_cap
                );
                self.current_max_events = new_cap;
                // Retry promptly but never tight-loop.
                DeliveryOutcome::Backoff(Duration::from_millis(250))
            }
            (429, _) => {
                let d = match err.retry_after_seconds {
                    Some(s) => self.backoff.delay_from_retry_after(s),
                    None => self.backoff.next_delay(),
                };
                info!("ingest backpressure (429); honoring Retry-After: waiting {d:?}");
                DeliveryOutcome::Backoff(d)
            }
            (402, _) | (403, _) => {
                // Trial expired / tenant frozen: keep buffering, retry slowly.
                let d = self.backoff.next_delay();
                warn!(code = err.code, "ingest rejected ({}); buffering and waiting {d:?}", err.status);
                DeliveryOutcome::Backoff(d)
            }
            _ => {
                let d = match err.retry_after_seconds {
                    Some(s) => self.backoff.delay_from_retry_after(s),
                    None => self.backoff.next_delay(),
                };
                warn!(code = err.code, status = err.status, "delivery failed; backing off {d:?}");
                DeliveryOutcome::Backoff(d)
            }
        }
    }

    /// Long-running delivery loop. Exits when `shutdown` flips true or the
    /// device is revoked (in which case `revoked` is flipped true).
    pub async fn run(
        mut self,
        buffer: Arc<Mutex<DiskBuffer>>,
        mut shutdown: watch::Receiver<bool>,
        revoked: watch::Sender<bool>,
    ) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            let outcome = self.deliver_once(&buffer).await;
            let wait = match outcome {
                DeliveryOutcome::Delivered { accepted } => {
                    tracing::debug!(accepted, "batch delivered");
                    continue; // immediately try to drain more
                }
                DeliveryOutcome::Idle => self.cfg.poll_interval,
                DeliveryOutcome::Backoff(d) => d,
                DeliveryOutcome::Revoked => {
                    let _ = revoked.send(true);
                    return;
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => {}
            }
        }
    }
}
