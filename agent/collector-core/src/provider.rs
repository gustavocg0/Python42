//! Pluggable telemetry-provider abstraction (AC-62).
//!
//! Provider choice is configuration, not compile-time forking: `agentd`
//! instantiates a `Box<dyn TelemetryProvider>` from the config `provider`
//! key. Providers run their own OS threads and push events into the core's
//! bounded channel via [`EventSink`]; if the pipeline stalls, the sink blocks
//! the provider thread (bounded memory — telemetry degrades before the host
//! does, ADR-0002 #2).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::AgentEvent;

/// Heartbeat wire values per api-contracts §10: `"ok" | "degraded" | "failed"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Ok,
    Degraded,
    Failed,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider not supported on this platform: {0}")]
    Unsupported(String),
    #[error("provider failed to start: {0}")]
    Start(String),
}

/// Handle providers use to emit events into the core pipeline.
#[derive(Clone)]
pub struct EventSink {
    tx: tokio::sync::mpsc::Sender<AgentEvent>,
}

impl EventSink {
    pub fn new(tx: tokio::sync::mpsc::Sender<AgentEvent>) -> Self {
        EventSink { tx }
    }

    /// Blocking send from a provider-owned OS thread. Returns `false` when the
    /// pipeline is shut down (provider should stop).
    pub fn send_blocking(&self, event: AgentEvent) -> bool {
        self.tx.blocking_send(event).is_ok()
    }

    /// Non-blocking variant; returns `false` if the channel is full or closed.
    pub fn try_send(&self, event: AgentEvent) -> bool {
        self.tx.try_send(event).is_ok()
    }
}

/// A telemetry source (ETW, simulated; later eBPF / Endpoint Security).
pub trait TelemetryProvider: Send {
    /// Wire name for heartbeat `providers[].name` (`"etw"` / `"simulated"`).
    fn name(&self) -> &'static str;

    /// Start collection; the provider owns any threads it spawns and must
    /// stop them on [`TelemetryProvider::stop`].
    fn start(&mut self, sink: EventSink) -> Result<(), ProviderError>;

    /// Stop collection and join internal threads. Idempotent.
    fn stop(&mut self);

    /// Current status, reported in every heartbeat (AC-60).
    fn status(&self) -> ProviderStatus;
}
