//! soc-collector-core — the endpoint agent's core library.
//!
//! Owns (per PRD Epic E8 / ADR-0002 / ADR-0006 / ADR-0007):
//! - the versioned agent wire-event model (`model`, matches
//!   `docs/contracts/event-schema.md` §5 agent shapes),
//! - the pluggable telemetry-provider trait (`provider`, AC-62),
//! - the disk ring buffer with documented shedding order (`buffer`, AC-66/67),
//! - jittered exponential backoff (`backoff`, AC-68),
//! - enrollment / device identity persistence (`enroll`, `identity`, AC-56..58, SEC-8),
//! - mTLS HTTP client construction (`http`, AC-69),
//! - batch delivery to `POST /v1/agent/events` (`delivery`, AC-34/66/68),
//! - heartbeat + credential renewal (`heartbeat`, `renew`, AC-59/60, SEC-11),
//! - self health sampling and host info (`health`).

pub mod backoff;
pub mod buffer;
pub mod delivery;
pub mod enroll;
pub mod health;
pub mod heartbeat;
pub mod http;
pub mod identity;
pub mod model;
pub mod provider;
pub mod renew;

/// Version reported in heartbeats and User-Agent. Single source: workspace package version.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
