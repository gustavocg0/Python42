//! Windows ETW telemetry provider (AC-62a, AC-63) — Phase 1, user mode only
//! (ADR-0002: NO kernel driver).
//!
//! # Coverage (honest statement)
//!
//! This MVP provider implements a **real** ETW real-time consumer session and
//! subscribes to the `Microsoft-Windows-Kernel-Process` manifest provider,
//! emitting **process-start** (and best-effort process-stop) events parsed
//! via TDH. That satisfies the process-start portion of AC-63 on a real host.
//!
//! **Documented gaps for MVP (tracked for a fast-follow):**
//! - **Network events:** not yet collected. The kernel network rundown
//!   (`Microsoft-Windows-Kernel-Network`) requires additional TDH parsing of
//!   IPv4/IPv6 connect/accept events; deferred. `network_activity` is fully
//!   covered by the simulated provider for CI (AC-64).
//! - **Authentication (logon/logoff/failed):** requires the
//!   `Microsoft-Windows-Security-Auditing` channel, which is SYSTEM-only and
//!   gated by audit policy; wiring it needs the service to run as SYSTEM and
//!   is deferred to the packaged (MSI/service) build. Covered by the
//!   simulated provider for CI.
//! - **cmd_line / sha256 / process owner:** command line is extracted from
//!   the Kernel-Process event when present; where unavailable the event falls
//!   back to `exe_path` for `cmd_line` (schema requires the field). Image
//!   hashing is not performed in Phase 1.
//!
//! On non-Windows targets this crate compiles to a stub whose `start` returns
//! [`ProviderError::Unsupported`], so the workspace builds and tests on the
//! CI/dev machine regardless of OS.

use soc_collector_core::provider::{EventSink, ProviderError, ProviderStatus, TelemetryProvider};

#[cfg(windows)]
mod win;

/// The Windows ETW provider.
pub struct EtwProvider {
    #[cfg(windows)]
    inner: win::EtwSession,
    #[cfg(not(windows))]
    _priv: (),
}

impl EtwProvider {
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            EtwProvider { inner: win::EtwSession::new() }
        }
        #[cfg(not(windows))]
        {
            EtwProvider { _priv: () }
        }
    }
}

impl Default for EtwProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryProvider for EtwProvider {
    fn name(&self) -> &'static str {
        "etw"
    }

    #[cfg(windows)]
    fn start(&mut self, sink: EventSink) -> Result<(), ProviderError> {
        self.inner.start(sink)
    }

    #[cfg(not(windows))]
    fn start(&mut self, _sink: EventSink) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported(
            "ETW is only available on Windows; use provider=\"simulated\" on this OS".into(),
        ))
    }

    fn stop(&mut self) {
        #[cfg(windows)]
        self.inner.stop();
    }

    fn status(&self) -> ProviderStatus {
        #[cfg(windows)]
        {
            self.inner.status()
        }
        #[cfg(not(windows))]
        {
            ProviderStatus::Failed
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_off_windows() {
        let mut p = EtwProvider::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let sink = EventSink::new(tx);
        assert!(matches!(p.start(sink), Err(ProviderError::Unsupported(_))));
        assert_eq!(p.status(), ProviderStatus::Failed);
    }
}
