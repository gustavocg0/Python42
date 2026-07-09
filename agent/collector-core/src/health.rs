//! Self resource sampling (heartbeat `cpu_pct` / `rss_mb`, AC-60) and host
//! information collection (event-schema §2.1 `host` object).

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

use crate::model::{Host, OsFamily};

pub struct HealthSampler {
    sys: System,
    pid: Pid,
    cpus: usize,
}

impl HealthSampler {
    pub fn new() -> Self {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        HealthSampler {
            sys: System::new(),
            pid: Pid::from_u32(std::process::id()),
            cpus,
        }
    }

    /// (cpu_pct across all cores, rss_mb). First call returns cpu 0.0
    /// (sysinfo needs two refreshes to compute a rate).
    pub fn sample(&mut self) -> (f64, f64) {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        match self.sys.process(self.pid) {
            Some(p) => {
                // sysinfo cpu_usage() is % of a single core.
                let cpu = (p.cpu_usage() as f64 / self.cpus as f64).max(0.0);
                let rss_mb = p.memory() as f64 / (1024.0 * 1024.0);
                (round2(cpu), round2(rss_mb))
            }
            None => (0.0, 0.0),
        }
    }
}

impl Default for HealthSampler {
    fn default() -> Self {
        Self::new()
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn os_family() -> OsFamily {
    if cfg!(target_os = "windows") {
        OsFamily::Windows
    } else if cfg!(target_os = "linux") {
        OsFamily::Linux
    } else if cfg!(target_os = "macos") {
        OsFamily::Macos
    } else {
        OsFamily::Other
    }
}

/// Kernel/OS version string for the heartbeat `os_version` field.
pub fn os_version_string() -> String {
    System::os_version().unwrap_or_else(|| "unknown".into())
}

/// Collect the host object sent with every event (event-schema §2.1).
/// `ip`/`mac` are optional per schema and omitted in the MVP skeleton
/// (documented gap; asset dedup keys on device_id + hostname/os_family).
pub fn collect_host() -> Host {
    let hostname = System::host_name()
        .unwrap_or_else(|| "unknown-host".into())
        .to_lowercase();
    let os_name = System::long_os_version()
        .or_else(System::name)
        .unwrap_or_else(|| "unknown".into());
    Host {
        hostname,
        os_family: os_family(),
        os_name,
        os_version: os_version_string(),
        ip: None,
        mac: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_schema_complete() {
        let h = collect_host();
        assert!(!h.hostname.is_empty());
        assert_eq!(h.hostname, h.hostname.to_lowercase(), "hostname stored lowercased");
        assert!(!h.os_name.is_empty());
        assert!(!h.os_version.is_empty());
    }

    #[test]
    fn sampler_returns_sane_values() {
        let mut s = HealthSampler::new();
        let (_cpu0, _rss0) = s.sample();
        // Burn a little CPU so the second sample has a rate to measure.
        let mut x = 0u64;
        for i in 0..2_000_000u64 {
            x = x.wrapping_add(i);
        }
        std::hint::black_box(x);
        let (cpu, rss) = s.sample();
        assert!(cpu >= 0.0);
        assert!(rss > 0.0, "own RSS must be nonzero");
        assert!(rss < 10_000.0);
    }
}
