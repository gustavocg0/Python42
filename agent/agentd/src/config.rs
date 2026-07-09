//! Agent configuration (TOML file + selected env overrides).
//!
//! Provider selection is configuration, not compile-time (AC-62). See
//! `agent.example.toml` for the full documented key reference (also used by
//! QA to run the simulated provider in CI).

use std::path::PathBuf;

use serde::Deserialize;
use soc_provider_simulated::SimConfig;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Etw,
    /// Cross-platform default so CI/dev works without Windows.
    #[default]
    Simulated,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Base URL of the ingestion edge (must be https in release builds).
    pub server_url: String,
    /// Enrollment token (only needed until the device is enrolled).
    #[serde(default)]
    pub enrollment_token: Option<String>,
    /// Local state directory for identity + credentials.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub provider: ProviderKind,
    /// Additional TLS trust anchor(s), PEM (compose/dev CA or private PKI).
    #[serde(default)]
    pub server_ca_pem_path: Option<PathBuf>,
    /// Heartbeat interval; the server value from enrollment overrides this.
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_interval_seconds: u64,
    #[serde(default)]
    pub buffer: BufferSettings,
    #[serde(default)]
    pub delivery: DeliverySettings,
    #[serde(default)]
    pub simulated: SimulatedSettings,
    #[cfg(debug_assertions)]
    #[serde(default)]
    pub dev: DevSettings,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BufferSettings {
    #[serde(default = "default_buffer_dir")]
    pub dir: Option<PathBuf>,
    #[serde(default = "default_buffer_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_segment_max_bytes")]
    pub segment_max_bytes: u64,
}

impl Default for BufferSettings {
    fn default() -> Self {
        BufferSettings {
            dir: None,
            max_bytes: default_buffer_max_bytes(),
            segment_max_bytes: default_segment_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeliverySettings {
    #[serde(default = "default_max_batch_events")]
    pub max_batch_events: usize,
    #[serde(default = "default_max_batch_bytes")]
    pub max_batch_bytes: u64,
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_base_backoff_ms")]
    pub base_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// Channel depth between providers and the buffer drainer.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for DeliverySettings {
    fn default() -> Self {
        DeliverySettings {
            max_batch_events: default_max_batch_events(),
            max_batch_bytes: default_max_batch_bytes(),
            poll_interval_ms: default_poll_ms(),
            base_backoff_ms: default_base_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            channel_capacity: default_channel_capacity(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SimulatedSettings {
    #[serde(default = "default_eps")]
    pub events_per_second: u32,
    /// 0 = random; non-zero = deterministic (CI). See `SimConfig`.
    #[serde(default)]
    pub seed: u64,
    #[serde(default = "default_true")]
    pub suspicious_patterns: bool,
}

impl Default for SimulatedSettings {
    fn default() -> Self {
        SimulatedSettings {
            events_per_second: default_eps(),
            seed: 0,
            suspicious_patterns: true,
        }
    }
}

impl SimulatedSettings {
    pub fn to_sim_config(&self, hostname: String) -> SimConfig {
        SimConfig {
            events_per_second: self.events_per_second,
            seed: self.seed,
            suspicious_patterns: self.suspicious_patterns,
            hostname,
        }
    }
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DevSettings {
    /// Debug-build-only: disable TLS verification for local testing without a
    /// CA. Compiled OUT of release builds (AC-69).
    #[serde(default)]
    pub danger_accept_invalid_certs: bool,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("agent-state")
}
fn default_buffer_dir() -> Option<PathBuf> {
    None
}
fn default_heartbeat_secs() -> u64 {
    60
}
fn default_buffer_max_bytes() -> u64 {
    soc_collector_core::buffer::DEFAULT_MAX_TOTAL_BYTES
}
fn default_segment_max_bytes() -> u64 {
    soc_collector_core::buffer::DEFAULT_SEGMENT_MAX_BYTES
}
fn default_max_batch_events() -> usize {
    soc_collector_core::delivery::MAX_BATCH_EVENTS
}
fn default_max_batch_bytes() -> u64 {
    soc_collector_core::delivery::MAX_BATCH_BYTES
}
fn default_poll_ms() -> u64 {
    1000
}
fn default_base_backoff_ms() -> u64 {
    1000
}
fn default_max_backoff_ms() -> u64 {
    300_000
}
fn default_channel_capacity() -> usize {
    8192
}
fn default_eps() -> u32 {
    5
}
fn default_true() -> bool {
    true
}

impl AgentConfig {
    /// Load from a TOML file, then apply env overrides.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("reading config {}: {e}", path.display()))?;
        let mut cfg: AgentConfig =
            toml::from_str(&raw).map_err(|e| format!("parsing config: {e}"))?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SOC_AGENT_SERVER_URL") {
            self.server_url = v;
        }
        if let Ok(v) = std::env::var("SOC_AGENT_ENROLLMENT_TOKEN") {
            self.enrollment_token = Some(v);
        }
        if let Ok(v) = std::env::var("SOC_AGENT_STATE_DIR") {
            self.state_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("SOC_AGENT_SERVER_CA_PEM_PATH") {
            self.server_ca_pem_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("SOC_AGENT_PROVIDER") {
            match v.to_ascii_lowercase().as_str() {
                "etw" => self.provider = ProviderKind::Etw,
                "simulated" => self.provider = ProviderKind::Simulated,
                other => tracing::warn!("ignoring unknown SOC_AGENT_PROVIDER={other}"),
            }
        }
        if let Ok(v) = std::env::var("SOC_AGENT_SIM_SEED") {
            if let Ok(seed) = v.parse() {
                self.simulated.seed = seed;
            }
        }
    }

    pub fn buffer_dir(&self) -> PathBuf {
        self.buffer
            .dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("buffer"))
    }
}
