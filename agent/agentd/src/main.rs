//! `agentd` — the Phase 1 endpoint agent binary (PRD Epic E8, ADR-0002/0006/0007).
//!
//! Lifecycle: load config → enroll (if no local identity) → build mTLS client
//! → open disk buffer → start the configured telemetry provider → run the
//! drain, delivery, heartbeat, and renewal tasks concurrently until Ctrl-C or
//! server-driven revocation (AC-59).
//!
//! Crash isolation (ADR-0002 #3): provider start failure is tolerated — the
//! agent keeps running and reports provider `failed` in its heartbeat; the
//! provider can never take down the agent or the host.

mod config;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex, RwLock};
use tracing::{error, info, warn};

use soc_collector_core::buffer::{BufferConfig, DiskBuffer, DroppedCounts};
use soc_collector_core::delivery::{Deliverer, DeliveryConfig};
use soc_collector_core::enroll::{enroll, generate_key_and_csr, EnrollError};
use soc_collector_core::health::{self, HealthSampler};
use soc_collector_core::heartbeat::{
    self, HeartbeatRequest, HeartbeatSource, ProviderReport,
};
use soc_collector_core::http::{build_enroll_client, build_mtls_client, validate_server_url, TlsOptions};
use soc_collector_core::identity::{DeviceIdentity, IdentityStore};
use soc_collector_core::model::{now_rfc3339, AgentEvent};
use soc_collector_core::provider::{EventSink, ProviderStatus, TelemetryProvider};
use soc_collector_core::renew;
use soc_collector_core::AGENT_VERSION;

use config::{AgentConfig, ProviderKind};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var("SOC_AGENT_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("agent.toml"));

    if let Err(e) = run(config_path).await {
        error!("agent fatal error: {e}");
        std::process::exit(1);
    }
}

async fn run(config_path: PathBuf) -> Result<(), String> {
    let cfg = AgentConfig::load(&config_path)?;
    info!(version = AGENT_VERSION, provider = ?cfg.provider, "starting agentd");
    validate_server_url(&cfg.server_url).map_err(|e| e.to_string())?;

    let tls = build_tls_options(&cfg)?;
    let store = IdentityStore::new(&cfg.state_dir).map_err(|e| e.to_string())?;

    // --- Enrollment (once) -------------------------------------------------
    let identity = if store.is_enrolled() {
        let id = store.load().map_err(|e| e.to_string())?;
        info!(device_id = id.device_id, "loaded existing device identity");
        id
    } else {
        enroll_device(&cfg, &tls, &store).await?
    };

    // --- mTLS client (shared, swappable on renewal) ------------------------
    let identity_pem = store.client_identity_pem().map_err(|e| e.to_string())?;
    let mtls = build_mtls_client(&tls, &identity_pem).map_err(|e| e.to_string())?;
    let client = Arc::new(RwLock::new(mtls));

    // --- Disk buffer -------------------------------------------------------
    let buf_cfg = BufferConfig {
        dir: cfg.buffer_dir(),
        max_total_bytes: cfg.buffer.max_bytes,
        segment_max_bytes: cfg.buffer.segment_max_bytes,
    };
    let buffer = Arc::new(Mutex::new(DiskBuffer::open(buf_cfg).map_err(|e| e.to_string())?));

    // --- Provider ----------------------------------------------------------
    let (tx, rx) = tokio::sync::mpsc::channel::<AgentEvent>(cfg.delivery.channel_capacity);
    let sink = EventSink::new(tx);
    let host = health::collect_host();
    let mut provider: Box<dyn TelemetryProvider> = match cfg.provider {
        ProviderKind::Etw => Box::new(soc_provider_etw::EtwProvider::new()),
        ProviderKind::Simulated => Box::new(soc_provider_simulated::SimulatedProvider::new(
            cfg.simulated.to_sim_config(host.hostname.clone()),
        )),
    };
    let provider_name = provider.name();
    match provider.start(sink) {
        Ok(()) => info!(provider = provider_name, "telemetry provider started"),
        Err(e) => warn!(
            provider = provider_name,
            "provider failed to start (agent continues, reports degraded): {e}"
        ),
    }
    let provider = Arc::new(Mutex::new(provider));

    // --- Coordination signals ---------------------------------------------
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (revoked_tx, mut revoked_rx) = watch::channel(false);

    // Effective heartbeat interval: the server value (from enrollment) wins;
    // the config key is the pre-enrollment fallback.
    let hb_secs = if identity.heartbeat_interval_seconds > 0 {
        identity.heartbeat_interval_seconds
    } else {
        cfg.heartbeat_interval_seconds
    };
    let hb_interval = Duration::from_secs(hb_secs.max(1));

    // --- Spawn workers -----------------------------------------------------
    let drain = tokio::spawn(drain_loop(rx, buffer.clone(), shutdown_rx.clone()));

    let deliverer = Deliverer::new(
        client.clone(),
        identity.ingest_url.clone(),
        DeliveryConfig {
            max_batch_events: cfg.delivery.max_batch_events,
            max_batch_bytes: cfg.delivery.max_batch_bytes,
            poll_interval: Duration::from_millis(cfg.delivery.poll_interval_ms),
            backoff_base: Duration::from_millis(cfg.delivery.base_backoff_ms),
            backoff_cap: Duration::from_millis(cfg.delivery.max_backoff_ms),
        },
    );
    let delivery = tokio::spawn(deliverer.run(buffer.clone(), shutdown_rx.clone(), revoked_tx.clone()));

    let hb_source = Box::new(AgentHeartbeatSource {
        sampler: HealthSampler::new(),
        os_version: health::os_version_string(),
        provider: provider.clone(),
    });
    let heartbeat = tokio::spawn(heartbeat::run(
        client.clone(),
        identity.ingest_url.clone(),
        hb_interval,
        buffer.clone(),
        hb_source,
        shutdown_rx.clone(),
        revoked_tx.clone(),
    ));

    let renewal = tokio::spawn(renew::run(
        client.clone(),
        tls.clone(),
        IdentityStore::new(&cfg.state_dir).map_err(|e| e.to_string())?,
        identity.clone(),
        Duration::from_secs(15 * 60),
        shutdown_rx.clone(),
        revoked_tx.clone(),
    ));

    // --- Wait for shutdown or revocation -----------------------------------
    tokio::select! {
        _ = shutdown_signal() => info!("shutdown signal received"),
        _ = revoked_rx.changed() => {
            if *revoked_rx.borrow() {
                error!("device revoked by server; stopping telemetry and delivery (AC-59)");
            }
        }
    }

    let _ = shutdown_tx.send(true);
    provider.lock().await.stop();
    let _ = tokio::join!(drain, delivery, heartbeat, renewal);
    info!("agentd stopped");
    Ok(())
}
/// Resolve when the process is asked to stop: Ctrl-C (SIGINT) everywhere,
/// plus SIGTERM on Unix so `docker stop` / systemd shut the agent down
/// gracefully when agentd runs as PID 1 in a container.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to install SIGTERM handler ({e}); falling back to Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn build_tls_options(cfg: &AgentConfig) -> Result<TlsOptions, String> {
    let extra = match &cfg.server_ca_pem_path {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("reading server CA: {e}"))?),
        None => None,
    };
    Ok(TlsOptions {
        extra_trust_anchors_pem: extra,
        #[cfg(debug_assertions)]
        danger_accept_invalid_certs: cfg.dev.danger_accept_invalid_certs,
    })
}

async fn enroll_device(
    cfg: &AgentConfig,
    tls: &TlsOptions,
    store: &IdentityStore,
) -> Result<DeviceIdentity, String> {
    let token = cfg
        .enrollment_token
        .as_ref()
        .ok_or("no enrollment token configured and device is not enrolled")?;
    let material = generate_key_and_csr().map_err(|e| e.to_string())?;
    let host = health::collect_host();
    let client = build_enroll_client(tls).map_err(|e| e.to_string())?;

    info!(hostname = host.hostname, "enrolling device");
    let resp = match enroll(&client, &cfg.server_url, token, &material.csr_pem, &host, AGENT_VERSION)
        .await
    {
        Ok(r) => r,
        Err(EnrollError::TokenExpired) => return Err("enrollment token expired".into()),
        Err(EnrollError::TokenRevoked) => return Err("enrollment token revoked".into()),
        Err(EnrollError::TokenInvalid) => return Err("enrollment token invalid".into()),
        Err(EnrollError::EndpointCapReached) => {
            return Err("tenant endpoint cap reached; enrollment refused".into())
        }
        Err(EnrollError::TenantFrozen) => return Err("tenant is frozen; enrollment refused".into()),
        Err(e) => return Err(format!("enrollment failed: {e}")),
    };

    let identity = DeviceIdentity {
        device_id: resp.device_id.clone(),
        ingest_url: resp.ingest_url.clone(),
        heartbeat_interval_seconds: resp.heartbeat_interval_seconds,
        certificate_expires_at: resp.certificate_expires_at.clone(),
        credential_issued_at: now_rfc3339(),
    };
    store
        .save_credential(&identity, &material.key_pem, &resp.certificate_pem, &resp.ca_chain_pem)
        .map_err(|e| format!("persisting credential: {e}"))?;
    info!(device_id = identity.device_id, "device enrolled");
    Ok(identity)
}

/// Move events from the provider channel into the durable disk buffer.
async fn drain_loop(
    mut rx: tokio::sync::mpsc::Receiver<AgentEvent>,
    buffer: Arc<Mutex<DiskBuffer>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(ev) => {
                        let mut buf = buffer.lock().await;
                        if let Err(e) = buf.enqueue(&ev) {
                            error!("failed to buffer event: {e}");
                        }
                    }
                    None => return, // all providers dropped their senders
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Drain what's already queued, then exit.
                    while let Ok(ev) = rx.try_recv() {
                        let mut buf = buffer.lock().await;
                        let _ = buf.enqueue(&ev);
                    }
                    return;
                }
            }
        }
    }
}

struct AgentHeartbeatSource {
    sampler: HealthSampler,
    os_version: String,
    provider: Arc<Mutex<Box<dyn TelemetryProvider>>>,
}

impl HeartbeatSource for AgentHeartbeatSource {
    fn sample(&mut self, buffer_utilization_pct: f64, drops: DroppedCounts) -> HeartbeatRequest {
        let (cpu_pct, rss_mb) = self.sampler.sample();
        let (name, status) = match self.provider.try_lock() {
            Ok(p) => (p.name().to_string(), p.status()),
            Err(_) => ("unknown".to_string(), ProviderStatus::Degraded),
        };
        HeartbeatRequest {
            agent_version: AGENT_VERSION.to_string(),
            os_version: self.os_version.clone(),
            providers: vec![ProviderReport { name, status }],
            buffer_utilization_pct,
            cpu_pct,
            rss_mb,
            dropped_events_since_last: drops,
        }
    }
}
