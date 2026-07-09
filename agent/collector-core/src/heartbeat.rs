//! Heartbeat: `POST /v1/agent/heartbeat` every 60s (config), exact payload
//! per api-contracts §10 (AC-60). 401 `DEVICE_REVOKED` stops sending (AC-59).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex, RwLock};
use tracing::{debug, error, warn};

use crate::buffer::{DiskBuffer, DroppedCounts};
use crate::http::ApiError;
use crate::provider::ProviderStatus;

/// `providers[]` element (api-contracts §10).
#[derive(Debug, Clone, Serialize)]
pub struct ProviderReport {
    pub name: String,
    pub status: ProviderStatus,
}

/// Exact §10 request payload.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatRequest {
    pub agent_version: String,
    pub os_version: String,
    pub providers: Vec<ProviderReport>,
    pub buffer_utilization_pct: f64,
    pub cpu_pct: f64,
    pub rss_mb: f64,
    pub dropped_events_since_last: DroppedCounts,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatResponse {
    pub config_version: String,
    /// Reserved for future policy pushes; empty in MVP.
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
}

#[derive(Debug)]
pub enum HeartbeatOutcome {
    Ok(HeartbeatResponse),
    Revoked,
    Failed,
}

pub async fn send_heartbeat(
    client: &reqwest::Client,
    ingest_url: &str,
    req: &HeartbeatRequest,
) -> HeartbeatOutcome {
    let url = format!("{}/v1/agent/heartbeat", ingest_url.trim_end_matches('/'));
    let resp = match client.post(&url).json(req).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("heartbeat transport error: {e}");
            return HeartbeatOutcome::Failed;
        }
    };
    if resp.status().is_success() {
        match resp.json::<HeartbeatResponse>().await {
            Ok(body) => return HeartbeatOutcome::Ok(body),
            Err(e) => {
                warn!("heartbeat response parse error: {e}");
                return HeartbeatOutcome::Failed;
            }
        }
    }
    let err = ApiError::from_response(resp).await;
    if err.status == 401 && err.code == "DEVICE_REVOKED" {
        error!("device revoked by server (heartbeat); stopping all sending (AC-59)");
        return HeartbeatOutcome::Revoked;
    }
    warn!(status = err.status, code = err.code, "heartbeat rejected");
    HeartbeatOutcome::Failed
}

/// Everything the heartbeat loop samples each interval.
pub trait HeartbeatSource: Send {
    fn sample(&mut self, buffer_utilization_pct: f64, drops: DroppedCounts) -> HeartbeatRequest;
}

/// Periodic heartbeat loop. Missed sends are simply retried at the next
/// interval (the server marks the device offline after 3 missed intervals,
/// AC-61 — that is server-side behavior).
pub async fn run(
    client: Arc<RwLock<reqwest::Client>>,
    ingest_url: String,
    interval: Duration,
    buffer: Arc<Mutex<DiskBuffer>>,
    mut source: Box<dyn HeartbeatSource>,
    mut shutdown: watch::Receiver<bool>,
    revoked: watch::Sender<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
        }
        if *shutdown.borrow() {
            return;
        }
        let (util, drops) = {
            let mut buf = buffer.lock().await;
            (buf.utilization_pct(), buf.take_drop_delta())
        };
        let req = source.sample(util, drops);
        let client = client.read().await.clone();
        match send_heartbeat(&client, &ingest_url, &req).await {
            HeartbeatOutcome::Ok(resp) => {
                debug!(config_version = resp.config_version, "heartbeat ok");
            }
            HeartbeatOutcome::Revoked => {
                let _ = revoked.send(true);
                return;
            }
            HeartbeatOutcome::Failed => { /* retry next interval */ }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_contract_keys() {
        let req = HeartbeatRequest {
            agent_version: "0.1.0".into(),
            os_version: "10.0.26100".into(),
            providers: vec![
                ProviderReport { name: "etw".into(), status: ProviderStatus::Degraded },
                ProviderReport { name: "simulated".into(), status: ProviderStatus::Ok },
            ],
            buffer_utilization_pct: 12.5,
            cpu_pct: 0.8,
            rss_mb: 42.0,
            dropped_events_since_last: DroppedCounts {
                network_activity: 10,
                process_activity: 2,
                authentication: 0,
            },
        };
        let v = serde_json::to_value(&req).unwrap();
        // Exact §10 field names.
        assert!(v.get("agent_version").is_some());
        assert!(v.get("os_version").is_some());
        assert_eq!(v["providers"][0]["name"], "etw");
        assert_eq!(v["providers"][0]["status"], "degraded");
        assert_eq!(v["providers"][1]["status"], "ok");
        assert_eq!(v["buffer_utilization_pct"], 12.5);
        assert!(v.get("cpu_pct").is_some());
        assert!(v.get("rss_mb").is_some());
        assert_eq!(v["dropped_events_since_last"]["network_activity"], 10);
        assert_eq!(v["dropped_events_since_last"]["process_activity"], 2);
        assert_eq!(v["dropped_events_since_last"]["authentication"], 0);
    }
}
