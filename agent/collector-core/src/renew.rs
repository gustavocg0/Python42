//! Credential renewal: `POST /v1/agent/renew-credential` over the current
//! mTLS credential, from 2/3 of certificate lifetime (ADR-0006, SEC-11).
//!
//! A fresh keypair + CSR is generated per renewal (key hygiene); the server
//! reissues the SAME device identity regardless of CSR content (SEC-8/11).
//! On success the new credential is persisted atomically and the shared
//! mTLS client is rebuilt. Failures are logged and retried on the next
//! check; the agent buffers through renewal failures (ADR-0006).

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::{error, info, warn};

use crate::enroll::generate_key_and_csr;
use crate::http::{build_mtls_client, ApiError, TlsOptions};
use crate::identity::{DeviceIdentity, IdentityStore};
use crate::model::now_rfc3339;

/// Response fields for a renewed credential.
///
/// CONTRACT NOTE (for backend-architect): api-contracts §10 says
/// "200 new cert" without listing fields; the agent expects the same
/// credential fields as the enroll 201 response. `ingest_url` /
/// `heartbeat_interval_seconds` are intentionally NOT re-read here.
#[derive(Debug, Clone, Deserialize)]
pub struct RenewResponse {
    pub certificate_pem: String,
    #[serde(default)]
    pub ca_chain_pem: String,
    pub certificate_expires_at: String,
}

#[derive(Debug)]
pub enum RenewOutcome {
    Renewed,
    NotDue,
    Revoked,
    Failed,
}

pub async fn renew_if_due(
    client: &Arc<RwLock<reqwest::Client>>,
    tls: &TlsOptions,
    store: &IdentityStore,
    identity: &mut DeviceIdentity,
) -> RenewOutcome {
    if !identity.renewal_due(time::OffsetDateTime::now_utc()) {
        return RenewOutcome::NotDue;
    }

    let material = match generate_key_and_csr() {
        Ok(m) => m,
        Err(e) => {
            error!("renewal keygen failed: {e}");
            return RenewOutcome::Failed;
        }
    };

    let url = format!(
        "{}/v1/agent/renew-credential",
        identity.ingest_url.trim_end_matches('/')
    );
    let current = client.read().await.clone();
    let resp = match current
        .post(&url)
        .json(&serde_json::json!({ "csr_pem": material.csr_pem }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("renewal transport error: {e}");
            return RenewOutcome::Failed;
        }
    };

    if !resp.status().is_success() {
        let err = ApiError::from_response(resp).await;
        if err.status == 401 && err.code == "DEVICE_REVOKED" {
            error!("device revoked (renewal); stopping all sending (AC-59)");
            return RenewOutcome::Revoked;
        }
        warn!(status = err.status, code = err.code, "renewal rejected; will retry");
        return RenewOutcome::Failed;
    }

    let body: RenewResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            warn!("renewal response parse error: {e}");
            return RenewOutcome::Failed;
        }
    };

    identity.certificate_expires_at = body.certificate_expires_at.clone();
    identity.credential_issued_at = now_rfc3339();
    if let Err(e) = store.save_credential(
        identity,
        &material.key_pem,
        &body.certificate_pem,
        &body.ca_chain_pem,
    ) {
        error!("failed to persist renewed credential: {e}");
        return RenewOutcome::Failed;
    }

    // Rebuild the shared mTLS client with the new credential.
    match store
        .client_identity_pem()
        .map_err(|e| e.to_string())
        .and_then(|pem| build_mtls_client(tls, &pem).map_err(|e| e.to_string()))
    {
        Ok(new_client) => {
            *client.write().await = new_client;
            info!(
                expires_at = identity.certificate_expires_at,
                "device credential renewed"
            );
            RenewOutcome::Renewed
        }
        Err(e) => {
            error!("renewed credential unusable: {e}");
            RenewOutcome::Failed
        }
    }
}

/// Periodic renewal check loop (default every 15 minutes).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: Arc<RwLock<reqwest::Client>>,
    tls: TlsOptions,
    store: IdentityStore,
    mut identity: DeviceIdentity,
    check_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    revoked: watch::Sender<bool>,
) {
    let mut ticker = tokio::time::interval(check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately: check renewal right after startup
    // (the agent may have been off past the renewal point).
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
        }
        if *shutdown.borrow() {
            return;
        }
        match renew_if_due(&client, &tls, &store, &mut identity).await {
            RenewOutcome::Revoked => {
                let _ = revoked.send(true);
                return;
            }
            RenewOutcome::Renewed | RenewOutcome::NotDue | RenewOutcome::Failed => {}
        }
    }
}
