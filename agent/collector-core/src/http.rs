//! HTTP client construction and error-envelope handling.
//!
//! AC-69: every connection validates the server certificate chain. The only
//! trust configuration available in release builds is an *additional* PEM
//! trust anchor (`server_ca_pem`) — the same code path serves the compose
//! dev CA and a production private PKI (ADR-0006 §5). There is NO
//! insecure-skip-verify path in release builds: the
//! `danger_accept_invalid_certs` override only exists under
//! `#[cfg(debug_assertions)]` and is compiled out of release profiles.

use std::time::Duration;

use thiserror::Error;

use crate::AGENT_VERSION;

#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Optional extra trust anchor(s), PEM bundle (e.g. the stamp/dev CA).
    pub extra_trust_anchors_pem: Option<String>,
    /// Debug-build-only escape hatch for local development WITHOUT a CA.
    /// Does not exist in release builds (AC-69).
    #[cfg(debug_assertions)]
    pub danger_accept_invalid_certs: bool,
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("invalid TLS/client configuration: {0}")]
    Config(String),
    #[error("release builds require https:// server URLs, got {0}")]
    InsecureUrl(String),
}

/// Enforce https in release builds. Debug builds may use http:// for
/// mock-server integration tests only.
pub fn validate_server_url(url: &str) -> Result<(), HttpError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    {
        if url.starts_with("http://") {
            tracing::warn!(url, "using plaintext http server URL (debug build only)");
            return Ok(());
        }
    }
    Err(HttpError::InsecureUrl(url.to_string()))
}

fn base_builder(tls: &TlsOptions) -> Result<reqwest::ClientBuilder, HttpError> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .user_agent(format!("soc-agentd/{AGENT_VERSION}"))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60));

    if let Some(pem) = &tls.extra_trust_anchors_pem {
        for cert in split_pem_certs(pem) {
            let c = reqwest::Certificate::from_pem(cert.as_bytes())
                .map_err(|e| HttpError::Config(format!("trust anchor: {e}")))?;
            b = b.add_root_certificate(c);
        }
    }

    #[cfg(debug_assertions)]
    if tls.danger_accept_invalid_certs {
        tracing::warn!("TLS certificate validation DISABLED (debug build only)");
        b = b.danger_accept_invalid_certs(true);
    }

    Ok(b)
}

/// Client for enrollment: server-verified TLS, no client certificate yet
/// (api-contracts §10: enroll is authorized by the enrollment token).
pub fn build_enroll_client(tls: &TlsOptions) -> Result<reqwest::Client, HttpError> {
    base_builder(tls)?
        .build()
        .map_err(|e| HttpError::Config(e.to_string()))
}

/// mTLS client presenting the device certificate (AC-57/69).
/// `identity_pem` = device cert + chain + private key PEM bundle.
pub fn build_mtls_client(
    tls: &TlsOptions,
    identity_pem: &[u8],
) -> Result<reqwest::Client, HttpError> {
    let identity = reqwest::Identity::from_pem(identity_pem)
        .map_err(|e| HttpError::Config(format!("device identity: {e}")))?;
    base_builder(tls)?
        .identity(identity)
        .build()
        .map_err(|e| HttpError::Config(e.to_string()))
}

fn split_pem_certs(bundle: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = bundle;
    while let Some(start) = rest.find(BEGIN) {
        let Some(end) = rest[start..].find(END) else { break };
        let cert = &rest[start..start + end + END.len()];
        out.push(cert.to_string());
        rest = &rest[start + end + END.len()..];
    }
    out
}

/// Parsed non-2xx response per the api-contracts §1 error envelope:
/// `{"error": {"code": ..., "message": ..., "retry_after_seconds"?}}`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub retry_after_seconds: Option<u64>,
}

impl ApiError {
    pub async fn from_response(resp: reqwest::Response) -> ApiError {
        let status = resp.status().as_u16();
        let header_retry = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let (code, body_retry) = match resp.json::<serde_json::Value>().await {
            Ok(v) => (
                v.pointer("/error/code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                v.pointer("/error/retry_after_seconds").and_then(|r| r.as_u64()),
            ),
            Err(_) => ("UNKNOWN".to_string(), None),
        };
        ApiError { status, code, retry_after_seconds: header_retry.or(body_retry) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_always_allowed() {
        assert!(validate_server_url("https://ingest.example").is_ok());
    }

    #[test]
    fn garbage_scheme_rejected() {
        assert!(validate_server_url("ftp://x").is_err());
        assert!(validate_server_url("ingest.example").is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn http_allowed_only_in_debug() {
        assert!(validate_server_url("http://127.0.0.1:9999").is_ok());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn http_rejected_in_release() {
        assert!(validate_server_url("http://127.0.0.1:9999").is_err());
    }

    #[test]
    fn pem_bundle_split() {
        let bundle = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
                      -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let certs = split_pem_certs(bundle);
        assert_eq!(certs.len(), 2);
        assert!(certs[0].contains("AAA"));
        assert!(certs[1].contains("BBB"));
    }
}
