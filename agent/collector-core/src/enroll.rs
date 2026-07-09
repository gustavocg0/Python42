//! Enrollment: keypair + CSR → `POST /v1/agent/enroll` (api-contracts §10,
//! ADR-0006, AC-56..58).
//!
//! SEC-8: the CSR is proof-of-possession only. We generate an ECDSA P-256
//! key locally (never leaves the device) and an empty-subject CSR; the
//! server ignores all client-supplied subject/SAN content and assigns
//! `CN=<device_id>` itself.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http::ApiError;
use crate::model::Host;

#[derive(Debug, Error)]
pub enum EnrollError {
    // Distinct machine-readable failures per AC-58:
    #[error("enrollment token expired")]
    TokenExpired,
    #[error("enrollment token revoked")]
    TokenRevoked,
    #[error("enrollment token invalid")]
    TokenInvalid,
    #[error("tenant endpoint cap reached")]
    EndpointCapReached,
    #[error("tenant frozen")]
    TenantFrozen,
    #[error("rate limited (retry after {retry_after_seconds:?}s)")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("server unavailable (status {status}, code {code})")]
    Unavailable { status: u16, code: String },
    #[error("unexpected server response: status {status}, code {code}")]
    Unexpected { status: u16, code: String },
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid enrollment response: {0}")]
    BadResponse(String),
}

#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    csr_pem: &'a str,
    host: &'a Host,
    agent_version: &'a str,
}

/// 201 response per api-contracts §10.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub certificate_pem: String,
    pub ca_chain_pem: String,
    /// RFC3339.
    pub certificate_expires_at: String,
    /// Base URL for agent routes (`/v1/agent/events`, `/v1/agent/heartbeat`,
    /// `/v1/agent/renew-credential`).
    pub ingest_url: String,
    pub heartbeat_interval_seconds: u64,
}

/// A locally generated device keypair + CSR.
pub struct DeviceKeyMaterial {
    pub key_pem: String,
    pub csr_pem: String,
}

/// Generate an ECDSA P-256 keypair and an empty-subject CSR (SEC-8).
pub fn generate_key_and_csr() -> Result<DeviceKeyMaterial, EnrollError> {
    let key = rcgen::KeyPair::generate().map_err(|e| EnrollError::Crypto(e.to_string()))?;
    let params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| EnrollError::Crypto(e.to_string()))?;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| EnrollError::Crypto(e.to_string()))?;
    let csr_pem = csr.pem().map_err(|e| EnrollError::Crypto(e.to_string()))?;
    Ok(DeviceKeyMaterial { key_pem: key.serialize_pem(), csr_pem })
}

/// `POST {server_url}/v1/agent/enroll`. The client must be an
/// enrollment-capable client (server-verified TLS, no client cert).
pub async fn enroll(
    client: &reqwest::Client,
    server_url: &str,
    enrollment_token: &str,
    csr_pem: &str,
    host: &Host,
    agent_version: &str,
) -> Result<EnrollResponse, EnrollError> {
    let url = format!("{}/v1/agent/enroll", server_url.trim_end_matches('/'));
    let req = EnrollRequest { enrollment_token, csr_pem, host, agent_version };
    let resp = client.post(&url).json(&req).send().await?;

    if resp.status().as_u16() == 201 {
        let body: EnrollResponse = resp
            .json()
            .await
            .map_err(|e| EnrollError::BadResponse(e.to_string()))?;
        if body.device_id.is_empty() || body.certificate_pem.is_empty() {
            return Err(EnrollError::BadResponse("missing device_id/certificate".into()));
        }
        return Ok(body);
    }

    let err = ApiError::from_response(resp).await;
    Err(map_enroll_error(err))
}

fn map_enroll_error(err: ApiError) -> EnrollError {
    match (err.status, err.code.as_str()) {
        (410, _) | (_, "ENROLLMENT_TOKEN_EXPIRED") => EnrollError::TokenExpired,
        (_, "ENROLLMENT_TOKEN_REVOKED") => EnrollError::TokenRevoked,
        (_, "ENROLLMENT_TOKEN_INVALID") => EnrollError::TokenInvalid,
        (_, "ENDPOINT_CAP_REACHED") => EnrollError::EndpointCapReached,
        (_, "TENANT_FROZEN") => EnrollError::TenantFrozen,
        (429, _) | (_, "RATE_LIMITED") => {
            EnrollError::RateLimited { retry_after_seconds: err.retry_after_seconds }
        }
        (s, _) if s >= 500 => EnrollError::Unavailable { status: s, code: err.code },
        (s, _) => EnrollError::Unexpected { status: s, code: err.code },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_is_pem_and_key_is_pkcs8() {
        let m = generate_key_and_csr().unwrap();
        assert!(m.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(m.key_pem.contains("BEGIN PRIVATE KEY"));
        // Fresh keys every call (never reuse across devices, SEC-8).
        let m2 = generate_key_and_csr().unwrap();
        assert_ne!(m.key_pem, m2.key_pem);
    }

    #[test]
    fn error_mapping_is_distinct() {
        let e = |status, code: &str| ApiError {
            status,
            code: code.into(),
            retry_after_seconds: None,
        };
        assert!(matches!(
            map_enroll_error(e(410, "ENROLLMENT_TOKEN_EXPIRED")),
            EnrollError::TokenExpired
        ));
        assert!(matches!(
            map_enroll_error(e(403, "ENROLLMENT_TOKEN_REVOKED")),
            EnrollError::TokenRevoked
        ));
        assert!(matches!(
            map_enroll_error(e(403, "ENROLLMENT_TOKEN_INVALID")),
            EnrollError::TokenInvalid
        ));
        assert!(matches!(
            map_enroll_error(e(403, "ENDPOINT_CAP_REACHED")),
            EnrollError::EndpointCapReached
        ));
        assert!(matches!(map_enroll_error(e(403, "TENANT_FROZEN")), EnrollError::TenantFrozen));
        assert!(matches!(
            map_enroll_error(e(429, "RATE_LIMITED")),
            EnrollError::RateLimited { .. }
        ));
        assert!(matches!(
            map_enroll_error(e(503, "SERVICE_UNAVAILABLE")),
            EnrollError::Unavailable { .. }
        ));
    }
}
