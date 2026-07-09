//! Device identity persistence (ADR-0006).
//!
//! State directory contents:
//! - `device_key.pem`   — the device private key (never leaves the device)
//! - `device_cert.pem`  — the server-issued client certificate
//! - `ca_chain.pem`     — issuing chain returned at enrollment/renewal
//! - `identity.json`    — device_id + endpoints + certificate timing
//!
//! Permissions: on Unix the directory is 0700 and the key file 0600. On
//! Windows, NTFS ACLs restricting the state dir to SYSTEM/Administrators are
//! the installer's job (MSI fast-follow per ADR-0007); the skeleton relies
//! on the parent directory's inherited ACLs and documents this. DPAPI/TPM
//! key protection is the ADR-0006 roadmap item for the packaged build.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const KEY_FILE: &str = "device_key.pem";
pub const CERT_FILE: &str = "device_cert.pem";
pub const CHAIN_FILE: &str = "ca_chain.pem";
pub const IDENTITY_FILE: &str = "identity.json";

/// Persisted metadata about the enrolled identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    /// Base URL for agent routes (from the enrollment response `ingest_url`).
    pub ingest_url: String,
    pub heartbeat_interval_seconds: u64,
    /// RFC3339, from the server.
    pub certificate_expires_at: String,
    /// RFC3339, when the current credential was obtained (enroll or renew).
    pub credential_issued_at: String,
}

impl DeviceIdentity {
    /// Renewal is due from 2/3 of the certificate lifetime (ADR-0006/SEC-11).
    pub fn renewal_due(&self, now: OffsetDateTime) -> bool {
        let (Ok(issued), Ok(expires)) = (
            OffsetDateTime::parse(&self.credential_issued_at, &Rfc3339),
            OffsetDateTime::parse(&self.certificate_expires_at, &Rfc3339),
        ) else {
            // Unparseable timing: renew eagerly rather than expire silently.
            return true;
        };
        if expires <= issued {
            return true;
        }
        let lifetime = expires - issued;
        now >= issued + lifetime * 2 / 3
    }
}

pub struct IdentityStore {
    dir: PathBuf,
}

impl IdentityStore {
    pub fn new(state_dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = state_dir.into();
        fs::create_dir_all(&dir)?;
        restrict_dir(&dir)?;
        Ok(IdentityStore { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_enrolled(&self) -> bool {
        self.dir.join(IDENTITY_FILE).exists()
            && self.dir.join(KEY_FILE).exists()
            && self.dir.join(CERT_FILE).exists()
    }

    pub fn load(&self) -> io::Result<DeviceIdentity> {
        let raw = fs::read_to_string(self.dir.join(IDENTITY_FILE))?;
        serde_json::from_str(&raw).map_err(io::Error::other)
    }

    /// Persist a freshly issued credential (enrollment or renewal).
    /// Writes are atomic (tmp + rename) so a crash never leaves a torn key.
    pub fn save_credential(
        &self,
        identity: &DeviceIdentity,
        key_pem: &str,
        cert_pem: &str,
        ca_chain_pem: &str,
    ) -> io::Result<()> {
        write_atomic(&self.dir.join(KEY_FILE), key_pem.as_bytes(), true)?;
        write_atomic(&self.dir.join(CERT_FILE), cert_pem.as_bytes(), false)?;
        write_atomic(&self.dir.join(CHAIN_FILE), ca_chain_pem.as_bytes(), false)?;
        let json = serde_json::to_string_pretty(identity).map_err(io::Error::other)?;
        write_atomic(&self.dir.join(IDENTITY_FILE), json.as_bytes(), false)?;
        Ok(())
    }

    /// PEM bundle (cert + chain + key) for `reqwest::Identity::from_pem`.
    pub fn client_identity_pem(&self) -> io::Result<Vec<u8>> {
        let cert = fs::read(self.dir.join(CERT_FILE))?;
        let chain = fs::read(self.dir.join(CHAIN_FILE)).unwrap_or_default();
        let key = fs::read(self.dir.join(KEY_FILE))?;
        let mut out = Vec::with_capacity(cert.len() + chain.len() + key.len() + 2);
        out.extend_from_slice(&cert);
        if !cert.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(&chain);
        if !chain.is_empty() && !chain.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(&key);
        Ok(out)
    }
}

fn write_atomic(path: &Path, data: &[u8], restrict: bool) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    if restrict {
        restrict_file(&tmp)?;
    }
    // On Windows, rename fails if the target exists; remove first.
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> io::Result<()> {
    // Windows: state-dir ACLs (SYSTEM/Administrators only) are set by the
    // MSI installer (ADR-0007 fast-follow). Documented in agent/README.md.
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn identity(issued: &str, expires: &str) -> DeviceIdentity {
        DeviceIdentity {
            device_id: "dev_01TEST".into(),
            ingest_url: "https://ingest.example".into(),
            heartbeat_interval_seconds: 60,
            certificate_expires_at: expires.into(),
            credential_issued_at: issued.into(),
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = IdentityStore::new(dir.path().join("state")).unwrap();
        assert!(!store.is_enrolled());
        let id = identity("2026-07-01T00:00:00Z", "2026-09-29T00:00:00Z");
        store
            .save_credential(&id, "KEYPEM", "CERTPEM", "CHAINPEM")
            .unwrap();
        assert!(store.is_enrolled());
        let loaded = store.load().unwrap();
        assert_eq!(loaded.device_id, "dev_01TEST");
        let pem = store.client_identity_pem().unwrap();
        let s = String::from_utf8(pem).unwrap();
        assert!(s.contains("CERTPEM") && s.contains("CHAINPEM") && s.contains("KEYPEM"));
        // cert before key so rustls sees the chain first
        assert!(s.find("CERTPEM").unwrap() < s.find("KEYPEM").unwrap());
    }

    #[test]
    fn renewal_due_at_two_thirds_lifetime() {
        // 90-day cert issued 2026-07-01 → renewal from ~2026-08-30.
        let id = identity("2026-07-01T00:00:00Z", "2026-09-29T00:00:00Z");
        let before = OffsetDateTime::parse("2026-08-01T00:00:00Z", &Rfc3339).unwrap();
        let after = OffsetDateTime::parse("2026-09-01T00:00:00Z", &Rfc3339).unwrap();
        assert!(!id.renewal_due(before));
        assert!(id.renewal_due(after));
    }

    #[test]
    fn renewal_due_on_bad_timestamps() {
        let id = identity("garbage", "2026-09-29T00:00:00Z");
        assert!(id.renewal_due(OffsetDateTime::now_utc()));
    }
}
