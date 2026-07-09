# Packaging (fast-follow)

Decision recorded in `docs/adr/0007-endpoint-agent-language-packaging.md`
(resolves PRD OQ-10):

- **MVP install format: MSI**, built with **cargo-wix** (WiX Toolset) from the
  `agentd` binary. MSI is the only format that supports GPO software
  installation, which AC-56's silent fleet rollout targets; Intune wraps the
  same MSI.
- **Not built yet.** The MSI + Authenticode signing of the MSI and binaries
  ride the devsecops signing pipeline (ADR-0002 non-negotiable #1: signed
  artifacts, no unsigned ships). Until it lands, QA/e2e uses `agentd --config`
  directly (the simulated provider needs no installer).

## Planned MSI responsibilities

- Install `agentd.exe` per-machine and register it as an auto-start Windows
  service.
- Create the state directory under `%ProgramData%` with NTFS ACLs restricting
  it to `SYSTEM` + `Administrators` (protects `device_key.pem`).
- Accept silent-install public properties for enrollment:
  `msiexec /i agent.msi /qn ENROLLMENT_TOKEN=... SERVER_URL=...`
  written into the service's config file / environment.
- Use `UpgradeCode` + versioning for in-place upgrades; this complements (does
  not replace) the ADR-0002 signed self-update + staged-rollout channel.

## Install docs must carry (SEC-13)

A warning that GPO startup scripts expose the enrollment token to all
domain-readable storage, with guidance to use the shortest practical token
expiry and to revoke the token immediately after rollout.
