# ADR-0007: Endpoint agent implementation language and Windows packaging

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** Architect Agent (dictated) + endpoint-agent
- **Related:** ADR-0002 (first-party agent, phasing, perf budget), ADR-0006
  (enrollment/device identity), PRD Epic E8 (AC-56..69), PRD OQ-10

## Context

Epic E8 requires a Phase 1 Windows user-mode agent: ETW telemetry provider +
cross-platform simulated provider behind a pluggable abstraction (AC-62),
enrollment via CSR → per-device X.509 (ADR-0006), mTLS delivery with no
insecure-skip-verify path in release builds (AC-69), a 256 MB disk ring
buffer with documented shedding (AC-66/67), jittered backoff (AC-68), and a
hard resource budget of ≤2% average CPU and ≤250 MB RSS (AC-65, ADR-0002
non-negotiable #2). OQ-10 asks which silent-install packaging format(s) the
MVP ships (MSI vs EXE; GPO/Intune requirements per AC-56).

The build machine for this repo provides **cargo/rustc 1.87 (MSVC)**; no Go
toolchain is installed. The agent is the highest-privilege component we ship
(ADR-0002), so memory-safety of the implementation language is a direct
security property, not a preference.

## Decision

**Language: Rust (edition 2021, MSVC target for Windows).** Decided by the
Architect for:

1. **Toolchain availability** — cargo 1.87 is present on the build machine;
   the agent must build and test in this repo's CI today. No Go toolchain.
2. **No-GC footprint fit** — the AC-65 budget (≤2% CPU, ≤250 MB RSS,
   "degrade telemetry before degrading the host") favors deterministic
   memory behavior over a GC runtime; Rust gives bounded, predictable RSS
   and no pause-driven CPU spikes on end-user machines.
3. **Memory safety in the highest-privilege component** — rules out C/C++
   for new code (ADR-0002 security posture); `unsafe` is confined to the
   ETW FFI boundary in `agent/providers/etw`.
4. **First-class Windows FFI** — the `windows` crate covers ETW
   (StartTrace/EnableTraceEx2/ProcessTrace/TDH) without hand-written
   bindings; Phase 2 has credible paths (eBPF via aya on Linux; macOS
   Endpoint Security via FFI).
5. **TLS stack** — `reqwest` + `rustls` gives a memory-safe TLS client with
   native client-certificate (mTLS) support and no OpenSSL distribution
   burden on endpoints.

**Repo shape:** `agent/` is a standalone cargo workspace (own release train
per ADR-0002): `collector-core` (provider trait, event model, buffer,
delivery, enrollment, heartbeat), `providers/etw`, `providers/simulated`,
`agentd` (binary). It consumes only the HTTP contracts in `docs/contracts/`
(design doc §1 boundary rule).

**Packaging (resolves OQ-10): MSI built with cargo-wix (WiX Toolset), as a
fast-follow build task.** Analysis:

| Criterion | MSI | EXE self-installer |
|---|---|---|
| GPO software installation (AC-56 rollout path) | Native — GPO software deployment **requires** MSI | Not deployable via GPO software installation (script hacks only) |
| Intune | Line-of-business app (MSI) or Win32 `.intunewin`; both fine | Win32 `.intunewin` only |
| Silent install | Standard: `msiexec /i agent.msi /qn ENROLLMENT_TOKEN=... SERVER_URL=...` (public properties → config file + service registration) | Custom flag conventions, more support surface |
| Upgrades/rollback | UpgradeCode/versioning built in; complements (does not replace) the ADR-0002 signed self-update channel | Hand-rolled |
| Per-machine service install, ProgramData ACLs | Declarative in WiX (service unit, state-dir ACLs restricting the key file to SYSTEM/Administrators) | Imperative code we must maintain |
| Build effort | cargo-wix from the same workspace; needs WiX on build host | Lower initial effort |

Decision: **MSI is the only MVP install format**; an EXE bootstrapper is not
built (Intune wraps the MSI where needed). The MSI build (`agent/packaging/`,
cargo-wix) and Authenticode signing of MSI + binaries are **fast-follow**
tasks gated on the devsecops signing pipeline; the Phase 1 skeleton in this
repo ships the `agentd` binary + example config so QA/e2e (simulated
provider, AC-64) is not blocked on packaging.

## Alternatives Considered

- **Go:** good cross-platform story, but no toolchain on the build machine
  (blocking today), GC runtime works against the AC-65 RSS/CPU budget on
  low-end SME hardware, and Windows ETW requires cgo/syscall bindings that
  are weaker than the `windows` crate. Rejected (Architect directive).
- **C/C++:** maximal Windows API fit; rejected — memory-unsafe language for
  the highest-privilege shipped component contradicts ADR-0002's security
  posture; slower to build safely.
- **C# / .NET:** excellent Windows integration; rejected — runtime
  footprint vs 250 MB RSS bound across the fleet, Native AOT still awkward
  for ETW consumers + Windows services, and a second ecosystem for the
  Phase 2 Linux/macOS providers.
- **EXE-only packaging:** rejected as primary — breaks the GPO rollout path
  AC-56 explicitly targets.
- **MSIX:** modern, but per-machine service installation and enterprise GPO
  reach are still worse than MSI for this class of software. Revisit
  post-MVP.

## Consequences

- Easier: single static-ish binary, deterministic footprint, memory-safe
  TLS/parsing; the simulated provider compiles and runs on any OS for CI
  (AC-64); Phase 2 providers slot into the same workspace.
- Harder: `unsafe` FFI at the ETW/TDH boundary must be reviewed carefully;
  Rust build times in CI; WiX/cargo-wix is an extra build-host dependency
  when the MSI fast-follow lands.
- Accepted: MVP skeleton ships without an installer artifact — install docs
  and the console `install_command` (AC-56) can only be finalized when the
  MSI fast-follow lands; until then QA uses `agentd --config` directly.

## Security Considerations

To be reviewed by security-architect with the E8 final review: `unsafe`
blocks confined to `agent/providers/etw`; release builds contain no
insecure-skip-verify path (the only trust override is `#[cfg(debug_assertions)]`-
gated, AC-69); MSI + binary Authenticode signing rides the devsecops signing
pipeline (ADR-0002 non-negotiable #1) — unsigned artifacts never ship;
install docs must carry the SEC-13 GPO token-exposure warning.
