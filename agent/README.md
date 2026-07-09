# Endpoint Agent — Phase 1 skeleton

First-party endpoint agent (PRD Epic E8; ADR-0002 Phase 1 = Windows user-mode
only, NO kernel driver). Cargo workspace, owned end-to-end by the
endpoint-agent domain. Language/packaging rationale: `docs/adr/0007-endpoint-agent-language-packaging.md`.

## Workspace layout

| Crate | Purpose |
|---|---|
| `collector-core` | Provider trait (AC-62), wire event model (event-schema §3/§5), disk ring buffer + shedding (AC-66/67), jittered backoff (AC-68), enrollment/identity (ADR-0006), mTLS HTTP (AC-69), batch delivery, heartbeat, credential renewal |
| `providers/etw` | Windows ETW provider — real Kernel-Process consumer for process events; stub off-Windows |
| `providers/simulated` | Cross-platform generator (process/network/auth + suspicious scenarios), deterministic seed mode for CI (AC-64) |
| `agentd` | The binary: TOML config, provider selection by config, main loop |

## Build & test

```
cd agent
cargo build            # debug
cargo build --release  # release: no insecure-skip-verify path (AC-69)
cargo test             # unit + integration (wiremock) tests
cargo clippy --all-targets
```

Toolchain: cargo 1.87 (MSVC) on Windows. `time` and `wiremock` are pinned in
`Cargo.lock` to 1.87-compatible versions.

## Running

```
cp agent.example.toml agent.toml    # edit server_url + token
SOC_AGENT_ENROLLMENT_TOKEN=et_xxx ./target/debug/agentd agent.toml
```

Provider is chosen by config (`provider = "etw" | "simulated"`), never at
compile time (AC-62). On non-Windows hosts use `simulated`.

## State directory

`{state_dir}/` holds `device_key.pem` (0600 on Unix), `device_cert.pem`,
`ca_chain.pem`, `identity.json`, and `buffer/` (per-class segment files).
On Windows, NTFS ACLs restricting this directory to SYSTEM/Administrators are
the MSI installer's responsibility (ADR-0007 fast-follow); DPAPI/TPM key
protection is the ADR-0006 roadmap item for the packaged build.

## Local buffering and shedding (AC-65/66/67)

Events are written to a per-class disk ring buffer (default 256 MiB cap).
Replay is oldest-first across classes by a global sequence, so the server
deduplicates by the persisted `source_event_id` (AC-34). When the cap would be
exceeded, whole oldest segments are dropped in this **documented order**:

1. `network_activity` (dropped first)
2. `process_activity`
3. `authentication` (retained longest)

Per-class drop counts are reported as deltas in the next heartbeat
(`dropped_events_since_last`).

## ETW coverage — honest status (AC-63)

The ETW provider implements a **real** real-time consumer session subscribed to
`Microsoft-Windows-Kernel-Process`, emitting **process-start** (and
best-effort process-stop) events parsed with TDH. Gaps for this MVP skeleton,
tracked as fast-follow:

- **Network events:** not yet collected (needs Kernel-Network TDH parsing).
- **Authentication events:** not yet collected (needs the SYSTEM-only
  Security-Auditing channel + audit policy; wire up in the service/MSI build).
- **cmd_line / process owner / image sha256:** command line taken from the
  Kernel-Process event where present, else falls back to `exe_path`; owner and
  hash are not resolved in Phase 1.

`network_activity` and `authentication` are fully exercised in CI by the
**simulated** provider (AC-64). The ETW path has an elevated smoke test:
`cargo test -p soc-provider-etw -- --ignored --nocapture` on an elevated
Windows host.

If ETW session setup fails (e.g. not elevated), the agent keeps running and
reports provider status `failed`/`degraded` in its heartbeat — the provider
never takes down the agent or the host (crash isolation, ADR-0002 #3).

## Config keys QA needs for the simulated provider in CI (AC-64)

```toml
provider = "simulated"

[simulated]
events_per_second = 50     # throughput for the e2e run
seed = 1234                # NON-ZERO => deterministic, reproducible stream
suspicious_patterns = true # emit det- tripping scenarios
```

Equivalent env: `SOC_AGENT_PROVIDER=simulated`, `SOC_AGENT_SIM_SEED=1234`.
With a fixed non-zero seed the event sequence (including `source_event_id`
UUIDs) is byte-identical across runs modulo `event_time`, so CI can assert on
exact detections. Suspicious scenarios generated: failed-logon brute force
then success, `winword.exe` -> encoded `powershell.exe` + outbound to
`185.220.101.7:443`, and an lsass credential-dump (`comsvcs.dll MiniDump`)
pattern.

## Packaging

MVP install format is an MSI (cargo-wix), built as a fast-follow gated on the
devsecops signing pipeline. See `packaging/README.md` and ADR-0007.
