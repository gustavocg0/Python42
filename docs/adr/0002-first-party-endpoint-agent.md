# ADR-0002: Build a first-party endpoint agent

- **Status:** Accepted
- **Date:** 2026-07-07
- **Deciders:** Architect Agent + product owner decision; solution-architect,
  security-architect, endpoint-agent

## Context

Launch telemetry includes "endpoint agents (EDR-lite)" and two premium
differentiators (automated response, AI investigation depth) require deep
endpoint access: host isolation, process kill, file quarantine, rich
process/network telemetry. Alternatives (wrapping osquery/Sysmon,
integrating Microsoft Defender) were considered and rejected by the
product owner in favor of a first-party agent.

## Decision

Build a first-party, cross-platform endpoint agent as a distinct product
line, delivered in phases. The agent is the strategic moat for response
capability and per-endpoint pricing.

## Phasing (de-risking plan)

- **Phase 1 — launch (Windows, user mode only):** ETW-based process,
  network, and authentication telemetry; embedded osquery for inventory;
  response actions via supported OS interfaces (firewall-based host
  isolation, process termination, session logoff). NO kernel driver at
  launch.
- **Phase 2:** Linux (eBPF) and macOS (Endpoint Security framework).
- **Phase 3:** Windows kernel-mode sensor + tamper protection (ELAM/WHQL
  signing pipeline), only after Phase 1 telemetry is proven in production.

## Non-negotiable engineering requirements

1. **Safe updates:** signed artifacts, ring/staged rollout (canary →
   early → broad), automatic rollback, and strict separation of code
   updates from content/config updates. A bad content push must never be
   able to crash hosts (industry incident lesson, July 2024).
2. **Performance budget:** <2% average CPU, bounded memory, local event
   buffering with backpressure; the agent degrades telemetry before it
   degrades the host.
3. **Crash isolation:** user-mode first; watchdog + self-recovery; agent
   failure must never impair the endpoint.
4. **Security of the agent itself:** mutually authenticated mTLS to the
   ingestion edge, per-device identity and enrollment tokens, signed
   config, anti-tamper roadmap.
5. **Schema discipline:** versioned telemetry schema mapped to the
   platform's normalized event model (OCSF) at the edge or ingestion.
6. **Fleet management:** enrollment, health, version, and policy state
   feed the asset inventory service (billing depends on it).

## Alternatives Considered

- **Wrap open collectors (osquery/Sysmon):** faster, cheaper; rejected —
  weaker response capability and differentiation.
- **Integrate existing EDRs (Defender):** agentless speed; rejected —
  dependency on customer licensing, no owned response path. NOTE: keep as
  a complementary connector, not a replacement.

## Consequences

- Engineering cost and timeline increase materially; the agent is
  effectively a second product with its own release train, CI (per-OS
  build/test matrix), and support burden.
- A dedicated endpoint-agent subagent owns this domain (see
  `.claude/agents/endpoint-agent.md`).
- QA scope expands: per-OS matrix testing, performance regression tests,
  update/rollback drills, and fault-injection on the agent.
- Time-to-market risk is mitigated by Phase 1's user-mode-only scope and
  by shipping the M365/Workspace and firewall connectors independently.

## Security Considerations

The agent is the highest-privilege component we ship and a prime supply-
chain target. security-architect must threat-model: update channel,
enrollment, local privilege boundaries, and build pipeline (signing keys
in HSM, provenance/SLSA). Final review required before Phase 1 GA.
