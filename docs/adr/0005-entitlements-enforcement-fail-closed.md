# ADR-0005: Entitlements enforcement — central service, cached client, fail-closed

- **Status:** Accepted (amended per threat model §5(a)/SEC-39; exclusion list binding)
- **Date:** 2026-07-08
- **Deciders:** Architect Agent + solution-architect + security-architect
- **Threat model:** `docs/security/threat-model-platform-foundation-mvp.md` §2.8, §5(a), SEC-39..41, G-1

## Context

Business-model consequence #4: every tier limit is backend-enforced. The
PRD requires: no hardcoded tier values in data-plane services (AC-12),
entitlement reads p95 ≤50ms with cache TTL ≤5 min (AC-13), changes
effective within 5 minutes (AC-15), and an explicit decision on behavior
when the entitlements service is unreachable (S-8). Entitlements gate both
revenue (endpoint caps, quotas, deep investigation) and cost (ingest
rates, LLM spend). Fail-open risks unlimited free usage and unmetered LLM
cost; naive fail-closed turns an entitlements blip into a platform outage.

## Decision

1. **Single source of truth:** controlplane `entitlements` module, backed
   by plan-config tables (values changeable without code deploy, per PRD
   §4). Served at `GET /internal/v1/tenants/{id}/entitlements`.
2. **Enforcement points call `packages/entitlements-client`**, never the
   raw values: two-layer cache — Redis (shared, TTL 5 min, invalidated on
   plan change, writable only by the entitlements service per SEC-41) and
   in-process last-known-good (LKG) copy retained up to **30 minutes**
   past its TTL for outage bridging. Stale-serving emits a metric and a
   structured log with staleness age; 30 minutes is a hard ceiling.
3. **Fail-closed with LKG grace.** When the entitlements service is
   unreachable:
   - If an LKG value ≤30 min stale exists ⇒ enforce using LKG (tenants see
     no impact; the stale-cache metric fires).
   - If no LKG exists (cold cache) ⇒ **deny**: capability-granting checks
     (enrollment, deep investigation, plan-gated features) return 403
     `ENTITLEMENT_DENIED`/quota codes; ingest returns 503
     `ENTITLEMENTS_UNAVAILABLE` + `Retry-After` (agents buffer per
     AC-66/68, so brief closures lose nothing).
   - Never fail-open: no code path substitutes permissive defaults.
4. **LKG grace applies ONLY to quantitative plan values** (caps, quotas,
   retention, rates, response_mode, trial-expiry status). **The following
   are NEVER graced** — each is checked against its own authoritative
   store (SEC-10/17/39/3 allowlist patterns), never the entitlements
   cache, so cut-off is effective in ≤60s:
   - device status (revocation) — SEC-10;
   - ingest-key status (revocation) — SEC-17;
   - **`tenant.abuse_frozen` flag** (abuse freeze; tenant model field
     defined in design doc §5) — SEC-39;
   - session/role validity — SEC-3.
5. **Read paths don't gate:** viewing already-collected alerts/assets never
   requires an entitlement decision (frozen-trial read-only access, AC-9,
   also depends on this).
6. Plan changes write audit records with old+new values and publish a cache
   invalidation, meeting the 5-minute propagation bound (AC-11/15).

## Alternatives Considered

- **Pure fail-open ("availability first"):** rejected — silently unlimited
  endpoints/LLM spend during outages; contradicts business-model
  consequence #4 and is unauditable.
- **Strict fail-closed, no LKG grace:** rejected — a 2-minute control-plane
  blip would 503 every ingest request across all tenants; the LKG window
  bounds staleness (worst case: a *downgraded* — not revoked — tenant
  keeps old limits ≤35 min including cache TTL — bounded, logged, and
  ratified as acceptable by security-architect).
- **Entitlements pushed into JWTs/sessions:** rejected for MVP — agents and
  ingest keys don't carry sessions; revocation/downgrade latency becomes
  token lifetime; harder to audit.
- **Library with local plan-config file per service:** rejected — violates
  AC-12 (values must come from the service; QA contract-tests this).

## Consequences

- Easier: one place to retune plans (OQ-1), uniform QA contract tests,
  clean fail-closed audit story.
- Harder: entitlements service is now availability-critical infrastructure;
  it must be the most boring, replicated service in the stamp; client
  library must be flawless about staleness metrics; the never-graced
  exclusion list adds a second lookup (device/key/abuse-freeze status) on
  hot paths — mitigated by the same Redis-cached allowlist pattern.
- Accepted risks: ≤35 min stale enforcement of quantitative values during
  outages; cold-cache denial can reject legitimate traffic during a
  combined restart+control-plane outage (mitigated by Redis-layer
  persistence and agent buffering).

## Security Considerations

Reviewed by security-architect: ratified with conditions per threat model
§5(a) — the never-graced exclusion list above is BINDING and enumerated;
grace covers quantitative plan values only; the `abuse_frozen` tenant flag
(G-1) is added to the design so the exclusion is enforceable; abusive
tenants are cut off in ≤60s via the status-store path, independent of
entitlement caching. Fail-closed remains the security-correct default for
capability grants (PRD S-8). Final review verifies SEC-39/40/41.
