# ADR-0006: Agent enrollment and device identity — token-bootstrapped per-device X.509 client certificates

- **Status:** Accepted (amended per threat model B-1/B-3; conditions SEC-7..SEC-15 binding)
- **Date:** 2026-07-08
- **Deciders:** Architect Agent + solution-architect + security-architect
- **Threat model:** `docs/security/threat-model-platform-foundation-mvp.md` §2.2, §5(b)(c)(d), B-1, B-3

## Context

ADR-0002 (non-negotiable #4) requires mutually authenticated mTLS to the
ingestion edge with per-device identity and enrollment tokens. The PRD
requires: tenant-scoped expiring revocable enrollment tokens with silent
install (AC-56), unique per-device identity/credential (AC-57), distinct
failures for expired/revoked/foreign tokens (AC-58), console-driven device
revocation effective at next connect (AC-59), and mTLS with server-cert
validation on every agent connection (AC-69). The MVP must work in
docker-compose without an external PKI product.

## Decision

**Two-phase scheme: multi-use enrollment token → per-device X.509 client
certificate issued by a stamp-internal CA.**

1. **Enrollment token (bootstrap):** admin-generated, tenant-scoped,
   expiring (default 72h, plan-config), revocable, **multi-use** (one token
   rolls out to a whole fleet via GPO/Intune). Stored hashed; embedded in
   the copy-paste silent-install command. It authorizes exactly one
   operation: `POST /v1/agent/enroll`. Conditions per SEC-7/12/13:
   entropy/hashing/constant-time compare, per-IP and per-token rate
   limits, atomic cap check, enrollment-velocity anomaly notification,
   per-enrollment audit (token ID, source IP, claimed hostname), and
   GPO-exposure warning + revoke-after-rollout guidance in install docs.
2. **Device credential:** at enrollment the agent generates a keypair
   locally (private key never leaves the device; OS-protected storage —
   DPAPI/TPM-backed where available, endpoint-agent to specify) and sends a
   CSR. Per SEC-8 the CSR is used ONLY as proof-of-possession of the
   public key: the server ignores all client-supplied subject/SAN content
   and assigns identity itself. The dataplane issues an X.509 client
   certificate from the **stamp-internal issuing CA** (offline root, one
   issuing CA per stamp; production issuing key in KMS/HSM behind an
   isolated signer per SEC-9): subject `CN=<device_id>`, URI SAN
   `urn:platform:tenant:<tenant_id>:device:<device_id>`, lifetime **90
   days**, renewable via `POST /v1/agent/renew-credential` (mTLS with the
   current non-revoked cert, from 2/3 of lifetime; ≤24h old-serial
   overlap; SEC-11).
3. **Verification path (amended per B-1 + B-3):** the ingest-gateway
   (nginx) terminates mTLS, verifies the chain against the stamp CA, and
   forwards the validated identity to dataplane-api over an authenticated
   hop with unconditional identity-header stripping on every route
   (mechanism specified in design doc §5 and SEC-14). Device authorization
   on every agent-route request is an **ALLOWLIST of active device-status
   records, fail-closed** (SEC-10):
   - PostgreSQL `devices` is the source of truth; Redis key
     `device:{tenant_id}:{device_id}` = `{status, cert_serial}` is a cache
     seeded/backfilled from PG.
   - Redis miss ⇒ read PG and backfill. PG says revoked or absent ⇒ 401
     `DEVICE_REVOKED` / `DEVICE_IDENTITY_INVALID`.
   - **Both Redis and PG unavailable ⇒ 503 (deny). The request is never
     accepted on store failure.**
   - The presented cert serial must match the device's current serial (or
     the ≤24h renewal-overlap previous serial).
   - A pure revocation *blocklist* (absence = allowed) is **FORBIDDEN** —
     it fails open on Redis flush/restart/eviction (threat model B-1).
   Revocation is therefore effective at next connect without CRL/OCSP
   distribution (AC-59), and deny-by-default holds under infrastructure
   failure.
4. **Cap check:** enrollment consults the deduplicated billable count
   (AC-14/27) before issuing any credential, atomically against concurrent
   enrollments (SEC-12); failure creates no partial device record.
5. Agents validate the server certificate chain; release builds have no
   insecure-skip-verify path (AC-69). Local compose uses a dev CA generated
   by a bootstrap script — same code path, different trust anchor (dev CA
   is explicitly non-production per SEC-9).

## Alternatives Considered

- **Signed device tokens (JWT/opaque) over one-way TLS:** simplest server
  side; rejected — contradicts ADR-0002's explicit mTLS requirement;
  bearer tokens are exfiltratable and replayable from another machine,
  whereas mTLS binds identity to a locally held private key.
- **Per-tenant CA:** stronger cryptographic tenant separation; rejected
  for MVP — CA-per-tenant lifecycle at self-serve signup adds provisioning
  time and operational surface; tenant binding lives in the SAN and is
  enforced server-side. Revisit for the dedicated tier.
- **SPIFFE/SPIRE:** right long-term shape; rejected for MVP — heavy for
  docker-compose and adds an attestation model we don't need for Phase 1.
- **Single-use enrollment tokens:** better theft containment; rejected as
  the default — breaks GPO/Intune fleet rollout (AC-56). Ratified with
  conditions by security-architect (threat model §5(b)): short expiry,
  instant revocation, per-token enrollment count + velocity anomaly
  notification, cap check on every enrollment, documentation warnings.
- **Redis revocation blocklist (original proposal):** superseded by B-1 —
  fails open on Redis flush/restart; replaced by the PG-backed
  device-status allowlist above.

## Consequences

- Easier: strong per-device identity satisfying ADR-0002; revocation is a
  status-record lookup (PG-backed, Redis-cached, deny-on-unknown) that
  fails closed; identity doubles as the asset-inventory anchor (dedup key
  #1, AC-22) and the ingest idempotency scope (AC-34).
- Harder: we operate a small CA (issuing keys, rotation, backup — KMS/HSM
  + isolated signer in production per SEC-9; cloud-platform + devsecops
  own custody and the rotation runbook, required before GA per G-2); nginx
  mTLS + header-stripping config becomes a critical, QA-tested artifact
  (SEC-14/15); cert renewal is a new failure mode (agents must renew early
  and buffer through failures); agent-route availability now depends on
  the device-status store — mitigated by the Redis cache layer and by
  agent buffering (AC-66) through 503 windows.
- Accepted risks: multi-use token theft during its 72h window (bounded by
  cap + revocation + audit + velocity alerting per SEC-13); local admin
  extracting the device key forges telemetry as that one device (tamper
  protection is ADR-0002 Phase 3; per-device revocation is the response
  path); stamp-wide CA compromise is catastrophic — root kept offline,
  issuing key in KMS/HSM.

## Security Considerations

Reviewed by security-architect: initial threat model
`docs/security/threat-model-platform-foundation-mvp.md` (§2.2 is the
highest-risk surface there). Ratified with binding conditions
SEC-7..SEC-15; blocking findings B-1 (device-status allowlist) and B-3
(authenticated, header-stripped gateway hop) are incorporated above and in
the design doc. Final security review (lifecycle step 8) will verify
implementation of B-1/B-3 plus negative tests: header injection from
outside the gateway, revoked-device replay, foreign-tenant token probes.
