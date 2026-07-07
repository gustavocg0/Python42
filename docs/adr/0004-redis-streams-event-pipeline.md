# ADR-0004: Redis Streams as the MVP event-pipeline transport

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** Architect Agent + solution-architect + security-architect; consulted: backend-architect, cloud-platform, database-architect
- **Threat model:** `docs/security/threat-model-platform-foundation-mvp.md` §2.4, SEC-19..22 (ratified; G-4 residual risk documented)

## Context

The pipeline (ingest → normalize → detect → alert → triage) needs an async
transport with consumer groups, replay of unacknowledged work, and
horizontal consumer scaling, meeting AC-30 (202 ≤300ms), AC-37 (ingest→alert
≤60s), and AC-91 (no silent loss). The MVP must run locally via
docker-compose; Redis is already required (cache, quotas, sessions). Kafka
would add ZooKeeper/KRaft operational weight, JVM footprint, and a fourth
stateful system for volumes the MVP will not reach (tenant quotas cap
ingest at tens of thousands of events/min).

## Decision

Use **Redis Streams with consumer groups** as the only pipeline transport
for MVP, behind a thin transport interface in `packages/pipeline`
(`publish(stream, msg)`, `consume(stream, group, handler)`) so the
implementation can be swapped for Kafka without touching business logic.

Operating rules (binding):
- Streams and payloads per design doc §4; every message carries
  `tenant_id` and `trace_id`. The envelope `tenant_id` is set ONLY by the
  authenticated producer; consumers establish tenant context per message
  through `packages/pipeline`, never from event-payload fields (SEC-20).
- At-least-once delivery: consumers ACK only after side effects complete;
  all side effects are idempotent (ES `op_type=create` with deterministic
  `_id`; alert dedup keyed upserts; triage upsert by alert_id).
- Stuck messages reclaimed via `XAUTOCLAIM` (min-idle 60s); after 5
  delivery attempts a message goes to the Postgres dead-letter table with
  its error — never dropped (AC-91).
- Streams capped with `MAXLEN ~ 1,000,000`; producers (ingest API) are the
  backpressure point — tenant quotas (429) fire long before caps.
- Redis runs with AOF `everysec` persistence in the stamp, hardened per
  SEC-19 (AUTH/ACLs denying FLUSH*/CONFIG/KEYS/DEBUG/SHUTDOWN to the app
  user, no external exposure).

## Alternatives Considered

- **Kafka/Redpanda:** best-in-class semantics and retention; rejected for
  MVP — heaviest infra in the compose stack, operational burden
  disproportionate to quota-capped MVP volume. Revisit trigger: sustained
  stamp-wide ingest > ~5k events/sec, need for multi-day replay, or >3
  consumers per stream stage.
- **PostgreSQL queue (SKIP LOCKED):** simplest, transactional; rejected —
  couples pipeline throughput to the OLTP database that also serves alerts
  and assets, and polling adds latency against AC-37.
- **RabbitMQ:** solid queueing; rejected — adds a fourth stateful service
  while Redis (already present) covers MVP needs; no stream replay.

## Consequences

- Easier: one less stateful system; trivial local dev; consumer scaling by
  adding worker replicas to a group.
- Harder/accepted risks: (a) at-least-once means duplicates — mitigated by
  end-to-end idempotency (AC-34 pairs with this); (b) bounded retention —
  a long full-pipeline outage can hit MAXLEN; mitigated by ops alerting on
  stream depth and by ingest 429s; (c) Redis memory is the ceiling —
  stream depth and consumer lag become first-class observability metrics
  (observability agent); (d) **documented residual risk (G-4/SEC-22,
  accepted for MVP):** AOF `everysec` can lose ≤1s of 202-acknowledged
  batches on Redis crash, and MAXLEN trim under extreme backlog drops
  oldest messages — depth alerting must fire long before MAXLEN; this
  nuance against AC-91's letter goes in the runbook.
- The `packages/pipeline` abstraction is mandatory; no module may call
  redis stream APIs directly.

## Security Considerations

Reviewed by security-architect (initial threat model §2.4): logical
multi-tenant separation in shared streams accepted for the shared pool,
conditional on SEC-19 (Redis hardening: AUTH/ACLs, network isolation, AOF),
SEC-20 (tenant context only from the authenticated envelope, forced by the
`packages/pipeline` consume API), SEC-21 (DLQ under RLS, capped, untrusted
content), and SEC-22 (depth/lag/DLQ alerting). Redis is never exposed to
tenants.
