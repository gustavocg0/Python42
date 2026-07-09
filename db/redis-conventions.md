# Redis key conventions — Platform Foundation MVP

Owner: database-architect. This document is the BINDING contract for every
Redis key the platform uses (threat model §4.3, SEC-19/20). Service agents
code against these exact prefixes. Rules first, then the registry.

## Rules (binding)

1. Every tenant-scoped key embeds the server-side tenant UUID; keys are
   built ONLY from server-side context (never from client-supplied strings).
2. No `KEYS`/`SCAN` across tenant prefixes in request paths. `SCAN` on a
   single tenant's prefixes is allowed only in the tenant-pinned purge job
   (SEC-46).
3. Redis is hardened per SEC-19: app ACL user denied
   `FLUSHALL/FLUSHDB/CONFIG/KEYS/DEBUG/SHUTDOWN`, AOF `everysec`, internal
   network only. Sessions and status caches must survive restart (AOF).
4. Caches of PG state (`device:*`, `ingestkey:*`, `tenantstatus:*`) are
   ALLOWLIST caches (B-1/SEC-10/17): a miss means "read PG and backfill",
   absence in BOTH stores means DENY, both stores down means 503. Writers
   must DELETE the key on any status change (revoke/freeze) so the ≤60s TTL
   is the worst-case propagation, not the mechanism.
5. Entitlements cache (`ent:*`) is written ONLY by the entitlements
   service/client path (SEC-41) and is NEVER an enforcement source for
   device/key status, abuse freeze, or sessions (SEC-39 exclusion list).
6. New keys/prefixes require updating this file (Architect-reviewed).

## Key registry

TTLs marked "≤60s" implement the ≤60s revocation/freeze SLO (SEC-10/17/39).
`{t}` = tenant UUID, `{yyyymmdd}` = UTC date.

| Key | Type / value | Owner (writer) | TTL |
|---|---|---|---|
| `device:{t}:{device_id}` | HASH `{status, cert_serial, prev_cert_serial, prev_valid_until}` cached from `tenantdata.devices` | dataplane enrollment / tenancy middleware | 60s + delete-on-change |
| `ingestkey:{t}:{key_id}` | HASH `{status, key_hash}` cached from `tenantdata.ingest_keys` | dataplane ingest / tenancy middleware | 60s + delete-on-change |
| `tenantstatus:{t}` | HASH `{status, abuse_frozen}` cached from `control.tenants` (SEC-39 path, NOT entitlements) | controlplane (writes/invalidates), dataplane (reads/backfills) | 60s + delete-on-change |
| `ent:{t}` | STRING JSON entitlements payload + `as_of` (ADR-0005 LKG cache) | entitlements client (`packages/entitlements-client`) only (SEC-41) | 300s (5 min); LKG grace ≤30 min handled client-side |
| `quota:ingest:{t}:{bucket}` | STRING counter; sliding window 60s in 10 x 6s buckets, `{bucket}` = `floor(unix_seconds/6)` | dataplane ingest API | 120s |
| `quota:di:{t}:{yyyymmdd}` | STRING counter, seeded from entitlements at first use; atomic check-and-DECR Lua (AC-55); `-1` plan = key not used | dataplane investigation | 48h (resets by key date, 00:00 UTC) |
| `budget:triage:{t}:{yyyymmdd}` | STRING counter of triage tokens spent today (SEC-37 cost backstop) | worker-triager | 48h |
| `usage:ingest:{t}:{yyyymmdd}:{metric}` | STRING counter; `{metric}` ∈ `throttled_batches`, `rejected_events`, `events_accepted`, `duplicates_dropped` (AC-88); flushed daily to `tenantdata.usage_counters` | dataplane ingest + normalizer; jobs-scheduler flushes | 48h |
| `sess:{session_id}` | HASH `{user_id, tenant_id, role, csrf_token, created_at, absolute_expires_at}` (SEC-3; PG `control.sessions` holds metadata) | controlplane identityadmin | 24h idle (refreshed), hard-capped by `absolute_expires_at` (7d) checked on read |
| `sess:user:{user_id}` | SET of active session ids (invalidate-all on password/role change, SEC-3) | controlplane identityadmin | 7d |
| `throttle:login:acct:{user_id}` | STRING failure counter (SEC-4 lockout/backoff) | controlplane identityadmin | 15 min rolling |
| `throttle:login:ip:{ip}` | STRING failure counter (SEC-4 per-IP) | controlplane identityadmin | 15 min rolling |
| `abuse:signup:ip:{ip}` | STRING signup counter (AC-8/SEC-5, threshold `platform_config.signup_per_ip_hourly_threshold`) | controlplane signup | 1h |
| `rl:enroll:token:{t}:{token_id}` | STRING counter (SEC-12, default 30/min) | dataplane enrollment | 60s |
| `rl:enroll:ip:{ip}` | STRING counter (SEC-12, default 10/min) | dataplane enrollment | 60s |
| `onboarding:{t}` | HASH step signals `{install_agent, create_ingest_key, first_event, view_queue}` = "1" (AC-70; PG `tenantdata.onboarding_steps` is source of truth) | dataplane (any module observing the step) | none; deleted when all steps done |
| `lock:job:{job_name}` | STRING owner token; `SET NX PX` singleton lock for jobs-scheduler tasks | jobs-scheduler | job-specific (≤ job period) |

## Streams (ADR-0004; shared, NOT per-tenant)

Isolation inside streams is the message envelope `tenant_id`, set only by
the authenticated producer; consumers establish tenant context per message
via `packages/pipeline` (SEC-20). All streams: `XADD ... MAXLEN ~ 1000000`,
at-least-once, `XAUTOCLAIM` for stuck messages, 5 delivery attempts then DLQ
(PG `tenantdata.dead_letter_events`). Every message carries `tenant_id` and
`trace_id`.

| Stream | Producer | Consumer group |
|---|---|---|
| `pipe:raw` | ingest API | `normalizers` |
| `pipe:normalized` | worker-normalizer | `detectors` |
| `pipe:detections` | worker-detector | `alerters` |
| `pipe:alerts.triage` | worker-alerter (new alerts only) | `triagers` |
| `pipe:asset.observations` | normalizer + enrollment | `asset-dedup` |

## Tenant purge (SEC-46 step 3)

The purge job deletes, tenant-pinned: `device:{t}:*`, `ingestkey:{t}:*`,
`tenantstatus:{t}`, `ent:{t}`, `quota:ingest:{t}:*`, `quota:di:{t}:*`,
`budget:triage:{t}:*`, `usage:ingest:{t}:*`, `onboarding:{t}`,
`rl:enroll:token:{t}:*`, and all `sess:*` whose `tenant_id` matches (via
`sess:user:{user_id}` sets of the tenant's users). Streams need no purge
action (tenant frozen ≥30 days before purge ⇒ entries long consumed/trimmed);
the purge verification still probes for stray unconsumed entries (CR-11).
