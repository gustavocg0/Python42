# PRD: Platform Foundation MVP

- **Feature slug:** `platform-foundation-mvp`
- **Status:** Draft v1 for review — 2026-07-07
- **Author:** product-manager agent
- **Priority:** P0 — foundational; nothing else ships without it
- **Rough sizing:** XL (multi-team, ~6 parallel workstreams; est. 8–12 engineering weeks with parallelization)
- **Depends on:** `docs/prd/business-model.md`, ADR-0001 (control plane / stamp), ADR-0002 (first-party endpoint agent)
- **Scope authority:** Vertical slice fixed by the Architect Agent. Do not expand without Architect approval.

---

## 1. Problem Statement

Small and medium enterprises (SMEs) face the same attackers as large enterprises but
have no SOC, no security analysts, and no budget for enterprise SIEM/EDR stacks.
Existing tools either assume a dedicated security team (too complex) or are point
products (no correlation, no triage). SMEs need a self-serve platform that:

1. Onboards a tenant in minutes with zero human touch,
2. Collects endpoint and log telemetry with a lightweight first-party agent,
3. Detects threats and produces a **prioritized, deduplicated, AI-triaged alert
   queue** that a generalist IT admin can act on without security expertise.

**Business value.** This MVP is the vertical slice that proves the entire business
model: per-endpoint pricing requires accurate, deduplicated asset inventory
(revenue-critical per business-model consequence #1); tier differentiation requires
backend-enforced entitlements (consequence #4); margin protection requires ingest
quotas and AI cost metering (consequences #2, #5). Every later feature (response
playbooks, connectors, deep AI investigation) builds on the tenancy, ingestion,
detection, and entitlement rails delivered here. Without this slice there is no
trial funnel, no billable metric, and no product to demo.

---

## 2. Target Users / Personas

### P1 — Sam, SME IT Admin (primary)
- IT generalist at a 20–250 employee company; security is 10–20% of the job.
- No SIEM/SOC experience; does not know MITRE ATT&CK or Sigma.
- Needs: 15-minute self-serve onboarding, agent rollout via existing tooling
  (GPO/Intune/script), an alert queue that says **what happened, how bad it is,
  and what to do**, in plain language.
- Success looks like: checks the console 1–2x/day, handles the top alerts in
  under 30 minutes, trusts the endpoint count on the (future) invoice.

### P2 — Morgan, MSP-lite Operator (secondary)
- Independent consultant / small IT services shop informally managing IT for
  3–10 SME clients. (Formal MSP multi-tenant management is deferred — see
  business-model open questions — but Morgan signs up one tenant per client today.)
- Needs: fast repeatable tenant onboarding, per-tenant separation with zero risk
  of cross-client data leakage, filterable/sortable alert queue to work
  efficiently, exportable/asset-level visibility to justify their own billing.
- Success looks like: onboards a new client tenant in under 15 minutes; triages
  a client's queue remotely; never sees another client's data under any condition.

### Non-persona stakeholders
- **Internal:** detection engineering (rule content), finance/ops (asset counts
  feed future billing), support (tenant/agent health visibility).
- **Explicitly not targeted in MVP:** enterprise SOC analysts, formal MSPs with
  cross-tenant dashboards.

---

## 3. MVP Scope Table

| # | Capability | In / Out | Notes |
|---|---|---|---|
| 1 | Self-serve tenant signup, email verification, automated provisioning | **In** | Control plane; trial tenants are full tenants (business model consequence #3) |
| 2 | Entitlements service (endpoint cap, retention days, deep-investigation quota, response mode) | **In** | Backend-enforced; driven by plan config, not payments |
| 3 | Asset inventory with cross-source deduplication | **In** | Billing-critical; sources in MVP: endpoint agent + generic ingest |
| 4 | Authenticated event ingestion API (agent + generic webhook/syslog-style JSON) | **In** | Data plane, one stamp |
| 5 | Normalization to OCSF-inspired internal event schema | **In** | Versioned schema |
| 6 | Detection engine executing Sigma-style rules + starter rule pack | **In** | Rule authoring UI is out; rules ship as managed content |
| 7 | Alert generation with dedup/correlation + prioritized alert queue API | **In** | |
| 8 | AI triage (fast model) on every alert: summary + severity/priority score | **In** | Per-tenant LLM cost metering |
| 9 | AI deep investigation | **Stub only** | Entitlement-gated, metered; returns "coming soon" stub result |
| 10 | Endpoint agent Phase 1 skeleton: enrollment, per-device identity, heartbeat, process+network+auth telemetry, local buffering/backpressure, secure delivery | **In** | Windows ETW-based design; MVP may ship cross-platform collector core with simulated/polled provider |
| 11 | Web UI: tenant onboarding, prioritized alert queue with filter/triage actions, alert detail with AI summary, asset inventory view | **In** | Minimal SOC console |
| 12 | Multi-tenant isolation (Postgres RLS, per-tenant ES index patterns) | **In** | Per ADR-0001 |
| 13 | Audit logging of all state-changing actions | **In** | |
| 14 | Ingest fair-use quotas per tenant | **In** | |
| 15 | Automated response playbooks | **Out** | Response mode is stored/displayed as an entitlement only |
| 16 | M365 / Google Workspace / firewall connectors | **Out** | Generic JSON ingest is the only non-agent source in MVP |
| 17 | Kernel-mode sensor / tamper protection | **Out** | ADR-0002 Phase 3 |
| 18 | macOS / Linux telemetry providers | **Out** | ADR-0002 Phase 2; collector core must not preclude them |
| 19 | SSO / SAML | **Out** | Email+password with MFA-ready design; SSO is Pro-tier, later |
| 20 | Billing / payment integration | **Out** | Entitlements set by plan config; no payment collection |
| 21 | Dedicated-stamp provisioning automation | **Out (design only)** | Services must remain tenancy-mode agnostic per ADR-0001 |
| 22 | Trial auto-expiry freeze/purge pipeline | **Partially in** | Freeze at expiry is in (E2); purge-at-T+30 job is in; conversion/payment is out |

---

## 4. Epics, User Stories, and Acceptance Criteria

Acceptance criteria are numbered globally (AC-1…AC-91) so QA can reference them
directly. All numeric limits marked *(plan-config)* are defaults loaded from plan
configuration and must be testable by changing the config, not code.

**Plan-config defaults for MVP** (single source of truth for the ACs below;
finance/product may retune values without code change):

| Entitlement | Trial | Core | Pro |
|---|---|---|---|
| Trial duration | 14 days | — | — |
| Endpoint cap | 100 | 250 | 1000 |
| Hot retention (days) | 14 | 30 | 90 |
| AI deep-investigation quota (runs/day) | 5 | 5 | unlimited |
| Response mode | `recommend_only` | `recommend_only` | `playbooks_with_approval` |
| Ingest fair-use (events/min, tenant-wide) | 5,000 | 10,000 | 40,000 |

Trial runs at Pro feature level with Trial caps, per the business model.

---

### EPIC E1 — Tenant Signup & Provisioning (Control Plane)

**US-1.1** As an SME IT admin, I want to sign up with my work email and get a
working tenant automatically, so that I can start a trial without talking to sales.

- **AC-1** Given a visitor on the signup page, when they submit organization name,
  admin email, and a password meeting policy (min 12 chars; checked against a
  breached-password list), then an account in `pending_verification` state is
  created and a verification email with a single-use, expiring (24h) link is sent.
- **AC-2** Given a `pending_verification` account, when the verification link is
  used within 24h, then tenant provisioning starts automatically; when used after
  24h or a second time, then a clear error with a "resend verification" option is
  shown and no tenant is provisioned.
- **AC-3** Given a verified signup, when provisioning completes, then the tenant
  exists in the shared-pool stamp with: tenant record, RLS tenant context,
  per-tenant ES index pattern, Trial-tier entitlements, and an admin user — and
  the admin lands in the onboarding UI. Time from email verification to usable
  console is ≤ 60 seconds (p95).
- **AC-4** Given a signup with an email domain already owned by an existing tenant
  admin, when submitted, then signup is blocked with a message directing the user
  to their org's admin (no information about the existing tenant is leaked beyond
  "this domain already has an account").
- **AC-5** Given provisioning fails at any step, when the failure occurs, then the
  system retries idempotently; after exhausting retries the account is marked
  `provisioning_failed`, an internal operational alert fires, and the user sees a
  "we're on it" page — no half-provisioned tenant is ever reachable.
- **AC-6** Given a completed signup, when the tenant is created, then a trial
  expiry timestamp = creation + trial duration *(plan-config, default 14 days)* is
  stored on the tenant.

**US-1.2** As an MSP-lite operator, I want signup to be repeatable per client,
so that I can onboard multiple client tenants quickly.

- **AC-7** Given an operator who already administers tenant A, when they sign up
  with a different email/domain for client B, then a fully separate tenant B is
  created with no shared data, users, or entitlements with tenant A.
- **AC-8** Given signup abuse controls, when more than 3 signups originate from
  the same IP within 24h or a disposable-email domain (blocklist-based) is used,
  then the signup is held for verification challenge (e.g., CAPTCHA) and the
  event is logged for review. *(Threshold plan-config.)*

**US-1.3** As the platform operator, I want trial tenants to freeze at expiry and
purge later, so that trials cannot become free-forever tenants.

- **AC-9** Given a trial tenant past its expiry timestamp, when any ingest request
  arrives, then it is rejected with HTTP 402 and machine-readable code
  `TRIAL_EXPIRED`; when the admin logs in, then the console is read-only with a
  visible "trial expired" banner (alert/asset data still viewable).
- **AC-10** Given a frozen trial tenant, when 30 days pass after expiry without
  plan change, then a purge job deletes tenant event/alert data and marks the
  tenant `purged`; the purge is recorded in the audit log and is verifiable by QA
  (queries for that tenant's data return empty).
- **AC-11** Given a frozen trial tenant, when an internal operator changes its
  plan config to Core or Pro (no payment flow in MVP), then ingest and console
  write-access resume within 5 minutes without re-onboarding, and previously
  collected data is intact.

---

### EPIC E2 — Entitlements Service

**US-2.1** As the platform operator, I want every tier limit enforced in the
backend, so that feature gates can never be bypassed by calling APIs directly.

- **AC-12** Given any tenant, when a service needs an entitlement decision
  (endpoint cap, retention days, deep-investigation quota, response mode, ingest
  quota), then it obtains it from the entitlements service API — QA verifies via
  contract tests that no data-plane service hardcodes tier values.
- **AC-13** Given the entitlements API, when queried with a tenant ID, then it
  returns the full entitlement set with values and the plan name, with p95
  latency ≤ 50 ms (cached reads permitted; cache TTL ≤ 5 minutes).
- **AC-14** Given a tenant at its endpoint cap *(plan-config)*, when an
  additional device attempts enrollment, then enrollment is rejected with
  machine-readable code `ENDPOINT_CAP_REACHED`, the rejection is visible in the
  console (asset inventory view banner), and no partial device record is created.
- **AC-15** Given a tenant whose entitlement changes (e.g., Trial → Core plan
  config change), when the change is saved, then all enforcement points reflect
  the new values within 5 minutes and the change is audit-logged with old and
  new values.
- **AC-16** Given retention entitlements, when event data exceeds the tenant's
  hot retention days *(plan-config)*, then a scheduled job removes it from hot
  storage within 24h of expiry; QA can verify with a tenant whose retention is
  config-shortened to 1 day.
- **AC-17** Given any UI feature gate (e.g., deep investigation button), when
  the equivalent API is called directly without entitlement, then the API rejects
  with HTTP 403 and a machine-readable entitlement code — UI hiding alone is
  never the enforcement mechanism.
- **AC-18** Given response mode, when the tenant's entitlements are fetched, then
  `response_mode` is returned (`recommend_only` for all MVP tenants) and displayed
  read-only in the console; no response execution paths exist in MVP.

---

### EPIC E3 — Asset Inventory with Cross-Source Deduplication (billing-critical)

**US-3.1** As an SME IT admin, I want an accurate list of my monitored devices,
so that I trust what I will be charged for.

- **AC-19** Given an enrolled agent, when enrollment completes, then an asset
  record exists within 60 seconds containing: stable asset ID, hostname, OS
  name/version, first-seen, last-seen, source(s) = `agent`, and agent
  version/health.
- **AC-20** Given events arriving via the generic ingest API that reference a
  host not seen before (by the dedup keys in AC-22), when normalized, then an
  asset record with source `log_ingest` is created (observed asset, marked as
  such).
- **AC-21** Given the asset inventory API/UI, when listed, then each asset shows:
  hostname, OS, sources, agent status (enrolled/healthy/offline/none), first
  seen, last seen, and billable flag; the list supports filter by source, agent
  status, and billable flag, and text search by hostname.

**US-3.2** As the platform operator, I want one physical device to count as one
billable asset regardless of how many sources report it, so that endpoint counts
are defensible and disputes don't cause churn.

- **AC-22** Given the same device reported by both the agent (device identity)
  and log ingest (hostname/IP/MAC in events), when dedup runs, then exactly one
  billable asset exists. Dedup match order: (1) agent device ID, (2) exact
  case-insensitive hostname + OS family match, (3) MAC address when present.
  Matching is deterministic and the applied rule is stored on the asset record.
- **AC-23** Given two genuinely different devices sharing a hostname (e.g.,
  re-imaged machines), when the agent device IDs differ, then they remain two
  assets — agent identity always wins over hostname matching.
- **AC-24** Given a merged asset, when viewed in the UI/API, then all
  contributing sources and their identifiers are listed, so an admin can audit
  why records merged.
- **AC-25** Given dedup produced a wrong merge or split, when an admin uses the
  manual "split asset" / "merge assets" action in the UI, then the correction is
  applied, persisted against future automatic re-merge of the same identifiers,
  and audit-logged.
- **AC-26** Given the billable count, when computed, then it equals the number of
  deduplicated assets with `billable = true` seen within the last 30 days; the
  count is exposed via API (`GET /v1/assets/billable-count`) and shown in the
  console; assets not seen for 30 days automatically become non-billable.
  *(Window plan-config.)*
- **AC-27** Given the endpoint cap check (AC-14), when evaluated, then it uses
  the deduplicated billable count from AC-26 — never raw source counts.

---

### EPIC E4 — Event Ingestion & Normalization (Data Plane)

**US-4.1** As an SME IT admin, I want my agents and existing log sources to send
data securely, so that detection covers my environment.

- **AC-28** Given the ingestion API, when an agent submits events, then the
  connection is mutually authenticated (mTLS with per-device identity from
  enrollment); events from unauthenticated or unknown identities are rejected
  with HTTP 401 and counted in an internal rejection metric.
- **AC-29** Given the generic ingest endpoint, when a tenant admin creates an
  ingest key in the console, then a scoped API key (tenant-bound, revocable,
  shown once) is issued; JSON events posted with that key over TLS are accepted;
  posts with a revoked or foreign-tenant key are rejected with HTTP 401/403.
- **AC-30** Given a valid ingest request with a JSON batch (≤ 1,000 events or
  ≤ 5 MB), when accepted, then the API responds HTTP 202 within p95 ≤ 300 ms
  with a batch receipt ID; oversized batches are rejected with HTTP 413 and a
  machine-readable code.
- **AC-31** Given accepted events, when processed, then each is normalized to the
  versioned OCSF-inspired internal schema with required envelope fields:
  `event_id` (UUID), `tenant_id`, `event_time`, `ingest_time`, `source_type`,
  `schema_version`, `event_class` (process_activity, network_activity,
  authentication, or generic), plus class-specific fields defined in the
  solution-architect's schema contract.
- **AC-32** Given a malformed event within an otherwise valid batch, when
  normalized, then the malformed event is quarantined to a per-tenant dead-letter
  store with the parse error (retained 7 days), the rest of the batch proceeds,
  and a per-tenant `events_rejected` counter increments; malformed events never
  crash or stall the pipeline.
- **AC-33** Given normalized events, when stored, then they are written only to
  that tenant's ES index pattern and are queryable by tenant-scoped APIs within
  30 seconds (p95) of ingestion.
- **AC-34** Given duplicate delivery from agent retries (same agent event ID),
  when ingested twice, then exactly one normalized event is stored
  (idempotent ingest keyed on source event ID + device identity).

---

### EPIC E5 — Detection Engine (Sigma-style rules)

**US-5.1** As an SME IT admin, I want known-bad behavior detected automatically
without me writing rules, so that I get protection out of the box.

- **AC-35** Given the detection engine, when a normalized event stream flows,
  then enabled Sigma-style rules are evaluated and matches produce detection
  hits with: rule ID, rule version, rule title, severity, MITRE ATT&CK technique
  ID(s), matched event reference(s), and tenant ID.
- **AC-36** Given the MVP starter rule pack (authored by detection-engineering),
  when the platform is deployed, then ≥ 20 enabled rules covering process,
  network, and authentication event classes are active for every tenant, each
  mapped to at least one ATT&CK technique.
- **AC-37** Given detection latency, when an event matching an enabled rule is
  ingested, then the corresponding alert (E6) exists within 60 seconds (p95)
  end-to-end (ingest → alert).
- **AC-38** Given a rule disabled per tenant by an admin (simple on/off toggle in
  the console rule list; no rule editing in MVP), when matching events arrive,
  then no new alerts fire for that rule/tenant, and the toggle is audit-logged.
- **AC-39** Given a rule pack content update (managed content, separate from code
  deploys per ADR-0002 principle), when published, then new/updated rules take
  effect for all tenants without service restart, and each alert records the
  rule version that fired.
- **AC-40** Given a rule that errors at evaluation (bad content), when it fails,
  then the engine disables that rule, fires an internal operational alert, and
  continues evaluating all other rules — one bad rule never stops detection.

---

### EPIC E6 — Alert Generation, Dedup/Correlation, Prioritized Queue API

**US-6.1** As an SME IT admin, I want repeated identical detections collapsed
into one alert, so that I see 5 real problems instead of 500 duplicate rows.

- **AC-41** Given a detection hit, when no open alert exists for the same
  (tenant, rule ID, entity key — e.g., host + user) within the dedup window
  *(plan-config, default 60 minutes)*, then a new alert is created with state
  `new`, severity from the rule, occurrence count = 1, and links to the matched
  event(s).
- **AC-42** Given a detection hit matching an existing open alert's dedup key
  within the window, when processed, then no new alert is created; the existing
  alert's occurrence count increments, `last_seen` updates, and the new event is
  linked.
- **AC-43** Given multiple related alerts (same host, overlapping time window
  ≤ 30 min *(plan-config)*, different rules), when created, then they are
  correlated into a shared correlation group ID exposed on the alert and in the
  API, and the alert detail view lists sibling alerts in the group.

**US-6.2** As an MSP-lite operator, I want a prioritized, filterable alert queue
API and UI, so that I can work the most important things first.

- **AC-44** Given the alert queue API (`GET /v1/alerts`), when called, then it
  returns tenant-scoped alerts sorted by priority score (E7) descending by
  default, with pagination, and filters for: state (`new`, `acknowledged`,
  `closed`), severity, rule ID, host, time range, and correlation group.
  p95 latency ≤ 500 ms for a tenant with 10,000 alerts.
- **AC-45** Given triage actions, when a user acknowledges an alert, closes it
  (required close reason: `resolved`, `false_positive`, `expected_behavior`,
  `duplicate`), or reopens it, then the state transition is applied atomically,
  returned by subsequent reads, and audit-logged with actor and timestamp.
- **AC-46** Given an alert closed as `false_positive`, when closed, then the
  close reason is stored in a form consumable by detection-engineering for FP
  reduction (rule ID + entity + reason exported/queryable) — no automated tuning
  in MVP.
- **AC-47** Given invalid state transitions (e.g., closing an already-closed
  alert, acknowledging a nonexistent alert), when attempted via API, then the
  API rejects with HTTP 409/404 and machine-readable codes; no partial writes.

---

### EPIC E7 — AI Triage (fast model) + Deep Investigation Stub

**US-7.1** As an SME IT admin who is not a security expert, I want every alert
explained in plain language with a clear priority, so that I know what to do
without googling attack names.

- **AC-48** Given a newly created alert, when AI triage runs, then within 120
  seconds (p95) the alert carries: (a) a plain-language summary ≤ 120 words
  stating what happened, why it matters, and a recommended next step;
  (b) an AI severity (`low`/`medium`/`high`/`critical`); (c) a priority score
  0–100 used for queue ordering. Reading-level target: understandable by a
  non-security IT generalist (ux-designer to define style guide; QA verifies
  structure and presence, not prose quality).
- **AC-49** Given AI triage output, when displayed, then it is visibly labeled
  as AI-generated, shows the rule's original severity alongside the AI severity,
  and never hides the underlying raw detection data (progressive disclosure:
  summary first, evidence expandable).
- **AC-50** Given the triage model call fails or times out (30 s), when it does,
  then the alert still enters the queue immediately with priority derived from
  rule severity alone, marked `triage: unavailable`, and triage is retried up to
  3 times with backoff; alert delivery is never blocked on the LLM.
- **AC-51** Given LLM usage, when any triage call completes, then tokens, model
  ID, latency, and computed cost are recorded per tenant per day and are
  queryable via an internal metering API (business-model consequence #5).
- **AC-52** Given prompt safety, when alert/event content is included in the
  triage prompt, then tenant data from one tenant can never appear in another
  tenant's triage context (single-tenant prompt assembly; QA verifies by
  injection-style test with marker strings across two tenants).

**US-7.2** As an SME IT admin on a limited plan, I want deep investigation
gated and metered, so that the platform's premium tiers are meaningful (and, as
the operator, so LLM spend is controlled).

- **AC-53** Given an alert detail view, when the user has remaining
  deep-investigation quota *(plan-config: Trial/Core 5/day, Pro unlimited)*,
  then a "Run deep investigation" action is available; invoking it decrements
  the tenant's daily quota atomically, records the run in metering, and returns
  the MVP stub result (clearly labeled placeholder payload defined in the API
  contract).
- **AC-54** Given a tenant with zero remaining daily quota, when deep
  investigation is invoked via UI or directly via API, then it is rejected with
  HTTP 403 and code `QUOTA_EXCEEDED_DEEP_INVESTIGATION`, the UI shows remaining
  quota and reset time (00:00 UTC), and no quota is consumed.
- **AC-55** Given quota accounting, when concurrent invocations race at the last
  remaining unit, then at most the quota'd number of runs succeed (no
  oversubscription; QA verifies with a concurrency test).

---

### EPIC E8 — Endpoint Agent Phase 1 Skeleton

**US-8.1** As an SME IT admin, I want to install the agent with one command and
an enrollment token, so that device onboarding fits my existing rollout tooling.

- **AC-56** Given the console onboarding flow, when an admin generates an
  enrollment token, then the token is tenant-scoped, expiring *(plan-config,
  default 72h)*, revocable, and shown with a copy-paste install command
  (silent-install capable for GPO/Intune/script rollout).
- **AC-57** Given a fresh device and a valid enrollment token, when the agent
  installs and enrolls, then it receives a unique per-device identity and
  credential (per ADR-0002: basis for mTLS to ingestion), the device appears in
  asset inventory within 60 seconds, and the enrollment is audit-logged.
- **AC-58** Given an expired, revoked, or foreign-tenant enrollment token, when
  enrollment is attempted, then it fails with a distinct machine-readable error,
  no device identity is issued, and the attempt is logged server-side.
- **AC-59** Given an enrolled device whose admin revokes it in the console, when
  the agent next connects, then its credentials are rejected, its asset record
  is marked `revoked` (non-billable), and buffered data from it is not accepted.

**US-8.2** As the platform operator, I want agent heartbeat and health visible,
so that support and admins can distinguish "quiet host" from "dead agent."

- **AC-60** Given an enrolled agent, when running, then it sends a heartbeat
  every 60 s *(config)* containing agent version, OS version, telemetry-provider
  status, buffer utilization %, and basic self-resource usage (CPU %, RSS).
- **AC-61** Given missed heartbeats, when 3 consecutive intervals pass with none,
  then the asset's agent status becomes `offline` in inventory/UI within 1
  minute of the threshold; a resumed heartbeat returns it to `healthy` within
  1 minute.

**US-8.3** As a security platform, the agent must collect process, network, and
authentication telemetry via a provider abstraction, so that Windows ETW is the
first provider but not the only possible one.

- **AC-62** Given the collector core, when built, then telemetry providers are a
  pluggable interface with two MVP implementations: (a) Windows ETW provider
  (process create/terminate, network connections, logon/logoff and failed
  logons), (b) a simulated/polled provider producing the same event shapes on
  any OS for development, CI, and demo use. Provider choice is configuration,
  not compile-time forking. *(Design per ADR-0002; no kernel driver.)*
- **AC-63** Given the Windows ETW provider on a test host, when a process is
  started, a network connection is made, and a failed logon occurs, then
  corresponding events conforming to the versioned agent telemetry schema arrive
  in the tenant's normalized event store within 60 seconds each (p95).
- **AC-64** Given the simulated provider, when enabled in CI, then the full
  end-to-end path (agent → ingest → normalize → detect → alert → AI triage) is
  exercised by automated tests without Windows-specific infrastructure.
- **AC-65** Given agent resource limits (ADR-0002 budget), when collecting under
  normal load, then average CPU ≤ 2% and memory stays within a configured bound
  *(default 250 MB)*; when the bound is approached, then the agent degrades
  telemetry (documented shedding order: network flows first, then process, auth
  last) before ever degrading the host. QA verifies with a load test.

**US-8.4** As an SME with unreliable connectivity, I want the agent to buffer
locally and catch up, so that offline periods don't lose critical telemetry.

- **AC-66** Given loss of connectivity to ingestion, when events are generated,
  then the agent buffers to local disk up to a cap *(default 256 MB, config)*;
  on reconnect, buffered events are delivered oldest-first and are accepted
  exactly once (pairs with AC-34).
- **AC-67** Given a full buffer, when new events arrive, then the agent drops
  events by documented priority (drop network-flow telemetry first, retain auth
  events longest), increments a locally tracked drop counter, and reports drops
  in the next heartbeat — the agent process itself never exhausts disk beyond
  its cap or crashes due to buffering.
- **AC-68** Given delivery to ingestion, when the server responds with
  backpressure (HTTP 429 with `Retry-After`), then the agent honors the delay
  with jittered backoff and does not tight-loop retry (QA verifies via fault
  injection).
- **AC-69** Given all agent↔platform communication, when inspected, then every
  connection is TLS with the per-device identity (mTLS) from AC-57; the agent
  validates server certificates (no insecure-skip-verify path in release builds).

---

### EPIC E9 — Web UI: Minimal SOC Console

**US-9.1** As an SME IT admin, I want a guided onboarding after signup, so that
I reach "first telemetry flowing" without documentation.

- **AC-70** Given first login to a new tenant, when the console loads, then an
  onboarding checklist is shown: (1) generate enrollment token / install agent,
  (2) optional: create generic ingest key, (3) confirm first events received,
  (4) view alert queue. Each step shows live completion state (e.g., step 3
  auto-completes when the first event is ingested).
- **AC-71** Given no data yet, when any console view is opened, then empty
  states explain what will appear and link to the relevant onboarding step
  (no blank tables or spinners without explanation).

**US-9.2** As an MSP-lite operator, I want an alert queue I can filter and act
on quickly, so that triage takes minutes.

- **AC-72** Given the alert queue view, when loaded, then alerts appear sorted
  by priority score descending, showing: priority, severity, title,
  plain-language one-liner from AI triage (or rule title if triage unavailable),
  affected host/user, occurrence count, first/last seen, and state; filters from
  AC-44 are available as UI controls, and the applied filters are shareable via
  URL.
- **AC-73** Given queue actions, when the user acknowledges or closes alerts
  (single and multi-select bulk, bulk ≤ 50), then the actions call the E6 APIs,
  optimistic UI updates reconcile with the server response, and failures surface
  a retryable error toast without silently losing the action.
- **AC-74** Given the alert detail view, when opened, then it shows: AI triage
  summary (labeled per AC-49), AI + rule severity, priority score,
  MITRE technique(s) with plain-language descriptions, correlated sibling alerts
  (AC-43), linked normalized events (expandable raw view), affected asset link,
  the alert's action history (audit trail), and the deep-investigation action
  with quota state (AC-53/54).
- **AC-75** Given the asset inventory view, when opened, then AC-21's list,
  filters, and billable count (AC-26) are presented, with per-asset drill-in
  showing sources/merge audit (AC-24) and the manual merge/split actions (AC-25).
- **AC-76** Given console performance, when a tenant has 10,000 alerts and 1,000
  assets, then queue and inventory first meaningful render completes in ≤ 3 s
  (p95) on a standard broadband connection.
- **AC-77** Given authentication, when a session is idle for 24h or the password
  is changed, then the session is invalidated; login supports email+password for
  MVP with rate-limited attempts (lockout/backoff after 10 failures) — SSO/SAML
  explicitly out of scope.
- **AC-78** Given roles, when users are managed, then MVP supports two tenant
  roles: `admin` (all actions, user management, tokens/keys) and `analyst`
  (view + alert triage actions only); role checks are enforced server-side
  (pairs with AC-17 philosophy).

---

### EPIC E10 — Non-Functional: Isolation, Audit, Quotas

**US-10.1** As an MSP-lite operator with multiple client tenants, I want hard
tenant isolation, so that no client can ever see another's data.

- **AC-79** Given PostgreSQL access, when any data-plane query runs, then it
  executes under RLS with the tenant context from the authenticated request;
  a QA test suite proves that for every tenant-scoped table, queries with tenant
  A's context return zero tenant-B rows, including via every public API endpoint.
- **AC-80** Given Elasticsearch access, when events/alerts are queried, then
  queries are constrained to the tenant's index pattern; QA verifies cross-tenant
  leakage tests fail closed (error or empty, never foreign data).
- **AC-81** Given any API request lacking tenant context or presenting a token
  for tenant A with a resource ID belonging to tenant B, when processed, then
  the response is 404 (not 403 revealing existence), and the attempt is logged.
- **AC-82** Given tenancy-mode agnosticism (ADR-0001), when services resolve
  tenant context, then it derives solely from the request/entitlement layer;
  QA verifies the same stamp build passes the full test suite with no
  deployment-shape assumptions (single config difference).

**US-10.2** As a compliance-minded operator, I want every state-changing action
audited, so that incidents and disputes are reconstructable.

- **AC-83** Given any state-changing action (signup, provisioning, entitlement
  change, token/key create/revoke, enrollment/revocation, rule toggle, alert
  state change, asset merge/split, user/role change, deep-investigation run,
  retention purge, trial freeze/purge), when it occurs, then an audit record is
  written with: timestamp (UTC), tenant ID, actor (user ID / system job / device
  ID), action type, target resource, and before/after values where applicable.
- **AC-84** Given audit records, when written, then they are append-only via the
  application layer (no update/delete API), tenant-queryable by admins in the
  console (filter by actor, action type, time range), and retained ≥ 365 days
  regardless of event-data retention tier. *(Retention plan-config; security-
  architect to confirm storage/immutability approach.)*
- **AC-85** Given a failed authorization attempt (AC-17, AC-54, AC-58, AC-81),
  when it occurs, then it is also captured in the audit/security log with actor
  and reason code.

**US-10.3** As the platform operator, I want per-tenant ingest fair-use quotas,
so that one noisy tenant cannot degrade the shared stamp or destroy margin.

- **AC-86** Given a tenant exceeding its ingest rate *(plan-config, see table)*,
  when further batches arrive, then the API responds HTTP 429 with `Retry-After`
  and code `INGEST_QUOTA_EXCEEDED`; compliant clients (incl. our agent per AC-68)
  back off; no accepted-then-dropped behavior (never 202 followed by silent drop).
- **AC-87** Given quota enforcement, when one tenant is throttled, then other
  tenants' ingest latency (AC-30) and detection latency (AC-37) SLOs remain
  within bounds (QA verifies with a noisy-neighbor load test).
- **AC-88** Given quota consumption, when an admin views the console, then
  current usage vs. quota (events/min, rolling) is visible, and crossing 80%
  sustained for 15 minutes surfaces a console notification.
- **AC-89** Given quota metrics, when emitted, then per-tenant ingest volume,
  throttle counts, and rejection counts are available to the observability
  stack (observability agent wires dashboards; this AC only requires the
  metrics to exist and be labeled by tenant).

**US-10.4** Platform-level operational readiness (Definition-of-Done support).

- **AC-90** Given the stamp deployment, when deployed to a clean environment via
  the standard Helm/Terraform path, then all MVP services start, pass health
  checks, and a scripted end-to-end smoke test (signup → enroll simulated agent
  → ingest → alert → triage → close alert) passes.
- **AC-91** Given service errors, when any pipeline stage (ingest, normalize,
  detect, alert, triage) fails, then the failure is observable via structured
  logs and metrics with tenant and stage labels — no silent data loss anywhere
  in the pipeline (every event is either stored, dead-lettered per AC-32, or
  rejected with an error code).

---

## 5. Success Metrics

| Metric | Target (MVP exit) | Source |
|---|---|---|
| Time-to-tenant (verify → usable console, p95) | ≤ 60 s | AC-3; ADR-0001 SLO |
| Onboarding completion (signup → first event ingested) | ≥ 70% of verified signups within 24h; median ≤ 15 min | Onboarding checklist telemetry (AC-70) |
| Ingest → alert latency (p95) | ≤ 60 s | AC-37 |
| Alert triage coverage | ≥ 95% of alerts carry AI triage within 120 s | AC-48/50 |
| Asset dedup accuracy | 0 duplicate billable assets in QA cross-source test matrix; < 1% manual merge/split corrections in beta tenants | AC-22–26 |
| Alert dedup effectiveness | ≥ 80% reduction of raw detection hits → queue rows in the QA burst scenario | AC-41/42 |
| Cross-tenant isolation defects | 0 (release-blocking) | AC-79–81 |
| Agent footprint | ≤ 2% avg CPU, ≤ 250 MB RSS in load test | AC-65 |
| LLM cost visibility | 100% of triage/deep-investigation calls metered per tenant | AC-51/53 |
| Quota protection | Noisy-neighbor test: unaffected tenants stay within SLO | AC-87 |

---

## 6. Out of Scope (explicit)

1. Automated response playbooks (response mode is a stored entitlement only; no execution paths).
2. M365 / Google Workspace / firewall connectors (generic JSON ingest is the only non-agent source).
3. Kernel-mode sensor and tamper protection (ADR-0002 Phase 3).
4. macOS / Linux telemetry providers (ADR-0002 Phase 2; provider abstraction must not preclude them — AC-62).
5. SSO / SAML (email+password only in MVP).
6. Billing/payment integration (entitlements set by plan config; no payment collection, invoicing, or checkout).
7. Dedicated-stamp provisioning automation (design-only; services stay tenancy-mode agnostic — AC-82).
8. Rule authoring/editing UI (per-tenant on/off toggle only — AC-38).
9. Real deep investigation (stub behind entitlement gate — AC-53).
10. Formal MSP multi-tenant management console (Morgan uses one tenant per client).
11. Email/chat alert notifications (console-only in MVP). *(Flagged as a fast-follow candidate — see open questions.)*

---

## 7. Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| OQ-1 | Confirm plan-config defaults in §4 table (endpoint caps for Core/Pro, deep-investigation quotas, ingest rates). Values are placeholders pending pricing research (business-model open question). | product-manager + product owner | No — config-driven, retune anytime |
| OQ-2 | Trial duration: 14 vs 30 days (business model allows range). MVP default is 14; marketing may want 30. | product owner | No |
| OQ-3 | Exact OCSF field mapping and `event_class` taxonomy for the internal schema (AC-31) — needs a formal schema contract before E4/E5/E8 implementation. | solution-architect | **Yes** for E4/E5/E8 |
| OQ-4 | Priority-score formula inputs (rule severity, AI severity, asset criticality?, occurrence count?) — MVP needs a deterministic, documented formula QA can test. | ai-platform + detection-engineering, ratified by solution-architect | **Yes** for E7/AC-48 |
| OQ-5 | Disposable-email blocklist source and CAPTCHA provider for signup abuse controls (AC-8). | security-architect | No |
| OQ-6 | Is console-only alerting acceptable for MVP exit, or is email notification for critical alerts a launch requirement? (SMEs won't watch a console all day.) Recommend fast-follow decision before beta. | product owner | No, but decide before beta |
| OQ-7 | Data residency/region for the single shared stamp at launch (affects trial signup messaging and EU prospects). | product owner + cloud-platform | No |
| OQ-8 | Deep-investigation stub payload shape — must be defined in the API contract so the real feature slots in without breaking clients (AC-53). | solution-architect + ai-platform | Yes for AC-53 |
| OQ-9 | Manual asset merge/split (AC-25): does a manual correction affect historical billable counts or only forward-looking? MVP assumption: forward-looking only. | product-manager + product owner | No (assumption stated) |
| OQ-10 | Agent silent-install packaging format(s) for MVP (MSI vs EXE; Intune/GPO requirements) — AC-56. | endpoint-agent | Yes for AC-56 |

**Assumptions made (flag if wrong):** trial = 14 days default; quota reset at
00:00 UTC (AC-54); billable window = 30 days last-seen (AC-26); two roles only
(AC-78); audit retention 365 days (AC-84); alert dedup window 60 min (AC-41).

---

## 8. Security & Privacy Flags (for security-architect)

Per business-model consequence and CLAUDE.md conventions, the following require
security-architect threat modeling **before implementation starts**:

- **S-1** Signup, email verification, session/auth design, abuse controls (E1; AC-1, AC-4, AC-8, AC-77).
- **S-2** Agent enrollment, per-device identity, mTLS, token lifecycle, revocation (E8; AC-56–59, AC-69) — ADR-0002 names this a prime supply-chain target.
- **S-3** Tenant isolation: RLS policy design, ES index-pattern enforcement, 404-vs-403 behavior (E10; AC-79–82).
- **S-4** Ingest key scheme for generic ingest: scoping, rotation, revocation (AC-29).
- **S-5** Audit log immutability and retention approach (AC-83–85).
- **S-6** LLM prompt assembly and cross-tenant contamination controls; PII in triage prompts and model-provider data handling (AC-48, AC-52).
- **S-7** Trial purge pipeline: verified, complete data deletion (AC-10) — privacy/GDPR-relevant.
- **S-8** Entitlement service as an enforcement dependency: fail-closed vs fail-open behavior when entitlements are unreachable (AC-12/13) — decision needed.
