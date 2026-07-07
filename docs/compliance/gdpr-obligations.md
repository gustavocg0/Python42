# GDPR Obligation Map — Platform Foundation MVP

- **Feature slug:** `platform-foundation-mvp`
- **Status:** Baseline v1 — 2026-07-08
- **Author:** compliance agent
- **Inputs:** `docs/prd/business-model.md`, `docs/prd/platform-foundation-mvp.md`,
  `docs/design/platform-foundation-mvp.md`, ADR-0001, ADR-0002
- **Audience:** Architect Agent (fold §3 into acceptance criteria), security-architect
  (S-5, S-6, S-7), product-manager (§4 handoffs), product owner (OQ-7 decision)
- **Regulatory baseline verified against current guidance as of July 2026** (sources in §5):
  EDPB Guidelines 07/2020 (controller/processor concepts), EDPB Opinion 22/2024
  (reliance on processors and sub-processors), EDPB Guidelines 1/2024 (Art. 6(1)(f)
  legitimate interest, incl. the network-and-information-security use case), EDPB
  Opinion 28/2024 (AI models and personal data), EDPB report "AI Privacy Risks &
  Mitigations — LLMs" (Apr 2025), EDPB Guidelines 9/2022 (breach notification),
  and the current (unstable) status of the EU–US Data Privacy Framework.

> **Terminology.** "Vendor" = us, the platform operator. "Customer" = the SME tenant
> (the employer whose endpoints are monitored). "Data subjects" = primarily the
> customer's employees, whose usernames, hostnames, IP addresses, authentication
> events, and process command lines (which can embed names, file paths under
> `C:\Users\<name>`, email addresses, URLs, and occasionally credentials) flow
> through the platform as endpoint telemetry.

---

## 1. Role Analysis — Controller vs. Processor per Data Category

Per EDPB Guidelines 07/2020, the role follows from who determines **purposes and
means** of each processing operation, assessed per data category — not per company.
We are simultaneously a controller and a processor.

| # | Data category | Examples in this platform | Our role | Customer's role | Legal basis notes |
|---|---|---|---|---|---|
| D1 | **Signup / account data** | Org name, admin email, password hash (argon2id), verification tokens (AC-1/2), signup IP + abuse signals (AC-8), user records and roles (AC-78), sessions (AC-77), plan/entitlement state | **Controller** | — (data subjects are the customer's staff acting as our users) | Art. 6(1)(b) (contract — account creation, provisioning, trial lifecycle AC-6/9/10); Art. 6(1)(f) (abuse controls AC-4/8, breached-password screening AC-1, login lockout AC-77 — the "fraud prevention" and "information security" legitimate-interest use cases recognized in EDPB Guidelines 1/2024 and Recital 49). Marketing use of signup emails would need a separate basis (Art. 6(1)(a) or 6(1)(f) + Art. 21(2) opt-out) — not in MVP scope. |
| D2 | **Endpoint telemetry** | Process create/terminate incl. command lines, network connections, logon/logoff/failed logons (AC-62/63), hostnames, usernames, IPs, generic JSON ingest events (AC-29), DLQ quarantined raw events (AC-32) | **Processor** (Art. 4(8), Art. 28) | **Controller** | Customer's basis: Art. 6(1)(f) — legitimate interest in network and information security, expressly contemplated by Recital 49 and treated as a named use case in EDPB Guidelines 1/2024. The three-step test (legitimate interest, necessity, balancing) is the **customer's** obligation, but it binds **our product design**: the customer can only pass the necessity/balancing test if the platform collects no more than needed (data minimization, Art. 5(1)(c)) and enforces retention limits (Art. 5(1)(e)). Employee-monitoring balancing is stricter in some Member States (e.g., DE §26 BDSG, works-council co-determination) — see §4 product opportunity P4. We must never repurpose telemetry for our own ends (e.g., training models, cross-tenant analytics) without becoming a controller for that purpose (Art. 28(10)). |
| D3 | **Alerts & detections** | Alert rows with entity keys (host + user, AC-41), correlation groups (AC-43), MITRE mappings, linked events | **Processor** (derived from D2 on the customer's behalf) | **Controller** | Same basis chain as D2; alerts are a transformation of telemetry, not a new purpose. |
| D4 | **AI triage prompts & outputs** | Single-tenant prompt context assembled from alert/event content (AC-48/52), LLM summaries, AI severity, priority scores | **Processor**; the **LLM model provider is our sub-processor** (Art. 28(2)/(4)) | **Controller** | Triage is a "means" of delivering the contracted service — still processing on the customer's documented instructions (Art. 28(3)(a)), provided the DPA names AI triage as an instruction and the LLM provider is an authorized sub-processor. If we ever use tenant prompts/outputs to improve our own models, that is processing for **our** purposes: we become controller for it and need our own Art. 6 basis — per EDPB Opinion 28/2024 this triggers the full legitimate-interest analysis for AI development. MVP must contractually and technically exclude it (§3 GDPR-11/12). |
| D5 | **Audit logs** | Actor user ID / device ID, action, before/after values, timestamps (AC-83–85), 365-day retention (AC-84) | **Mixed.** Tenant-scoped action audit (alert closes, rule toggles, merges): **processor** — it is part of the contracted service and tenant-queryable. Platform-security audit (failed authz AC-85, signup abuse AC-8, our own ops/security logging): **controller** — we determine purpose (protecting our platform, Art. 6(1)(f), Recital 49) | Controller for their staff's employment-context records | Retention beyond the customer's event-retention tier is justifiable under Art. 6(1)(f) (security, accountability, Art. 5(2)) and defense of legal claims — but must be documented in our records of processing and the DPA (see obligation O5 tension analysis). |
| D6 | **Usage metering & billing telemetry** | Per-tenant LLM tokens/cost (AC-51), ingest volume (AC-89), billable asset count (AC-26) | **Controller** where aggregated to tenant level (our billing/margin purposes); processor for the underlying per-event data | — | Art. 6(1)(b)/(f). Keep metering records aggregate (tenant/day counts, no event content, no usernames) so this category holds no employee personal data — design already does this (design §5, metering row per run). |
| D7 | **Asset inventory** | Hostname, OS, MAC, IPs, agent identity, first/last seen (AC-19–27) | **Processor** (service data) + **controller** for the deduplicated billable count as a billing input (AC-26) | **Controller** | Hostnames frequently identify persons (`DESKTOP-JSMITH`, `Anna's-MacBook`); treat asset records as personal data. |

**Boundary consequences (binding):**

1. The control plane never holds tenant security event data (ADR-0001 security
   considerations) — keep it that way; it cleanly separates our controller store
   (D1) from processor stores (D2–D4).
2. Any feature that reads telemetry for **our** purposes (product analytics, rule
   quality tuning across tenants, model improvement) converts us to controller for
   that operation (Art. 28(10) — a processor that determines purposes becomes a
   controller and infringes Art. 28). AC-46's false-positive export to
   detection-engineering sits exactly on this line: exporting `rule ID + entity +
   reason` includes entity keys (host|user). See §3 GDPR-14.

---

## 2. Obligation Map

Each obligation: **what it requires → how the MVP design already addresses it →
gaps.** Legend: ✅ addressed, 🟡 partial, ❌ gap.

### O1 — Art. 28: Processor duties and the Data Processing Agreement

**Requires.** We may only process telemetry under a binding contract per
Art. 28(3), containing at minimum: subject matter/duration/nature/purpose of
processing, data categories, controller obligations and rights, and clauses
(a)–(h): documented instructions only (incl. transfers), confidentiality
commitments, Art. 32 measures, sub-processor conditions per Art. 28(2)/(4),
assistance with data-subject rights (Art. 28(3)(e)), assistance with Arts. 32–36
(Art. 28(3)(f)), deletion or return at end of services (Art. 28(3)(g)), and
audit/information rights (Art. 28(3)(h)). EDPB Opinion 22/2024 adds: the DPA must
not merely restate Art. 28(3) but state concretely **how** each duty is met, and
the controller must be able to know the identity of all sub-processors at all
times regardless of risk level.

**MVP coverage.** 🟡 Technical substrate is strong (isolation AC-79–81, audit
AC-83–85, mTLS AC-28/69, revocable keys AC-29/56–59), but **no DPA exists and
self-serve signup (AC-1–3) has no DPA acceptance step**. For a self-serve product
the DPA must be part of click-through terms — there is no sales-cycle moment to
sign one later.

**Gaps.** (a) DPA drafted and bound into the signup flow before any EU customer
ingests telemetry — see §3 GDPR-01. (b) "Deletion at end of services"
(Art. 28(3)(g)) is only implemented for expired trials (AC-10); there is no
offboarding deletion path for paying tenants — GDPR-04. (c) "Documented
instructions" must expressly cover AI triage and the LLM sub-processor — GDPR-02.

### O2 — Art. 30(2): Records of processing (processor) / Art. 30(1) (controller)

**Requires.** As processor: a written record per controller with categories of
processing, sub-processors, transfers with safeguards, and a general description
of Art. 32 measures. As controller (D1, D5-security, D6): our own Art. 30(1)
record. The Art. 30(5) small-enterprise carve-out will not apply: processing is
not occasional and endpoint monitoring is systematic.

**MVP coverage.** ❌ Nothing exists. However, the tenant registry, plan config,
and entitlements service already hold most per-controller facts (tenant identity,
retention tier, data categories are fixed by the event schema AC-31), so the
record can be largely generated.

**Gaps.** Create and maintain the Art. 30(1)+(2) records; keep the sub-processor
register (LLM provider, cloud/hosting provider, production email provider,
CAPTCHA/blocklist providers per OQ-5) as its source of truth — GDPR-03, GDPR-13.

### O3 — Art. 32: Security of processing

**Requires.** Risk-appropriate technical/organisational measures; Art. 32(1)
names pseudonymisation and encryption, confidentiality/integrity/availability/
resilience, restore capability, and regular testing. Art. 28(3)(c) makes these
contractual; Art. 32(4) requires personnel act only on instructions.

**MVP coverage.** ✅ Strongest area — cite in the DPA's Annex II:
- Tenant isolation: Postgres RLS on every tenant-scoped table with QA-proven
  cross-tenant tests (AC-79), per-tenant ES index patterns failing closed
  (AC-80), 404-not-403 anti-enumeration (AC-81), tenant context solely via
  `packages/tenancy` middleware (AC-82, design §2).
- Transport security: mTLS with per-device identity for agents (AC-28, AC-69),
  TLS + scoped revocable ingest keys (AC-29), no insecure-skip-verify in release
  builds (AC-69).
- AuthN/AuthZ: argon2id, breached-password screening, session invalidation, rate
  limiting (AC-77), server-side role enforcement (AC-17/78).
- Auditability: append-only audit of all state-changing actions incl. failed
  authorization (AC-83–85).
- Resilience/testing: no-silent-data-loss pipeline invariant (AC-91), noisy-
  neighbor SLO protection (AC-87), e2e smoke test (AC-90), cross-tenant prompt
  contamination test (AC-52).

**Gaps.** 🟡 (a) **Encryption at rest is not specified anywhere** in the design
(PG, ES, Redis, agent local disk buffer AC-66, backups) — GDPR-05.
(b) Pseudonymisation of telemetry before the LLM sub-processor is not designed —
GDPR-11. (c) Backup/restore ("availability and resilience") is unstated — the
purge and retention jobs also need to reach backups within a defined window —
GDPR-04. (d) Regular testing exists in QA form; formalize as a recurring control
(pen test cadence) post-MVP [should].

### O4 — Art. 33/34: Breach notification

**Requires.** As **controller** (D1 account data): notify the supervisory
authority within 72 hours of awareness unless unlikely to result in risk
(Art. 33(1)), notify data subjects without undue delay when high risk
(Art. 34). As **processor** (D2–D4): notify **each affected controller
"without undue delay"** after becoming aware (Art. 33(2)) — no 72-hour cushion;
EDPB Guidelines 9/2022 treat the controller as "aware" once the processor tells
it, so customer contracts will demand tight windows (market norm: 24–48h,
often contractually less). We must also be able to supply Art. 33(3) content:
categories and approximate number of data subjects and records affected —
per tenant.

**MVP coverage.** 🟡 Building blocks exist: security-relevant events are audited
(AC-83/85), pipeline failures are observable with tenant labels (AC-91), internal
operational alerts fire (AC-5, AC-40). Cross-tenant isolation defects are
release-blocking (success metric: 0).

**Gaps.** (a) No incident-response/breach-notification **process**: no severity
classification, no clock-start definition, no per-tenant blast-radius query
("which tenants/data categories did incident X touch"), no customer notification
channel (MVP is console-only, OQ-6; a frozen-trial admin may not log in for
weeks). GDPR-06. (b) The DPA must state our processor notification commitment
and the information we will provide — GDPR-01(e).

### O5 — Art. 17 erasure, Art. 5(1)(e) storage limitation, retention

**Requires.** Retention proportionate to purpose; deletion at end of services
(Art. 28(3)(g)); assistance with erasure requests the **customer** receives from
its employees (Art. 28(3)(e) — for telemetry, Art. 17 requests go to the
customer, not us, but we must make compliance technically possible).

**MVP coverage.** ✅/🟡
- Retention tiers enforced by entitlement: hot-retention job removes expired
  event data within 24h, config-testable (AC-16; design: ES monthly index
  deletion; Trial 14d / Core 30d / Pro 90d per plan-config).
- Trial purge: freeze at expiry (AC-9), purge event/alert data at T+30, purge
  audit-logged and QA-verifiable-empty (AC-10; S-7 flags this to
  security-architect as GDPR-relevant).
- DLQ quarantine bounded at 7 days (AC-32) — good: raw malformed payloads are
  the least-minimized data in the system.

**Gaps / tensions.**
(a) **Purge completeness.** AC-10 says "event/alert data". A complete tenant
purge must cover: per-tenant ES indices (`events-v1-{tenant}-*` + aliases), PG
rows across **all** tenant-scoped tables (alerts, events-link, assets + identity
links + correction pins, devices, enrollment tokens, ingest keys, DLQ
`dead_letter_events`, triage/metering rows containing content, rules state,
users/sessions of that tenant), Redis (sessions, quota counters, onboarding
signals, entitlement cache entries, device-revocation entries, **and in-flight
Redis Streams messages** `pipe:*` which carry event payloads per design §4),
object storage when the warm tier lands, backups within a documented window, and
**LLM-provider-side retention** of prompts already sent. GDPR-04.
(b) **Audit-log tension.** AC-84 retains audit records ≥365 days "regardless of
event-data retention tier" — i.e., audit outlives both retention tiers and trial
purge. Defensible: Art. 17(3)(b)/(e) (legal obligation where applicable, legal
claims) and Recital 49-grounded legitimate interest in security accountability;
but only if (i) documented in the Art. 30 records and DPA, (ii) audit records
are minimized (actor ID + action metadata — never event/alert **content** in
before/after values), and (iii) post-purge audit records are the *only* personal
data surviving. GDPR-07.
(c) **No erasure-support surface.** Nothing lets a customer find/delete/export
one employee's data across telemetry (needed to *assist* under Art. 28(3)(e);
Art. 17 exceptions may often apply for security data — Art. 17(3), Recital 49 —
but the assessment is the customer's; we must make targeted search possible).
GDPR-08 [should for MVP, must before GA].

### O6 — Chapter V: International transfers (Arts. 44–49) + data residency

**Requires.** Any transfer of D1–D5 outside the EEA needs a Chapter V mechanism:
adequacy (Art. 45), or appropriate safeguards (Art. 46 — 2021 SCCs, BCRs) plus a
Schrems II transfer impact assessment and supplementary measures where needed.
Art. 28(3)(a): even *instructed* transfers must be documented; the DPA + SCC
annexes must disclose transfer destinations.

**Current legal posture (verified July 2026 — this moves fast):** the EU–US Data
Privacy Framework adequacy decision is formally still in force, but is under
acute threat: the 29 June 2026 US Supreme Court ruling against FTC independence
undermines a pillar of the framework's oversight, and the *Schrems III* challenge
is pending before the CJEU with an opinion expected late 2026/early 2027.
**Planning assumption: do not architect EU customer flows on DPF adequacy alone.**
Fallback = SCCs (Commission Decision 2021/914; Module 2 controller→processor for
customer→us, Module 3 processor→sub-processor for us→LLM/cloud) + documented TIA.

**MVP coverage.** ❌/🟡
- **OQ-7 is open**: data residency/region of the single shared stamp is
  undecided, while the PRD explicitly expects EU prospects. This is the
  launch-blocking compliance decision. ADR-0001's dedicated stamp is the
  premium answer (EU-region dedicated deployment) but the *shared pool's* region
  decides for every self-serve EU customer.
- **LLM provider location/region is unspecified** (design §4.2 shows
  `worker-triager -.-> model provider` with no region or terms). Triage prompts
  carry usernames/hostnames/command lines — a transfer to a US-region model
  endpoint is a Chapter V transfer of employee personal data.
- Positive: ADR-0001's stamp model makes an EU-region stamp a deployment
  decision, not a rewrite; tenancy-mode agnosticism (AC-82) preserves that.

**Gaps.** GDPR-09 (residency decision before EU launch), GDPR-10 (EU-region or
EU-processing LLM endpoint, or SCCs+TIA with the provider), GDPR-01(f) (SCC
annexes in the DPA).

### O7 — Art. 28(2)/(4): Sub-processor authorization chain

**Requires.** No sub-processor without prior specific or general written
authorization; under general authorization we must inform the controller of
intended additions/replacements and give an objection opportunity (Art. 28(2)).
The same data-protection obligations flow down by contract (Art. 28(4)), and we
remain fully liable to the controller for the sub-processor's performance.
EDPB Opinion 22/2024: the controller must be able to identify **every**
sub-processor in the chain (name, address, contact) at all times; we must verify
sub-processors provide "sufficient guarantees" regardless of risk level, and be
able to demonstrate it.

**Sub-processor register (MVP snapshot — maintain as living annex):**

| Sub-processor | Function | Data touched | Chapter V exposure |
|---|---|---|---|
| **LLM model provider** | AI triage (AC-48), future deep investigation (AC-53) | Alert/event content incl. usernames, hostnames, IPs, command lines (D4) | Depends on endpoint region — GDPR-10 |
| Cloud/hosting provider (stamp infra) | All stores (PG, ES, Redis), compute | D1–D6 | Depends on OQ-7 region + provider entity |
| Production email provider (mailpit is dev-only, design §7) | Verification/notification email (AC-1) | Admin emails (D1 — we are controller; still list for transparency) | Provider-dependent |
| CAPTCHA / disposable-email blocklist provider (OQ-5) | Signup abuse (AC-8) | Signup IP, email domain (D1, controller side) | Provider-dependent |
| Breached-password check source (AC-1) | Password policy | Must be k-anonymity range query or local corpus — never the password or full hash | None if k-anonymized/local |

**MVP coverage.** ❌ No register, no DPA to hang it on, no flow-down terms with
the LLM provider verified. AC-51 (model ID recorded per call) helpfully gives
per-tenant evidence of *which* model/provider processed each alert.

**Gaps.** GDPR-12 (LLM flow-down terms: no-training, retention, confidentiality,
Art. 32, audit, breach notice), GDPR-13 (register + change-notification
mechanism).

### O8 — Art. 25 + Art. 5(1)(c): Data protection by design / minimization (telemetry & AI)

**Requires.** Data protection by design and by default; collect/process only
what the security purpose needs. For LLM systems, the EDPB "AI Privacy Risks &
Mitigations — LLMs" report (Apr 2025) tells deployers to contractually and
technically control prompt retention, prohibit reuse for training/fine-tuning,
and minimize personal data in prompts. EDPB Opinion 28/2024 makes clear that
personal data in model interactions remains fully GDPR-governed unless genuinely
anonymized (a high bar).

**MVP coverage.** 🟡 Positive: single-tenant prompt assembly with QA marker-string
tests (AC-52); triage summaries bounded (AC-48); metering is content-free
aggregate (AC-51); DLQ bounded 7 days (AC-32); ADR-0002 collects a defined
telemetry set (process/network/auth) rather than full content capture — no
keystrokes, no file contents, no screen capture. That restraint is itself the
product's minimization story and supports the customer's Art. 6(1)(f) balancing.

**Gaps.** (a) Command lines are the highest-risk field (credentials, names,
tokens embedded in argv) — no scrubbing/redaction is designed anywhere between
agent and LLM. GDPR-11, GDPR-15. (b) No DPIA support: customers monitoring
employees will frequently need an Art. 35 DPIA (Art. 35(3)(a) systematic
evaluation; WP29/EDPB criteria: employee monitoring = "data concerning
vulnerable data subjects" + "systematic monitoring") — we should supply the
technical description that feeds it (§4 P2). (c) Our own Art. 37 DPO analysis:
Art. 37(1)(b) applies to processors whose **core activity** is regular and
systematic monitoring of data subjects on a large scale — an EDR/SOC platform is
close to the textbook case; appoint a DPO (or document why not) before EU
launch. GDPR-16. (d) If the vendor entity has no EU establishment, Art. 27 EU
representative designation is required when serving EU customers — GDPR-17.

---

## 3. MVP Design-Time Requirements (for the Architect)

Numbered `GDPR-xx`; each is phrased to be testable so it can become an AC.
`[must]` = hard legal obligation; `[should]` = best practice / risk reduction.

**GDPR-01 [must] — DPA in the signup flow.** (Art. 28(3)(a)–(h), 28(9))
Signup (extend AC-1) must record acceptance of Terms + DPA (versioned document
ID, timestamp, accepting user) before tenant provisioning completes; acceptance
is audit-logged (extends AC-83). The DPA must concretely cover: (a) processing
description matching the event schema (AC-31) and this document's D2–D5;
(b) instruction scope expressly including detection, alerting, and AI triage;
(c) Art. 32 measures annex citing the mechanisms in §2-O3; (d) sub-processor
general authorization + notification/objection mechanism (Art. 28(2));
(e) processor breach notification commitment with a defined window
(Art. 33(2)); (f) SCC Module 2 incorporation with transfer annexes if the stamp
or any sub-processor is outside the EEA; (g) deletion/return at end of services
(Art. 28(3)(g)). *Test:* no tenant can reach `active` state without a stored DPA
acceptance record.

**GDPR-02 [must] — AI triage disclosed as a documented instruction.**
(Art. 28(3)(a), Art. 13/14 transparency downstream) The DPA and a public
sub-processor page must state that alert/event content is sent to the named LLM
provider for triage, which fields, which regions, and the retention terms.
*Test:* documentation review; the field list matches the actual prompt builder's
tenant-scoped fetchers (design §5, LLM tenancy row).

**GDPR-03 [must] — Records of processing.** (Art. 30(1)+(2)) Maintain an
Art. 30(2) record per controller (generate from the tenant registry +
plan-config: identity, categories, retention tier, sub-processors, transfer
safeguards) and an Art. 30(1) record for controller-side processing (D1,
D5-security, D6). *Test:* record export exists for an arbitrary tenant and for
the vendor; reviewed against schema contract AC-31.

**GDPR-04 [must] — Tenant purge completeness (extends AC-10; applies to any
tenant offboarding, not only expired trials).** (Art. 28(3)(g), Art. 17,
Art. 5(1)(e)) A purge of tenant T must delete, and QA must verify empty:
(a) all ES indices/aliases matching `events-v1-{T}-*`; (b) all rows in every
RLS tenant-scoped PG table — alerts + event links, assets + identity links +
correction pins, devices, enrollment tokens, ingest keys, `dead_letter_events`,
triage outputs, rules state, users and sessions; (c) all Redis keys and stream
entries carrying `tenant_id = T` — sessions, quota/rate counters, entitlement
cache, device-revocation set, onboarding signals, and any unconsumed `pipe:*`
messages (drain-before-purge or tombstone filter); (d) content-bearing metering
rows (aggregate counts may be retained); (e) backups/snapshots within a
documented window stated in the DPA (e.g., ≤35 days); (f) a deletion request to
the LLM provider where its terms retain prompts, or evidence of a zero-retention
tier (pairs with GDPR-12). The purge writes a completion certificate to the
audit log enumerating stores purged (extends AC-10's audit entry). Paying-tenant
offboarding must trigger the same job. *Test:* extend AC-10's QA check to every
store above, including a probe event parked in the DLQ and an unconsumed stream
message.

**GDPR-05 [must] — Encryption at rest.** (Art. 32(1)(a)) All persistent stores
holding D1–D5 (PostgreSQL, Elasticsearch, Redis persistence/snapshots, object
storage when added, backups) use at-rest encryption; the agent's local disk
buffer (AC-66) is encrypted or OS-protected with documented rationale. *Test:*
infra config review per store; agent buffer file inspection on a test host.

**GDPR-06 [must] — Breach detection→notification runbook and blast-radius
query.** (Art. 33(1)–(3), 33(2), 33(5), Art. 34) Before GA: (a) documented
incident classification and clock-start ("awareness") definition; (b) an
internal-facing capability to enumerate, for a given incident window/component,
the affected tenants, data categories, and approximate record counts (leverages
tenant-labeled metrics AC-89/91 and audit AC-83/85) — this supplies Art. 33(3)
content; (c) an out-of-console notification channel to tenant admins (email —
note OQ-6 synergy); (d) an internal breach register per Art. 33(5). *Test:*
tabletop exercise produces a mock Art. 33(2) notice for a simulated cross-tenant
leak within the DPA-committed window.

**GDPR-07 [must] — Audit-log minimization for the 365-day tier.** (Art. 5(1)(c),
5(1)(e), Art. 17(3) reliance) Audit records (AC-83/84) must contain actor and
action **metadata only**; before/after values must never embed telemetry/alert
content bodies (reference IDs instead). Post-purge (GDPR-04), audit records are
the only surviving tenant-linked personal data, and the DPA states the 365-day
audit retention and its justification. *Test:* schema review of `audit_log` +
QA scan of audit rows generated by the e2e smoke test (AC-90) for event-content
fields; post-purge global scan finds tenant personal data only in `audit_log`.

**GDPR-08 [should — must before GA] — Data-subject search/export support.**
(Art. 28(3)(e); customer's Arts. 15–17) Tenant admins can query events/alerts
by user identifier and hostname across retention (exists via ES tenant-scoped
query and AC-44 host filter — add a user filter), and export the results
(machine-readable). Targeted single-subject deletion may be deferred with a
documented rationale (Recital 49 / Art. 17(3) security exemptions usually
apply), but the DPA must state how we assist. *Test:* per-user query returns
all and only that identifier's events for the tenant.

**GDPR-09 [must] — Data residency decision before EU launch (resolves OQ-7).**
(Arts. 44–46; Art. 28(3)(a)) The shared-pool stamp region, the failover/backup
region, and every sub-processor's processing region are decided and documented
before EU customers can sign up. If any is outside the EEA: execute SCCs
(2021/914, correct modules), complete a TIA, and — given the DPF's instability
(June 2026 FTC ruling; pending Schrems III) — **do not rely on DPF adequacy as
the sole mechanism**. Signup messaging states processing region (feeds §4 P3).
*Test:* documented decision + transfer map; contract annexes list regions.

**GDPR-10 [must] — LLM endpoint region and transfer mechanism.** (Arts. 44–46)
The triage model endpoint (worker-triager, design §4.2) is pinned to an
EEA-region or EU-processing endpoint for EU tenants, **or** the transfer is
covered by SCCs Module 3 + TIA with documented supplementary measures. Model
routing by tier (business model #5) must respect this pin — no silent fallback
to a non-compliant region. *Test:* worker-triager config review; AC-51's
recorded model ID/endpoint per call proves region at audit time.

**GDPR-11 [should] — Prompt minimization/pseudonymization before the LLM.**
(Art. 5(1)(c), Art. 25(1), Art. 32(1)(a); EDPB LLM report deployer measures)
The prompt builder sends only fields needed for triage quality; before
transmission it (a) drops direct identifiers not needed for the summary (e.g.,
replace usernames with stable per-tenant pseudonyms `user-7f3a`, re-resolved for
display in the console), and (b) runs secret/credential scrubbing on command
lines (regex classes: passwords-in-argv, tokens, connection strings). Where
full fidelity is needed for quality, the un-minimized variant requires a
documented decision + DPA disclosure. *Test:* marker-string test (extends
AC-52): plant a username and a fake credential in an event; assert the LLM-bound
payload contains the pseudonym and redaction, while the console alert detail
still shows the real values.

**GDPR-12 [must] — Model-provider terms: no-training, bounded/zero retention.**
(Art. 28(4), Art. 32; EDPB LLM report) Before the first EU tenant's alert is
triaged, the LLM provider contract must include: (a) prompts/outputs are **not
used for training or model improvement**; (b) zero data retention, or a
disclosed maximum retention window (incl. abuse-monitoring logs) stated in our
DPA; (c) Art. 28(3)-equivalent flow-down terms (confidentiality, security,
sub-sub-processor conditions, audit, breach notice, deletion); (d) processing
region commitment (pairs with GDPR-10). *Test:* contract on file; provider
config (e.g., ZDR flag/tier) verified in worker-triager deployment config.

**GDPR-13 [must] — Sub-processor register + change notification.** (Art. 28(2);
EDPB Opinion 22/2024) Maintain the §2-O7 register (name, entity address,
function, data categories, region, safeguard) as the single source of truth
referenced by the DPA; adding/replacing a sub-processor (e.g., new model in the
routing table) triggers advance notice to tenant admins with an objection window
per the DPA. *Test:* register exists and matches deployed reality (every model
ID recorded by AC-51 metering appears in the register).

**GDPR-14 [must] — FP-export minimization (constrains AC-46).** (Art. 28(10),
Art. 5(1)(b)/(c)) The false-positive dataset consumed by detection-engineering
contains rule ID, close reason, and **pseudonymized or generalized** entity data
(e.g., entity-type + tenant-hashed key), unless used strictly per-tenant on that
tenant's instruction. Any cross-tenant aggregate use for rule tuning is either
anonymous (EDPB Opinion 28/2024's negligible-identifiability standard) or
disclosed in the DPA as a permitted purpose. *Test:* schema review of the AC-46
export; no raw `host|user` keys in cross-tenant datasets.

**GDPR-15 [should] — Telemetry field-level minimization review.** (Art. 5(1)(c),
Art. 25(2)) The event schema contract (OQ-3, AC-31) gets a per-field privacy
annotation (identifier / quasi-identifier / content) reviewed by
security-architect; command-line capture supports a tenant-configurable
redaction policy post-MVP. Document why each collected field is necessary for
detection — this artifact also feeds customers' LIAs/DPIAs (§4 P2). *Test:*
schema contract contains the annotation column.

**GDPR-16 [must] — DPO designation analysis.** (Art. 37(1)(b), 37(2)) Before EU
launch, document the Art. 37 analysis; given that large-scale regular and
systematic monitoring is the platform's core activity, expect the answer to be
"appoint" (internal or external DPO; publish contact, notify the lead SA).
*Test:* documented analysis; DPO contact in the privacy notice and DPA.

**GDPR-17 [must, conditional] — Art. 27 EU representative.** If the vendor
entity has no EEA establishment, designate an EU representative before serving
EU customers (Art. 27(1); the Art. 27(2) exemption will not apply — processing
is not occasional and includes systematic monitoring). *Test:* representative
named in the privacy notice/DPA.

**GDPR-18 [should] — Breached-password check is privacy-preserving (constrains
AC-1).** (Art. 5(1)(c), Art. 32) The check uses a local corpus or a k-anonymity
range API; the candidate password or its full hash never leaves the control
plane. *Test:* code review + egress inspection during signup.

---

## 4. Product Opportunities (handoffs to product-manager — not specced here)

Customer GDPR obligations we can turn into differentiators. SMEs have no privacy
team; "compliance built in" sells the same way "SOC built in" does.

| # | Opportunity | Customer obligation it serves | Handoff |
|---|---|---|---|
| P1 | **Self-serve DPA download / acceptance center** — versioned DPA, SCC annexes, signature record, re-acceptance flow on updates | Art. 28(3), 28(9) (their duty to have a DPA with us) | product-manager |
| P2 | **DPIA/LIA support pack** — auto-generated technical description of what we collect per event class (from the AC-31 schema + GDPR-15 annotations), retention tier, sub-processors; exportable for the customer's Art. 35 DPIA and Art. 6(1)(f) LIA, incl. works-council conversations | Art. 35, Art. 6(1)(f), Art. 5(2) | product-manager |
| P3 | **Data-processing transparency page** — live region map (stamp region per OQ-7, LLM endpoint region), sub-processor list with change-notification signup (doubles as our GDPR-13 mechanism), retention tiers per plan | Art. 13/14 (their notices name us), Art. 28(2) | product-manager |
| P4 | **Per-tenant data export** — full tenant export (events, alerts, assets, audit) in machine-readable form; serves offboarding (Art. 28(3)(g) "return"), Art. 20 adjacency, and Morgan's MSP-lite billing-evidence need (P2 persona) | Art. 28(3)(g), Art. 15 assistance | product-manager |
| P5 | **Data-subject search console** (productized GDPR-08) — "show/export everything about user X" for admin response to employee Art. 15 requests | Art. 15, Art. 28(3)(e) | product-manager |
| P6 | **EU-region dedicated stamp as compliance SKU** — ADR-0001's dedicated tier marketed for residency-sensitive customers; premium price for guaranteed EEA-only processing incl. EU LLM endpoint | Chapter V comfort; procurement checkbox | product-manager |
| P7 | **Breach-support artifacts** — per-tenant incident timeline from the audit log (AC-83–85) packaged so an affected customer can draft its own Art. 33(1) notification from our Art. 33(2) notice | Art. 33(1)/(3) | product-manager |

---

## 5. Sources (verified 2026-07-08)

- [EDPB Guidelines 07/2020 on the concepts of controller and processor](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-072020-concepts-controller-and-processor-gdpr_en)
- [EDPB Opinion 22/2024 on reliance on processors and sub-processors](https://www.edpb.europa.eu/system/files/2024-10/edpb_opinion_202422_relianceonprocessors-sub-processors_en.pdf)
- [EDPB Guidelines 1/2024 on Art. 6(1)(f) legitimate interest (incl. network & information security use case)](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202401_legitimateinterest_en.pdf)
- [EDPB Opinion 28/2024 on AI models and personal data](https://www.edpb.europa.eu/system/files/2024-12/edpb_opinion_202428_ai-models_en.pdf)
- [EDPB report: AI Privacy Risks & Mitigations — Large Language Models (Apr 2025)](https://www.edpb.europa.eu/system/files/2025-04/ai-privacy-risks-and-mitigations-in-llms.pdf)
- [EDPB Recommendations 1/2026 on BCR-P (Art. 28(4) chains)](https://www.edpb.europa.eu/system/files/2026-01/edpb_recommendations202601_bcr-p_v1_en.pdf)
- [European Commission — EU–US data transfers status](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/eu-us-data-transfers_en)
- [DPF at risk after US Supreme Court FTC ruling (activeMind.legal analysis, 2026)](https://www.activemind.legal/guides/dpf-supreme-court/) and [DPF status 2026 overview](https://globaldatashield.com/blog/eu-us-data-privacy-framework-2026)
- [ICO: required contents of controller–processor contracts (Art. 28(3) checklist)](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/contracts-and-liabilities-between-controllers-and-processors-multi/what-needs-to-be-included-in-the-contract/)
- EDPB Guidelines 9/2022 on personal data breach notification (processor "without undue delay" and controller awareness timing).

---

## Report

**1. Summary.** Baseline GDPR obligation map produced for
`platform-foundation-mvp`. Role split: controller for signup/account data,
billing metering, and platform-security audit; processor for telemetry, alerts,
and AI-triage content, with the LLM provider as a sub-processor requiring
Art. 28(2)/(4) treatment. The MVP's Art. 32 posture is strong (RLS AC-79–81,
mTLS, append-only audit AC-83–85, no-silent-loss AC-91); the material gaps are
contractual and lifecycle: no DPA in the self-serve signup flow, no Art. 30
records or sub-processor register, purge (AC-10) not yet provably complete
across ES/PG/Redis/DLQ/streams/backups/LLM-side retention, no breach runbook or
per-tenant blast-radius capability, encryption at rest unspecified, and two
launch-blocking transfer decisions open (stamp residency OQ-7 and LLM endpoint
region — with DPF reliance inadvisable given the June 2026 FTC ruling and
pending Schrems III). Eighteen numbered, testable design-time requirements
(GDPR-01..18, [must]/[should]) are ready for the Architect to fold into
acceptance criteria.

**2. Files.** Created: `D:\agent\eng-org\docs\compliance\gdpr-obligations.md`
(this document).

**3. Obstacles.** (a) OQ-7 (data residency) and the LLM provider/endpoint region
are unresolved upstream decisions; GDPR-09/10 are written to force them before
EU launch rather than assume an answer. (b) The DPF's legal status is in flux
(Schrems III pending; CJEU opinion expected late 2026/early 2027) — this
document takes the conservative SCC+TIA planning assumption and should be
re-verified at each release. (c) The vendor's corporate establishment (EEA or
not) is unknown, so GDPR-17 (Art. 27 representative) is conditional.

**4. Handoffs.** Architect: fold GDPR-01..18 into `platform-foundation-mvp`
acceptance criteria (GDPR-04 extends AC-10; GDPR-07 constrains AC-84; GDPR-11
extends AC-52; GDPR-14 constrains AC-46; GDPR-18 constrains AC-1).
security-architect: GDPR-04/05/06/07/11 intersect flags S-5, S-6, S-7.
product owner + cloud-platform: decide OQ-7 (GDPR-09). ai-platform: GDPR-10/11/12
(model endpoint region, prompt minimization, provider terms). product-manager:
opportunities P1–P7 (§4). Legal counsel (external): DPA drafting per GDPR-01,
SCC execution, DPO appointment (GDPR-16).
