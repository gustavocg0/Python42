# NIS2 Baseline Obligation Map — SaaS SOC Platform (Vendor as MSSP)

- **Document:** `docs/compliance/nis2-obligations.md`
- **Status:** Baseline v1 — 2026-07-08
- **Author:** compliance agent
- **Scope:** Directive (EU) 2022/2555 ("NIS2") obligations of the **platform vendor** (us), plus product opportunities arising from **customers'** NIS2 obligations. GDPR, CRA, DORA are out of scope of this document (separate maps needed; flagged in §5).
- **Inputs:** `docs/prd/business-model.md`, `docs/prd/platform-foundation-mvp.md` (AC-1..AC-91), `docs/design/platform-foundation-mvp.md`, ADR-0001, ADR-0002
- **Primary legal sources (verified against current text, July 2026):**
  - Directive (EU) 2022/2555 (NIS2), esp. Art. 2, 3, 20, 21, 23, 24, 26, 27, Annex I
  - Commission Implementing Regulation (EU) 2024/2690 of 17 Oct 2024 ("CIR 2024/2690") — technical/methodological requirements for Art. 21(2) measures and significance thresholds for digital-infrastructure-type entities **including managed security service providers** (CIR Art. 1; MSSP incident thresholds in CIR Art. 10)
  - ENISA *Technical Implementation Guidance on Cybersecurity Risk Management Measures*, v1.0, 26 June 2025 (non-binding; interprets the CIR Annex)

---

## 1. Applicability Analysis

### 1.1 What we are

The vendor operates a multi-tenant SaaS SOC: detection, AI triage, and (per business model) automated response for SME customers. This squarely matches the NIS2 definition of a **managed security service provider (MSSP)** — Art. 6(40): a managed service provider (Art. 6(39)) "carrying out or providing assistance for activities relating to cybersecurity risk management." MSSPs are listed in **Annex I ("Sectors of high criticality"), sector 8 "ICT service management (business-to-business)"** — not Annex II. The first-party endpoint agent (ADR-0002) and remote response capability are exactly the "high level of access to customers' systems" that the Directive's recitals cite as the reason MSPs/MSSPs were pulled into the high-criticality annex.

### 1.2 Size-cap rule — and a correction of a common misconception

- **Art. 2(1):** NIS2 applies to Annex I/II entity types that qualify as **medium-sized enterprises** under Recommendation 2003/361/EC (≥50 employees, or >€10M annual turnover/balance sheet) or exceed the medium ceilings.
- **Art. 2(2)(a):** the "regardless of size" carve-in covers only (i) providers of public electronic communications networks/services, (ii) trust service providers, (iii) TLD name registries and DNS service providers. **MSSPs are NOT in this list.** Vendor blogs frequently claim otherwise; the Directive text does not support it (verified against Art. 2(2), July 2026).
- **Art. 2(2)(b)–(e):** a below-threshold MSSP can still be individually designated by a Member State (sole provider of a critical service, significant systemic impact, criticality at national/regional level). Unlikely for us at launch; possible at scale.

**Consequence:** as an early-stage company below the medium-enterprise thresholds we are likely **not yet formally in scope**. We cross into scope automatically the day we reach 50 employees or >€10M turnover — with no transition period. Retrofitting Art. 21 measures into a shipped platform is far more expensive than designing them in now, and our customers (§1.5) will demand equivalent assurances contractually regardless. **Working assumption for all engineering: design and operate as an important entity from day one.**

### 1.3 Essential vs. important

- **Art. 3(1):** Annex I entities that **exceed** the medium-enterprise ceilings (i.e., large: ≥250 employees or >€50M turnover and >€43M balance sheet) are **essential entities**.
- **Art. 3(2):** Annex I/II entities in scope that do not qualify as essential are **important entities**.
- Therefore: **medium-sized us = important entity; large us = essential entity.** The substantive Art. 20/21/23 obligations are identical; the difference is supervision (essential = ex-ante + ex-post supervision, important = ex-post only, Art. 32/33) and maximum fines (essential: ≥€10M or 2% worldwide turnover; important: ≥€7M or 1.4% — Art. 34(4)–(5)).

### 1.4 Jurisdiction and transposition status (mid-2026)

- **Art. 26(1)(b):** MSSPs fall under the jurisdiction of the Member State of their **main establishment** (where cybersecurity risk-management decisions are predominantly taken; fallbacks in Art. 26(2)). **If the company has no EU establishment but offers services in the EU, Art. 26(3) requires designating an EU representative** — failing which any Member State where we serve customers can take action. The company's establishment/legal seat is not stated in any input doc; this is an open decision (ties to PRD OQ-7 data residency) and gates which national law applies to us.
- **Transposition:** the deadline was 17 Oct 2024; as of mid-2026 roughly two-thirds of Member States have transposed (Germany's NIS2UmsuCG in force 6 Dec 2025; France still in legislative process as of May 2026; Commission infringement actions ongoing against laggards). Practical effect: our own registration/reporting duties crystallize under the national law of our main establishment; our EU customers' obligations arrive on a per-country schedule through 2026.
- **CIR 2024/2690 applies to us directly** (it is a Regulation, no transposition needed) once we are an in-scope MSSP: its Annex specifies *how* Art. 21(2) measures must be implemented, and its Art. 3, 4 and 10 define *when* one of our incidents is "significant" for Art. 23.

### 1.5 Indirect applicability today (before we hit the size cap)

Many of our SME customers will themselves be NIS2 essential/important entities. Under **Art. 21(2)(d) and 21(3)** they must manage supply-chain security "taking into account the vulnerabilities specific to each direct supplier and service provider." An MSSP with an endpoint agent on every customer machine is their highest-risk supplier. Expect security questionnaires, contractual flow-down of Art. 21-equivalent measures, and incident-notification SLAs in customer contracts **from launch**, regardless of our own formal scope status.

---

## 2. Article-by-Article Obligation Map

Legend: **Status** = how the MVP (PRD AC-1..91 + design doc) addresses it today. Gaps feed §3.

### 2.1 Art. 20 — Governance

| Obligation | Source | MVP status | Gap |
|---|---|---|---|
| Management body must **approve** the cybersecurity risk-management measures and **oversee** implementation; members can be held personally liable for infringements | Art. 20(1) | Nothing — this is an organizational duty, not a code artifact. The PRD's security flags S-1..S-8 and mandatory security-architect reviews (ADR-0001/0002) are evidence of a review process but nobody formally "approves" a risk-measure set | **Gap:** no documented risk-management-measure set for the board/CEO-agent to approve; no approval record. See REQ-14 |
| Management body members must follow cybersecurity **training**; employees should be offered training regularly | Art. 20(2) | Nothing | **Gap:** training program + records. Org backlog, pre-GA. See REQ-15 |

### 2.2 Art. 21 — Cybersecurity risk-management measures (a)–(j)

Art. 21(1): "appropriate and proportionate technical, operational and organisational measures," all-hazards, proportional to risk/size/cost. For us, the CIR 2024/2690 **Annex** concretizes every point below; ENISA's June 2025 Technical Implementation Guidance gives evidence examples per requirement.

| § | Measure | MVP status (cite) | Gap |
|---|---|---|---|
| (a) | Policies on risk analysis and information system security | Threat-modeling gates exist (PRD §8 S-1..S-8 require security-architect **before implementation**); ADR security-considerations sections | No written information-security policy or risk-analysis method; no risk register. REQ-13/14 |
| (b) | **Incident handling** (our own incidents) | Strong observability substrate: AC-91 (every pipeline failure observable, per-tenant/stage labels, no silent loss), AC-89 (per-tenant quota/rejection metrics), AC-5/AC-40 (internal operational alerts on provisioning failure, bad rules), AC-83–85 (append-only audit log, 365-day retention — reconstructs actions) | No internal incident-response process: no classification against CIR Art. 3/10 significance thresholds, no on-call/escalation runbook, no "awareness" timestamping that starts the Art. 23(4) clock. REQ-1, REQ-2 |
| (c) | **Business continuity**: backup management, disaster recovery, crisis management | AC-90 (stamp redeploys cleanly via Helm/Terraform + smoke test) helps DR of *compute*. Nothing for *data*: the design (§3, §7) defines PG/ES/Redis but **no backup, restore, RPO/RTO, or crisis-management mechanism anywhere in the design doc** | Major gap for a platform holding customers' security telemetry. REQ-3 |
| (d) | **Supply-chain security** (our direct suppliers) | ADR-0002 non-negotiables: signed agent artifacts, staged rollout, HSM signing keys, SLSA provenance (agent supply chain treated as prime target). PRD S-6 flags LLM model-provider data handling | No supplier inventory or security terms: the **LLM provider receives tenant security-event content** (design §4, worker-triager → model provider) — our most sensitive external dependency; also ES/PG/Redis hosting, email provider, CAPTCHA provider (OQ-5). REQ-8 |
| (e) | Security in acquisition/development/maintenance, **vulnerability handling and disclosure** | devsecops function exists (CI security gates); ADR-0002 update-channel requirements; import-linter boundary enforcement (design §1) | No coordinated vulnerability disclosure (CVD) policy, no security.txt, no patch-management SLA for our own stack. REQ-6, REQ-7 |
| (f) | Policies/procedures to **assess effectiveness** of the measures | QA-verifiable ACs are a real asset: AC-79/80 (cross-tenant isolation proof suite, release-blocking per success metrics), AC-87 (noisy-neighbor SLO test), AC-64 (full-pipeline e2e in CI), AC-55 (quota concurrency test) | Continuous internal tests exist, but no periodic independent assessment (pentest/audit) is scheduled. REQ-9 |
| (g) | Basic **cyber hygiene** practices and cybersecurity training | — | Org-level; pairs with Art. 20(2). REQ-15 |
| (h) | Policies on **cryptography and encryption** | Strong in transit: AC-28/AC-69 (mTLS with per-device identity, no insecure-skip-verify), AC-29 (TLS ingest), argon2id password hashing (design §5), dev CA bootstrap (design §7) | **No encryption-at-rest requirement** for PG/ES/backups anywhere in PRD or design; no written crypto policy (algorithms, key management, rotation). REQ-4 |
| (i) | **HR security, access-control policies, asset management** | Customer-side access control is well covered: AC-77 (session lifecycle, lockout), AC-78 (admin/analyst roles enforced server-side), AC-17 (backend enforcement, never UI-only), AC-81 (404-not-403). Customer asset management: E3 (AC-19–27) | **Internal/operator access is undesigned:** AC-11 has an "internal operator" changing plan config with no defined internal role model, access-control policy, or joiner/leaver process for production access. REQ-5 |
| (j) | **Multi-factor or continuous authentication**, secured voice/video/text and emergency communications | Design §5: auth is email+password only; "MFA-ready: user model carries `mfa_enrolled` fields unused in MVP"; SSO/SAML explicitly out (PRD out-of-scope #5) | MFA is required by CIR Annex practice (ENISA guidance expects MFA at least for privileged/remote/admin access) on **our own** systems: production access, internal operator tooling. Customer-console MFA is the same control surface. REQ-5 (internal, MVP) and REQ-10 (customer console, pre-GA) |

### 2.3 Art. 23 — Incident reporting (24h / 72h / 1 month)

What it requires of **us** once in scope:

1. **Art. 23(1):** notify our CSIRT/competent authority of any **significant incident** without undue delay; also notify **recipients of our services** (customers) of significant incidents likely to adversely affect the provision of the service.
2. **Art. 23(2):** communicate to potentially affected customers, without undue delay, any **significant cyber threat** plus measures/remedies they can take.
3. **Art. 23(3):** an incident is significant if it (a) has caused or can cause severe operational disruption or financial loss for us, or (b) has affected or can affect others by causing considerable material/non-material damage.
4. **CIR 2024/2690 sharpens (3) for MSSPs** — for us an incident is significant when, inter alia (CIR Art. 3 general + Art. 10 MSP/MSSP-specific):
   - direct financial loss > **€500,000 or 5% of annual turnover**, whichever is lower (CIR Art. 3(a)); exfiltration of trade secrets; death or considerable damage to health; **successful, suspectedly malicious unauthorized access capable of causing severe operational disruption** (CIR Art. 3);
   - the managed security service is **completely unavailable for > 30 minutes** (CIR Art. 10(a));
   - availability limited for **> 5% of users in the Union or > 1M users** (whichever smaller) for **> 1 hour** (CIR Art. 10(b));
   - integrity/confidentiality/authenticity of service-related data **compromised by suspectedly malicious action** (CIR Art. 10(c)) — note: **no user-count floor** on this one; a single malicious cross-tenant read is reportable;
   - such compromise impacting > 5% / 1M users in the Union (CIR Art. 10(d));
   - **recurring incidents** — ≥2 in 6 months with the same apparent root cause that only collectively meet the loss threshold count as one significant incident (CIR Art. 4).
5. **Art. 23(4) timeline:** **early warning ≤ 24h** of becoming aware (flag suspected unlawful/malicious cause, possible cross-border impact) → **incident notification ≤ 72h** (initial assessment of severity/impact, indicators of compromise) → **intermediate report on request** → **final report ≤ 1 month** after the incident notification (detailed description, root cause/threat type, mitigations, cross-border impact); for ongoing incidents, a progress report then final report within 1 month of handling completion.

**MVP status.** The platform can *observe* its own failures unusually well for an MVP (AC-91 per-stage/per-tenant failure metrics; AC-89; AC-85 security-relevant auth failures logged; AC-83–84 audit trail), and the trigger events of CIR Art. 10(c) are exactly what AC-79/80/81 isolation tests are designed to prevent. What is missing is everything between "metric fired" and "regulator notified":

- No definition of "aware" and no timestamped incident record starting the 24h clock (REQ-1).
- No ability to quantify blast radius in CIR Art. 10(b)/(d) terms — *which tenants, how many users, for how long* — as a queryable fact within hours (REQ-2). The per-tenant labels required by AC-89/AC-91 are the correct substrate; an aggregation is missing.
- **No out-of-band customer notification channel.** PRD out-of-scope #11 makes alerting console-only; if the console (or a tenant) is down, we cannot fulfil Art. 23(1)/(2) duties to notify recipients. OQ-6 (email notifications) is therefore not merely a UX decision — it has a compliance dimension for us as vendor (REQ-11).

### 2.4 Art. 24 — Certification

- **Art. 24(1):** Member States *may* require use of ICT products/services/processes certified under EU schemes (Regulation (EU) 2019/881). **Art. 24(2):** the Commission *may*, by delegated act, mandate certification for categories of essential/important entities. **Art. 24(3):** the Commission may ask ENISA to prepare candidate schemes where none exist.
- **Current position (mid-2026):** no delegated act mandates certification for MSSPs; the EU cloud scheme (EUCS) remains unadopted. **No hard obligation today.** [should]: monitor delegated acts; expect national procurement and enterprise customers to ask for ISO/IEC 27001 or equivalent as a market (not legal) requirement — see REQ-16 and §4.

### 2.5 Registration duties — Art. 27 (and Art. 3(3)–(4))

- **Art. 27(1) explicitly lists managed security service providers.** We must submit to the competent authority (forwarded to ENISA's registry): entity name, Annex I/II sector/sub-sector, main-establishment address and other EU establishments (or EU representative), up-to-date contact details, **the Member States where we provide services, and our IP ranges**. Baseline deadline was 17 Jan 2025 for entities then in scope; for us the duty attaches when we come into scope, and **changes must be notified within 3 months** (Art. 27(4)).
- **Art. 3(3)–(4):** Member States list essential/important entities (first lists due 17 Apr 2025, biennial review); entities supply name, address, contacts, sector, service list, Member States of service — updates **within two weeks** of change. National transpositions implement this via registration portals (e.g., Germany's BSI reporting portal).
- **MVP status:** purely organizational; no code dependency. The one design touchpoint: we must be able to state our service IP ranges — the single-stamp architecture (ADR-0001, design §7) makes this trivial today; keep it true as stamps multiply (REQ-12).

---

## 3. MVP Design-Time Requirements (for the Architect)

Numbered NIS2-REQ-n. Each is phrased as a testable requirement, labeled **[must]** (hard legal obligation once in scope — and design-time-cheap now) or **[should]** (best practice / market-driven / obligation that can mature later), with the NIS2 source and the phase: **MVP** (fold into platform-foundation-mvp acceptance criteria) or **pre-GA backlog** (scheduled item that must exist before general availability to EU customers).

1. **NIS2-REQ-1 [must] [MVP]** — *Incident awareness clock.* Every internal operational alert (the AC-5, AC-40 class, plus new infra/security alert sources) SHALL create a persistent, timestamped internal incident record with a mandatory triage decision field: significant-per-CIR yes/no/undetermined, decided against the CIR 2024/2690 Art. 3 and Art. 10 criteria checklist. Test: QA raises a synthetic pipeline failure; an incident record with awareness timestamp and classification decision exists. (Art. 23(4)(a) — the 24h clock runs from "becoming aware"; Art. 21(2)(b).)
2. **NIS2-REQ-2 [must] [MVP]** — *Blast-radius query.* The platform SHALL answer, from the AC-89/AC-91 per-tenant metrics and tenant records, within 1 hour of an incident: (a) which tenants were affected by a given stage failure/outage window, (b) total affected tenants as % of active tenants, (c) their aggregate user count, (d) outage duration per tenant. Test: QA induces a 45-minute simulated ingest outage; the query returns the affected-tenant set and durations. (CIR Art. 10(a), (b), (d) — the >30 min / >5%-of-users thresholds are unanswerable without this; feeds Art. 23(4)(b) 72h impact assessment.)
3. **NIS2-REQ-3 [must] [MVP for backups; pre-GA for tested restore]** — *Backup and DR.* PostgreSQL (control + tenant schemas, including the audit log) and Elasticsearch event indices SHALL be backed up on a defined schedule with a documented RPO/RTO; backups SHALL be encrypted and access-controlled; a restore SHALL be exercised (game-day) before GA. Test: restore drill recovers a tenant's alerts/assets/audit trail to within RPO. (Art. 21(2)(c); CIR Annex business-continuity/backup section. The current design doc specifies zero backup mechanism — the largest single gap found.)
4. **NIS2-REQ-4 [must] [MVP]** — *Encryption at rest + crypto policy.* All data stores (PG, ES, Redis persistence, backups, agent local buffer per AC-66) SHALL encrypt data at rest; a one-page cryptography policy (approved algorithms, TLS versions, key management/rotation, argon2id parameters) SHALL exist in docs/compliance. Test: infra config review + storage-level verification. (Art. 21(2)(h); CIR Annex cryptography section.)
5. **NIS2-REQ-5 [must] [MVP]** — *Internal operator access control.* The "internal operator" path (AC-11 plan changes, provisioning intervention per AC-5, rule-pack publishing per AC-39) SHALL be a defined internal role with MFA-protected authentication, least-privilege scoping, and audit logging via the AC-83 pipeline (actor = named operator, never a shared account). Test: plan change without MFA-authenticated operator identity is rejected; audit record shows named actor. (Art. 21(2)(i), (j); CIR Annex access-control/MFA requirements. AC-83 already lists entitlement change as auditable — the missing half is who may do it and how they authenticate.)
6. **NIS2-REQ-6 [must] [MVP]** — *Vulnerability handling & CVD.* Publish a coordinated vulnerability disclosure policy and security contact (RFC 9116 security.txt on web + docs); define internal SLAs for triaging/remediating vulnerabilities in platform and agent (the agent is the highest-privilege component we ship, ADR-0002). Test: security.txt served; a submitted test report enters the tracked triage flow. (Art. 21(2)(e) — "vulnerability handling and disclosure" is verbatim in the measure; CIR Annex 6.x.)
7. **NIS2-REQ-7 [must] [MVP — already substantially designed]** — *Agent update-channel integrity as testable ACs.* Convert ADR-0002 non-negotiable #1 into acceptance criteria: signed artifacts verified by the agent before apply; staged ring rollout; automatic rollback; strict code-vs-content separation (AC-39 already separates rule content from code deploys — extend the same discipline to agent binaries/config). Test: unsigned/tampered update is rejected by the agent; rollback drill passes. (Art. 21(2)(e); Art. 21(2)(d) — we are the supply chain of every customer.)
8. **NIS2-REQ-8 [must] [MVP for the LLM provider; pre-GA for full register]** — *Supplier security register.* Maintain a register of direct suppliers with security assessment: **the LLM model provider first** (it receives tenant security-event content per design §4 worker-triager; require contractual no-training/retention limits and EU processing terms — pairs with PRD S-6), then cloud/hosting, email, CAPTCHA (OQ-5). Test: register exists with per-supplier data-classes-shared and contract clauses noted. (Art. 21(2)(d), 21(3).)
9. **NIS2-REQ-9 [should] [pre-GA]** — *Independent effectiveness assessment.* Schedule an external penetration test covering the multi-tenant isolation surface (AC-79–81), agent enrollment (AC-56–59), and ingest auth (AC-28/29) before GA, and annually thereafter; keep the AC-79/80 isolation suite and AC-87 noisy-neighbor test as continuous controls. (Art. 21(2)(f); CIR Annex effectiveness-assessment section.)
10. **NIS2-REQ-10 [should — must before serving essential-entity customers] [pre-GA]** — *Customer console MFA.* Implement TOTP MFA on the customer console; the design's `mfa_enrolled` user-model fields (design §5, AC-77 "MFA-ready") make this a scheduled backlog item, not a redesign. A security vendor selling to NIS2-regulated customers cannot credibly ship password-only auth at GA. (Art. 21(2)(j) as applied to the service we operate; customers' own Art. 21(2)(j) duties make this a procurement blocker.)
11. **NIS2-REQ-11 [must] [MVP: verified contact + procedure; pre-GA: email pipeline]** — *Out-of-band customer notification channel.* MVP: retain the verified admin email from signup (AC-1/AC-2) as a designated security-notification contact, editable in console, and document an operational procedure to mass-notify affected tenants outside the console. Pre-GA: automated email notification (resolves OQ-6 — note its compliance dimension: Art. 23(1) second subparagraph and 23(2) oblige us to notify **recipients of our services** of significant incidents/threats without undue delay; console-only notification fails when the platform itself is the incident). Test: mass-notification drill reaches all tenant admin contacts of a marked tenant set.
12. **NIS2-REQ-12 [must] [org task, MVP-timeframe]** — *Registration readiness.* Maintain a standing record of: legal entity, main establishment (or designation of an EU representative if the company is not EU-established — Art. 26(3), open decision, ties OQ-7), Member States where services are provided, contact details, and current service IP ranges (trivial with the single stamp, ADR-0001; keep an authoritative list as stamps multiply). Submit to the national registry within the national deadline when we come into scope; keep updates within 3 months (Art. 27(4)) / two weeks for Art. 3(4) list data.
13. **NIS2-REQ-13 [should] [MVP-timeframe, document-only]** — *Information-security policy + risk register.* Write the baseline ISMS-lite: information-security policy, risk-analysis method, and a living risk register seeded from PRD §8 S-1..S-8 and the ADR security-considerations sections. (Art. 21(2)(a); CIR Annex security-policy section. Cheap now, painful later.)
14. **NIS2-REQ-14 [must once in scope; should now] [org task]** — *Management-body approval.* The risk-management measure set (this document's §3 + the security-architect outputs) SHALL be formally approved by company management with a dated record, and re-approved on material change. (Art. 20(1) — approval, oversight, personal liability.)
15. **NIS2-REQ-15 [must once in scope; should now] [org backlog]** — *Training.* Cybersecurity training for management, then all staff, recorded. (Art. 20(2); Art. 21(2)(g).)
16. **NIS2-REQ-16 [should] [watch item]** — *Certification watch.* No certification mandate for MSSPs exists today (Art. 24(2) delegated act not adopted; EUCS pending). Track quarterly; plan ISO/IEC 27001 as market-driven pre-requisite for essential-entity customers rather than as a NIS2 legal duty. (Art. 24.)

**MVP vs pre-GA summary:** REQ-1, 2, 4, 5, 6, 7, 8(LLM), 11(contact+procedure), plus REQ-3 backup jobs → fold into platform-foundation-mvp ACs now. REQ-3 restore drill, 9, 10, 11(email) → scheduled pre-GA backlog with owners. REQ-12–16 → organizational track, start now, cheap.

---

## 4. Product Opportunities (customers' NIS2 obligations → features)

Our SME customers that are essential/important entities carry the same Art. 20/21/23 duties with far less capacity. Each item below is a **handoff to product-manager** — flagged, not specced.

1. **Incident evidence export for Art. 23 deadlines.** One-click export of an alert/correlation group (AC-43 group, linked events per AC-41/42, asset context per E3, audit trail per AC-74) pre-structured to the Art. 23(4) fields: early-warning payload (suspected malicious cause? cross-border impact?) for the customer's 24h deadline, and the 72h notification fields (severity, impact, indicators of compromise). National CSIRT form formats vary by transposition — a per-country template layer is the moat. *(Customer obligation: Art. 23(4)(a)–(b).)*
2. **"Significance" triage assist.** Extend AI triage (AC-48) with a guided checklist mapping an incident to the customer's Art. 23(3) significance test (and, for customers who are themselves Annex-covered digital entities, CIR 2024/2690 thresholds), producing a documented significant/not-significant rationale. Positioning: decision support, clearly labeled per AC-49 — never automated legal judgment. *(Art. 23(3); CIR Art. 3/4.)*
3. **Log-retention attestation & retention upsell.** Generate a signed attestation of what event classes were collected and retained for how long (retention entitlement per AC-16, audit log per AC-83–84). NIS2-regulated customers need evidence for supervisors (Art. 21(2)(f), Art. 32/33 supervision); the 90-day Pro hot-retention ceiling (business model) becomes a natural "compliance retention" tier upsell. *(Art. 21(2)(b), (f).)*
4. **Asset-inventory evidence.** E3's deduplicated, source-audited inventory (AC-21/22/24, billable-count API AC-26) doubles as the customer's Art. 21(2)(i) asset-management evidence — an exportable, timestamped inventory report is nearly free to build.
5. **Management reporting pack (Art. 20 oversight).** Periodic plain-language security-posture report (alert volumes, top risks, MTTR, coverage) formatted for the customer's management body to discharge its Art. 20(1) oversight duty — a natural extension of the AI triage voice (AC-48 reading-level target).
6. **Supply-chain questionnaire responder / trust page.** Because customers must assess *us* under Art. 21(2)(d)/(3), a public trust page (subprocessors, measures mapped to Art. 21(2)(a)–(j), pentest summaries per REQ-9) converts a compliance cost into a sales asset.
7. **Registration/reporting reminders.** Lightweight: surface the customer's own registration duties (Art. 3(4) two-week update window, Art. 27 where applicable) and per-country CSIRT contacts in-product. Low effort, high SME goodwill.

---

## 5. Related regimes not covered here (future compliance maps)

- **GDPR** — trial purge (AC-10, S-7), telemetry PII in LLM prompts (S-6), data residency (OQ-7). Separate map required; several MVP mechanisms serve both regimes.
- **Cyber Resilience Act (CRA)** — the endpoint agent is a "product with digital elements"; CRA obligations (in force, main obligations applying from Dec 2027) will hit the agent product line (ADR-0002). Separate map before agent GA.
- **DORA** — if we acquire financial-entity customers, we become an ICT third-party service provider under their DORA duties; contractual, not direct.
- **EU AI Act** — AI triage/deep investigation classification to be assessed; likely limited-risk transparency duties (AC-49's AI-labeling already aligns).

---

## Sources

- Directive (EU) 2022/2555 (NIS2) — [EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555); article texts verified via [nis-2-directive.com](https://www.nis-2-directive.com/) (Art. 2, 3, 20, 21, 23, 24, 26, 27), July 2026
- Commission Implementing Regulation (EU) 2024/2690 — [EUR-Lex](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng) (Art. 1, 3, 4, 10; Annex)
- ENISA, *NIS2 Technical Implementation Guidance*, v1.0, 26 June 2025 — [enisa.europa.eu](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance)
- Transposition status — [European Commission NIS2 transposition tracker](https://digital-strategy.ec.europa.eu/en/policies/nis-transposition); [ECSO tracker](https://ecs-org.eu/policy/nis2-directive-transposition-tracker/); Germany NIS2UmsuCG in force 6 Dec 2025; France pending as of May 2026
