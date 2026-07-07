# Business Plan — Living Document

- **Document:** `docs/business/business-plan.md`
- **Status:** v1.0 — 2026-07-08
- **Owner:** business-planner agent
- **Discipline:** every cost, gate, SKU, and GTM claim in this plan traces to a compliance finding ID, a CEO directive, or a business-model decision. Items are tagged **[cost]**, **[gate]**, or **[opportunity]**.
- **Inputs (binding):**
  - `docs/prd/business-model.md` (Draft v1, 2026-07-07) — tier ladder, pricing metric, deployment shapes ("BM" citations below)
  - `docs/compliance/nis2-obligations.md` (Baseline v1, 2026-07-08) — findings **NIS2-REQ-1..16**
  - `docs/compliance/dora-obligations.md` (Baseline v1, 2026-07-08) — findings **COMP-1..13**
  - `docs/compliance/gdpr-obligations.md` (Baseline v1, 2026-07-08) — findings **GDPR-01..18**, opportunities P1–P7
- **CEO directives:** none exist yet (`docs/ceo/` is empty as of this version). All strategic assumptions below are therefore provisional on future CEO direction; items that would normally require a directive are flagged **[needs-CEO]**.
- **Financial figures:** ALL figures in this document are **estimates** from public market comparables (sources in §7) unless stated otherwise. No price points are set here — per-tier price points remain an open question in the business model (BM Open Questions).

---

## 0. Plan-on-a-page

The compliance baselines converge on one strategic fact: **our target customers' regulations are our sales channel, and our own regulatory posture is our license to use it.** NIS2-obligated SMEs and DORA financial entities are forced buyers of exactly what we sell — but they can only buy from a vendor that can survive their supplier due diligence (NIS2 Art. 21(2)(d) flow-down per nis2-obligations §1.5; DORA Art. 28(8)/30 per dora-obligations §2). The plan therefore sequences spend and sales as: **(1) MVP-blocking contractual/residency decisions → (2) pre-GA assurance artifacts → (3) compliance-differentiated SKUs at premium price points.**

---

## 1. Compliance Cost Register

Every cost the compliance findings imply. "Tier/price affected" states where the cost must be recovered in the tier ladder (BM Tier Ladder). Sizing figures are **estimates** (see §7 sources); internal-effort costs are noted qualitatively because no staffing/rate baseline exists yet **[needs-CEO]**.

| # | [cost] item | One-off / recurring | Rough sizing (estimate) | Source finding ID(s) | Tier/price affected |
|---|---|---|---|---|---|
| C-1 | **ISO/IEC 27001 certification** (implementation + certification audit; scope = the stamp per design §2) | One-off implementation + 3-yr cert cycle with annual surveillance audits | Year 1 all-in **~$20k–50k** (cert-body fees ~$10k–22k + implementation/tooling/internal hours); surveillance years **~$8k–15k/yr**. 200–500 internal hours year 1 | COMP-9 (audit-rights resolution at multi-tenant scale), NIS2-REQ-16 (market-driven, not legal duty; essential-entity customers will demand it), NIS2 §4.6 (trust page) | Enables FE and essential-entity sales at **Pro/Dedicated**; amortize into Pro+ pricing. Start now — 6–12 month lead time per COMP-9 |
| C-2 | **SOC 2 Type II** (optional bundle with C-1; primarily for non-EU/US-influenced buyers) | Recurring annual attestation | **~$20k–60k/yr** all-in; bundling with ISO 27001 through one firm saves ~20–35% | COMP-9 (named alongside ISO 27001 as the pooled-audit substitute) | Same as C-1. Decision to do one or both is **[needs-CEO]** (depends on target-market mix) |
| C-3 | **External legal counsel — DPA + SCC annexes bound into signup flow** | One-off drafting + periodic re-versioning | **~€15k–40k** initial drafting (DPA with concrete Art. 28(3)(a)–(h) content per EDPB Opinion 22/2024, SCC Modules 2/3, transfer annexes, TIA support); smaller recurring re-review | GDPR-01, GDPR-09 (SCC/TIA fallback given DPF instability), GDPR-02, GDPR-07 (DPA must state audit-retention justification) | All tiers — DPA acceptance is a provisioning precondition for every EU tenant (Gate G-1). Cost is tier-independent overhead |
| C-4 | **External legal counsel — DORA contractual addendum** (all Art. 30(2)(a)–(i) + 30(3)(a)–(f) clauses, self-serve e-sign at Core/Pro) | One-off drafting + updates on Level-2 changes | **~€10k–30k** (estimate; scoped narrower than C-3, reuses its service description). Combined C-3+C-4 engagement likely cheaper | COMP-7, COMP-4 (transition-support terms), COMP-12 (TLPT clause) | Unlocks the FE segment (Opportunity O-2); recover via FE-lane pricing/premium retention add-ons |
| C-5 | **DPO — fractional/external** | Recurring | **~€21k–35k/yr** (typical band €1,750–2,900/mo; SaaS/security platforms trend to the upper band) | GDPR-16 (Art. 37(1)(b) — large-scale systematic monitoring is our core activity; expect "appoint") | All tiers, EU launch precondition; overhead spread across EU revenue |
| C-6 | **EU representative (Art. 27 GDPR + NIS2 Art. 26(3))** — conditional: only if vendor entity has no EEA establishment | Recurring | **~€1k–3k/yr** (service-provider market rate) | GDPR-17, NIS2-REQ-12 | All EU-serving tiers. Conditional on establishment decision **[needs-CEO — the establishment question itself is open per NIS2 §1.4 / GDPR-17]** |
| C-7 | **External penetration test** (multi-tenant isolation surface, agent enrollment, ingest auth) | Recurring annual, first before GA | **~$10k–35k per engagement** (SaaS scope incl. tenant isolation) | NIS2-REQ-9, COMP-9 (pen-test summaries in due-diligence pack), GDPR §2-O3(d) | Pre-GA overhead; summaries become sales collateral for Pro/Dedicated (NIS2 §4.6) |
| C-8 | **EU-region infrastructure** — EU stamp region, EU backups, encryption at rest, backup/DR with tested restore | Recurring infra premium + one-off engineering | Sizing depends on cloud provider choice (open). Components: KMS/at-rest encryption (small %), backup storage + game-day drills (engineering days), possible EU-region price delta vs. cheapest region | GDPR-05, GDPR-09, GDPR-04(e) (backup purge windows), NIS2-REQ-3, NIS2-REQ-4, COMP-1, COMP-11 | All tiers (shared pool must itself be residency-clean per GDPR-09 — Dedicated is *not* the fix for self-serve EU customers) |
| C-9 | **LLM provider enterprise terms** — no-training, zero/bounded retention, EU-region or EU-processing endpoint, flow-down clauses | Recurring (enterprise-tier inference pricing typically carries a premium over consumer/API list) | Premium over base inference cost — quantify when model provider is selected (ai-platform decision in flight) | GDPR-10, GDPR-11, GDPR-12, COMP-3, NIS2-REQ-8 (LLM provider = highest-sensitivity supplier) | Directly hits **AI-triage COGS in every tier** (BM consequence #5: LLM spend is per-tenant first-class metric). Deep-investigation margin math must use the compliant endpoint's price, not list price |
| C-10 | **LEI registration** | One-off + annual renewal | **~€100 initial, ~€60–100/yr renewal** (GLEIF-accredited issuer rates; estimate) | COMP-13 (CIR 2024/2956 provider-identification template expects a code) | Negligible; unlocks FE register-of-information data pack (Opportunity O-2) |
| C-11 | **Customer-facing incident/breach notification pipeline** — production email vendor, status page, per-tenant impact reporting | One-off engineering + small recurring vendor fees | Email vendor **~$100–500/mo** at SME scale (estimate); status page SaaS **~$0–1k/yr**; engineering effort the dominant cost | NIS2-REQ-11, COMP-5, GDPR-06(c) | All tiers — console-only alerting fails Art. 23(1)/(2) NIS2, Art. 30(2)(f) DORA, Art. 33(2) GDPR simultaneously. Highest-severity shared gap across all three maps |
| C-12 | **Incident-response capability** — awareness clock, CIR-threshold classification checklist, blast-radius query, breach register, tabletop exercises | One-off engineering (mostly reuses AC-89/91 substrate) + recurring drill time | Engineering days + ~2–4 tabletop exercises/yr (internal time) | NIS2-REQ-1, NIS2-REQ-2, GDPR-06(a)(b)(d), COMP-5 (tenant-impact attribution hook) | Overhead, all tiers |
| C-13 | **CVD program** — security.txt, disclosure policy, triage SLAs (optionally later a bug-bounty budget) | One-off setup; bounty (if any) recurring | Setup ~engineering days; bounty program deferred **[needs-CEO]** | NIS2-REQ-6 | Overhead, all tiers |
| C-14 | **Supplier/sub-processor register + change-notification mechanism** (versioned, machine-readable; objection windows) | One-off doc + small recurring maintenance | Internal time; notification tooling rides C-11 | NIS2-REQ-8, COMP-2, GDPR-13 | Overhead; becomes customer-facing trust asset (Opportunity O-1/O-2) |
| C-15 | **Governance track** — ISMS-lite policy set, risk register, management approval records, staff training | Recurring internal | Document-only now ("cheap now, painful later" per NIS2-REQ-13); training **~€100–300/head/yr** (estimate) once staffed | NIS2-REQ-13, NIS2-REQ-14, NIS2-REQ-15 | Overhead, all tiers |
| C-16 | **NIS2 registration & regulator-cooperation readiness** — registry filings, IP-range record, named regulatory contact, single-tenant disclosure procedure | Recurring admin (small) | Internal time; filings free | NIS2-REQ-12, COMP-10 | Overhead. Attaches automatically at 50 employees / €10M turnover (Risk R-3) |
| C-17 | **Paid-tenant export & offboarding machinery** (bulk export in documented formats, verified deletion incl. backups + LLM-side, transition-period support) | One-off engineering | Engineering sprint(s); reuses trial-purge machinery (AC-10) | COMP-4, GDPR-04, GDPR-08 | All paid tiers; doubles as revenue asset ("DORA exit-ready", Opportunity O-2.5) |
| C-18 | **Customer console MFA (TOTP)** | One-off engineering | Small (design is "MFA-ready" per NIS2-REQ-10) | NIS2-REQ-10 | Gate for essential-entity customers; table-stakes for a security vendor at GA |
| C-19 | **TLPT cooperation** (policy now; per-engagement cost later, served via dedicated stamp) | Contingent per TLPT-scoped customer | Policy = document-only now; actual TLPT participation costs borne per engagement — price into Dedicated contracts | COMP-12 | **Dedicated tier only** — reinforces dedicated-stamp premium (BM: dedicated deployment is a premium differentiator) |
| C-20 | **Regulatory watch** — quarterly certification-mandate watch (Art. 24/EUCS), transposition tracker, DPF/Schrems III status, annual CTPP reassessment | Recurring internal (compliance agent) | Internal time | NIS2-REQ-16, dora-obligations §1.3, GDPR §2-O6 | Overhead; drives Risk Register §5 re-verification dates |

**Cost shape summary (estimates):** Year-1 one-off spend concentrates in C-1 + C-3 + C-4 + C-7 ≈ **$60k–160k** external spend, plus engineering time. Steady-state recurring compliance overhead ≈ **$45k–110k/yr** (C-1/C-2 surveillance, C-5, C-6, C-7, C-10, C-11, C-20) before infra deltas. This is the compliance floor that per-endpoint pricing must clear — feed into the open price-point research (BM Open Questions). **[needs-CEO: budget approval; also NIS2-REQ-14 requires management to formally approve the risk-measure set — the same approval meeting should ratify this register.]**

---

## 2. Gated Milestone Timeline

Sales gates are as binding as engineering gates. A [gate] is violated equally by shipping the thing or by *selling/claiming* the thing.

### Phase 1 — MVP-blocking (nothing below can be deferred without re-scoping the MVP)

| # | [gate] | Blocked until | Source |
|---|---|---|---|
| G-1 | **No EU tenant may reach `active` state** | Data-residency decision made and documented (resolves OQ-7) + DPA acceptance step in signup flow + LLM endpoint region/terms compliant | GDPR-01, GDPR-09, GDPR-10, GDPR-12, COMP-1, COMP-3 |
| G-2 | **No LLM/model provider may be adopted or switched** (incl. per-tier routing additions per BM consequence #5) | Provider terms verified: no-training, defined retention, disclosed processing locations, flow-down clauses; provider entered in versioned sub-processor register | GDPR-12, COMP-2, COMP-3, NIS2-REQ-8 |
| G-3 | **No marketing or signup flow targeting financial entities** | FE self-identification flag exists in signup/settings (so DORA obligations are at least *visible* when they arrive silently) | COMP-7 (MVP hook), dora-obligations §1.1 |
| G-4 | **No production data stores without encryption at rest; no launch without backup jobs running** | GDPR-05 / NIS2-REQ-4 verified per store; NIS2-REQ-3 backup schedule live | NIS2-REQ-3, NIS2-REQ-4, GDPR-05 |
| G-5 | **No internal-operator production actions via shared accounts / without MFA** | Internal operator role with MFA + named-actor audit | NIS2-REQ-5 |

### Phase 2 — Pre-GA (must exist before general availability to EU customers)

| # | [gate] | Blocked until | Source |
|---|---|---|---|
| G-6 | **No GA to EU customers** | Restore drill passed (RPO/RTO measured); breach runbook + blast-radius query + breach register operational; out-of-band notification email pipeline live; external pentest done; DPO analysis documented (expect: appoint); EU representative designated if non-EEA established; records of processing exist; data-subject search/export available | NIS2-REQ-3 (restore), NIS2-REQ-9, NIS2-REQ-11, GDPR-03, GDPR-06, GDPR-08, GDPR-16, GDPR-17 |
| G-7 | **No financial-entity customer signed — or knowingly retained after FE self-identification** | DORA addendum executed/e-signable covering all Art. 30(2)/30(3) items + subcontractor register customer-visible with notification/objection window + paid-tenant export & offboarding path + platform-incident notification channel with committed window | COMP-2, COMP-4, COMP-5, COMP-7 |
| G-8 | **No essential-entity (large NIS2) customer onboarded** | Customer console MFA shipped | NIS2-REQ-10 |
| G-9 | **No "EU-only processing" / residency-based sale of the Dedicated stamp** | EU stamp region AND EU/EEA LLM endpoint both pinned and documented — a dedicated EU stamp with a US-region model endpoint is not an EU-only offering | GDPR-10, GDPR §4-P6, COMP-1 |
| G-10 | **No paid-tier price publication for compliance SKUs** | Cost register §1 totals reflected in unit economics (open BM question on price points) — prices set below the compliance floor are a business-model violation, not just a margin problem | BM Open Questions (price points), §1 summary |

### Phase 3 — Pre-scale (before deliberate scale-up of regulated segments)

| # | [gate] | Blocked until | Source |
|---|---|---|---|
| G-11 | **No scaled FE go-to-market motion** (outbound, FE-specific campaigns) | ISO 27001 (± SOC 2) certification achieved — Art. 28(8) due diligence and Art. 30(3)(e) audit rights are unsatisfiable at self-serve scale without it; start now, 6–12 mo lead | COMP-9 |
| G-12 | **No TLPT-scoped customer contract** | TLPT cooperation policy + dedicated-stamp path in the addendum | COMP-12 |
| G-13 | **No crossing of 50 employees / €10M turnover without registration readiness** | NIS2 registration package ready to file within national deadline; scope attaches automatically with no transition period | NIS2-REQ-12, nis2-obligations §1.2 |
| G-14 | **No opt-in to DORA CTPP oversight** (standing directive until reversed) | Recommendation stands: do not opt in under Art. 31(11); re-evaluate only on CEO directive | dora-obligations §1.3 **[needs-CEO to ratify]** |

---

## 3. Compliance-Driven Revenue Opportunities

Segments and SKUs created by **customers'** regulatory obligations. Each traces to the product-opportunity handoffs in the compliance docs (NIS2 §4.1–4.7, DORA §4.1–4.6, GDPR §4 P1–P7). Product-manager owns the specs; this section owns the commercial rationale. Revenue figures are directional **estimates** — no market-size research has been commissioned yet (pairs with the open BM price-point question).

### O-1 [opportunity] — NIS2-obligated SME segment (priority: **HIGHEST — build first**)

- **Who:** essential/important entities among EU SMEs (medium-sized: ≥50 employees or >€10M turnover, Annex I/II sectors) whose obligations arrive per-country through 2026 as transposition completes. These are **forced buyers**: Art. 21(2)(b) incident handling and Art. 23 reporting are legal duties they cannot staff internally.
- **SKUs / features (source: nis2-obligations §4.1–4.7):** incident evidence export pre-structured to Art. 23(4) fields with per-country CSIRT templates (§4.1 — "the per-country template layer is the moat"); significance-triage assist (§4.2); log-retention attestation (§4.3); asset-inventory evidence export (§4.4); management reporting pack for Art. 20 oversight (§4.5); public trust page / questionnaire responder (§4.6 — converts our own compliance cost C-1/C-7/C-14 into collateral); registration reminders (§4.7).
- **Pricing fit:** §4.3 explicitly makes the 90-day Pro hot-retention ceiling a natural **"compliance retention" upsell** — package §4.1+§4.2+§4.3+§4.5 as a **"NIS2 evidence pack" add-on or Pro-tier differentiator**. Premium justified: the buyer's alternative is external consultants at multiples of our subscription price. Directional uplift assumption: **+15–30% ARPA** on affected tenants (estimate, validate in price research).
- **Timing:** sellable the moment the honest-claims rules in §4 allow (features describable as "designed for NIS2 incident-reporting timelines" without any certification prerequisite) — this is why it is first.

### O-2 [opportunity] — DORA financial-entity segment (priority: **HIGH, gated by G-7/G-11**)

- **Who:** SME-sized payment institutions, e-money institutions, boutique investment firms, MiCA-authorised CASPs (dora-obligations §1.1 realism table). Every one of them **must** obtain Art. 30(2)/(3) contract terms and register-of-information data from every ICT vendor — a vendor that hands these over self-serve wins on procurement friction alone.
- **SKUs / features (source: dora-obligations §4.1–4.6):** DORA evidence pack / register-of-information export aligned to CIR 2024/2956 templates (§4.1, builds on COMP-2/COMP-13); incident classification & reporting assistant tracking the 4h/24h/72h/1-month clocks (§4.2 — long-range: Art. 19(1) permits outsourcing the reporting itself → **premium managed-reporting tier**); per-tenant service-level attainment reports (§4.3 — nearly free, metrics exist); FE-aligned retention add-on, 1yr+ (§4.4); "DORA exit-ready" export/offboarding as trust feature (§4.5); self-serve FE onboarding lane (§4.6 — keeps FE acquisition self-serve instead of sales-led, protecting the BM's self-serve economics).
- **Pricing fit:** FE lane naturally lands at **Pro-with-add-ons or Dedicated**; the managed-reporting concept is a genuinely new premium SKU above the current ladder **[needs-CEO before committing — it implies regulated-adjacent service delivery]**. Directional: FE tenants should carry **+25–50% ARPA** vs. like-sized non-FE tenants via the evidence-pack + retention + SLA-reporting bundle (estimate).
- **Timing:** after G-7 (addendum) — legal spend C-4 is the unlock; certification C-1 (G-11) is the scale unlock.

### O-3 [opportunity] — EU-residency Dedicated stamp as compliance SKU (priority: **MEDIUM-HIGH, premium anchor**)

- **Who:** residency-sensitive customers of any segment; TLPT-scoped FEs (COMP-12 names the dedicated stamp as the clean TLPT answer); customers whose regulators insist on unrestricted audit (COMP-9 names it as the escalation answer).
- **Source:** GDPR §4-P6 ("premium price for guaranteed EEA-only processing incl. EU LLM endpoint"), BM decision: dedicated single-tenant is already the premium deployment shape — compliance gives it a *reason to exist* beyond preference.
- **Pricing fit:** justifies the Dedicated tier's annual-commit premium; the EEA-only guarantee (incl. LLM endpoint per G-9) is a checkbox competitors without a first-party stamp model cannot cheaply copy (ADR-0001 "one stamp, two shapes" per BM consequence #7 makes our marginal cost low).
- **Directional sizing:** low volume, high ACV; treat as top-of-ladder anchor rather than volume play.

### O-4 [opportunity] — GDPR trust surface for every EU SME (priority: **MEDIUM — mostly cheap, bundle don't charge**)

- **Source:** GDPR §4 P1–P5, P7: self-serve DPA center (P1), DPIA/LIA support pack (P2), transparency page (P3, doubles as our own GDPR-13 mechanism), per-tenant export (P4), data-subject search console (P5), breach-support artifacts (P7).
- **Commercial role:** these are **conversion and churn-prevention assets**, not standalone SKUs — "compliance built in sells the same way SOC built in does" (gdpr-obligations §4). Exception: P2 (DPIA pack) and P5 (data-subject search) have standalone upsell potential in employee-monitoring-sensitive markets (DE works-council contexts, GDPR §2 D2 note) — price test later.

**Cross-cutting pricing note:** the existing tier ladder (BM) differentiates on features and retention. The compliance opportunities add a second, orthogonal premium axis — **evidence and assurance** — which monetizes best as add-on packs (NIS2 evidence pack, DORA evidence pack, compliance retention) so that the per-endpoint base price stays competitive for unregulated SMEs. Recommendation to CEO/product-manager: keep compliance packs as attachable SKUs rather than forcing a fifth tier. **[needs-CEO]**

---

## 4. GTM Positioning Constraints

Binding rules for marketing at each milestone. Rationale: NIS2 §2 and DORA/GDPR obligation maps document **gaps** — until each gap's verdict is PASS (by compliance agent review or external audit), claiming the end-state is a misrepresentation with regulatory and contractual consequences (an FE customer relies on our claims for its own Art. 28(8) due diligence — a false claim becomes their compliance incident and our liability).

### 4.1 Never — at any milestone, until the named verdict exists

| Forbidden claim | Permitted only after | Source |
|---|---|---|
| "NIS2 compliant" / "NIS2 certified" | There is no NIS2 product certification to have (Art. 24 delegated act not adopted; EUCS pending). Claim is forbidden **indefinitely** in certification form; "compliant" form only after NIS2-REQ-1..15 verdicts are PASS *and* legal review of the phrase | NIS2-REQ-16, nis2-obligations §2.4 |
| "DORA ready" / "DORA compliant" | COMP-1..7 [must] set is PASS, addendum live, register pack shipping | COMP-1..7, dora-obligations §3 blocking summary |
| "GDPR compliant" (absolute form) | Never in absolute form (standard counsel guidance); specific verifiable statements only (see 4.2) | GDPR-01..18 (open [must] items) |
| "EU data residency" / "your data never leaves the EU" | G-9 satisfied: stamp region + backup region + **LLM endpoint** all EEA, documented | GDPR-09, GDPR-10, COMP-1 |
| "ISO 27001 certified" / "SOC 2 attested" | Certificates in hand (C-1/C-2) | COMP-9 |
| "Bank-grade" / any implied financial-sector endorsement | Never without substantiation; after G-7+G-11, use factual form: "meets DORA Art. 30 contractual requirements for ICT services supporting critical or important functions" | dora-obligations §1.2, COMP-7 |
| Naming customer counts/segments in FE marketing that could feed CTPP concentration narratives | Standing caution — coordinate with compliance before publishing FE-penetration statistics | dora-obligations §1.3 (Risk R-2) |

### 4.2 What CAN honestly be said, by milestone

| Milestone | Honest claims unlocked |
|---|---|
| **Now (pre-MVP)** | "Designed for NIS2 incident-reporting timelines (24h/72h/1-month)" (design-intent claim, NIS2 §4.1); "built on tenant-isolated architecture with release-blocking cross-tenant tests" (AC-79–81 exist, per GDPR §2-O3); "endpoint telemetry limited to process/network/auth events — no keystrokes, no file contents, no screen capture" (GDPR §2-O8 — the minimization story is real today) |
| **After G-1 (DPA + residency + LLM terms)** | "GDPR data-processing agreement included in self-serve signup"; "processing locations disclosed per component"; "AI triage runs under no-training, bounded-retention terms with [named provider]" (GDPR-01/02/12); processing-region statement in signup per GDPR-09 |
| **After G-6 (pre-GA set done)** | "Independently penetration-tested" (C-7); "tested backup and restore with published RPO/RTO"; "breach-notification commitments with defined windows in the DPA"; "data-subject search and export built in" (NIS2-REQ-3/9, GDPR-06/08) |
| **After G-7 (DORA addendum live)** | "DORA Art. 30 addendum available self-serve"; "register-of-information data pack for your CIR 2024/2956 templates"; "supports your 4h/24h/72h incident-reporting clocks" (COMP-7/13, DORA §4.1–4.2) |
| **After G-11 (certification)** | "ISO 27001 certified" (scope statement must match design §2 per COMP-9); pooled-audit and certification-based assurance offered in contracts |
| **After own-scope NIS2 registration (G-13 trigger)** | "Registered NIS2 [important/essential] entity" — factual once true; until then we do not imply we are in scope (we are likely **not yet**, per nis2-obligations §1.2 — claiming otherwise is also false) |

### 4.3 Standing copy rules

- Every compliance-adjacent claim must carry its verifiable basis (link to trust page item, certificate, or DPA clause) — the trust page (NIS2 §4.6, GDPR P3) is the single source marketing may cite.
- AI features: always "decision support," never automated legal judgment (NIS2 §4.2 positioning constraint; aligns with AC-49 AI labeling).
- Claims inventory to be reviewed by compliance agent at each milestone transition. **[gate]** No new compliance claim ships without a finding-ID citation in the marketing-asset PR.

---

## 5. Risk Register

Regulatory risks with business impact. Each has a re-verification date or trigger condition. Compliance agent owns re-verification (C-20 watch); business-planner owns the business-impact response.

| # | Risk | Business impact | Trigger / re-verification | Source |
|---|---|---|---|---|
| R-1 | **EU–US transfer framework instability (Schrems III pending).** DPF adequacy formally in force but undermined (June 2026 US Supreme Court FTC ruling); CJEU opinion expected late 2026/early 2027. If DPF falls and we depend on US-region processing (stamp or LLM endpoint), EU revenue is exposed overnight | Worst case: EU sales freeze until SCC+TIA posture proven; forced LLM-provider/region migration (a notifiable sub-processor change for every tenant per GDPR-13/COMP-2 — churn risk) | **Re-verify at CJEU opinion publication (expected late 2026/early 2027) and at every release** per gdpr-obligations Report §3(b). Standing mitigation already adopted: never rely on DPF alone (GDPR-09) | GDPR §2-O6, GDPR-09, GDPR-10 |
| R-2 | **CTPP designation (DORA Art. 31).** Low probability 2–4 yrs, monotonically increasing with FE count; our FE footprint is visible to ESAs from year one via customers' registers | Designation brings lead-overseer inspections, remediation plans, fees — disproportionate cost at our scale; also Art. 31(12)–(13) constrains non-EU corporate structure | **Re-assess annually or at 100 confirmed FE tenants, whichever first** (compliance agent, per dora-obligations §1.3). Watch: concentration within any single member state's payment/CASP population. Standing posture: do not opt in (G-14) | dora-obligations §1.3 |
| R-3 | **NIS2 size-threshold crossing (50 employees or >€10M turnover).** Scope attaches automatically, **no transition period**; registration deadlines and Art. 20 personal liability of management follow | Unplanned compliance sprint at exactly the moment of scale-up; fines exposure (important entity: ≥€7M or 1.4% turnover) | **Trigger: headcount ≥40 or turnover forecast ≥€8M** (early-warning margin) → activate G-13 package. Review at every headcount/budget planning cycle | nis2-obligations §1.2, §1.3, NIS2-REQ-12/14 |
| R-4 | **National transposition unevenness.** ~⅓ of Member States not yet transposed (France pending as of May 2026); customers' obligations — and therefore Opportunity O-1 demand — arrive per-country through 2026; our own duties depend on main-establishment national law | GTM timing risk: NIS2 evidence-pack demand is country-staggered; per-country CSIRT report formats vary (the §4.1 template moat requires per-country maintenance) | **Quarterly review of transposition trackers** (compliance agent); before entering any new EU market, confirm that country's transposition status and CSIRT format | nis2-obligations §1.4, §4.1 |
| R-5 | **Art. 24 certification mandate / EUCS adoption.** Today no certification is legally required of MSSPs; a delegated act or adopted EUCS could change that with a compliance deadline | Could convert C-1 from market-driven to legally mandatory with a fixed deadline and possibly a specific scheme (sunk cost risk if we certified against the "wrong" scheme) | **Quarterly watch** per NIS2-REQ-16 | NIS2-REQ-16, nis2-obligations §2.4 |
| R-6 | **LLM-provider dependency as regulated supply chain.** Any model add/switch (incl. tier-based routing per BM consequence #5) is a notifiable sub-processor change with customer objection windows — providers can also change terms/regions under us | Slows AI iteration speed (a core differentiator per BM premium differentiators); a provider terms change could force migration mid-contract | **Trigger: any model-routing change → G-2 process.** Mitigation to explore: multi-provider abstraction with ≥2 pre-approved EU-compliant providers in the register | COMP-2, COMP-3, GDPR-12, GDPR-13, NIS2-REQ-8 |
| R-7 | **Employee-monitoring law stricter in some Member States** (e.g., DE §26 BDSG, works-council co-determination) — affects customers' lawful basis, therefore our addressable market per country | Sales friction in DE and similar markets; product may need per-country configurability (redaction policies per GDPR-15) | Before DE-market push: **handoff H-2 (below)** — per-country employee-monitoring survey. No date; trigger = market-entry decision | GDPR §1 D2, GDPR §4-P2, GDPR-15 |
| R-8 | **CRA obligations on the endpoint agent** (product with digital elements; main obligations apply from **Dec 2027**) | Agent product line (first-party agent per BM/ADR-0002 — a load-bearing business decision) acquires its own conformity obligations; unbudgeted in §1 | **Trigger: before agent GA; hard date Dec 2027.** Handoff H-1 — CRA map required, flagged but not yet written | nis2-obligations §5 |
| R-9 | **EU AI Act classification of AI triage/deep investigation** — likely limited-risk transparency duties, but unassessed | If classification lands worse than expected, AI differentiators (the Pro/Dedicated premium per BM) carry new duties | **Trigger: before marketing AI-autonomy upgrades; handoff H-3.** AC-49 AI-labeling already aligns with the likely outcome | nis2-obligations §5 |

---

## 6. Open Handoffs to Compliance (questions this plan must NOT answer itself)

| # | Question | Needed by | Blocks |
|---|---|---|---|
| H-1 | **CRA obligation map for the endpoint agent** (flagged in nis2-obligations §5; obligations from Dec 2027) | Before agent GA planning | Cost register completeness (R-8); agent roadmap |
| H-2 | **Per-country employee-monitoring law survey** (DE §26 BDSG etc.) — which markets need product-level accommodations | Before country-level GTM prioritization | O-1 country sequencing; R-7 |
| H-3 | **EU AI Act classification** of AI triage / deep investigation | Before expanding AI autonomy claims | R-9; AI-feature marketing copy |
| H-4 | **CIR 2024/2956 Annex III service-type code mapping (S01–S19)** — dora-obligations §2.2 says "exact mapping to be confirmed"; must be stated once, consistently, to all customers | Before first FE evidence pack ships | O-2 evidence-pack SKU; COMP-13 |
| H-5 | **Whether "NIS2-ready"-style qualified phrases survive legal review** in each target market's unfair-competition law (the §4 rules here are conservative defaults, not legal advice) | Before first compliance-led campaign | GTM §4 copy library |
| H-6 | **Main-establishment / corporate-seat decision** — legally a CEO/business decision, but compliance must map its consequences (which national NIS2 law, Art. 26(3)/GDPR Art. 27 representative need, Art. 31(12) CTPP structure constraint) | Before EU launch | C-6, G-6, GDPR-17, NIS2-REQ-12 **[needs-CEO]** |

---

## 7. Estimate Sources (retrieved 2026-07-08)

Market comparables used for §1 sizing — all figures are estimates, not quotes:

- ISO 27001 / SOC 2 costs: [Sprinto — ISO 27001 certification cost](https://sprinto.com/blog/iso-27001-certification-cost/), [High Table — ISO 27001 cost guide](https://hightable.io/iso-27001-certification-cost/), [SecureLeap — SOC 2 cost 2026](https://www.secureleap.tech/blog/soc-2-certification-cost), [Bright Defense — SOC 2 cost](https://www.brightdefense.com/resources/soc-2-certification-cost/), [SOC2Auditors — SOC 2 vs ISO 27001 2026](https://soc2auditors.org/insights/soc-2-vs-iso-27001/)
- Fractional DPO: [Engage Compliance — Fractional DPO pricing benchmark 2026](https://www.engagecompliance.co/fractional-dpo-pricing-benchmark-2026), [Evalian — DPO as a service costs](https://evalian.co.uk/dpo-as-a-service-costs-a-comprehensive-guide/)
- Penetration testing: [Blaze InfoSec — pentest cost 2026](https://www.blazeinfosec.com/post/how-much-does-penetration-testing-cost/), [Invicti — pentest pricing guide](https://www.invicti.com/blog/web-security/penetration-testing-pricing-guide)
- EU representative: [EDPO — representative pricing](https://edpo.com/data-protection-representative-price/), [Article27Representative.eu — pricing](https://article27representative.eu/en-us/pricing/), [Eldris — EU representative cost 2026](https://responsible.eldris.ai/data-centre/eu-responsible-person-service-brands/eu-authorised-representative-cost-2026)
- LEI: GLEIF-accredited issuer public list rates (typical ~€60–100/yr) — estimate from general market knowledge; confirm at purchase (trivial spend).

---

## 8. Changelog

| Date | Version | Change | Driving inputs |
|---|---|---|---|
| 2026-07-08 | v1.0 | Initial plan: compliance cost register (C-1..C-20), gated milestone timeline (G-1..G-14, phased MVP-blocking → pre-GA → pre-scale), compliance-driven revenue opportunities (O-1..O-4), GTM positioning constraints, risk register (R-1..R-9), compliance handoffs (H-1..H-6). Noted absence of CEO directives (`docs/ceo/` empty); all [needs-CEO] items pending. | `docs/prd/business-model.md` (Draft v1); `docs/compliance/nis2-obligations.md` (NIS2-REQ-1..16); `docs/compliance/dora-obligations.md` (COMP-1..13); `docs/compliance/gdpr-obligations.md` (GDPR-01..18, P1–P7); market-comparable searches per §7 |
