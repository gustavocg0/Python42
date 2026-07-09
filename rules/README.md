# Managed Rule Pack (starter pack v1.0.0)

Owner: **detection-engineering**. This directory is managed detection content —
25 Sigma-style rules (12 process_activity, 6 network_activity, 5 authentication,
2 generic), every rule mapped to at least one MITRE ATT&CK technique (AC-36).
Format and evaluation semantics: [`FORMAT.md`](FORMAT.md) (normative).

```
rules/
├── FORMAT.md          # rule format + evaluation semantics (normative)
├── pack.yaml          # pack manifest (what ships, versions, enabled flags)
├── rules/*.yml        # one rule per file
└── tests/cases/*.json # per-rule must-match / must-not-match fixtures (QA input)
```

## How the pack is published (SEC-27 — content, not code)

Rule content ships **separately from code deploys** (AC-39, ADR-0002 principle):

1. Change is made here via PR; CI runs the pack validation (YAML parse, compile
   against FORMAT.md, per-class field allowlist from
   `docs/contracts/event-schema.md`, fixture pass for every rule).
2. Publish is an **authenticated, audited internal operation** (operator or CI
   identity over the internal API per SEC-40): it validates the pack again
   server-side and writes it to the PG `rule_pack` tables **atomically** — one
   invalid rule rejects the entire pack version (SEC-27). The manifest SHA-256,
   `pack_version`, and publish actor are recorded in PG and in the audit log.
3. worker-detector polls the published pack version every 30 s and hot-reloads —
   **no service restart** (AC-39). Every alert records the firing rule's
   `rule_id`, rule `version`, and `pack_version`.
4. Per-tenant enable/disable toggles (AC-38) are an overlay in PG on top of the
   global pack; publishing a new pack never resets tenant overlays.
5. Content signing of the pack is a devsecops fast-follow (SEC-27); MVP minimum
   is the authenticated channel + recorded hash.

Rollback = publishing the previous pack version again (packs are immutable once
published; versions are never reused).

## Versioning policy

- **Rule `version` (semver, per rule):**
  - PATCH — metadata only (description, FP notes, references). Match behavior identical.
  - MINOR — narrows or tunes matching (FP reduction, list additions/removals),
    severity or entity change.
  - MAJOR — meaning of the rule changes (different behavior detected); prefer a
    new rule id and retirement of the old one instead.
  - Rule ids are stable forever and never reused after retirement.
- **`pack_version` (semver, whole pack):**
  - PATCH — metadata-only rule changes.
  - MINOR — rule added, rule updated (minor/major), rule default-disabled.
  - MAJOR — rule removed/retired, or a `FORMAT.md` change that requires a newer
    detector (format changes also bump the `schema:` marker).
- Every rule declares `min_schema_version`; a bump of the event schema's MAJOR
  requires a coordinated pack release (see event-schema.md §1).
- Fixtures (`tests/cases/`) MUST be updated in the same PR as any matching-logic
  change; CI enforces `rule_version` equality between rule file, manifest, and
  fixture file.

## Thresholds and lists — tuning rationale

Every numeric threshold, port list, and keyword list carries its rationale in the
rule's `description`/`false_positives` (e.g., the 100 MiB single-flow threshold in
`net-large-outbound-transfer`, the C2 port list in `net-outbound-known-c2-port`).
Pre-GA these are a-priori choices — there is no production data yet. They are the
first candidates for data-driven retuning once FP feedback flows (below).

## FP feedback loop (AC-46)

When an analyst closes an alert as `false_positive` (or `expected_behavior`), the
platform stores `{rule_id, rule_version, entity_key, close_reason, tenant_id,
timestamp}` in a form queryable by detection-engineering via the internal
fp-feedback API (threat model E-6). Working the loop:

1. **Weekly review** of FP closes aggregated by `(rule_id, rule_version)`:
   FP-close rate = fp_closes / total alerts per rule.
2. Rules above ~20% FP-close rate across multiple tenants get tuned first:
   narrow the condition (add exclusions/AND terms), adjust the threshold, lower
   severity, or as a last resort default-disable in `pack.yaml` (never delete —
   retire with a MAJOR pack bump).
3. Every tuning change ships as a rule MINOR bump + pack MINOR bump, with
   updated fixtures reproducing the FP as a `must_not_match` case so the
   regression is pinned forever.
4. Single-tenant-only FP patterns are NOT fixed in global content — the tenant
   uses the per-tenant toggle (AC-38); tenant-level suppressions/overrides are a
   post-MVP feature request to product-manager.
5. No automated tuning in MVP (per AC-46) — every change is a reviewed PR here.

## Adding a rule (checklist)

- [ ] Fields used exist in `docs/contracts/event-schema.md` for the rule's class.
- [ ] ≥ 1 MITRE technique id; severity justified in description; ≥ 1 FP note; references.
- [ ] `entity` chosen for sensible dedup (default `[host.hostname, user.name]`).
- [ ] `not` over optional fields guarded with `exists` (FORMAT.md §5.3).
- [ ] No regex unless unavoidable; if used, RE2 subset per FORMAT.md §3.3.
- [ ] Fixture file with ≥ 1 must_match and ≥ 1 near-miss must_not_match.
- [ ] Manifest entry added; pack_version bumped per policy.
