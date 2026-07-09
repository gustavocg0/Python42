# Rule Format Specification — `rule-pack/v1`

- **Status:** v1.0 — 2026-07-08
- **Owner:** detection-engineering
- **Consumers:** worker-detector (detection-engineering, next phase), rule-pack publish
  pipeline (SEC-27), qa (fixture-driven conformance tests), web console (rule list display)
- **Binding inputs:** `docs/contracts/event-schema.md` (fields), design §5 rule-pack row,
  threat model SEC-27/28/29, PRD AC-35..40
- This document is the single source of truth for rule syntax **and** evaluation
  semantics. The detector implementation and QA test suites MUST both derive from it;
  on conflict, this document wins.

---

## 1. Files and layout

```
rules/
├── FORMAT.md            # this spec
├── README.md            # publish, versioning, FP-feedback process
├── pack.yaml            # pack manifest (§6)
├── rules/<rule-id>.yml  # one rule per file; filename MUST equal the rule id
└── tests/cases/<rule-id>.json  # per-rule fixtures (§7)
```

All YAML files MUST be parseable by a YAML 1.1 **safe loader** (no tags, no anchors/
aliases, no merge keys, no multi-document files). All strings are UTF-8.

## 2. Rule document — top-level fields

| Field | Type | Req | Constraints |
|---|---|---|---|
| `id` | string | yes | Stable slug `^[a-z0-9]+(-[a-z0-9]+)*$`, ≤ 64 chars, unique in pack, never reused after retirement. Convention: prefix `proc-`/`net-`/`auth-`/`gen-` by event class. |
| `version` | string | yes | Semver `MAJOR.MINOR.PATCH`. See README §Versioning. |
| `title` | string | yes | ≤ 120 chars, human-readable. |
| `description` | string | yes | What the rule detects, why it matters, and (where a threshold/list exists) the rationale for it. |
| `severity` | enum | yes | `low` \| `medium` \| `high` \| `critical` (§2.1). Feeds priority per `docs/contracts/priority-score.md`. |
| `event_class` | enum | yes | `process_activity` \| `network_activity` \| `authentication` \| `generic`. Exactly one; a rule is evaluated **only** against events whose `event_class` equals it (§5.1). |
| `min_schema_version` | string | yes | Semver. Rule applies iff event `schema_version` has the same MAJOR and is `>=` this value (semver compare). Current pack: `"1.0.0"`. |
| `mitre_technique_ids` | list[string] | yes | ≥ 1 entry, each `^T\d{4}(\.\d{3})?$` (AC-36). |
| `entity` | list[string] | yes | 1–4 normalized field paths forming the alert-dedup entity key (§5.4). Default when no better key exists: `[host.hostname, user.name]`. |
| `detection` | object | yes | Exactly one key: `condition` — the condition tree (§3). |
| `false_positives` | list[string] | yes | ≥ 1 entry. Known benign triggers and what an admin should do (guides `expected_behavior`/`false_positive` close reasons, AC-45/46). |
| `references` | list[string] | yes | ≥ 1 entry; MITRE technique URL(s) required, others optional. |

Unknown top-level keys ⇒ **compile error** (rule invalid; whole pack publish rejected
atomically per SEC-27).

### 2.1 Severity semantics

| Severity | Meaning |
|---|---|
| `critical` | Behavior with essentially no benign explanation (known attack tool, destructive/ransomware precursor, credential theft in progress). Act now. |
| `high` | Strong malicious indicator; benign causes are rare and identifiable. Investigate same day. |
| `medium` | Suspicious; plausible benign explanations exist. Review in normal triage. |
| `low` | Informational / context signal; value comes mainly from occurrence counts and correlation. |

## 3. Condition tree

`detection.condition` is a single **node**. A node is exactly one of:

```yaml
# Leaf — one field test
field: <normalized field path>     # §4
op: <operator>                     # §3.1
value: <scalar or list>            # omitted only for op: exists

# AND — all children must match (1..32 children)
all:
  - <node>
  - <node>

# OR — at least one child matches (1..32 children)
any:
  - <node>

# NOT — negates exactly one child (read §5.3 on missing fields!)
not: <node>
```

A mapping containing more than one of `field`/`all`/`any`/`not`, or none of them,
is a compile error.

**Bounds (SEC-29 CPU budget, enforced at compile time):** tree depth ≤ 8; total leaf
count per rule ≤ 64; string values ≤ 1024 chars; lists ≤ 64 entries.

### 3.1 Operators

| op | Field type | Value type | Semantics |
|---|---|---|---|
| `equals` | string/number/bool | same-type scalar | Exact match. Strings: byte-exact (case-sensitive). Numbers: numeric equality (int/float interchangeable). Bools: exact. **No cross-type coercion — type mismatch ⇒ no match.** |
| `iequals` | string | string | Case-insensitive equality (§3.2). |
| `contains` / `icontains` | string | string **or list[string]** | Substring test; list means "any of" (logical OR over the list). |
| `startswith` / `istartswith` | string | string or list[string] | Prefix test; list = any of. |
| `endswith` / `iendswith` | string | string or list[string] | Suffix test; list = any of. |
| `in` | string/number/bool | list of scalars | Equality against any list element, `equals` semantics per element. |
| `iin` | string | list[string] | Case-insensitive `in`. |
| `gt` / `gte` / `lt` / `lte` | number | number | Numeric comparison. Field must be a JSON number (bool is NOT a number) else no match. |
| `exists` | any scalar | — (no `value` key) | True iff the path resolves to a non-null **scalar** (string/number/bool). |
| `regex` | string | string (pattern) | **Discouraged — see §3.3.** |

For all string operators: if the resolved field value is not a string ⇒ no match.
Empty-string values are legal and match per normal substring/prefix rules.

### 3.2 Case folding

Case-insensitive operators (`iequals`, `icontains`, `istartswith`, `iendswith`, `iin`)
compare after applying **Unicode full case folding** (exactly Python `str.casefold()`)
to both the field value and the rule value. Case-sensitive operators compare code
points exactly. Implementations MUST NOT use locale-dependent folding.

### 3.3 Regex (restricted; SEC-29)

The `regex` primitive exists in the format but is **discouraged**; prefer the string
operators. Pack v1.0.0 ships **zero** regex rules. Constraints (compile-enforced at
publish, re-enforced by the detector):

- Pattern language is the **RE2 subset** only: NO backreferences, NO lookahead, NO
  lookbehind, NO atomic/possessive groups, NO recursion, NO conditional groups.
- Pattern length ≤ 512 chars. Case-insensitivity via inline `(?i)` only.
- The detector MUST evaluate with a linear-time engine (RE2-class), **or** enforce a
  hard 10 ms per-match wall-clock timeout. A timeout is a runtime evaluation error
  handled per SEC-28(b): counted in `rule_eval_errors`, event skipped for that rule,
  **rule stays enabled**.
- Semantics: unanchored search (match anywhere in the string), field must be a string.

## 4. Field paths

- A field path is a dot-joined sequence of literal JSON keys resolved against the
  **normalized event** (post-normalizer, as defined in `docs/contracts/event-schema.md`).
  Examples: `process.cmd_line`, `parent.name`, `host.hostname`, `dst.port`, `src_ip`,
  `user.name`, `fields.action` (generic class only).
- No wildcards, no array indexing, no traversal into `raw` or `unmapped` (compile
  error — those objects are not contract-stable).
- Rules may reference envelope fields and the class-specific fields of the rule's
  own `event_class` only. Referencing another class's fields is a compile error (the
  publish validator carries the per-class field allowlist derived from
  event-schema.md). The matchable **envelope** allowlist is exactly
  (v1.0 clarification, 2026-07-08): `activity`, `event_time`, `time_inferred`,
  `source_type`, `source_event_id`, `severity_hint`, `host.hostname`,
  `host.os_family`, `host.os_name`, `host.os_version`, `host.ip`, `host.mac`,
  `source.vendor`, `source.product`, `source.agent_version`.
- `tenant_id`, `event_id`, `batch_id`, `ingest_time` are not matchable (compile error):
  rules are global content and must be tenant-agnostic. For the same reason
  `source.device_id` and `source.ingest_key_id` (tenant-coupled identity) are not
  matchable. `schema_version` and `event_class` are gates (§5.1), not matchable
  fields (compile error).
- Generic-class rules may match `fields.<key>` (exactly one sub-segment; `fields` is
  a flat object of scalars). Matching `fields` itself, or deeper nesting, is a
  compile error.

## 5. Evaluation semantics (normative)

### 5.1 Scoping — which rules run against which event

For each normalized event, the detector evaluates rule R iff ALL hold:

1. `event.event_class == R.event_class` (exact string equality),
2. `event.schema_version` MAJOR == `R.min_schema_version` MAJOR and
   `event.schema_version >= R.min_schema_version` (semver order),
3. R is enabled in the active pack AND not disabled by the event's tenant's
   per-tenant overlay (AC-38; overlay read from PG `rule_pack` tables per design §5).

Each event is evaluated independently — the engine is **stateless per event** in MVP.
No rule may depend on prior events, wall-clock time, counters, or external lookups.
Tenant scoping: the event's `tenant_id` travels with the detection hit; rules never
see or filter on it.

### 5.2 Path resolution

Walk the dotted path from the event root. If any segment is absent, or any
intermediate value is not a JSON object, or the final value is `null`, an object, or
an array ⇒ the path is **unresolved**.

### 5.3 Missing fields — the one rule everyone must remember

**An unresolved path makes the leaf evaluate `false` (no match), for every operator
including `exists`.** There are no errors and no null-propagation.

Consequence: `not: <leaf on optional field>` evaluates **true** when the field is
missing. When absence must NOT match, authors MUST guard with `exists`:

```yaml
all:
  - field: src_ip
    op: exists
  - not:
      field: src_ip
      op: istartswith
      value: ["10.", "192.168."]
```

Every rule in this pack that negates over an **optional** field carries an `exists`
guard; negation over **required** fields (per event-schema.md Req column) needs no
guard. QA fixtures cover this edge.

### 5.4 Entity key (alert dedup input)

For a matching event, the detection hit carries:

`entity_key = join("|", [ fold(resolve(event, p)) for p in rule.entity ])`

where `fold(v)` = casefold(v) for strings, decimal rendering for numbers, `"true"`/
`"false"` for bools, and the **empty string** for unresolved paths. Order is exactly
as declared in `entity`. The alerter dedups on `(tenant_id, rule_id, entity_key)`
within the 60-minute plan-config window (design §5, AC-41/42) — tenant scoping is the
alerter's job, never encoded in `entity`. This means per-event stateless rules on
bursty behavior (e.g., failed logons) still collapse into a single alert with a
rising occurrence count.

### 5.5 Detection hit contents (AC-35)

One message per (rule, event) hit, emitted to `pipe:detections`. `tenant_id` and
`trace_id` travel ONLY in the soc_pipeline envelope — the envelope tenant is
authoritative (SEC-20), never a payload field. Canonical FLAT payload (Architect
integration ruling, 2026-07-08 — the alerter needs `event_time`/`entity_hostname`
for its dedup-window math and correlation; `es_index` lets it build `event_refs`
without recomputing index names):

```json
{
  "rule_id": "...", "rule_version": "...", "title": "...", "severity": "...",
  "mitre_technique_ids": ["T...."],
  "entity_key": "...",
  "entity_hostname": "...",
  "entity_user": "...",
  "event_id": "...",
  "event_time": "<RFC3339 of the matched event — REQUIRED>",
  "es_index": "events-v1-<tenant>-<yyyy.MM>",
  "pack_version": "..."
}
```

- `entity_hostname`: the matched event's `host.hostname`; present only when the
  event carries one.
- `entity_user`: the event's `user.name`; present only when the rule declares
  `user.name` in its `entity` list and the event carries one.
- All other keys are always present. The alerter accepts `title` or `rule_title`;
  the detector emits `title`.

### 5.6 Errors (SEC-28 taxonomy, binding)

- **Compile-time** (unknown key, bad op, bad field path, bound exceeded, bad regex):
  detected at publish; the entire pack version is rejected atomically (SEC-27). A
  compile error found at detector load time (should not happen post-publish) disables
  that rule and fires an ops alert.
- **Runtime per-event exceptions** (unexpected value shapes, regex timeout): caught
  per (rule, event); `rule_eval_errors{rule_id, tenant_id}` incremented; the event is
  skipped **for that rule only**; the rule STAYS enabled. Attacker-crafted events must
  never disable detection.
- **Runtime auto-disable** only on sustained failure fraction across multiple tenants
  (plan-config threshold) + ops review alert, per design §5.

### 5.7 Determinism requirements

Given the same (rule, event) pair, evaluation MUST return the same boolean on every
run, on every backend. Backend-specific translations (e.g., ES query pushdown) must
be **generated** from this tree and proven equivalent by the §7 fixtures — never
hand-forked.

## 6. Pack manifest — `pack.yaml`

```yaml
schema: rule-pack/v1
pack_version: "1.0.0"        # semver of the CONTENT pack (README §Versioning)
generated_at: "<set-at-publish>"  # RFC3339 UTC; placeholder in git, stamped by publish op
min_schema_version: "1.0.0"  # max of all rules' min_schema_version (informational)
rules:
  - id: <rule-id>
    version: "<rule semver>"   # MUST equal the version inside the rule file
    path: rules/<rule-id>.yml
    enabled: true              # global default; per-tenant overlay may disable (AC-38)
```

Publish validation (SEC-27): every listed file exists, parses, compiles; every rule
file is listed exactly once; `id`/`version` match between manifest and rule file;
manifest SHA-256 recorded in PG and stamped onto every alert with the firing rule's
`rule_id` + `version` + `pack_version` (AC-39).

## 7. Test fixtures — `tests/cases/<rule-id>.json`

One JSON file per rule (required for publish):

```json
{
  "rule_id": "<rule-id>",
  "rule_version": "<must equal rule file>",
  "must_match": [ {"name": "<case name>", "event": { ...normalized event... }} ],
  "must_not_match": [ {"name": "<near-miss case name>", "event": { ... }} ]
}
```

- ≥ 1 `must_match` and ≥ 1 `must_not_match` case per rule; near-misses MUST be the
  same `event_class` as the rule (so they exercise the condition, not the class gate).
- Every fixture event MUST be a fully valid normalized event per event-schema.md
  (envelope + class-required fields), so the same fixtures double as normalizer/
  pipeline test data.
- QA automation contract: load pack → for each case, evaluate the named rule against
  the event → assert match/no-match. Any failure blocks publish.
