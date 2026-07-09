# Elasticsearch: events index design

Owner: database-architect. Contract inputs: `docs/contracts/event-schema.md`
(envelope + class fields), design §3 (per-tenant index pattern), SEC-24
(single tenant-scoped query helper), AC-16/33/34/80.

## Index pattern and alias (per tenant)

| Thing | Value |
|---|---|
| Index template | `events-v1-template.json`, matches `events-v1-*` |
| Concrete index | `events-v1-{tenant_id}-{yyyy.MM}` — one index per tenant per UTC month |
| Read alias | `events-{tenant_id}` — spans all of that tenant's monthly indices |
| Write path | Direct to the concrete monthly index, month taken from `event_time` (UTC). No write alias / rollover: monthly bucketing is deterministic from the document itself. |
| Document `_id` | `sha256(tenant_id + ":" + source_scope + ":" + source_event_id)`, `source_scope` = `device_id` (agent) or `ingest_key_id` (generic); written with `op_type=create` → duplicates rejected, counted, dropped (AC-34) |

`{tenant_id}` is always the server-side tenant UUID (lowercase, hyphenated),
never any client-derived string — validated by the single ES query helper in
`packages/` before any index name is built (SEC-24, AC-80). No query may ever
target `events-v1-*` unscoped.

Provisioning (saga step `es_index`): the template is installed once per
stamp (`PUT _index_template/events-v1`); per tenant, create the current
month's index and add the `events-{tenant_id}` alias:

```
PUT _index_template/events-v1        # body: events-v1-template.json
PUT events-v1-{tenant_id}-{yyyy.MM}
POST _aliases {"actions":[{"add":{"index":"events-v1-{tenant_id}-*","alias":"events-{tenant_id}"}}]}
```

The normalizer creates the next monthly index lazily on first write of a new
month (template auto-applies; alias uses the wildcard action above so new
months are covered).

## Mapping rules

- `dynamic: strict` — security event data gets NO dynamic mappings. Unknown
  source fields are preserved by the normalizer under `unmapped`
  (stored-only, not indexed). The `generic` class `fields` object is
  `flattened` (indexed key/value matching for rules without mapping
  explosion); `raw` is stored-only.
- `process.cmd_line` is `wildcard` (Sigma-style contains matching, 32KB cap
  enforced by the normalizer per SEC-29); `message` is `match_only_text`.
- IP fields use `ip` type with `ignore_malformed: true` (a bad IP must not
  dead-letter an otherwise valid event; the raw value stays in `_source`).
- `refresh_interval: 5s` serves AC-33 (event queryable ≤30s p95).
- `number_of_replicas: 0` is the single-node MVP setting; the Helm stamp
  overrides to ≥1 (cloud-platform).
- Schema versioning: additive optional fields = minor bump, edit this
  template in place (new fields only). Renames/removals = major bump = new
  `events-v2-*` template + dual-read window (event-schema.md §1).

## Retention / lifecycle (why there is no ILM delete policy)

Retention is a per-tenant PLAN value (Trial 14d / Core 30d / Pro 90d,
`control.plan_config.retention_days`) and changes when a tenant's plan
changes (AC-15/16). A single ILM policy cannot express per-tenant,
plan-driven retention, and per-tenant ILM policies would have to be rewritten
on every plan change. Instead, the jobs-scheduler retention job (AC-16,
tenant-pinned per SEC-46) runs daily:

1. For each tenant: cutoff month = first month wholly older than
   `retention_days`.
2. `DELETE events-v1-{tenant_id}-{yyyy.MM}` for expired months (whole-index
   deletes — cheap, no delete-by-query).
3. Tenant purge (SEC-46/CR-11) deletes ALL `events-v1-{tenant_id}-*` indices
   and the alias, then verifies count == 0 before marking `purged`.

Monthly granularity means data can outlive its retention by up to one month
minus a day inside the newest expired index; acceptable for MVP and
documented here deliberately (flagged in design §7 — purge deletes from hot,
no warm tier).
