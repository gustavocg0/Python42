"""dataplane.core — settings, resource assembly (PG pool / Redis / ES), and
cross-cutting server primitives (allowlist status stores, quotas, sessions,
CA signing, pagination, ids).

Module ownership note: `dataplane.core` and `dataplane.api` belong to the
backend-architect agent; `dataplane.workers` / `dataplane.jobs` import
`dataplane.core` (settings/db/redis helpers) but never `dataplane.api`.
"""
