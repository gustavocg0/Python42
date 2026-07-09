# db/ — data layer (PostgreSQL, Elasticsearch, Redis)

Owner: database-architect. Contents:

| Path | What |
|---|---|
| `migrations/NNNN_*.sql` | Plain-SQL reversible migrations (`-- migrate:up` / `-- migrate:down` sections), applied in filename order, one transaction each |
| `migrate.py` | Runner (`psycopg` v3). Tracks applied files in `public.schema_migrations` |
| `seed_dev.sql` | DEV-ONLY sample data (two marker tenants). Never a migration, never prod |
| `elasticsearch/` | `events-v1` index template + per-tenant index/alias/retention doc |
| `redis-conventions.md` | Binding Redis key contract for all services |
| `tests/test_migrations.py` | Static checks (always run) + destructive live-PG suite (env-gated) |

## Running migrations

```bash
uv sync                                            # from repo root (workspace)
python db/migrate.py --dsn postgresql://... up     # or DATABASE_URL env
python db/migrate.py status
python db/migrate.py down --steps 1                # revert last migration
```

Run as a dedicated **owner** user (e.g. `soc_owner`) — the migration user
owns all objects. NEVER run migrations as a runtime user.

## Role model (SEC-23/42, AC-79)

Migrations create four NOLOGIN, NOBYPASSRLS roles: `app_control`,
`app_dataplane`, `audit_writer`, `system_jobs`. **LOGIN users are created
per deployment** (compose bootstrap / K8s secret provisioning, credentials
from the secrets store per SEC-49) and granted role memberships:

```sql
CREATE ROLE svc_controlplane LOGIN PASSWORD '...';  -- controlplane-api
GRANT app_control, audit_writer TO svc_controlplane;
CREATE ROLE svc_dataplane LOGIN PASSWORD '...';     -- dataplane-api + workers
GRANT app_dataplane, audit_writer TO svc_dataplane;
CREATE ROLE svc_jobs LOGIN PASSWORD '...';          -- jobs-scheduler
GRANT system_jobs, audit_writer TO svc_jobs;

-- soc_audit's AUDIT_INSERT_SQL targets the unqualified name `audit_log`,
-- so audit-writing users need tenantdata on their search_path:
ALTER ROLE svc_controlplane SET search_path = control, tenantdata, public;
ALTER ROLE svc_dataplane    SET search_path = tenantdata, public;
ALTER ROLE svc_jobs         SET search_path = tenantdata, public;
```

`tenantdata.audit_log` columns follow the binding writer contract in
`packages/audit/src/soc_audit/writer.py` (`AUDIT_INSERT_SQL`): `tenant_id,
actor_type, actor_id, action_type, target_type, target_id, before, after,
reason_code, created_at` (+ `id` PK and optional `source_ip`, which the
writer never sets).

`audit_writer` membership is what lets the SAME transaction write business
state + the audit row (SEC-43) while no role anywhere holds UPDATE/DELETE on
`tenantdata.audit_log` (guard triggers block them even for the owner).

Grant matrix (details in `0008_grants_and_registry.sql` +
`0010_platform_config_access.sql`):

| Role | control schema | tenantdata schema |
|---|---|---|
| `app_control` | SELECT/INSERT/UPDATE/DELETE on all tables | — |
| `app_dataplane` | SELECT on `platform_config` ONLY (0010: SEC-28c rule-error thresholds, SEC-37 triage budget) | SELECT/INSERT/UPDATE (no DELETE); `audit_log`: SELECT only |
| `audit_writer` | — | `audit_log`: INSERT+SELECT only |
| `system_jobs` | SELECT on `tenants`/`plans`/`plan_config`/`platform_config`/`entitlement_overrides`/`purge_registry`; UPDATE(`status`,`frozen_at`,`purged_at`,`updated_at`) on `tenants` | SELECT/INSERT/UPDATE/DELETE; `audit_log`: SELECT + EXECUTE `audit_purge_expired()` |

Tenant context: every request/consumer message runs
`SET LOCAL app.tenant_id = '<uuid>'` inside its transaction
(`packages/tenancy` is the only place that sets it). Unset GUC ⇒ RLS returns
zero rows (deny-by-default). Jobs that cross tenants iterate the tenant list
from `control.tenants` and pin the GUC per tenant (SEC-46) — RLS is never
bypassed.

Platform-scope audit entries (rule-pack publish, operator actions) use the
reserved tenant id `00000000-0000-0000-0000-000000000000`.

## Audit retention

365 days is a hard floor (SEC-44). The only deletion path is
`SELECT tenantdata.audit_purge_expired(retention_days)` (SECURITY DEFINER,
EXECUTE granted to `system_jobs` only); it refuses `retention_days < 365`
and records its own run in the audit log.

## Tenant purge registry (SEC-46)

`control.purge_registry` lists every tenant-scoped table with its purge
action (`delete` / `retain`). CI/QA gate: `SELECT * FROM
control.purge_registry_gaps` must return zero rows — any new tenantdata
table with a `tenant_id` column must be registered in the same migration.

## Adding a migration (checklist)

1. Next `NNNN_description.sql` with both `-- migrate:up` and
   `-- migrate:down` sections (reversibility is mandatory).
2. Tenant-scoped table? `tenant_id uuid NOT NULL` + ENABLE + FORCE RLS +
   `tenant_isolation` policy (copy the NULLIF pattern) + composite
   `(tenant_id, id)` UNIQUE/FKs + a `control.purge_registry` row.
3. Explicit GRANTs for the runtime roles (no default privileges on purpose).
4. Justify every index in a comment (named query/AC it serves).
5. Static tests in `tests/test_migrations.py` enforce most of this.

## Testing

```bash
uv run pytest db/tests                       # static layer only (no PG)
SOC_DB_TEST_DSN=postgresql://postgres:dev@localhost:5432/soc_test \
  uv run pytest db/tests                     # + destructive live-PG suite
```

Live-PG tests auto-skip when the DSN is absent/unreachable or
`SOC_DB_SKIP_PG=1`. CI (devsecops) runs them against a `postgres:16`
service container.
