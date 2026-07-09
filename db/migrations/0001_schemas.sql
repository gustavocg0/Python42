-- 0001_schemas.sql
-- Two PostgreSQL schemas in one database for MVP (design §3, ADR-0001/0003):
--   control    -- control-plane tables (accounts, tenants, plans, users, ...)
--   tenantdata -- data-plane tables, tenant-scoped, protected by RLS
-- Requires PostgreSQL >= 13 (gen_random_uuid() in core); target is postgres:16.

-- migrate:up

CREATE SCHEMA IF NOT EXISTS control;
CREATE SCHEMA IF NOT EXISTS tenantdata;

COMMENT ON SCHEMA control IS
  'Control-plane tables. No RLS; isolation is runtime role separation: only '
  'app_control (and narrowly system_jobs) may touch this schema. '
  'Cross-plane access goes over HTTP /internal/v1 APIs, never direct SQL.';

COMMENT ON SCHEMA tenantdata IS
  'Data-plane tables. Every tenant-scoped table carries tenant_id uuid and is '
  'protected by ENABLE + FORCE ROW LEVEL SECURITY with the app.tenant_id GUC '
  'policy (threat model §4.1, SEC-23). Exceptions (global platform content, '
  'no tenant_id, no RLS): rule_packs, rules, rule_runtime_disables.';

-- migrate:down

DROP SCHEMA IF EXISTS tenantdata CASCADE;
DROP SCHEMA IF EXISTS control CASCADE;
