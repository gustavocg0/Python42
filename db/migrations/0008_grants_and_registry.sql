-- 0008_grants_and_registry.sql
-- Least-privilege grants for the runtime roles created in 0002 (AC-79,
-- SEC-23/42), plus the SEC-46 purge registry.
--
-- Grant matrix (summary):
--                       control schema        tenantdata schema
--   app_control         SELECT/INS/UPD/DEL    -- (none)
--   app_dataplane       -- (none)             SELECT/INS/UPD (no DELETE);
--                                             audit_log: SELECT only
--   audit_writer        -- (none)             audit_log: INSERT+SELECT only
--   system_jobs         tenants: SELECT +     SELECT/INS/UPD/DEL
--                       UPDATE(status cols);  (audit_log: SELECT +
--                       config: SELECT        EXECUTE audit_purge_expired)
--
-- NOTE for future migrations: grants below cover tables existing NOW.
-- Every later migration that adds a table MUST add its own grants (no
-- ALTER DEFAULT PRIVILEGES on purpose -- grants stay explicit/reviewable).

-- migrate:up

---------------------------------------------------------------------------
-- Control plane: app_control owns nothing, touches only `control`.
---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA control
  TO app_control;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA control TO app_control;

-- jobs-scheduler needs: tenant enumeration + trial freeze/purge status
-- flips (AC-9/10), plan/config reads for retention + quota seeding.
GRANT SELECT ON control.tenants, control.plans, control.plan_config,
                control.platform_config, control.entitlement_overrides
  TO system_jobs;
GRANT UPDATE (status, frozen_at, purged_at, updated_at) ON control.tenants
  TO system_jobs;

---------------------------------------------------------------------------
-- Data plane: app_dataplane works only under RLS (GUC-pinned). No DELETE:
-- revocations are status updates; deletion is the purge/retention job's.
---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA tenantdata
  TO app_dataplane;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tenantdata
  TO app_dataplane, audit_writer, system_jobs;

-- audit_log: INSERT only via audit_writer membership (SEC-42/43). The
-- dataplane login user is a member of BOTH app_dataplane and audit_writer,
-- so the same transaction can write state + audit rows (SEC-43) while no
-- role ever holds UPDATE/DELETE.
REVOKE INSERT, UPDATE ON tenantdata.audit_log FROM app_dataplane;
GRANT INSERT, SELECT ON tenantdata.audit_log TO audit_writer;

---------------------------------------------------------------------------
-- system_jobs: retention purge, trial purge (SEC-46), DLQ 7-day cleanup,
-- billable 30-day window, agent-offline marker -- always tenant-pinned via
-- the same RLS GUC, never by bypassing RLS.
---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenantdata
  TO system_jobs;
REVOKE INSERT, UPDATE, DELETE ON tenantdata.audit_log FROM system_jobs;
GRANT EXECUTE ON FUNCTION tenantdata.audit_purge_expired(integer)
  TO system_jobs;

---------------------------------------------------------------------------
-- Purge registry (SEC-46/CR-11): PG deletion during tenant purge is driven
-- by this registry. CI/QA check: control.purge_registry_gaps must be empty
-- (i.e. every tenantdata table with a tenant_id column is registered --
-- new tables can't be silently missed).
---------------------------------------------------------------------------
CREATE TABLE control.purge_registry (
  schema_name  text NOT NULL,
  table_name   text NOT NULL,
  purge_action text NOT NULL CHECK (purge_action IN ('delete','retain')),
  note         text,
  PRIMARY KEY (schema_name, table_name)
);

INSERT INTO control.purge_registry (schema_name, table_name, purge_action, note) VALUES
  ('tenantdata','assets',                  'delete', NULL),
  ('tenantdata','asset_identities',        'delete', NULL),
  ('tenantdata','asset_identity_pins',     'delete', NULL),
  ('tenantdata','asset_merge_audit',       'delete', NULL),
  ('tenantdata','devices',                 'delete', NULL),
  ('tenantdata','enrollment_tokens',       'delete', NULL),
  ('tenantdata','ingest_keys',             'delete', NULL),
  ('tenantdata','correlation_groups',      'delete', NULL),
  ('tenantdata','alerts',                  'delete', NULL),
  ('tenantdata','alert_events',            'delete', NULL),
  ('tenantdata','alert_history',           'delete', NULL),
  ('tenantdata','rule_toggles',            'delete', NULL),
  ('tenantdata','dead_letter_events',      'delete', '<=7d anyway; delete per SEC-46'),
  ('tenantdata','deep_investigation_runs', 'delete', 'contains summaries (content-bearing)'),
  ('tenantdata','onboarding_steps',        'delete', NULL),
  ('tenantdata','usage_counters',          'delete', NULL),
  ('tenantdata','llm_metering',            'retain', 'aggregates/reference ids only, no content (SEC-48/CR-11)'),
  ('tenantdata','audit_log',               'retain', 'survives purge; 365d via audit_purge_expired() (SEC-48/CR-12)');

-- Gap detector: tenant-scoped tenantdata tables missing from the registry.
CREATE VIEW control.purge_registry_gaps AS
SELECT c.table_schema AS schema_name, c.table_name
FROM information_schema.columns c
WHERE c.table_schema = 'tenantdata'
  AND c.column_name  = 'tenant_id'
  AND NOT EXISTS (
    SELECT 1 FROM control.purge_registry r
    WHERE r.schema_name = c.table_schema AND r.table_name = c.table_name);

GRANT SELECT ON control.purge_registry, control.purge_registry_gaps
  TO app_control, system_jobs;

-- migrate:down

DROP VIEW IF EXISTS control.purge_registry_gaps;
DROP TABLE IF EXISTS control.purge_registry;

REVOKE EXECUTE ON FUNCTION tenantdata.audit_purge_expired(integer)
  FROM system_jobs;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA tenantdata
  FROM app_dataplane, audit_writer, system_jobs;
REVOKE ALL ON ALL TABLES IN SCHEMA tenantdata
  FROM app_dataplane, audit_writer, system_jobs;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control FROM app_control;
REVOKE ALL ON ALL TABLES IN SCHEMA control FROM app_control, system_jobs;
