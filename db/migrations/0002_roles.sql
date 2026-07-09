-- 0002_roles.sql
-- Runtime NOLOGIN roles (least privilege; grants land in 0008 after tables
-- exist). Binding rules (AC-79, SEC-23, SEC-42):
--   * runtime roles NEVER own tables (owner = the migration user running
--     migrate.py, e.g. `soc_owner`);
--   * runtime roles have NOBYPASSRLS and are not superusers;
--   * per-deployment LOGIN users are created OUTSIDE migrations (deployment
--     bootstrap / secrets store) and are GRANTed these roles:
--       controlplane-api login user -> GRANT app_control, audit_writer;
--       dataplane-api + workers     -> GRANT app_dataplane, audit_writer;
--       jobs-scheduler              -> GRANT system_jobs, audit_writer;
--     (audit_writer membership is what allows the same-transaction audit
--      INSERT per SEC-43; no role ever gets UPDATE/DELETE on audit_log.)
--
-- Roles:
--   app_control   -- controlplane-api: control schema only
--   app_dataplane -- dataplane-api + pipeline workers: tenantdata schema,
--                    always under RLS with SET LOCAL app.tenant_id
--   audit_writer  -- INSERT+SELECT on tenantdata.audit_log ONLY (SEC-42)
--   system_jobs   -- jobs-scheduler (retention, trial freeze/purge, billable
--                    window, agent-offline, DLQ cleanup); cross-tenant work is
--                    done tenant-pinned via the same RLS GUC (SEC-46), never
--                    by bypassing RLS.

-- migrate:up

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_control') THEN
    CREATE ROLE app_control NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_dataplane') THEN
    CREATE ROLE app_dataplane NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'system_jobs') THEN
    CREATE ROLE system_jobs NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$;

-- Schema visibility (table grants come in 0008_grants_and_registry.sql).
GRANT USAGE ON SCHEMA control    TO app_control, system_jobs;
GRANT USAGE ON SCHEMA tenantdata TO app_dataplane, audit_writer, system_jobs;

-- Nothing in either schema is reachable by PUBLIC.
REVOKE ALL ON SCHEMA control    FROM PUBLIC;
REVOKE ALL ON SCHEMA tenantdata FROM PUBLIC;

-- migrate:down

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_control','app_dataplane','audit_writer','system_jobs']
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I', r);  -- revokes grants in this DB
      EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP;
END
$$;
