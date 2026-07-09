-- 0007_audit_log.sql
-- Immutable tenant audit log (AC-83..85, SEC-42..45, SEC-48, CR-12).
--
-- COLUMN CONTRACT (binding): matches AUDIT_INSERT_SQL in
-- packages/audit/src/soc_audit/writer.py --
--   (tenant_id, actor_type, actor_id, action_type,
--    target_type, target_id, before, after, reason_code, created_at)
-- created_at from the DB clock (now()). Extra columns beyond the writer
-- contract (id PK, source_ip) are nullable/defaulted; the writer never sets
-- them. The writer inserts into the UNQUALIFIED name `audit_log`, so
-- audit-writing login users must have tenantdata on their search_path
-- (see db/README.md bootstrap SQL).
--
-- Enforcement layers:
--   1. Privileges (0008): audit_writer gets INSERT+SELECT ONLY; NO runtime
--      role ever gets UPDATE/DELETE/TRUNCATE.
--   2. Guard triggers (here, defense in depth): UPDATE and TRUNCATE always
--      raise; DELETE raises unless performed inside audit_purge_expired().
--   3. RLS: tenant-scoped reads/writes via app.tenant_id GUC.
--
-- Content rules (SEC-44/CR-12): records carry actor + action METADATA only.
-- Never secret material (token/key plaintext or hashes, passwords, cert
-- keys -- record IDs/fingerprint prefixes instead) and never raw event
-- payloads or alert/telemetry content bodies (reference IDs instead).
--
-- Timestamps: `created_at` comes from the DB clock. The writer's INSERT
-- passes now() explicitly; the BEFORE INSERT trigger below re-forces it so
-- no code path can ever supply an actor-controlled timestamp (SEC-45).
--
-- Platform-scope entries (e.g. rule-pack publish, operator plan changes
-- audited from the control plane): use the RESERVED platform tenant id
-- '00000000-0000-0000-0000-000000000000' as tenant_id (writer pins the GUC
-- to it). Real tenants can never read those rows (their GUC never matches).
--
-- Retention: 365 days minimum (plan-config `audit_retention_days`),
-- independent of event retention; rows SURVIVE trial purge (SEC-48) -- see
-- control.purge_registry ('retain'). Expiry deletion happens ONLY through
-- audit_purge_expired(), which enforces the 365-day floor.

-- migrate:up

CREATE TABLE tenantdata.audit_log (
  id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   uuid        NOT NULL,
  actor_type  text        NOT NULL CHECK (actor_type IN ('user','system','device')),
  actor_id    text        NOT NULL,
  action_type text        NOT NULL,  -- e.g. alert.close, device.revoke,
                                     -- user.role_change, tenant.plan_change
  target_type text,
  target_id   text,
  before      jsonb,                 -- metadata only (SEC-44)
  after       jsonb,                 -- metadata only (SEC-44)
  reason_code text,
  created_at  timestamptz NOT NULL DEFAULT now(),  -- DB clock, trigger-forced
  source_ip   inet                   -- optional; writer contract doesn't set it
);

-- Dictated audit query path: GET /v1/audit-logs, newest first (AC-83).
CREATE INDEX audit_log_tenant_created_at_idx
  ON tenantdata.audit_log (tenant_id, created_at DESC);

---------------------------------------------------------------------------
-- Trigger: force DB-clock timestamp on insert (SEC-45).
---------------------------------------------------------------------------
CREATE FUNCTION tenantdata.audit_log_set_created_at() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  NEW.created_at := now();
  RETURN NEW;
END;
$fn$;

CREATE TRIGGER audit_log_set_created_at
  BEFORE INSERT ON tenantdata.audit_log
  FOR EACH ROW EXECUTE FUNCTION tenantdata.audit_log_set_created_at();

---------------------------------------------------------------------------
-- Guard triggers: append-only enforcement (SEC-42).
---------------------------------------------------------------------------
CREATE FUNCTION tenantdata.audit_log_guard() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit_log is append-only (SEC-42): UPDATE forbidden';
  ELSIF TG_OP = 'DELETE' THEN
    IF current_setting('app.audit_purge', true) IS DISTINCT FROM 'retention' THEN
      RAISE EXCEPTION 'audit_log is append-only (SEC-42): DELETE forbidden '
                      'outside audit_purge_expired()';
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'audit_log is append-only (SEC-42): TRUNCATE forbidden';
  END IF;
  RETURN NULL;
END;
$fn$;

CREATE TRIGGER audit_log_guard_row
  BEFORE UPDATE OR DELETE ON tenantdata.audit_log
  FOR EACH ROW EXECUTE FUNCTION tenantdata.audit_log_guard();

CREATE TRIGGER audit_log_guard_truncate
  BEFORE TRUNCATE ON tenantdata.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION tenantdata.audit_log_guard();

---------------------------------------------------------------------------
-- RLS: tenant-scoped access; plus a DELETE policy usable ONLY under the
-- retention-purge GUC and ONLY for rows older than the 365-day floor.
---------------------------------------------------------------------------
ALTER TABLE tenantdata.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenantdata.audit_log
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY audit_retention_delete ON tenantdata.audit_log
  FOR DELETE
  USING (current_setting('app.audit_purge', true) = 'retention'
         AND created_at < now() - interval '365 days');

---------------------------------------------------------------------------
-- audit_purge_expired(): the ONLY sanctioned deletion path. SECURITY
-- DEFINER (runs as the migration owner); EXECUTE granted to system_jobs
-- only (0008). Enforces the 365-day retention floor (SEC-44) and records
-- its own run in the audit log under the reserved platform tenant.
---------------------------------------------------------------------------
CREATE FUNCTION tenantdata.audit_purge_expired(retention_days integer DEFAULT 365)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = tenantdata, pg_temp AS $fn$
DECLARE
  deleted bigint;
BEGIN
  IF retention_days < 365 THEN
    RAISE EXCEPTION 'audit retention floor is 365 days (SEC-44), got %',
      retention_days;
  END IF;
  PERFORM set_config('app.audit_purge', 'retention', true);
  DELETE FROM tenantdata.audit_log
   WHERE created_at < now() - make_interval(days => retention_days);
  GET DIAGNOSTICS deleted = ROW_COUNT;
  PERFORM set_config('app.audit_purge', '', true);

  PERFORM set_config('app.tenant_id',
                     '00000000-0000-0000-0000-000000000000', true);
  INSERT INTO tenantdata.audit_log
    (tenant_id, actor_type, actor_id, action_type, after, reason_code)
  VALUES
    ('00000000-0000-0000-0000-000000000000'::uuid, 'system',
     'jobs-scheduler', 'audit.retention_purge',
     jsonb_build_object('deleted_rows', deleted,
                        'retention_days', retention_days),
     'retention');
  RETURN deleted;
END;
$fn$;

REVOKE ALL ON FUNCTION tenantdata.audit_purge_expired(integer) FROM PUBLIC;

-- migrate:down

DROP FUNCTION IF EXISTS tenantdata.audit_purge_expired(integer);
DROP TABLE IF EXISTS tenantdata.audit_log;
DROP FUNCTION IF EXISTS tenantdata.audit_log_guard();
DROP FUNCTION IF EXISTS tenantdata.audit_log_set_created_at();
