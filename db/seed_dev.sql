-- seed_dev.sql -- DEV-ONLY SAMPLE DATA. NEVER RUN IN PRODUCTION.
-- =====================================================================
-- Not a migration: apply manually after `python db/migrate.py up`, e.g.
--   psql "$DATABASE_URL" -f db/seed_dev.sql
-- Creates two marker tenants (the SEC-26 cross-tenant QA suite needs two),
-- sample assets/devices/keys/alerts, and onboarding rows. All secrets here
-- are public dev fixtures:
--   enrollment token (tenant A): et_devtoken1.dev-enroll-secret-a
--   ingest key       (tenant A): ik_devkey1.dev-ingest-secret-a
--   ingest key       (tenant B): ik_devkey2.dev-ingest-secret-b
-- User password hashes are PLACEHOLDERS -- controlplane dev bootstrap must
-- set a real argon2id hash before login works.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------- control
INSERT INTO control.accounts (id, org_name, email, email_domain, password_hash, state) VALUES
  ('aaaaaaaa-0000-0000-0000-000000000001', 'Acme GmbH',  'admin@acme-dev.example',  'acme-dev.example',
   '$argon2id$DEV-PLACEHOLDER-NOT-A-REAL-HASH', 'verified'),
  ('aaaaaaaa-0000-0000-0000-000000000002', 'Beta S.A.',  'admin@beta-dev.example',  'beta-dev.example',
   '$argon2id$DEV-PLACEHOLDER-NOT-A-REAL-HASH', 'verified')
ON CONFLICT DO NOTHING;

INSERT INTO control.tenants (id, account_id, name, status, plan_id, trial_expires_at,
                             security_contact_email, provisioned_at) VALUES
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-000000000001',
   'Acme GmbH', 'active', 'trial', now() + interval '14 days',
   'admin@acme-dev.example', now()),
  ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-0000-0000-0000-000000000002',
   'Beta S.A.', 'active', 'pro', NULL,
   'admin@beta-dev.example', now())
ON CONFLICT DO NOTHING;

INSERT INTO control.users (id, tenant_id, email, role, state, password_hash) VALUES
  ('bbbbbbbb-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111',
   'admin@acme-dev.example', 'admin', 'active', '$argon2id$DEV-PLACEHOLDER-NOT-A-REAL-HASH'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111',
   'analyst@acme-dev.example', 'analyst', 'active', '$argon2id$DEV-PLACEHOLDER-NOT-A-REAL-HASH'),
  ('bbbbbbbb-0000-0000-0000-000000000003', '22222222-2222-2222-2222-222222222222',
   'admin@beta-dev.example', 'admin', 'active', '$argon2id$DEV-PLACEHOLDER-NOT-A-REAL-HASH')
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------- tenant A (Acme)
-- RLS: pin tenant context (FORCE RLS applies even to the owner).
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', true);

INSERT INTO tenantdata.assets (id, tenant_id, hostname, os_family, os_name, os_version,
                               sources, agent_status, billable, created_via, dedup_rule) VALUES
  ('cccccccc-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111',
   'fin-laptop-07', 'windows', 'Windows 11 Pro', '10.0.26100',
   '{agent}', 'healthy', true, 'agent_enrollment', 'device_id_match')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.enrollment_tokens (id, tenant_id, name, token_hash, expires_at, created_by) VALUES
  ('et_devtoken1', '11111111-1111-1111-1111-111111111111', 'dev rollout token',
   encode(sha256('dev-enroll-secret-a'::bytea), 'hex'), now() + interval '72 hours',
   'bbbbbbbb-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.devices (id, tenant_id, asset_id, status, cert_serial,
                                cert_issued_at, cert_expires_at, public_key_fingerprint,
                                enrollment_token_id, enrolled_ip, claimed_hostname,
                                agent_version, last_heartbeat_at) VALUES
  ('dev_01J9ZK3T', '11111111-1111-1111-1111-111111111111',
   'cccccccc-0000-0000-0000-000000000001', 'active', '0adevserial01',
   now(), now() + interval '90 days',
   encode(sha256('dev-device-pubkey-a'::bytea), 'hex'),
   'et_devtoken1', '10.1.4.23', 'fin-laptop-07', '0.3.1', now())
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.asset_identities (tenant_id, asset_id, source, identifier_type, value) VALUES
  ('11111111-1111-1111-1111-111111111111', 'cccccccc-0000-0000-0000-000000000001',
   'agent', 'device_id', 'dev_01J9ZK3T'),
  ('11111111-1111-1111-1111-111111111111', 'cccccccc-0000-0000-0000-000000000001',
   'log_ingest', 'hostname_os', 'fin-laptop-07|windows')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.ingest_keys (id, tenant_id, name, key_hash, created_by) VALUES
  ('ik_devkey1', '11111111-1111-1111-1111-111111111111', 'dev firewall feed',
   encode(sha256('dev-ingest-secret-a'::bytea), 'hex'),
   'bbbbbbbb-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.alerts (id, tenant_id, state, rule_id, rule_version, rule_title,
                               rule_severity, mitre_technique_ids, entity_key,
                               entity_hostname, entity_user, asset_id, occurrence_count,
                               first_seen, last_seen, priority_score, priority_inputs,
                               triage_status) VALUES
  ('al_01DEVSEED0000000000000001', '11111111-1111-1111-1111-111111111111', 'new',
   'win_susp_encoded_powershell', '1.0.0', 'Suspicious encoded PowerShell',
   'high', '{T1059.001}', 'fin-laptop-07|sam.jones',
   'fin-laptop-07', 'sam.jones', 'cccccccc-0000-0000-0000-000000000001', 3,
   now() - interval '10 minutes', now() - interval '1 minute', 78,
   '{"rule_severity":"high","occurrence_count":3,"priority_formula_version":1}',
   'pending')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.alert_history (tenant_id, alert_id, actor_type, actor_id, action, to_state) VALUES
  ('11111111-1111-1111-1111-111111111111', 'al_01DEVSEED0000000000000001',
   'system', 'worker-alerter', 'created', 'new')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.onboarding_steps (tenant_id, step_id, state, completed_at) VALUES
  ('11111111-1111-1111-1111-111111111111', 'install_agent',     'done', now()),
  ('11111111-1111-1111-1111-111111111111', 'create_ingest_key', 'done', now()),
  ('11111111-1111-1111-1111-111111111111', 'first_event',       'done', now()),
  ('11111111-1111-1111-1111-111111111111', 'view_queue',        'todo', NULL)
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------- tenant B (Beta)
-- Marker data so cross-tenant leak tests (SEC-26) have something to miss.
SELECT set_config('app.tenant_id', '22222222-2222-2222-2222-222222222222', true);

INSERT INTO tenantdata.assets (id, tenant_id, hostname, os_family, os_name, os_version,
                               sources, agent_status, billable, created_via) VALUES
  ('cccccccc-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222',
   'MARKER-TENANT-B-HOST', 'linux', 'Ubuntu', '24.04',
   '{log_ingest}', 'none', true, 'log_ingest')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.ingest_keys (id, tenant_id, name, key_hash, created_by) VALUES
  ('ik_devkey2', '22222222-2222-2222-2222-222222222222', 'MARKER-TENANT-B-KEY',
   encode(sha256('dev-ingest-secret-b'::bytea), 'hex'),
   'bbbbbbbb-0000-0000-0000-000000000003')
ON CONFLICT DO NOTHING;

INSERT INTO tenantdata.onboarding_steps (tenant_id, step_id) VALUES
  ('22222222-2222-2222-2222-222222222222', 'install_agent'),
  ('22222222-2222-2222-2222-222222222222', 'create_ingest_key'),
  ('22222222-2222-2222-2222-222222222222', 'first_event'),
  ('22222222-2222-2222-2222-222222222222', 'view_queue')
ON CONFLICT DO NOTHING;

COMMIT;
