-- 0009_seed_plans.sql
-- Production-required seed data: the three plans and the PRD §4 plan-config
-- defaults ("single source of truth for the ACs"; finance/product may retune
-- values without code change -- hence ON CONFLICT DO NOTHING so re-running
-- migrations never clobbers retuned values).
--
-- Dev-only sample data lives in db/seed_dev.sql (NOT a migration).

-- migrate:up

INSERT INTO control.plans (id, display_name) VALUES
  ('trial', 'Trial'),
  ('core',  'Core'),
  ('pro',   'Pro')
ON CONFLICT (id) DO NOTHING;

-- PRD §4 plan-config defaults. deep_investigation_daily_quota -1 = unlimited.
INSERT INTO control.plan_config (plan_id, key, value) VALUES
  ('trial', 'trial_duration_days',             '14'),
  ('trial', 'endpoint_cap',                    '100'),
  ('trial', 'retention_days',                  '14'),
  ('trial', 'deep_investigation_daily_quota',  '5'),
  ('trial', 'response_mode',                   '"recommend_only"'),
  ('trial', 'ingest_events_per_min',           '5000'),

  ('core',  'endpoint_cap',                    '250'),
  ('core',  'retention_days',                  '30'),
  ('core',  'deep_investigation_daily_quota',  '5'),
  ('core',  'response_mode',                   '"recommend_only"'),
  ('core',  'ingest_events_per_min',           '10000'),

  ('pro',   'endpoint_cap',                    '1000'),
  ('pro',   'retention_days',                  '90'),
  ('pro',   'deep_investigation_daily_quota',  '-1'),
  ('pro',   'response_mode',                   '"playbooks_with_approval"'),
  ('pro',   'ingest_events_per_min',           '40000')
ON CONFLICT (plan_id, key) DO NOTHING;

-- Plan-independent platform knobs referenced as "(plan-config)" in the PRD.
INSERT INTO control.platform_config (key, value) VALUES
  ('alert_dedup_window_minutes',            '60'),      -- AC-41
  ('correlation_window_minutes',            '30'),      -- AC-43
  ('enrollment_token_default_expiry_hours', '72'),      -- AC-56/ADR-0006
  ('audit_retention_days',                  '365'),     -- AC-84 (floor 365)
  ('billable_window_days',                  '30'),      -- AC-26
  ('dlq_retention_days',                    '7'),       -- AC-32/SEC-21
  ('trial_purge_after_days',                '30'),      -- AC-10
  ('heartbeat_interval_seconds',            '60'),      -- contract §10
  ('agent_offline_after_missed_heartbeats', '3'),       -- AC-61
  ('cert_renewal_overlap_hours',            '24'),      -- SEC-11
  ('ingest_batch_max_events',               '1000'),    -- AC-30
  ('ingest_batch_max_bytes',                '5242880'), -- AC-30 (5MB)
  ('enroll_rate_limit_per_token_per_min',   '30'),      -- SEC-12
  ('enroll_rate_limit_per_ip_per_min',      '10'),      -- SEC-12
  ('token_velocity_alert_per_hour',         '50'),      -- SEC-13
  ('signup_per_ip_hourly_threshold',        '5'),       -- AC-8/SEC-5
  ('rule_error_disable_fraction',           '0.05'),    -- SEC-28c
  ('rule_error_min_tenants',                '3'),       -- SEC-28c
  ('triage_daily_token_budget',             '2000000')  -- SEC-37 backstop
ON CONFLICT (key) DO NOTHING;

-- migrate:down

DELETE FROM control.platform_config WHERE key IN
  ('alert_dedup_window_minutes','correlation_window_minutes',
   'enrollment_token_default_expiry_hours','audit_retention_days',
   'billable_window_days','dlq_retention_days','trial_purge_after_days',
   'heartbeat_interval_seconds','agent_offline_after_missed_heartbeats',
   'cert_renewal_overlap_hours','ingest_batch_max_events',
   'ingest_batch_max_bytes','enroll_rate_limit_per_token_per_min',
   'enroll_rate_limit_per_ip_per_min','token_velocity_alert_per_hour',
   'signup_per_ip_hourly_threshold','rule_error_disable_fraction',
   'rule_error_min_tenants','triage_daily_token_budget');

DELETE FROM control.plan_config WHERE plan_id IN ('trial','core','pro');
DELETE FROM control.plans WHERE id IN ('trial','core','pro');
