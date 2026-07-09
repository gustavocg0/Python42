-- 0010_platform_config_access.sql
-- Architect ruling: dataplane workers need READ access to
-- control.platform_config -- worker-detector reads the SEC-28(c)
-- rule-error thresholds (rule_error_disable_fraction,
-- rule_error_min_tenants) and worker-triager reads the SEC-37 triage
-- token budget (triage_daily_token_budget).
--
-- Scope is deliberately minimal: app_dataplane gets schema USAGE on
-- `control` plus SELECT on platform_config ONLY -- no other control table
-- is visible to the data plane (schema USAGE alone exposes nothing without
-- table grants, so plane separation holds).
--
-- Notes:
--   * system_jobs already holds SELECT on control.platform_config from
--     0008; the GRANT below is an idempotent no-op included per the
--     Architect instruction. The down section does NOT revoke it (that
--     privilege belongs to 0008 and must survive this migration's revert).
--   * `triage_daily_token_budget` = 2000000 is ALREADY seeded by
--     0009_seed_plans.sql (verified) -- nothing missing, no insert here.

-- migrate:up

GRANT USAGE ON SCHEMA control TO app_dataplane;
GRANT SELECT ON control.platform_config TO app_dataplane, system_jobs;

-- migrate:down

-- Revert only what this migration introduced: app_dataplane's access.
-- system_jobs keeps SELECT (granted by 0008).
REVOKE SELECT ON control.platform_config FROM app_dataplane;
REVOKE USAGE ON SCHEMA control FROM app_dataplane;
