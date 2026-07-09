-- 0006_rules_dlq_metering.sql
-- Rule pack state (SEC-27/28, AC-35..40), dead-letter queue (AC-32/SEC-21),
-- LLM metering (AC-51/SEC-37/CR-2), deep-investigation runs (AC-53..55),
-- onboarding steps (AC-70), usage counters (AC-88).
--
-- NOTE on RLS exceptions: rule_packs, rules and rule_runtime_disables are
-- GLOBAL platform content (one managed pack for all tenants, design §5).
-- They carry no tenant_id and no RLS; writes happen only via the
-- authenticated, audited content-publish operation (SEC-27). rule_toggles
-- is the per-tenant overlay and IS tenant-scoped + RLS.

-- migrate:up

---------------------------------------------------------------------------
-- rule_packs: published pack versions (manifest hash recorded per SEC-27).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.rule_packs (
  version       text        NOT NULL,
  manifest_hash text        NOT NULL,        -- sha256 of pack.yaml (SEC-27)
  status        text        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','superseded')),
  rule_count    integer     NOT NULL,
  published_by  text        NOT NULL,        -- named operator/CI identity
  published_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (version)
);

---------------------------------------------------------------------------
-- rules: rule rows per pack version (detector loads the active pack;
-- 30s version poll for hot reload).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.rules (
  pack_version        text    NOT NULL
                              REFERENCES tenantdata.rule_packs(version) ON DELETE CASCADE,
  rule_id             text    NOT NULL,
  rule_version        text    NOT NULL,      -- e.g. '1.2.0' (AC-39)
  title               text    NOT NULL,
  severity            text    NOT NULL CHECK (severity IN
                                ('low','medium','high','critical')),
  mitre_technique_ids text[]  NOT NULL DEFAULT '{}',
  event_classes       text[]  NOT NULL DEFAULT '{}',
  description         text,
  min_schema_version  text    NOT NULL DEFAULT '1.0.0',
  definition          jsonb   NOT NULL,      -- compiled Sigma-style body
  enabled_default     boolean NOT NULL DEFAULT true,  -- false = disabled at
                                             -- publish (compile error, SEC-28a)
  compile_error       text,
  PRIMARY KEY (pack_version, rule_id)
);

---------------------------------------------------------------------------
-- rule_runtime_disables (SEC-28c): runtime auto-disable ONLY on sustained
-- multi-tenant failure + ops review. Per-event exceptions never land here.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.rule_runtime_disables (
  rule_id          text        NOT NULL,
  disabled_at      timestamptz NOT NULL DEFAULT now(),
  reason           text        NOT NULL,
  error_fraction   numeric,
  tenants_affected integer,
  created_by       text        NOT NULL DEFAULT 'system',
  PRIMARY KEY (rule_id)
);

---------------------------------------------------------------------------
-- rule_toggles: per-tenant overlay on the global pack (AC-38). Tenant-
-- effective enabled = NOT runtime-disabled AND enabled_default overridden
-- by toggle when a row exists.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.rule_toggles (
  tenant_id  uuid        NOT NULL,
  rule_id    text        NOT NULL,
  enabled    boolean     NOT NULL,
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rule_id)
);

ALTER TABLE tenantdata.rule_toggles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.rule_toggles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.rule_toggles
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- dead_letter_events (AC-32, SEC-21, event-schema §6): malformed events.
-- Payload capped 64KB; 7-day retention enforced by jobs-scheduler.
-- Content is UNTRUSTED -- always rendered escaped.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.dead_letter_events (
  id          uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   uuid        NOT NULL,
  batch_id    uuid,
  source_type text        NOT NULL CHECK (source_type IN ('agent','generic')),
  received_at timestamptz NOT NULL DEFAULT now(),
  raw_payload bytea       NOT NULL
              CHECK (octet_length(raw_payload) <= 65536),  -- 64KB cap (SEC-21)
  error_code  text        NOT NULL,
  error_detail text,
  PRIMARY KEY (id)
);
-- 7-day purge scan + tenant-scoped listing.
CREATE INDEX dlq_tenant_received_idx
  ON tenantdata.dead_letter_events (tenant_id, received_at);

ALTER TABLE tenantdata.dead_letter_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.dead_letter_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.dead_letter_events
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- llm_metering (AC-51, SEC-37, CR-2): one row per model call. Contains
-- NO event/prompt content -- reference ids and aggregates only, so rows
-- may survive purge as 'retain' per SEC-48/CR-11 (see purge registry).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.llm_metering (
  id              bigint         GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id       uuid           NOT NULL,
  call_type       text           NOT NULL DEFAULT 'triage'
                                 CHECK (call_type IN ('triage','deep_investigation')),
  alert_id        text,          -- reference only; no FK (metering outlives alerts)
  model_id        text           NOT NULL,
  endpoint_region text,          -- CR-2 region-pin audit evidence
  tokens_in       integer        NOT NULL DEFAULT 0,
  tokens_out      integer        NOT NULL DEFAULT 0,
  cost_usd        numeric(12,6)  NOT NULL DEFAULT 0,
  latency_ms      integer,
  outcome         text           NOT NULL CHECK (outcome IN
                                   ('ok','error','timeout','over_budget')),
  created_at      timestamptz    NOT NULL DEFAULT now()
);
-- /internal/v1/metering/llm?tenant_id=&from=&to= (AC-51).
CREATE INDEX llm_metering_tenant_time_idx
  ON tenantdata.llm_metering (tenant_id, created_at);

ALTER TABLE tenantdata.llm_metering ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.llm_metering FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.llm_metering
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- deep_investigation_runs (AC-53..55, contract §9): stub in MVP; the
-- response shape is the permanent contract, so jsonb columns mirror it.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.deep_investigation_runs (
  id                  text        NOT NULL,   -- 'inv_...'
  tenant_id           uuid        NOT NULL,
  alert_id            text        NOT NULL,
  status              text        NOT NULL DEFAULT 'completed'
                                  CHECK (status IN ('queued','completed','failed')),
  is_stub             boolean     NOT NULL DEFAULT true,
  engine_version      text        NOT NULL DEFAULT 'stub-1',
  requested_by        uuid        NOT NULL,
  requested_at        timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  summary             text,
  confidence          numeric,
  findings            jsonb       NOT NULL DEFAULT '[]'::jsonb,
  timeline            jsonb       NOT NULL DEFAULT '[]'::jsonb,
  evidence_graph      jsonb       NOT NULL DEFAULT '{"nodes":[],"edges":[]}'::jsonb,
  recommended_actions jsonb       NOT NULL DEFAULT '[]'::jsonb,
  quota_limit         integer,    -- snapshot at run time (-1 = unlimited)
  quota_remaining     integer,
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, alert_id)
    REFERENCES tenantdata.alerts (tenant_id, id) ON DELETE CASCADE
);
-- GET /v1/alerts/{id}/deep-investigations (paginated, newest first).
CREATE INDEX di_runs_alert_idx
  ON tenantdata.deep_investigation_runs (tenant_id, alert_id, requested_at DESC);

ALTER TABLE tenantdata.deep_investigation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.deep_investigation_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.deep_investigation_runs
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- onboarding_steps (AC-70): PG is source of truth; Redis onboarding
-- signals are transient triggers.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.onboarding_steps (
  tenant_id    uuid        NOT NULL,
  step_id      text        NOT NULL CHECK (step_id IN
                 ('install_agent','create_ingest_key','first_event','view_queue')),
  state        text        NOT NULL DEFAULT 'todo' CHECK (state IN ('todo','done')),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, step_id)
);

ALTER TABLE tenantdata.onboarding_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.onboarding_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.onboarding_steps
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- usage_counters (AC-88): daily per-tenant aggregates flushed from Redis
-- (throttled_batches, rejected_events, events_accepted, duplicates_dropped).
-- Live sliding-window counters stay in Redis.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.usage_counters (
  tenant_id  uuid        NOT NULL,
  day        date        NOT NULL,
  metric     text        NOT NULL,
  value      bigint      NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, day, metric)
);

ALTER TABLE tenantdata.usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.usage_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.usage_counters
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- migrate:down

DROP TABLE IF EXISTS tenantdata.usage_counters;
DROP TABLE IF EXISTS tenantdata.onboarding_steps;
DROP TABLE IF EXISTS tenantdata.deep_investigation_runs;
DROP TABLE IF EXISTS tenantdata.llm_metering;
DROP TABLE IF EXISTS tenantdata.dead_letter_events;
DROP TABLE IF EXISTS tenantdata.rule_toggles;
DROP TABLE IF EXISTS tenantdata.rule_runtime_disables;
DROP TABLE IF EXISTS tenantdata.rules;
DROP TABLE IF EXISTS tenantdata.rule_packs;
