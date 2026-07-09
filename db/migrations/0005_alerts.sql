-- 0005_alerts.sql
-- Alerts (AC-41..47), correlation groups (AC-43), alert->event links,
-- alert history (audit trail rendered on GET /v1/alerts/{id}).
-- Alert ids are app-generated 'al_' + ULID (lexicographically sortable ->
-- stable cursor tie-break per contract sort rules).

-- migrate:up

---------------------------------------------------------------------------
-- correlation_groups (AC-43): open alerts, same tenant+host, last_seen
-- within 30 min (plan-config), different rules.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.correlation_groups (
  id              text        NOT NULL,   -- 'cg_...'
  tenant_id       uuid        NOT NULL,
  entity_hostname text        NOT NULL,
  alert_count     integer     NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_alert_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id)
);
-- Alerter join-window lookup: existing group for tenant+host in window.
CREATE INDEX correlation_groups_lookup_idx
  ON tenantdata.correlation_groups (tenant_id, entity_hostname, last_alert_at DESC);

ALTER TABLE tenantdata.correlation_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.correlation_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.correlation_groups
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- alerts: queue rows. Rule fields are denormalized from the pack version
-- that fired (AC-39: alert always carries rule id+version).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.alerts (
  id                   text        NOT NULL,   -- 'al_' + ULID
  tenant_id            uuid        NOT NULL,
  state                text        NOT NULL DEFAULT 'new'
                                   CHECK (state IN ('new','acknowledged','closed')),
  rule_id              text        NOT NULL,
  rule_version         text        NOT NULL,
  rule_title           text        NOT NULL,
  rule_severity        text        NOT NULL CHECK (rule_severity IN
                                     ('low','medium','high','critical')),
  mitre_technique_ids  text[]      NOT NULL DEFAULT '{}',
  entity_key           text        NOT NULL,   -- dedup key: 'hostname|user'
                                               -- (rule-declared, AC-41)
  entity_hostname      text,
  entity_user          text,
  asset_id             uuid,                   -- resolved asset, if any
  occurrence_count     integer     NOT NULL DEFAULT 1,   -- AC-42
  first_seen           timestamptz NOT NULL,
  last_seen            timestamptz NOT NULL,
  correlation_group_id text,
  priority_score       integer     NOT NULL
                                   CHECK (priority_score BETWEEN 0 AND 100),
  priority_inputs      jsonb       NOT NULL DEFAULT '{}'::jsonb, -- incl.
                                   -- priority_formula_version, agent_status
  -- Triage fields, written by worker-triager (AC-48..50):
  triage_status        text        NOT NULL DEFAULT 'pending' CHECK
                                   (triage_status IN ('pending','completed','unavailable')),
  triage_summary       text,                   -- plain text; rendered escaped
                                               -- (SEC-31/33)
  ai_severity          text        CHECK (ai_severity IN
                                     ('low','medium','high','critical')),
  ai_severity_effective text       CHECK (ai_severity_effective IN
                                     ('low','medium','high','critical')),
                                   -- B-4/SEC-34 clamp; scoring only
  triage_model_id      text,
  triage_completed_at  timestamptz,
  triage_attempts      integer     NOT NULL DEFAULT 0,
  -- State machine (AC-45/47):
  close_reason         text        CHECK (close_reason IN
                                     ('resolved','false_positive',
                                      'expected_behavior','duplicate')),
  close_comment        text,
  closed_by            uuid,
  closed_at            timestamptz,
  acknowledged_by      uuid,
  acknowledged_at      timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, correlation_group_id)
    REFERENCES tenantdata.correlation_groups (tenant_id, id),
  CHECK (state <> 'closed' OR close_reason IS NOT NULL)
);

-- AC-44 queue: default sort -priority, tie-break -last_seen, then id;
-- p95 <= 500ms @ 10k alerts. Dictated composite index.
CREATE INDEX alerts_queue_idx
  ON tenantdata.alerts (tenant_id, state, priority_score DESC, last_seen DESC, id);
-- AC-41/42 dedup: AT MOST ONE open alert per (rule, entity) -- the UNIQUE
-- partial index is the concurrency-safe dedup mechanism (alerter upserts
-- against it). Dictated predicate.
CREATE UNIQUE INDEX alerts_open_dedup_uq
  ON tenantdata.alerts (tenant_id, rule_id, entity_key)
  WHERE state IN ('new','acknowledged');
-- AC-43 correlation-window lookup: open alerts for tenant+host by recency.
CREATE INDEX alerts_correlation_idx
  ON tenantdata.alerts (tenant_id, entity_hostname, last_seen DESC)
  WHERE state IN ('new','acknowledged');
-- sort=last_seen / from-to range filters (contract §8 query params).
CREATE INDEX alerts_last_seen_idx
  ON tenantdata.alerts (tenant_id, last_seen DESC, id);
-- Siblings by correlation_group_id (GET /v1/alerts/{id}).
CREATE INDEX alerts_correlation_group_idx
  ON tenantdata.alerts (tenant_id, correlation_group_id)
  WHERE correlation_group_id IS NOT NULL;
-- FP-feedback export (AC-46, /internal/v1/fp-feedback?rule_id=&from=&to=).
CREATE INDEX alerts_close_reason_idx
  ON tenantdata.alerts (tenant_id, close_reason, closed_at DESC)
  WHERE close_reason IS NOT NULL;

ALTER TABLE tenantdata.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.alerts
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- alert_events: alert -> ES event references (contract event_refs[]).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.alert_events (
  tenant_id  uuid        NOT NULL,
  alert_id   text        NOT NULL,
  event_id   uuid        NOT NULL,   -- ES envelope event_id
  es_index   text        NOT NULL,   -- e.g. events-v1-<tenant>-2026.07
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, alert_id, event_id),
  FOREIGN KEY (tenant_id, alert_id)
    REFERENCES tenantdata.alerts (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE tenantdata.alert_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.alert_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.alert_events
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- alert_history: per-alert trail (contract §8 `history`; CR-20 evidence
-- completeness). Distinct from tenantdata.audit_log, which is the tenant-
-- wide immutable audit; [A]-endpoint transitions write BOTH (same tx).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.alert_history (
  id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  alert_id   text        NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  actor_type text        NOT NULL CHECK (actor_type IN ('user','system','device')),
  actor_id   text        NOT NULL,
  action     text        NOT NULL,  -- created|acknowledged|closed|reopened|
                                    -- occurrence_added|correlated|
                                    -- triage_completed|triage_unavailable
  from_state text,
  to_state   text,
  reason     text,
  comment    text,
  details    jsonb       NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (tenant_id, alert_id)
    REFERENCES tenantdata.alerts (tenant_id, id) ON DELETE CASCADE
);
-- History rendered per alert, ordered.
CREATE INDEX alert_history_alert_idx
  ON tenantdata.alert_history (tenant_id, alert_id, at);

ALTER TABLE tenantdata.alert_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.alert_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.alert_history
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- migrate:down

DROP TABLE IF EXISTS tenantdata.alert_history;
DROP TABLE IF EXISTS tenantdata.alert_events;
DROP TABLE IF EXISTS tenantdata.alerts;
DROP TABLE IF EXISTS tenantdata.correlation_groups;
