-- 0003_control_tables.sql
-- Control-plane tables (design §3, api-contracts §3-5).
-- No RLS here: control tables are reachable only by app_control (and
-- narrowly system_jobs) -- runtime role separation, enforced in 0008.

-- migrate:up

-- Tenant status per design §5 ("Trial freeze" row) -- dictated enum.
CREATE TYPE control.tenant_status AS ENUM
  ('provisioning', 'provisioning_failed', 'active', 'frozen', 'purged');

CREATE TYPE control.user_role AS ENUM ('admin', 'analyst');

---------------------------------------------------------------------------
-- accounts: one signup = one account (pre-tenant). AC-1..8.
---------------------------------------------------------------------------
CREATE TABLE control.accounts (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_name      text        NOT NULL
                            CHECK (char_length(org_name) BETWEEN 2 AND 120),
  email         text        NOT NULL,
  email_domain  text        NOT NULL,     -- part after '@', lowercased by app
  password_hash text        NOT NULL,     -- argon2id (SEC-1); never plaintext
  state         text        NOT NULL DEFAULT 'pending_verification'
                            CHECK (state IN ('pending_verification','verified')),
  created_at    timestamptz NOT NULL DEFAULT now()
);
-- Login lookup + uniqueness.
CREATE UNIQUE INDEX accounts_email_uq ON control.accounts (lower(email));
-- AC-4: one account per email domain (409 DOMAIN_ALREADY_REGISTERED).
CREATE UNIQUE INDEX accounts_email_domain_uq
  ON control.accounts (lower(email_domain));

---------------------------------------------------------------------------
-- plans + plan_config: PRD §4 plan-config defaults table. Values are data,
-- not code (AC-11..18); seeded in 0009_seed_plans.sql.
---------------------------------------------------------------------------
CREATE TABLE control.plans (
  id           text        PRIMARY KEY CHECK (id IN ('trial','core','pro')),
  display_name text        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.plan_config (
  plan_id    text        NOT NULL REFERENCES control.plans(id) ON DELETE CASCADE,
  key        text        NOT NULL,   -- e.g. endpoint_cap, retention_days
  value      jsonb       NOT NULL,   -- number | string | bool
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (plan_id, key)
);

-- Plan-independent platform knobs (dedup window, correlation window, rate
-- limits, audit retention, ...). "Plan-config" in PRD prose covers both.
CREATE TABLE control.platform_config (
  key        text        PRIMARY KEY,
  value      jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

---------------------------------------------------------------------------
-- tenants: status + abuse_frozen (G-1/SEC-39, orthogonal to status).
---------------------------------------------------------------------------
CREATE TABLE control.tenants (
  id                     uuid                  PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id             uuid                  NOT NULL UNIQUE
                                               REFERENCES control.accounts(id),
  name                   text                  NOT NULL,
  status                 control.tenant_status NOT NULL DEFAULT 'provisioning',
  abuse_frozen           boolean               NOT NULL DEFAULT false, -- SEC-39
  abuse_frozen_reason    text,
  abuse_frozen_at        timestamptz,
  plan_id                text                  NOT NULL DEFAULT 'trial'
                                               REFERENCES control.plans(id),
  trial_expires_at       timestamptz,          -- AC-9; NULL for paid plans
  is_financial_entity    boolean               NOT NULL DEFAULT false,  -- CR-14
  dpa_version            text,                 -- CR-13: DPA acceptance record
  dpa_accepted_at        timestamptz,
  dpa_accepted_by_email  text,
  security_contact_email text,                 -- CR-10: out-of-band contact
  provisioned_at         timestamptz,
  frozen_at              timestamptz,
  purged_at              timestamptz,
  created_at             timestamptz           NOT NULL DEFAULT now(),
  updated_at             timestamptz           NOT NULL DEFAULT now()
);
-- jobs-scheduler scans: trial freeze (status/trial_expires_at) and purge
-- (frozen 30d) -- AC-9/AC-10.
CREATE INDEX tenants_status_idx ON control.tenants (status);
CREATE INDEX tenants_trial_expiry_idx ON control.tenants (trial_expires_at)
  WHERE trial_expires_at IS NOT NULL;

---------------------------------------------------------------------------
-- entitlement_overrides: per-tenant deviations from plan defaults
-- (internal operator only; audited per SEC-40/CR-16).
---------------------------------------------------------------------------
CREATE TABLE control.entitlement_overrides (
  tenant_id  uuid        NOT NULL REFERENCES control.tenants(id) ON DELETE CASCADE,
  key        text        NOT NULL,
  value      jsonb       NOT NULL,
  reason     text        NOT NULL,
  created_by text        NOT NULL,   -- named operator identity (CR-16)
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  PRIMARY KEY (tenant_id, key)
);

---------------------------------------------------------------------------
-- users: console users (AC-77/78). MFA-ready fields unused in MVP (CR-25).
---------------------------------------------------------------------------
CREATE TABLE control.users (
  id                  uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid              NOT NULL
                                        REFERENCES control.tenants(id) ON DELETE CASCADE,
  email               text              NOT NULL,
  role                control.user_role NOT NULL,
  state               text              NOT NULL DEFAULT 'invited'
                                        CHECK (state IN ('invited','active','disabled')),
  password_hash       text,             -- argon2id; NULL until invite accepted
  password_changed_at timestamptz,
  mfa_enrolled        boolean           NOT NULL DEFAULT false,
  mfa_secret_enc      text,             -- encrypted TOTP seed; NULL in MVP
  mfa_enrolled_at     timestamptz,
  failed_login_count  integer           NOT NULL DEFAULT 0,  -- SEC-4 lockout
  locked_until        timestamptz,
  created_at          timestamptz       NOT NULL DEFAULT now(),
  updated_at          timestamptz       NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE UNIQUE INDEX users_tenant_email_uq
  ON control.users (tenant_id, lower(email)) WHERE deleted_at IS NULL;

---------------------------------------------------------------------------
-- email_verifications: signup verification + user invites (SEC-2).
-- Tokens stored as sha256 hex, single-use enforced by used_at CAS update.
---------------------------------------------------------------------------
CREATE TABLE control.email_verifications (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  purpose    text        NOT NULL
                         CHECK (purpose IN ('signup_verification','user_invite')),
  account_id uuid        REFERENCES control.accounts(id) ON DELETE CASCADE,
  user_id    uuid        REFERENCES control.users(id) ON DELETE CASCADE,
  token_hash text        NOT NULL UNIQUE,  -- sha256 hex of the emailed token
  expires_at timestamptz NOT NULL,         -- 24h (SEC-2)
  used_at    timestamptz,                  -- set atomically, exactly once
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (account_id IS NOT NULL OR user_id IS NOT NULL)
);

---------------------------------------------------------------------------
-- sessions: METADATA only (Redis sess:{id} is the live session store,
-- SEC-3). Kept for invalidation sweeps ("all sessions of user X") + audit.
---------------------------------------------------------------------------
CREATE TABLE control.sessions (
  session_id_hash     text        PRIMARY KEY,  -- sha256 hex; plaintext id
                                                -- exists only in cookie+Redis
  user_id             uuid        NOT NULL
                                  REFERENCES control.users(id) ON DELETE CASCADE,
  tenant_id           uuid        NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at timestamptz NOT NULL,     -- created_at + 7d (SEC-3)
  revoked_at          timestamptz,
  revoke_reason       text,       -- logout|password_change|role_change|
                                  -- user_deleted|expired
  ip                  inet,
  user_agent          text
);
-- Invalidate-all-sessions-of-user path (SEC-3).
CREATE INDEX sessions_user_idx ON control.sessions (user_id);

---------------------------------------------------------------------------
-- provisioning saga (AC-3/AC-5, design §5): idempotent step machine.
---------------------------------------------------------------------------
CREATE TABLE control.provisioning_sagas (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      uuid        NOT NULL UNIQUE REFERENCES control.accounts(id),
  tenant_id       uuid        REFERENCES control.tenants(id),
  idempotency_key text        NOT NULL UNIQUE,
  state           text        NOT NULL DEFAULT 'running'
                              CHECK (state IN ('running','succeeded','failed')),
  current_step    text,
  last_error      text,
  started_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  completed_at    timestamptz
);

CREATE TABLE control.provisioning_saga_steps (
  saga_id      uuid        NOT NULL
                           REFERENCES control.provisioning_sagas(id) ON DELETE CASCADE,
  step         text        NOT NULL CHECK (step IN
                 ('tenant_row','rls_context','es_index',
                  'entitlements','admin_user','trial_expiry')),
  status       text        NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','done','failed')),
  attempts     integer     NOT NULL DEFAULT 0,
  last_error   text,
  completed_at timestamptz,
  PRIMARY KEY (saga_id, step)
);

---------------------------------------------------------------------------
-- signup_abuse_log: held/challenged/blocked signups for review (AC-8,
-- SEC-5). Live per-IP counters are Redis; this is the durable record.
---------------------------------------------------------------------------
CREATE TABLE control.signup_abuse_log (
  id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email        text,
  email_domain text,
  source_ip    inet,
  outcome      text        NOT NULL
                           CHECK (outcome IN ('allowed','challenged','held','blocked')),
  reason       text,       -- ip_velocity|disposable_domain|challenge_failed|...
  created_at   timestamptz NOT NULL DEFAULT now()
);
-- Review queries are time-windowed.
CREATE INDEX signup_abuse_log_created_idx
  ON control.signup_abuse_log (created_at);

-- migrate:down

DROP TABLE IF EXISTS control.signup_abuse_log;
DROP TABLE IF EXISTS control.provisioning_saga_steps;
DROP TABLE IF EXISTS control.provisioning_sagas;
DROP TABLE IF EXISTS control.sessions;
DROP TABLE IF EXISTS control.email_verifications;
DROP TABLE IF EXISTS control.users;
DROP TABLE IF EXISTS control.entitlement_overrides;
DROP TABLE IF EXISTS control.tenants;
DROP TABLE IF EXISTS control.platform_config;
DROP TABLE IF EXISTS control.plan_config;
DROP TABLE IF EXISTS control.plans;
DROP TABLE IF EXISTS control.accounts;
DROP TYPE IF EXISTS control.user_role;
DROP TYPE IF EXISTS control.tenant_status;
