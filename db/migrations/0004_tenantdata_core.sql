-- 0004_tenantdata_core.sql
-- Data-plane core: assets + identity links + correction pins + merge audit,
-- devices (SEC-10 allowlist source of truth), enrollment tokens, ingest keys.
--
-- RLS pattern (threat model §4.1, SEC-23) applied to EVERY table here:
--   ENABLE + FORCE ROW LEVEL SECURITY;
--   policy on NULLIF(current_setting('app.tenant_id', true), '')::uuid --
--   unset or empty GUC evaluates NULL -> predicate false -> ZERO rows,
--   deny-by-default (never error-with-data).
-- Composite FKs on (tenant_id, <id>) make cross-tenant references
-- structurally impossible (FK checks bypass RLS, so the FK itself must
-- carry the tenant).

-- migrate:up

---------------------------------------------------------------------------
-- assets: deduplicated inventory (AC-19..27). One row per real device/host.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.assets (
  id                   uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            uuid        NOT NULL,
  hostname             text,                    -- lowercased by normalizer
  os_family            text        CHECK (os_family IN
                                     ('windows','linux','macos','other')),
  os_name              text,
  os_version           text,
  ip                   text,
  mac                  text,                    -- aa:bb:cc:dd:ee:ff lowercased
  sources              text[]      NOT NULL DEFAULT '{}',  -- agent|log_ingest
  agent_status         text        NOT NULL DEFAULT 'none' CHECK (agent_status IN
                                     ('enrolled','healthy','offline','revoked','none')),
  billable             boolean     NOT NULL DEFAULT false,  -- AC-26 30d window
  billable_computed_at timestamptz,
  state                text        NOT NULL DEFAULT 'active'
                                   CHECK (state IN ('active','merged')),
  merged_into_asset_id uuid,                    -- set when state='merged'
  dedup_rule           text,       -- device_id_match|hostname_os_match|
                                   -- mac_match|manual_merge|manual_split (AC-24)
  created_via          text        NOT NULL DEFAULT 'log_ingest'
                                   CHECK (created_via IN
                                     ('agent_enrollment','log_ingest','manual_split')),
  first_seen           timestamptz NOT NULL DEFAULT now(),
  last_seen            timestamptz NOT NULL DEFAULT now(),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id)            -- composite-FK anchor + RLS-scoped lookup
);
-- Dedup key #2 lookup: (hostname, os_family) within tenant (AC-22).
CREATE INDEX assets_tenant_hostname_idx
  ON tenantdata.assets (tenant_id, hostname, os_family);
-- Billable count (AC-26): billable + last_seen >= now()-30d, and the
-- nightly billable-window job scan.
CREATE INDEX assets_billable_window_idx
  ON tenantdata.assets (tenant_id, billable, last_seen DESC);

ALTER TABLE tenantdata.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.assets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.assets
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- asset_identities: identity observations bound to an asset (AC-22..24).
-- UNIQUE(tenant, type, value): an identifier resolves to exactly one asset;
-- this index IS the dedup lookup path ("assets lookups by identity").
---------------------------------------------------------------------------
CREATE TABLE tenantdata.asset_identities (
  id              uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id       uuid        NOT NULL,
  asset_id        uuid        NOT NULL,
  source          text        NOT NULL CHECK (source IN ('agent','log_ingest')),
  identifier_type text        NOT NULL CHECK (identifier_type IN
                                ('device_id','hostname_os','mac')),
  value           text        NOT NULL,  -- 'dev_x' | 'host|windows' | mac
  first_seen      timestamptz NOT NULL DEFAULT now(),
  last_seen       timestamptz NOT NULL DEFAULT now(),
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, identifier_type, value),
  FOREIGN KEY (tenant_id, asset_id)
    REFERENCES tenantdata.assets (tenant_id, id) ON DELETE CASCADE
);
-- Reverse lookup: identities of an asset (GET /v1/assets/{id}).
CREATE INDEX asset_identities_asset_idx
  ON tenantdata.asset_identities (tenant_id, asset_id);

ALTER TABLE tenantdata.asset_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.asset_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.asset_identities
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- asset_identity_pins: manual merge/split corrections (AC-25). Consulted
-- BEFORE automatic dedup rules; a pin binds an identifier to an asset and
-- prevents automatic re-merge/re-split.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.asset_identity_pins (
  id              uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id       uuid        NOT NULL,
  identifier_type text        NOT NULL CHECK (identifier_type IN
                                ('device_id','hostname_os','mac')),
  value           text        NOT NULL,
  pinned_asset_id uuid        NOT NULL,
  origin          text        NOT NULL CHECK (origin IN ('merge','split')),
  reason          text        NOT NULL,
  created_by      uuid,       -- control.users id (admin); no cross-schema FK
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, identifier_type, value),
  FOREIGN KEY (tenant_id, pinned_asset_id)
    REFERENCES tenantdata.assets (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE tenantdata.asset_identity_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.asset_identity_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.asset_identity_pins
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- asset_merge_audit: per-asset merge/split trail (AC-24 merge_audit field).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.asset_merge_audit (
  id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  asset_id   uuid        NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  rule       text        NOT NULL,  -- device_id_match|hostname_os_match|
                                    -- mac_match|manual_merge|manual_split
  actor_type text        NOT NULL DEFAULT 'system'
                         CHECK (actor_type IN ('system','user')),
  actor_id   text,
  details    jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- merged identity, ids
  FOREIGN KEY (tenant_id, asset_id)
    REFERENCES tenantdata.assets (tenant_id, id) ON DELETE CASCADE
);
-- Rendered on GET /v1/assets/{id}.
CREATE INDEX asset_merge_audit_asset_idx
  ON tenantdata.asset_merge_audit (tenant_id, asset_id, at);

ALTER TABLE tenantdata.asset_merge_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.asset_merge_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.asset_merge_audit
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- enrollment_tokens (AC-56/58, SEC-7): hashed, expiring, revocable,
-- multi-use. Wire format 'et_<id>.<secret>'; only sha256(secret) stored.
---------------------------------------------------------------------------
CREATE TABLE tenantdata.enrollment_tokens (
  id                 text        NOT NULL,   -- 'et_...' (lookup segment)
  tenant_id          uuid        NOT NULL,
  name               text        NOT NULL,
  token_hash         text        NOT NULL UNIQUE,  -- sha256 hex (SEC-7)
  expires_at         timestamptz NOT NULL,         -- default now()+72h
  revoked_at         timestamptz,
  revoked_by         uuid,
  enrollment_count   integer     NOT NULL DEFAULT 0,  -- SEC-13 theft visibility
  last_enrollment_at timestamptz,
  created_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id)
);
-- Console list (GET /v1/enrollment-tokens).
CREATE INDEX enrollment_tokens_tenant_idx
  ON tenantdata.enrollment_tokens (tenant_id, created_at DESC);

ALTER TABLE tenantdata.enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.enrollment_tokens
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- devices: SOURCE OF TRUTH for the SEC-10/B-1 device allowlist. Redis
-- device:{tenant}:{device_id} is only a cache of (status, cert serials).
-- id is the public device_id ('dev_...'), also the cert CN (ADR-0006).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.devices (
  id                     text        NOT NULL,   -- 'dev_...' == cert CN
  tenant_id              uuid        NOT NULL,
  asset_id               uuid        NOT NULL,
  status                 text        NOT NULL DEFAULT 'active'
                                     CHECK (status IN ('active','revoked')),
  cert_serial            text        NOT NULL,   -- hex serial of current cert
  cert_issued_at         timestamptz NOT NULL,
  cert_expires_at        timestamptz NOT NULL,   -- issued + 90d (ADR-0006)
  prev_cert_serial       text,                   -- SEC-11 renewal overlap
  prev_cert_rotated_at   timestamptz,            -- prev serial honored for
                                                 -- <=24h after this instant
  public_key_fingerprint text        NOT NULL UNIQUE, -- sha256(SPKI); global
                                                 -- duplicate-key reject (SEC-8)
  enrollment_token_id    text,                   -- SEC-13 attribution
  enrolled_ip            inet,
  claimed_hostname       text,
  agent_version          text,
  last_heartbeat_at      timestamptz,
  provider_status        jsonb,                  -- last heartbeat providers[]
  revoked_at             timestamptz,
  revoked_by             uuid,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  -- Dictated allowlist lookup path: (tenant_id, device_id).
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id)
    REFERENCES tenantdata.assets (tenant_id, id),
  FOREIGN KEY (tenant_id, enrollment_token_id)
    REFERENCES tenantdata.enrollment_tokens (tenant_id, id)
);
-- Agent-offline job (AC-61): scan active devices by heartbeat age.
CREATE INDEX devices_heartbeat_idx
  ON tenantdata.devices (tenant_id, last_heartbeat_at)
  WHERE status = 'active';

ALTER TABLE tenantdata.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.devices
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

---------------------------------------------------------------------------
-- ingest_keys (AC-29, SEC-16/17): wire format 'ik_<id>.<secret>'; only
-- sha256(secret) stored; allowlist pattern like devices (Redis cache).
---------------------------------------------------------------------------
CREATE TABLE tenantdata.ingest_keys (
  id           text        NOT NULL,   -- 'ik_...'
  tenant_id    uuid        NOT NULL,
  name         text        NOT NULL,
  key_hash     text        NOT NULL,   -- sha256 hex of secret part (SEC-16)
  last_used_at timestamptz,
  revoked_at   timestamptz,
  revoked_by   uuid,
  created_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id)               -- allowlist lookup (SEC-17)
);

ALTER TABLE tenantdata.ingest_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenantdata.ingest_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenantdata.ingest_keys
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- migrate:down

DROP TABLE IF EXISTS tenantdata.ingest_keys;
DROP TABLE IF EXISTS tenantdata.devices;
DROP TABLE IF EXISTS tenantdata.enrollment_tokens;
DROP TABLE IF EXISTS tenantdata.asset_merge_audit;
DROP TABLE IF EXISTS tenantdata.asset_identity_pins;
DROP TABLE IF EXISTS tenantdata.asset_identities;
DROP TABLE IF EXISTS tenantdata.assets;
