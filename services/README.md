# services/ — boundary rules (binding)

This directory holds the two FastAPI applications (design doc
`docs/design/platform-foundation-mvp.md` §1–2):

- `services/controlplane` — signup, provisioning, entitlements, identity/admin.
- `services/dataplane` — ingest, enrollment, assets, alerts, rules,
  investigation, audit API, workers, jobs.

## Import boundaries (CI-enforced via import-linter, config: repo-root `.importlinter`)

1. `services/controlplane` and `services/dataplane` NEVER import each other.
   Cross-plane calls go over HTTP (`/internal/v1/...`) only, authenticated per
   design §5.1 / SEC-40 (HMAC service tokens — use
   `soc_entitlements.generate_service_token` / `verify_service_token`).
2. Both services may import the shared packages under `packages/`
   (import names: `soc_schemas`, `soc_pipeline`, `soc_tenancy`,
   `soc_entitlements`, `soc_audit`, `soc_telemetry`).
3. `packages/*` never import `services/*`. Never add a service import to a
   shared package; propose a contract change through the Architect instead.
4. `web/` and `agent/` consume only the HTTP contracts in `docs/contracts/`.

## Mandatory usage of shared packages (do not bypass)

- **Redis Streams**: only via `soc_pipeline` (`StreamProducer`,
  `StreamConsumer`). Direct redis stream API calls are banned (ADR-0004).
- **Tenant context**: only `soc_tenancy` sets the Postgres GUC
  (`set_local_tenant`) and the tenant contextvar; ES index/alias names come
  only from `soc_tenancy.events_alias` / `events_index` (SEC-23/24).
- **Gateway auth**: agent routes on dataplane-api must be behind
  `soc_tenancy.GatewayAuthMiddleware` (SEC-14, fail closed).
- **Entitlement reads**: only via `soc_entitlements.EntitlementsClient`
  (ADR-0005 fail-closed semantics). Never hardcode plan values (AC-12).
  Never enforce `abuse_frozen`/device/key status from this client — those use
  their own status stores (SEC-39, never-graced list).
- **Audit writes**: only via `soc_audit.write_audit`, in the SAME transaction
  as the state change (SEC-42..45).
- **Error responses**: every non-2xx uses the envelope from
  `soc_schemas.errors` (`ErrorCode`, `ErrorEnvelope`, `ApiError`) — stable
  machine-readable codes, no stack traces to clients (api-contracts.md §1–2).
- **Telemetry**: call `soc_telemetry.init_telemetry(service_name)` and
  `configure_json_logging(service_name)` at startup; pipeline stages emit
  metrics via `soc_telemetry.PipelineMetrics` labeled
  `{tenant_id, stage, outcome}` (AC-91).

## Workspace membership

The uv workspace root (`/pyproject.toml`) currently lists only
`packages/*` as members. When `services/controlplane`, `services/dataplane`,
and `db/` land, add them to `[tool.uv.workspace] members` and add the
services independence contract to `.importlinter` (TODO markers are in both
files).
