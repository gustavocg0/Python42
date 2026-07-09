# controlplane — signup, provisioning, auth/users, entitlements

Implements `docs/contracts/api-contracts.md` §3 (signup/provisioning), §4
(auth/users), §5 (entitlements incl. internal plan/abuse-freeze), §14
clarifications, plus `/healthz` `/readyz`. Design: `docs/design/
platform-foundation-mvp.md` §5/§5.1; threat model SEC-1..7/30/39/40/46.

## Processes (two listeners, deliberately separate)

| Command | Listener | Surface |
|---|---|---|
| `python -m controlplane.main` | `CP_HOST:CP_PORT` (default `0.0.0.0:8001`) | Public: `/v1/...` + health |
| `python -m controlplane.internal_main` | `CP_INTERNAL_HOST:CP_INTERNAL_PORT` (default `127.0.0.1:8101`) | Internal: `/internal/v1/...` + health |

Two separate processes/apps so internal routes are **never mountable on the
public listener** (SEC-30/40). Keep the internal listener on the internal
network (compose network / K8s NetworkPolicy); the HMAC service-token auth is
the second layer, not the only one. Run both in compose/Helm.

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `CP_ENV` | `dev` | |
| `CP_HOST` / `CP_PORT` | `0.0.0.0` / `8001` | public listener |
| `CP_INTERNAL_HOST` / `CP_INTERNAL_PORT` | `127.0.0.1` / `8101` | internal listener |
| `CP_DATABASE_URL` | dev localhost | login user `svc_controlplane` (roles `app_control` + `audit_writer`, search_path incl. `tenantdata` — db/README.md) |
| `CP_REDIS_URL` | `redis://localhost:6379/0` | keys per `db/redis-conventions.md` |
| `CP_CONSOLE_ORIGIN` | `http://localhost:3000` | CORS allowlist + verification/invite link base |
| `CP_COOKIE_SECURE` | `true` | set `false` only for plain-HTTP dev |
| `CP_TRUST_PROXY_HEADERS` | `false` | honor `X-Forwarded-For` (enable only behind the gateway) |
| `CP_DATAPLANE_INTERNAL_URL` | `http://localhost:8100` | dataplane internal listener |
| `CP_OUTBOUND_SERVICE_KEY` | — (required for provisioning) | HMAC key for tokens this service SIGNS (service name `controlplane`); dataplane verifies with the same key |
| `CP_OUTBOUND_SERVICE_NAME` | `controlplane` | |
| `CP_SVC_KEY_<SERVICE>` | — | inbound verification keys; suffix lowercased = caller service name (e.g. `CP_SVC_KEY_DATAPLANE`, `CP_SVC_KEY_OPSCONSOLE`); >=32 bytes |
| `CP_MAILER` | `console` | `smtp` for mailpit/real SMTP; `console` logs metadata only (never bodies/tokens) |
| `CP_SMTP_HOST/PORT/FROM/STARTTLS/USERNAME/PASSWORD` | mailpit defaults | |
| `CP_CHALLENGE_STUB_TOKEN` | — | dev/CI signup-challenge stub; unset = reject all challenges (fail closed). Production: swap in a Turnstile-style verifier behind `ChallengeVerifier` (OQ-5) |
| `CP_SESSION_IDLE_SECONDS` / `CP_SESSION_ABSOLUTE_SECONDS` | 24h / 7d | SEC-3 |
| `CP_LOGIN_LOCKOUT_THRESHOLD` / `CP_LOGIN_IP_THRESHOLD` / `CP_LOGIN_THROTTLE_WINDOW_SECONDS` | 10 / 20 / 900 | SEC-4 |
| `CP_SAGA_STEP_MAX_ATTEMPTS` / `CP_SAGA_RETRY_DELAY_SECONDS` | 3 / 2.0 | AC-5 |
| `CP_DOCS_ENABLED` | `false` | `/docs` + `/openapi.json` on the public app (dev only) |
| `SOC_OTEL_EXPORTER` | `none` | `console` / `otlp` (soc_telemetry) |

## Contracts other components must honor

- **dataplane**: implements `PUT /internal/v1/tenants/{tenant_uuid}/provision`
  (contract §13). This service calls it during the saga with
  `Authorization: Bearer v1.controlplane.<exp>.<sig>` (HMAC key =
  `CP_OUTBOUND_SERVICE_KEY`) and JSON body `{"tenant_id": "<uuid>"}` (must
  match the path id). Idempotent; 200/201/204 = success. Dataplane calls
  `GET /internal/v1/tenants/{id}/entitlements` here with its own token
  (`CP_SVC_KEY_DATAPLANE`).
- **web console**: cookies `sid` (HttpOnly, Secure, SameSite=Lax, path=/) and
  `csrf_token` (NOT HttpOnly, Secure, SameSite=Lax); echo `X-CSRF-Token` on
  every mutating request. Verification link:
  `{CP_CONSOLE_ORIGIN}/signup/verify?token=...&account_id=acc_...`. Invite
  link: `{CP_CONSOLE_ORIGIN}/invite/accept?token=...&user_id=usr_...` — the
  page posts `{token, password}` to public `POST /v1/auth/accept-invite`
  (204; 400 policy/breached leaves the token usable; 409/410 per §2).
  Frozen tenants: console writes get 403 `TENANT_FROZEN` EXCEPT logout and
  change-password (ratified exemptions). Unhandled 500s carry
  `INTERNAL_ERROR` (never `SERVICE_UNAVAILABLE`).
- **operators/ops tooling**: `PUT .../plan` and `PUT .../abuse-freeze` require
  a service token **plus** `X-Operator-Id` (recorded in audit, SEC-40).

## Tests

```bash
uv run pytest services/controlplane   # fakes only: no live PG/ES/Redis
```
