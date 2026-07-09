# ops/ — local POC container stack

Owner: cloud-platform. Runs the ENTIRE platform locally with
`docker compose up` per design §7 (`docs/design/platform-foundation-mvp.md`).
Dev-grade by design: dev CA (SEC-9), plain-HTTP browser listener, generated
`.env` secrets. The production path is Helm/Terraform (`infra/`), not this.

## Quick start

```bash
scripts/poc-up.sh        # generate .env, build, up, wait healthy
scripts/poc-smoke.sh     # e2e: signup -> verify -> login -> ingest -> alert
# optional demo agent (after smoke wrote SOC_ENROLL_TOKEN into .env):
docker compose --profile demo up -d agent-sim
```

Windows: run from Git Bash. Requires Docker Desktop (WSL2), `curl`,
`python` on PATH. No `jq` needed.

## Host ports

| Port | What | Notes |
|---|---|---|
| 8080 | SOC console (browser origin) | gateway -> `web:3000` |
| 8081 | controlplane public API | gateway -> `controlplane-api:8001` |
| 8082 | dataplane public API + generic ingest | gateway -> `dataplane-api:8000`, injects `X-Gateway-Auth` |
| 8443 | agent mTLS listener | gateway (dev CA client verify) -> dataplane agent routes |
| 8025 | mailpit UI/API (dev email) | signup verification links land here |
| 5432/6379/9200 | postgres / redis / elasticsearch | **debug profile only**: `docker compose --profile debug up -d` (socat forwarders) |

All ports are overridable in `.env` (`*_PORT` keys).

## Service map

```
                        edge network              backend network (internal: true)
 browser ── 8080/8081/8082 ──► gateway ──────► web / controlplane-api / dataplane-api
 agent   ── 8443 (mTLS) ─────►   │
                                 └─ strips X-Device-*/X-Gateway-Auth on EVERY
                                    route, injects the gateway secret + cert
                                    identity headers (SEC-14, design §5)

 one-shot gates:  dev-ca-bootstrap ──► migrate ──► rulepub ──► app services
 apps:            controlplane-api, controlplane-internal (8101, HMAC SEC-40)
                  dataplane-api,   dataplane-internal   (8100, HMAC SEC-40)
 workers:         worker-normalizer/-detector/-alerter/-triager/-asset-dedup, jobs
 stores:          postgres:16, elasticsearch:8.17 (basic auth), redis:7 (AOF+pass),
                  mailpit
```

- **dev-ca-bootstrap** — generates the dev CA + gateway server cert into the
  `dev-ca` named volume (idempotent; runs as root once to chown key material:
  `dev-ca.key` -> uid 10001/dataplane, `gateway.key` -> uid 101/nginx).
- **migrate** — `db/migrate.py up`, per-deployment LOGIN roles + grants
  (`db/README.md`), `events-v1` ES index template, `db/seed_dev.sql`.
- **rulepub** — validates + publishes `rules/pack.yaml` (SEC-27); a
  re-published identical pack version counts as success (idempotent re-up).
- **worker-triager** runs with `TRIAGE_FAKE=1` (deterministic keyless triage —
  no LLM credentials in the POC). Set `ANTHROPIC_API_KEY` + drop the flag in
  `compose.yaml` to use a real model.

## Secrets (SEC-49)

`ops/docker/.env.example` is the committed template — **no real values**.
`scripts/poc-up.sh` copies it to the git-ignored repo-root `.env` and fills
every `__GENERATE__` with a fresh random hex secret: store passwords, the
gateway hop secret (`GATEWAY_AUTH_SECRET`), and the two SEC-40 HMAC
service-token keys (`SVC_KEY_CONTROLPLANE` == what dataplane verifies,
`SVC_KEY_DATAPLANE` == what controlplane verifies). Delete `.env` to rotate
everything (stores keep old passwords in their volumes — `docker compose
down -v` for a truly clean slate).

## Images (supply chain)

All base images are pinned by digest (linux/amd64 manifests, resolved
2026-07-09 — re-resolve when bumping). App images: multi-stage, non-root
(python uid 10001, node `node`, nginx-unprivileged uid 101), `uv sync
--frozen` / `npm ci` lockfile installs, `read_only: true` + tmpfs at runtime,
`cap_drop: ALL`, `no-new-privileges`. Triage prompt `.txt` files ship inside
the python image (editable workspace install copies the full source tree).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `elasticsearch` unhealthy, exit 78 / `vm.max_map_count` in logs | `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` (Docker Desktop) |
| `migrate` fails once on first boot | it retries stores internally for ~2–3 min; `docker compose up -d` again re-runs the one-shot |
| app services never start | one-shot gate failed: `docker compose logs dev-ca-bootstrap migrate rulepub` |
| smoke step 2 times out | open http://localhost:8025 — if the mail is there, your shell lacks `python`/`curl`; if not, `docker compose logs controlplane-api mailpit` |
| no alert after ingest | `docker compose logs worker-normalizer worker-detector worker-alerter`; confirm `rulepub` published the pack |
| 401 on `/v1/agent/*` from agent-sim | cert not issued yet (needs `SOC_ENROLL_TOKEN` in `.env` — run `scripts/poc-smoke.sh` first) |
| gateway restart loop | `docker compose logs gateway` — if a cert path error: `docker compose run --rm dev-ca-bootstrap` |
| need psql/redis-cli/ES from host | `docker compose --profile debug up -d` then connect to localhost:5432/6379/9200; or `docker compose exec postgres psql -U soc_owner soc` |
| read-only FS error from a service | report it to cloud-platform; as a stopgap remove `read_only: true` for that service in `compose.yaml` |

## Known dev-only deviations (tracked)

- Dev CA volume is mounted (ro) into `agent-sim` including `dev-ca.key`
  (0600, uid 10001 — unreadable by the agent user, but present). Split
  public/private material into separate volumes before any shared demo env.
- Browser listener is plain HTTP => `CP_COOKIE_SECURE=false`. Production
  terminates TLS at the gateway and keeps Secure cookies.
- Redis hardening is `requirepass` + disabled admin commands, not per-user
  ACLs (SEC-19 full ACLs land in the stamp).
- Elasticsearch runs basic auth over plain HTTP inside the internal network.
- nginx SAN parsing uses an njs substring match over the cert DER (see
  `ops/docker/gateway/njs/identity.js`) — fine for certs we issue; the
  production stamp needs a real ASN.1 parse or LB SAN support.
