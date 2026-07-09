#!/usr/bin/env bash
# One-shot bootstrap for the POC stack (gates every app service via
# depends_on: service_completed_successfully). Idempotent end to end:
#   1. wait for PostgreSQL + Elasticsearch
#   2. python db/migrate.py up                (owner DSN — NEVER a runtime role)
#   3. create per-deployment LOGIN roles + grants (db/README.md role model)
#   4. PUT the events-v1 ES index template    (db/elasticsearch/README.md)
#   5. apply db/seed_dev.sql                  (dev only, SEED_DEV=1)
set -euo pipefail

: "${DATABASE_URL:?owner DSN required (e.g. postgresql://soc_owner:...@postgres:5432/soc)}"
: "${ES_URL:?Elasticsearch URL required (credentials in URL are fine for dev)}"
: "${SVC_CONTROLPLANE_DB_PASSWORD:?}"
: "${SVC_DATAPLANE_DB_PASSWORD:?}"
: "${SVC_JOBS_DB_PASSWORD:?}"
SEED_DEV="${SEED_DEV:-0}"

# --- 1. wait for stores ------------------------------------------------------
echo "migrate: waiting for PostgreSQL..."
for _ in $(seq 1 60); do
    pg_isready -q -d "$DATABASE_URL" && break
    sleep 2
done
pg_isready -q -d "$DATABASE_URL" || { echo "migrate: PostgreSQL never became ready" >&2; exit 1; }

echo "migrate: waiting for Elasticsearch..."
for _ in $(seq 1 90); do
    curl -fsS -o /dev/null "$ES_URL/_cluster/health?wait_for_status=yellow&timeout=5s" && break
    sleep 2
done
curl -fsS -o /dev/null "$ES_URL/_cluster/health" \
    || { echo "migrate: Elasticsearch never became ready" >&2; exit 1; }

# --- 2. schema migrations ----------------------------------------------------
echo "migrate: applying db/migrations via db/migrate.py"
python /app/db/migrate.py --dsn "$DATABASE_URL" up

# --- 3. per-deployment LOGIN roles (db/README.md — grants live in migrations,
#        LOGIN users are a deployment concern). Passwords come from the
#        generated .env; they are hex tokens, safe for psql :'var' quoting.
echo "migrate: ensuring runtime LOGIN roles"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
     -v cp_pass="$SVC_CONTROLPLANE_DB_PASSWORD" \
     -v dp_pass="$SVC_DATAPLANE_DB_PASSWORD" \
     -v jobs_pass="$SVC_JOBS_DB_PASSWORD" <<'SQL'
SELECT 'CREATE ROLE svc_controlplane LOGIN'
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_controlplane') \gexec
SELECT 'CREATE ROLE svc_dataplane LOGIN'
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_dataplane') \gexec
SELECT 'CREATE ROLE svc_jobs LOGIN'
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_jobs') \gexec

ALTER ROLE svc_controlplane LOGIN PASSWORD :'cp_pass'   NOBYPASSRLS;
ALTER ROLE svc_dataplane    LOGIN PASSWORD :'dp_pass'   NOBYPASSRLS;
ALTER ROLE svc_jobs         LOGIN PASSWORD :'jobs_pass' NOBYPASSRLS;

GRANT app_control,   audit_writer TO svc_controlplane;
GRANT app_dataplane, audit_writer TO svc_dataplane;
GRANT system_jobs,   audit_writer TO svc_jobs;

-- soc_audit's AUDIT_INSERT_SQL targets the unqualified name `audit_log`
-- (db/README.md), so audit-writing users need tenantdata on search_path.
ALTER ROLE svc_controlplane SET search_path = control, tenantdata, public;
ALTER ROLE svc_dataplane    SET search_path = tenantdata, public;
ALTER ROLE svc_jobs         SET search_path = tenantdata, public;
SQL

# --- 4. ES index template (installed once per stamp) -------------------------
echo "migrate: installing events-v1 index template"
curl -fsS -o /dev/null -X PUT "$ES_URL/_index_template/events-v1" \
    -H 'Content-Type: application/json' \
    --data-binary @/app/db/elasticsearch/events-v1-template.json

# --- 5. dev seed (marker tenants; idempotent ON CONFLICT DO NOTHING) ---------
if [ "$SEED_DEV" = "1" ]; then
    echo "migrate: applying db/seed_dev.sql (DEV ONLY)"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f /app/db/seed_dev.sql
else
    echo "migrate: SEED_DEV != 1 — skipping dev seed"
fi

echo "migrate: bootstrap complete."
