#!/usr/bin/env bash
# Bring up the whole SOC POC stack:
#   1. generate repo-root .env from ops/docker/.env.example (fresh dev secrets)
#   2. docker compose build
#   3. docker compose up -d   (one-shots gate the apps: dev-ca -> migrate -> rulepub)
#   4. wait until the gateway + both public APIs answer
#
# Usage: scripts/poc-up.sh [--no-build]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
ENV_TEMPLATE="$REPO_ROOT/ops/docker/.env.example"
NO_BUILD=0
[ "${1:-}" = "--no-build" ] && NO_BUILD=1

cd "$REPO_ROOT"

command -v docker >/dev/null || { echo "docker CLI not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || {
    echo "ERROR: the Docker daemon is not reachable (docker info failed)." >&2
    echo "Start Docker Desktop / the docker service, then re-run." >&2
    exit 1
}

# Native Linux only: Elasticsearch needs vm.max_map_count >= 262144 (Docker
# Desktop's VM ships it; bare-metal Ubuntu defaults to 65530 and ES crashes).
if [ "$(uname -s)" = "Linux" ] && [ -r /proc/sys/vm/max_map_count ]; then
    mmc="$(cat /proc/sys/vm/max_map_count)"
    if [ "$mmc" -lt 262144 ]; then
        echo "poc-up: vm.max_map_count=$mmc is too low for Elasticsearch; raising to 262144 (needs sudo)"
        sudo sysctl -w vm.max_map_count=262144 || {
            echo "ERROR: could not raise vm.max_map_count. Run manually:" >&2
            echo "  sudo sysctl -w vm.max_map_count=262144" >&2
            echo "  (persist: echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf)" >&2
            exit 1
        }
    fi
fi

gen_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        python - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
    fi
}

# --- 1. .env -----------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
    echo "poc-up: generating $ENV_FILE from ops/docker/.env.example"
    cp "$ENV_TEMPLATE" "$ENV_FILE"
    # Replace each __GENERATE__ with an independent random hex secret (SEC-49).
    while grep -q "__GENERATE__" "$ENV_FILE"; do
        secret="$(gen_secret)"
        # Replace only the FIRST occurrence so every key gets its own value.
        awk -v s="$secret" '!done && sub(/__GENERATE__/, s) { done = 1 } 1' \
            "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
    done
    echo "poc-up: .env created (git-ignored; dev secrets only)"
else
    echo "poc-up: reusing existing $ENV_FILE"
    if grep -q "__GENERATE__" "$ENV_FILE"; then
        echo "ERROR: $ENV_FILE still contains __GENERATE__ placeholders — delete it and re-run." >&2
        exit 1
    fi
fi

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

# --- 2. build ------------------------------------------------------------------
if [ "$NO_BUILD" -eq 0 ]; then
    echo "poc-up: building images (uv --frozen / npm ci — first run takes a while)"
    docker compose build
fi

# --- 3. up ---------------------------------------------------------------------
echo "poc-up: starting the stack"
docker compose up -d --remove-orphans

# --- 4. wait healthy -------------------------------------------------------------
WEB_PORT="${WEB_HTTP_PORT:-8080}"
CP_PORT="${CP_HTTP_PORT:-8081}"
DP_PORT="${DP_HTTP_PORT:-8082}"

wait_http() { # url, name, tries
    local url="$1" name="$2" tries="${3:-90}"
    for _ in $(seq 1 "$tries"); do
        if curl -fsS -o /dev/null --max-time 3 "$url"; then
            echo "poc-up: $name is up ($url)"
            return 0
        fi
        sleep 2
    done
    echo "poc-up: TIMEOUT waiting for $name ($url)" >&2
    echo "        inspect: docker compose ps; docker compose logs --tail 50 $name" >&2
    return 1
}

echo "poc-up: waiting for services (one-shots run first: dev-ca -> migrate -> rulepub)..."
wait_http "http://localhost:$WEB_PORT/gw-healthz" "gateway" 60
wait_http "http://localhost:$CP_PORT/healthz" "controlplane-api" 120
wait_http "http://localhost:$DP_PORT/healthz" "dataplane-api" 120
wait_http "http://localhost:$WEB_PORT/" "web console" 60

cat <<EOF

poc-up: stack is up.

  Console:            http://localhost:$WEB_PORT
  Controlplane API:   http://localhost:$CP_PORT
  Dataplane API:      http://localhost:$DP_PORT
  Agent mTLS:         https://localhost:${AGENT_MTLS_PORT:-8443}
  Mailpit (dev mail): http://localhost:${MAILPIT_UI_PORT:-8025}

Next: scripts/poc-smoke.sh   (signup -> verify -> login -> ingest -> alert)
EOF
