#!/bin/sh
# Entrypoint for the soc-agent Docker image (simulated provider, POC/demo).
#
# Container interface (fixed contract with the compose stack):
#   SOC_GATEWAY_URL    (required)  base URL of the agent gateway,
#                                  e.g. https://gateway:8443
#   SOC_ENROLL_TOKEN   (required until enrolled) one-time enrollment token
#   SOC_CA_CERT_PATH   (default /certs/dev-ca.crt) CA bundle to trust for
#                                  the gateway TLS (read-only volume mount)
#
# Optional knobs:
#   SOC_SIM_EPS        (default 5)    simulated events per second
#   SOC_SIM_SEED       (default 0)    0 = random; non-zero = deterministic
#   SOC_SIM_SUSPICIOUS (default true) emit detection-tripping scenarios
#   SOC_AGENT_DATA_DIR (default /var/lib/socagent) writable data root
#
# Renders /usr/local/share/socagent/agent.toml.tmpl into the data dir and
# execs agentd in the foreground (logs to stdout). The enrollment token is
# passed via env (SOC_AGENT_ENROLLMENT_TOKEN), never written to disk.
set -eu

# Overridable only for out-of-container testing of this script.
TEMPLATE="${SOC_AGENT_TEMPLATE:-/usr/local/share/socagent/agent.toml.tmpl}"
AGENTD_BIN="${SOC_AGENTD_BIN:-/usr/local/bin/agentd}"

DATA_DIR="${SOC_AGENT_DATA_DIR:-/var/lib/socagent}"
STATE_DIR="$DATA_DIR/state"
CONFIG="$DATA_DIR/agent.toml"
CA_PATH="${SOC_CA_CERT_PATH:-/certs/dev-ca.crt}"
SIM_EPS="${SOC_SIM_EPS:-5}"
SIM_SEED="${SOC_SIM_SEED:-0}"
SIM_SUSPICIOUS="${SOC_SIM_SUSPICIOUS:-true}"

fail() {
    echo "socagent entrypoint: ERROR: $*" >&2
    exit 1
}

[ -n "${SOC_GATEWAY_URL:-}" ] \
    || fail "SOC_GATEWAY_URL is required (e.g. https://gateway:8443)"
case "$SOC_GATEWAY_URL" in
    https://*) ;;
    *) fail "SOC_GATEWAY_URL must be https:// (got: $SOC_GATEWAY_URL); \
release agentd builds refuse plaintext (AC-69)" ;;
esac

[ -r "$CA_PATH" ] \
    || fail "CA bundle not readable at $CA_PATH — mount the compose dev CA \
(e.g. -v ./certs/dev-ca.crt:/certs/dev-ca.crt:ro) or set SOC_CA_CERT_PATH"

[ -w "$DATA_DIR" ] || fail "$DATA_DIR is not writable by uid $(id -u) — \
use a named volume, or chown the bind mount to 10001:10001"

# Enrollment: only needed until a device identity exists in the volume.
if [ ! -f "$STATE_DIR/identity.json" ]; then
    [ -n "${SOC_ENROLL_TOKEN:-}" ] || fail "device is not enrolled and \
SOC_ENROLL_TOKEN is not set — create a token in the console \
(POST /v1/enrollment-tokens) and pass it as SOC_ENROLL_TOKEN"
    export SOC_AGENT_ENROLLMENT_TOKEN="$SOC_ENROLL_TOKEN"
else
    # Already enrolled: ignore any (possibly stale) token.
    unset SOC_AGENT_ENROLLMENT_TOKEN 2>/dev/null || true
fi

case "$SIM_EPS" in *[!0-9]*|'') fail "SOC_SIM_EPS must be an integer" ;; esac
case "$SIM_SEED" in *[!0-9]*|'') fail "SOC_SIM_SEED must be an integer" ;; esac
case "$SIM_SUSPICIOUS" in
    true|false) ;;
    *) fail "SOC_SIM_SUSPICIOUS must be 'true' or 'false'" ;;
esac

# Escape sed replacement metacharacters (&, \, and the | delimiter).
sed_escape() {
    printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

sed \
    -e "s|@SERVER_URL@|$(sed_escape "$SOC_GATEWAY_URL")|g" \
    -e "s|@STATE_DIR@|$(sed_escape "$STATE_DIR")|g" \
    -e "s|@CA_PATH@|$(sed_escape "$CA_PATH")|g" \
    -e "s|@SIM_EPS@|$SIM_EPS|g" \
    -e "s|@SIM_SEED@|$SIM_SEED|g" \
    -e "s|@SIM_SUSPICIOUS@|$SIM_SUSPICIOUS|g" \
    "$TEMPLATE" > "$CONFIG"

echo "socagent entrypoint: gateway=$SOC_GATEWAY_URL ca=$CA_PATH" \
     "state=$STATE_DIR sim(eps=$SIM_EPS seed=$SIM_SEED" \
     "suspicious=$SIM_SUSPICIOUS)"

exec "$AGENTD_BIN" "$CONFIG"
