#!/usr/bin/env bash
# End-to-end POC smoke test (run after scripts/poc-up.sh):
#
#   1. signup a fresh tenant           (controlplane, SEC-5 challenge-aware)
#   2. fetch the verification link     (mailpit API — dev mailbox)
#   3. verify + wait for provisioning  (AC-2/3 saga)
#   4. login                           (session cookie + CSRF double-submit)
#   5. create an enrollment token      (written to .env for --profile demo agent-sim)
#   6. create an ingest key            (AC-29)
#   7. POST a synthetic event batch    (payload reused from the detection
#      rule fixture rules/tests/cases/proc-powershell-encoded-command.json)
#   8. poll GET /v1/alerts until the detection fires (ingest->normalize->
#      detect->alert pipeline, AC-37)
#   9. check AI triage completes       (TRIAGE_FAKE keyless mode; non-fatal)
#
# Prints PASS/FAIL per step; exits non-zero on the first hard failure.
# Requires: bash, curl, python (3.x) on PATH. No jq needed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- config -------------------------------------------------------------------
if [ -f .env ]; then
    # shellcheck disable=SC1091
    set -a; . ./.env; set +a
fi
CP_BASE="http://localhost:${CP_HTTP_PORT:-8081}"
DP_BASE="http://localhost:${DP_HTTP_PORT:-8082}"
MAILPIT_BASE="http://localhost:${MAILPIT_UI_PORT:-8025}"
CHALLENGE_TOKEN="${CP_CHALLENGE_STUB_TOKEN:-}"

RUN_ID="$(date +%s)$RANDOM"
EMAIL="admin@poc-${RUN_ID}.example"
PASSWORD="Poc-Smoke-Passw0rd-${RUN_ID}"
ORG="POC Smoke ${RUN_ID}"
FIXTURE="rules/tests/cases/proc-powershell-encoded-command.json"

TMP_DIR="$(mktemp -d)"
JAR="$TMP_DIR/cookies.txt"
trap 'rm -rf "$TMP_DIR"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3
command -v "$PY" >/dev/null 2>&1 || { echo "FAIL python not found on PATH" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "FAIL curl not found on PATH" >&2; exit 1; }

# --- helpers --------------------------------------------------------------------
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; [ -n "${2:-}" ] && printf '      %s\n' "$2" >&2; exit 1; }

# http <curl args...> — sets globals RESP (body) and HTTP_CODE (status).
# Deliberately NOT called in a command substitution (subshells would drop the
# globals).
RESP=""
HTTP_CODE=""
http() {
    local out
    if ! out="$(curl -sS -w $'\n%{http_code}' "$@" 2>>"$TMP_DIR/curl.err")"; then
        RESP=""; HTTP_CODE="000"
        return 0
    fi
    HTTP_CODE="${out##*$'\n'}"
    RESP="${out%$'\n'*}"
}

# jget <dotted.path> — read JSON on stdin, print value ('' if absent).
jget() {
    "$PY" -c '
import json, sys
try:
    cur = json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
for part in sys.argv[1].split("."):
    if not part:
        continue
    try:
        cur = cur[int(part)] if isinstance(cur, list) else cur.get(part)
    except Exception:
        cur = None
    if cur is None:
        break
if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
' "$1"
}

rget() { printf '%s' "$RESP" | jget "$1"; }

# ================================================================ 1. signup
signup_body="$("$PY" -c '
import json, sys
print(json.dumps({"org_name": sys.argv[1], "email": sys.argv[2], "password": sys.argv[3]}))
' "$ORG" "$EMAIL" "$PASSWORD")"

http -X POST "$CP_BASE/v1/signup" -H 'Content-Type: application/json' -d "$signup_body"
if [ "$HTTP_CODE" = "400" ] && [ "$(rget error.code)" = "SIGNUP_CHALLENGE_REQUIRED" ]; then
    [ -n "$CHALLENGE_TOKEN" ] || fail "signup" "challenge required but CP_CHALLENGE_STUB_TOKEN is empty in .env"
    signup_body="$("$PY" -c '
import json, sys
print(json.dumps({"org_name": sys.argv[1], "email": sys.argv[2], "password": sys.argv[3],
                  "challenge_response": sys.argv[4]}))
' "$ORG" "$EMAIL" "$PASSWORD" "$CHALLENGE_TOKEN")"
    http -X POST "$CP_BASE/v1/signup" -H 'Content-Type: application/json' -d "$signup_body"
fi
[ "$HTTP_CODE" = "202" ] || fail "signup (POST /v1/signup)" "HTTP $HTTP_CODE: $RESP"
ACCOUNT_ID="$(rget account_id)"
[ -n "$ACCOUNT_ID" ] || fail "signup" "no account_id in response: $RESP"
pass "signup ($EMAIL -> $ACCOUNT_ID)"

# ============================================== 2. verification link (mailpit)
VERIFY_TOKEN=""
for _ in $(seq 1 30); do
    http --get "$MAILPIT_BASE/api/v1/search" --data-urlencode "query=to:$EMAIL"
    msg_id="$(rget messages.0.ID)"
    if [ -n "$msg_id" ]; then
        http "$MAILPIT_BASE/api/v1/message/$msg_id"
        VERIFY_TOKEN="$(rget Text | grep -o 'token=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)"
        [ -n "$VERIFY_TOKEN" ] && break
    fi
    sleep 2
done
[ -n "$VERIFY_TOKEN" ] || fail "verification email (mailpit $MAILPIT_BASE)" "no message with a token for $EMAIL"
pass "verification email received (mailpit)"

# ==================================================== 3. verify + provisioning
http -X POST "$CP_BASE/v1/signup/verify" -H 'Content-Type: application/json' \
    -d "{\"token\": \"$VERIFY_TOKEN\"}"
[ "$HTTP_CODE" = "200" ] || fail "verify (POST /v1/signup/verify)" "HTTP $HTTP_CODE: $RESP"
TENANT_ID="$(rget tenant_id)"
pass "email verified (tenant $TENANT_ID)"

state=""
for _ in $(seq 1 45); do
    http "$CP_BASE/v1/signup/provisioning-status?account_id=$ACCOUNT_ID"
    state="$(rget state)"
    [ "$state" = "ready" ] && break
    [ "$state" = "provisioning_failed" ] && fail "provisioning" "saga reported provisioning_failed"
    sleep 2
done
[ "$state" = "ready" ] || fail "provisioning" "state '$state' after 90s (AC-3 target: <=60s)"
pass "tenant provisioned (state=ready)"

# ==================================================================== 4. login
http -c "$JAR" -X POST "$CP_BASE/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}"
[ "$HTTP_CODE" = "200" ] || fail "login (POST /v1/auth/login)" "HTTP $HTTP_CODE: $RESP"
CSRF="$(awk '$(NF-1) == "csrf_token" { print $NF }' "$JAR" | tail -1)"
[ -n "$CSRF" ] || fail "login" "csrf_token cookie not found in the jar"
pass "login (session + CSRF token)"

# ====================================================== 5. enrollment token
http -b "$JAR" -X POST "$DP_BASE/v1/enrollment-tokens" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
    -d '{"name": "poc-smoke"}'
[ "$HTTP_CODE" = "201" ] || fail "enrollment token (POST /v1/enrollment-tokens)" "HTTP $HTTP_CODE: $RESP"
ENROLL_TOKEN="$(rget token)"
[ -n "$ENROLL_TOKEN" ] || fail "enrollment token" "no token in response: $RESP"
if [ -f .env ] && grep -q '^SOC_ENROLL_TOKEN=' .env; then
    sed -i.bak "s|^SOC_ENROLL_TOKEN=.*|SOC_ENROLL_TOKEN=$ENROLL_TOKEN|" .env && rm -f .env.bak
    pass "enrollment token created + written to .env (SOC_ENROLL_TOKEN — for: docker compose --profile demo up -d agent-sim)"
else
    pass "enrollment token created (no .env to update)"
fi

# ============================================================ 6. ingest key
http -b "$JAR" -X POST "$DP_BASE/v1/ingest-keys" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
    -d '{"name": "poc-smoke"}'
[ "$HTTP_CODE" = "201" ] || fail "ingest key (POST /v1/ingest-keys)" "HTTP $HTTP_CODE: $RESP"
INGEST_KEY="$(rget key)"
[ -n "$INGEST_KEY" ] || fail "ingest key" "no key in response: $RESP"
pass "ingest key created"

# ============================================== 7. synthetic event batch
# Reuse the detection-engineering fixture for proc-powershell-encoded-command
# (must_match case), dropping server-assigned fields (event-schema.md §5:
# clients MUST NOT send event_id/tenant_id/ingest_time/batch_id/source.*).
[ -f "$FIXTURE" ] || fail "ingest batch" "fixture not found: $FIXTURE"
batch="$("$PY" -c '
import json, sys
case = json.load(open(sys.argv[1], encoding="utf-8"))
ev = case["must_match"][0]["event"]
# Server-assigned/identity fields (event-schema.md §5) + source_type, which
# the platform derives from the authenticated ingest path (generic here).
for k in ("event_id", "tenant_id", "ingest_time", "batch_id", "source",
          "schema_version", "source_type"):
    ev.pop(k, None)
print(json.dumps({"events": [ev]}))
' "$FIXTURE")"

http -X POST "$DP_BASE/v1/ingest/events" \
    -H 'Content-Type: application/json' -H "X-Ingest-Key: $INGEST_KEY" \
    -d "$batch"
[ "$HTTP_CODE" = "202" ] || fail "ingest (POST /v1/ingest/events)" "HTTP $HTTP_CODE: $RESP"
[ "$(rget accepted)" = "1" ] || fail "ingest" "expected accepted=1, got: $RESP"
pass "event batch accepted (batch_id $(rget batch_id))"

# ============================================================ 8. alert fires
ALERT_ID=""
for _ in $(seq 1 60); do
    http -b "$JAR" "$DP_BASE/v1/alerts"
    ALERT_ID="$(rget items.0.id)"
    [ -n "$ALERT_ID" ] && break
    sleep 2
done
[ -n "$ALERT_ID" ] || fail "alert (GET /v1/alerts)" \
    "no alert after 120s — check: docker compose logs worker-normalizer worker-detector worker-alerter"
pass "alert fired ($ALERT_ID rule=$(rget items.0.rule.id) priority=$(rget items.0.priority_score))"

# ================================================= 9. triage (fake mode, soft)
triage_status=""
for _ in $(seq 1 20); do
    http -b "$JAR" "$DP_BASE/v1/alerts/$ALERT_ID"
    triage_status="$(rget triage.status)"
    [ "$triage_status" = "completed" ] && break
    sleep 3
done
if [ "$triage_status" = "completed" ]; then
    pass "AI triage completed (TRIAGE_FAKE keyless mode)"
else
    printf 'WARN  triage status is %s after 60s (alert queue never waits on triage — AC-50); check: docker compose logs worker-triager\n' "${triage_status:-unknown}"
fi

echo
echo "SMOKE: ALL STEPS PASSED"
echo "  Console:  http://localhost:${WEB_HTTP_PORT:-8080}  (login: $EMAIL)"
echo "  Demo agent: docker compose --profile demo up -d agent-sim"
