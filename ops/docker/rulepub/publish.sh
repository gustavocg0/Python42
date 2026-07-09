#!/usr/bin/env bash
# One-shot rule-pack publish for the POC stack (SEC-27: validate + publish is
# an authenticated, audited content operation — no code deploy).
#
# Idempotency wrapper: `python -m dataplane.rulepub publish` intentionally
# rejects re-publishing an already-published pack_version. On compose re-up
# that exact rejection means "content already live" and must gate SUCCESS,
# not failure. Any other error stays fatal.
set -uo pipefail

PACK_PATH="${PACK_PATH:-/app/rules/pack.yaml}"
PUBLISHED_BY="${PUBLISHED_BY:-poc-compose}"

out=$(python -m dataplane.rulepub publish "$PACK_PATH" --published-by "$PUBLISHED_BY" 2>&1)
status=$?
echo "$out"

if [ $status -eq 0 ]; then
    exit 0
fi
if echo "$out" | grep -q "already published"; then
    echo "rulepub: pack version already published — treating as success (idempotent re-up)."
    exit 0
fi
exit "$status"
