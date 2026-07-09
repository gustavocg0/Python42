# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# One image for every Python process in the POC stack:
#   controlplane-api / controlplane-internal   (python -m controlplane.main / .internal_main)
#   dataplane-api / dataplane-internal         (uvicorn --factory dataplane.main:build_app / .internal_main)
#   workers: normalizer, detector, alerter, triager, asset_dedup
#   jobs runner (python -m dataplane.jobs)
#   rulepub one-shot (python -m dataplane.rulepub ...)
#   `migrate` stage: one-shot migration/bootstrap container (adds psql + curl)
#
# uv workspace install with --frozen lockfile (supply-chain: reproducible).
# Workspace members are installed editable against /app source, so package
# data files (e.g. services/dataplane/src/dataplane/triage/prompts/*.txt)
# ship with the image by construction.
#
# Build context: repository root.
# ---------------------------------------------------------------------------

# Digest pins are linux/amd64 manifests resolved 2026-07-09 (POC targets a
# single-arch local host; re-resolve for multi-arch).
ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:129f9f5d5729767916d79f0021ba4fe56ff113332b08ef1213ecf529a9da7ebb

FROM ghcr.io/astral-sh/uv:0.7.2@sha256:8c2534159d236ad1722f1e763a8fa4b49743e1cdf5ec4ca2b119459c6d69d3da AS uv-dist

# --------------------------------------------------------------------- build
FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv-dist /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app
# Whole workspace: root manifests + every member (packages/*, services/*, db).
COPY pyproject.toml uv.lock .python-version ./
COPY packages/ packages/
COPY services/controlplane/ services/controlplane/
COPY services/dataplane/ services/dataplane/
COPY db/ db/

# --frozen: uv.lock is authoritative; fails the build on any drift.
RUN uv sync --frozen --no-dev

# ------------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime

# Non-root runtime user (fixed UID referenced by ops/docker/dev-ca-bootstrap
# for dev-ca.key ownership — keep in sync).
RUN groupadd --gid 10001 soc \
    && useradd --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin soc

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
# Source + venv together: workspace members are editable installs whose .pth
# entries point at /app/... (same path in both stages).
COPY --from=builder /app /app
# Idempotency wrapper for the rulepub one-shot (compose service `rulepub`).
COPY --chmod=0755 ops/docker/rulepub/publish.sh /usr/local/bin/rulepub-publish.sh

USER 10001:10001
# No default CMD: compose sets the exact process per service.

# ------------------------------------------------------------------- migrate
# One-shot bootstrap container: waits for PG/ES, applies db/migrations via
# db/migrate.py, creates the per-deployment LOGIN roles (db/README.md),
# installs the ES index template, and applies db/seed_dev.sql (dev only).
FROM runtime AS migrate
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 ops/docker/migrate/entrypoint.sh /usr/local/bin/migrate-entrypoint.sh
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/migrate-entrypoint.sh"]
