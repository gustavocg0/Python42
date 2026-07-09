# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# ingest-gateway (design §2 / §5, SEC-14/15): nginx terminating
#   :8080  console (proxies web)              — plain HTTP, dev only
#   :8081  controlplane public API
#   :8082  dataplane public API (console + generic ingest)
#   :8443  agent mTLS listener (dev CA client verify) -> dataplane agent routes
#
# nginx-unprivileged: master runs as uid 101 (non-root). The alpine variant
# ships ngx_http_js_module.so (njs), used to map the verified client cert to
# X-Device-Id / X-Device-Tenant / X-Client-Cert-Serial (ADR-0006 SAN URI).
#
# Config is an envsubst template (stock docker-entrypoint behavior): only
# ${GATEWAY_AUTH_SECRET} is substituted at container start (SEC-40 item 1).
# Build context: repository root.
# ---------------------------------------------------------------------------

FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:8059701048a6cc7d64e8ab2812a44be70161bfa9ecfc01d69e95b8ff2a648705

USER root
# Stock default vhost also listens on 8080 — remove to avoid a conflict.
RUN rm -f /etc/nginx/conf.d/default.conf
USER 101

COPY ops/docker/gateway/nginx.conf /etc/nginx/nginx.conf
COPY ops/docker/gateway/njs/identity.js /etc/nginx/njs/identity.js
COPY ops/docker/gateway/templates/ /etc/nginx/templates/

EXPOSE 8080 8081 8082 8443
