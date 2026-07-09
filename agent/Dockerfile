# syntax=docker/dockerfile:1.7
# soc-agent — endpoint agent container image (simulated provider; POC/demo).
#
# Build context is the agent/ workspace root:
#   docker build -t soc-agent -f agent/Dockerfile agent/
#
# Runtime contract (see packaging/docker/entrypoint.sh):
#   SOC_GATEWAY_URL, SOC_ENROLL_TOKEN, SOC_CA_CERT_PATH (/certs/dev-ca.crt),
#   persistent volume at /var/lib/socagent (device identity + disk buffer).
#
# Digests resolved from Docker Hub 2026-07-09 (multi-arch index digests).

# ---------------------------------------------------------------- build stage
FROM rust:1.87.0-slim-bookworm@sha256:437507c3e719e4f968033b88d851ffa9f5aceeb2dcc2482cc6cb7647811a55eb AS build

WORKDIR /src

# Workspace sources (target/ etc. excluded via .dockerignore).
COPY Cargo.toml Cargo.lock ./
COPY collector-core ./collector-core
COPY providers ./providers
COPY agentd ./agentd

# Release build: https-only (no insecure-skip-verify path, AC-69), small
# stripped binary (workspace [profile.release]). --locked enforces Cargo.lock
# (supply chain). Cache mounts keep registry + target out of image layers;
# the binary is copied out of the cached target dir within the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p agentd \
    && cp /src/target/release/agentd /agentd

# -------------------------------------------------------------- runtime stage
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

# Non-root service account. /var/lib/socagent is created owned by it so a
# fresh named volume inherits the ownership on first mount.
# uid 10002 deliberately differs from the platform runtime uid 10001: the
# compose demo mounts the shared dev-ca volume (whose dev-ca.key is 0600
# uid 10001) at /certs, and the agent must not be able to read the CA key.
RUN groupadd --system --gid 10002 socagent \
    && useradd --system --uid 10002 --gid socagent \
       --home-dir /var/lib/socagent --shell /usr/sbin/nologin socagent \
    && mkdir -p /var/lib/socagent \
    && chown socagent:socagent /var/lib/socagent \
    && chmod 0700 /var/lib/socagent

# TLS trust: agentd uses rustls with compiled-in webpki roots plus the
# explicitly mounted dev/private CA — no system ca-certificates needed.
COPY --from=build /agentd /usr/local/bin/agentd
COPY --chmod=0755 packaging/docker/entrypoint.sh /usr/local/bin/socagent-entrypoint
COPY packaging/docker/agent.toml.tmpl /usr/local/share/socagent/agent.toml.tmpl

USER socagent:socagent
VOLUME ["/var/lib/socagent"]

# Defaults per the compose contract; SOC_GATEWAY_URL/SOC_ENROLL_TOKEN are
# injected by compose. Simulated provider knobs: SOC_SIM_EPS, SOC_SIM_SEED,
# SOC_SIM_SUSPICIOUS (see entrypoint.sh).
ENV SOC_CA_CERT_PATH=/certs/dev-ca.crt

ENTRYPOINT ["/usr/local/bin/socagent-entrypoint"]
