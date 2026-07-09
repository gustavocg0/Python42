# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Next.js console (web/) — production standalone build.
# Build context: repository root.
#
# NEXT_PUBLIC_* values are inlined into the client bundle AT BUILD TIME
# (Next.js contract), so the API origins are build args, wired from
# compose.yaml / .env. Rebuild the image to change them.
# ---------------------------------------------------------------------------

ARG NODE_IMAGE=node:22-alpine@sha256:b74031e546d7f4faf561d797ac1b76beccac856a042815ca77db4fd047581605

# ---------------------------------------------------------------------- deps
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY web/package.json web/package-lock.json ./
# npm ci: exact lockfile install (supply chain).
RUN npm ci --no-audit --no-fund

# --------------------------------------------------------------------- build
FROM ${NODE_IMAGE} AS build
WORKDIR /app
ARG NEXT_PUBLIC_CONTROLPLANE_URL=http://localhost:8081
ARG NEXT_PUBLIC_DATAPLANE_URL=http://localhost:8082
ENV NEXT_PUBLIC_CONTROLPLANE_URL=${NEXT_PUBLIC_CONTROLPLANE_URL} \
    NEXT_PUBLIC_DATAPLANE_URL=${NEXT_PUBLIC_DATAPLANE_URL} \
    NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY web/ ./
RUN npm run build

# ------------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Runtime env for src/middleware.ts (CSP connect-src); same values as the
# build args by default — compose passes them explicitly.
ENV NEXT_PUBLIC_CONTROLPLANE_URL=http://localhost:8081 \
    NEXT_PUBLIC_DATAPLANE_URL=http://localhost:8082

# output: "standalone" (web/next.config.ts) produces a self-contained server.
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static

USER node
EXPOSE 3000
CMD ["node", "server.js"]
