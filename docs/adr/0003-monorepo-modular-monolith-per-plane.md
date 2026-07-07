# ADR-0003: Monorepo with one modular FastAPI application per plane

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** Architect Agent + solution-architect + security-architect; consulted: backend-architect, cloud-platform, devsecops
- **Threat model:** `docs/security/threat-model-platform-foundation-mvp.md` (ratified; SEC-30/40 bind the internal-API and route-authorization patterns)

## Context

ADR-0001 mandates a control-plane/data-plane split and a single deployable
stamp. The MVP (PRD `platform-foundation-mvp`) spans ~10 epics built by
parallel agents, must run locally via docker-compose (Postgres,
Elasticsearch, Redis), and must later scale out without a rewrite.
Fine-grained microservices would multiply contract surfaces, deploy
complexity, and compose footprint; a single app for everything would blur
the plane boundary ADR-0001 requires and invite entanglement.

## Decision

One monorepo (layout defined in `docs/design/platform-foundation-mvp.md` §1)
containing exactly **two modular FastAPI applications**:

1. `services/controlplane` — signup/verification/provisioning, entitlements
   & plan config, users/sessions/auth, trial lifecycle.
2. `services/dataplane` — ingest, enrollment/heartbeat, assets, alerts,
   rules, investigation, audit — plus **separate worker processes**
   (normalizer, detector, alerter, triager, jobs) importing the same
   dataplane codebase but running as their own containers.

Boundaries are enforced mechanically: import-linter forbids cross-plane
imports; planes communicate only via versioned internal HTTP APIs
(`/internal/v1/...`) authenticated per SEC-40 (mechanism recorded in the
design doc §5); shared code lives only in `packages/*`, which never
imports services. The pipeline transport is abstracted in
`packages/pipeline` (see ADR-0004) so workers can be extracted into
standalone services later without contract changes. `agent/`, `web/`,
`rules/`, `infra/` live in the same repo with their own toolchains.

## Alternatives Considered

- **Microservices per capability (8–10 services):** rejected for MVP —
  compose becomes unwieldy, every interface becomes a network contract to
  version, and parallel agents would spend the schedule on plumbing. The
  seams (modules + workers + transport abstraction) preserve the extraction
  path.
- **Single application for both planes:** rejected — violates ADR-0001's
  plane separation and its consequence that the control plane never holds
  tenant security event data; also blocks independently scaling ingest.
- **Polyrepo:** rejected — cross-cutting contract changes (event schema,
  API contracts) span agent, services, and web; atomic monorepo commits
  keep contracts and implementations in lockstep for a small team.

## Consequences

- Easier: local dev (12 compose services, 3 of them infra), atomic contract
  changes, shared pydantic models from `docs/contracts/`, one CI.
- Harder: discipline required — boundary enforcement must be in CI from day
  one (devsecops), or the monolith rots; worker crash isolates per process
  but a bad shared-library release affects all data-plane processes.
- Accepted risk: the two apps scale as units in MVP; per-module hotspots
  (ingest) are mitigated by running extra dataplane-api replicas behind the
  gateway and by worker horizontal scaling via Redis consumer groups.
- CI must build/test the stamp in both shapes (shared + dedicated) per
  ADR-0001; no module may read deployment shape (AC-82).

## Security Considerations

Reviewed by security-architect (initial threat model, 2026-07-08): plane
separation limits blast radius — control plane holds identities and
entitlements, never event data. Binding conditions: internal APIs are
network-restricted AND application-layer authenticated (SEC-40, scheme in
design §5); every route declares its required role, deny-by-default
(SEC-30); the RLS session-context pattern in `packages/tenancy` follows
threat model §4.1 (SEC-23). Final security review verifies these by
inspection.
