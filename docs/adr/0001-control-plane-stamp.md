# ADR-0001: Control plane / data plane split with single deployable stamp

- **Status:** Accepted
- **Date:** 2026-07-07
- **Deciders:** Architect Agent + solution-architect, cloud-platform, security-architect

## Context

The business model is self-serve SME SaaS priced per endpoint, with a
premium dedicated single-tenant option. We must support (a) thousands of
small shared tenants provisioned in seconds with zero human touch, and
(b) isolated single-tenant environments for compliance-sensitive
customers — without forking the codebase.

## Decision

Split the system into a global **control plane** (signup/onboarding,
asset inventory & metering, billing & entitlements, tenant provisioner)
and tenant-serving **data planes**. The entire tenant-serving platform
(ingestion, detection, AI, application, data stores) is packaged as one
deployable **stamp** (Helm chart + Terraform module). The shared SaaS
pool is one large stamp with row-level security (PostgreSQL) and
per-tenant index patterns (Elasticsearch); a dedicated customer is the
same stamp provisioned into its own namespace or cluster by the control
plane.

## Alternatives Considered

- **Separate codebase for dedicated:** rejected — permanent double
  maintenance, drift, and slower releases.
- **Database-per-tenant in the shared pool:** rejected for launch —
  operational overhead at SME scale (thousands of small tenants);
  row-level security + index patterns are sufficient and cheaper.
  Revisit if a mid-market segment emerges.
- **Dedicated-only (no shared pool):** rejected — per-tenant infra cost
  makes self-serve SME pricing impossible.

## Consequences

- Provisioning is fully automated for both shapes; time-to-tenant is a
  measurable SLO.
- All services must be tenancy-mode agnostic: tenant context comes from
  the request/entitlement layer, never from deployment assumptions.
- Entitlements (endpoint caps, retention, response automation, AI depth)
  are enforced in the backend against the billing service.
- CI/CD must test the stamp in both shapes before release.

## Security Considerations

Tenant isolation enforced at the data layer (RLS, index patterns) in the
shared pool; network isolation (namespaces, NetworkPolicies) added for
dedicated stamps. Control plane ↔ data plane communication is mutually
authenticated; the control plane never holds tenant security event data.
Final review by security-architect required before implementation.
