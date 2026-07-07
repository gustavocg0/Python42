# Business Model

Status: Draft v1 — decisions captured 2026-07-07

## Decisions

| Dimension | Decision |
|---|---|
| Primary buyer | SMEs directly, self-serve SaaS |
| Pricing metric | Per endpoint/asset monitored per month |
| Deployment | Multi-tenant SaaS + dedicated single-tenant (premium) |
| Acquisition | 14–30 day free trial (no permanent free tier) |
| Launch telemetry | Microsoft 365 / Google Workspace, endpoint agents (EDR-lite), firewall & network logs |
| Premium differentiators | Automated response, AI investigation depth, dedicated deployment |

## Tier Ladder (proposal)

| | Trial | Core | Pro | Dedicated |
|---|---|---|---|---|
| Duration/commit | 14–30 days | monthly/annual | monthly/annual | annual |
| Endpoint cap | ~100 | per plan | per plan | custom |
| Detection + alerting | full | yes | yes | yes |
| AI triage (fast model) | yes | yes | yes | yes |
| AI deep investigation | limited/day | limited/day | unlimited | unlimited |
| Response | recommendations only | recommendations only | automated playbooks w/ approval | automated + custom playbooks |
| Retention (hot) | 14 days | 30 days | 90 days | custom (1yr+) |
| Deployment | shared pool | shared pool | shared pool | dedicated stamp |
| SSO/SAML | — | — | yes | yes |

Trial runs at Pro feature level so prospects experience the differentiators;
caps (endpoints, deep-investigation runs/day, retention) control cost.

## Architectural Consequences (binding on all agents)

1. **Asset inventory is revenue-critical.** Endpoint counting must be
   accurate and deduplicated across sources (agent + M365 + network
   discovery = one billable asset). Disputes here are churn.
2. **Margin protection.** Revenue scales with endpoints; cost scales with
   data. Every tenant gets ingest fair-use quotas; hot Elasticsearch data
   ages to object storage; retention enforced by entitlement.
3. **Trial mechanics.** Trial tenants are real tenants (full provisioning
   day one — conversion must not require re-onboarding). Auto-expiry
   pipeline: freeze at T+0, purge data at T+30 unless converted. Abuse
   controls: signup verification, per-trial quotas.
4. **Entitlement enforcement is platform-level.** Feature gates (response
   automation, deep AI investigation, retention, endpoint caps) are
   checked in the backend against the billing service — never only in UI.
5. **AI cost metering.** Model routing by tier: fast/cheap model for
   universal triage; deep investigation agent gated and metered per
   tenant. LLM spend is tracked per tenant as a first-class metric.
6. **Response requires bidirectional connectors.** Premium response means
   the M365/Workspace, endpoint, and firewall integrations must support
   actions (disable user, isolate host, block IP), not just log pull.
   All automated actions: approval-by-default, fully audited, reversible
   where possible (security-architect review mandatory).
7. **One stamp, two shapes.** Dedicated tier = same Helm/Terraform stamp
   in an isolated namespace/cluster, provisioned by the control plane.
   No code fork.

## Open Questions

- ~~EDR-lite build vs. integrate~~ RESOLVED: build first-party agent (ADR-0002), phased; Defender kept as complementary connector.
- Price points per tier (requires market research; not set here).
- Partner/affiliate motion later (MSP resale was deferred, revisit at scale).
