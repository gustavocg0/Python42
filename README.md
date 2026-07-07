# Multi-Agent Engineering Organization

A Claude Code workspace configured as an autonomous software engineering
organization for building a SOC/security platform.

## How it works

- **`CLAUDE.md`** — the Architect Agent: coordination rules, delegation
  workflow, feature lifecycle, and definition of done. Claude Code loads
  this automatically in every session.
- **`.claude/agents/`** — 19 specialized subagents (one markdown file
  each), including a CEO agent that closes every feature lifecycle with a
  market-researched executive review, a compliance agent that maps
  NIS2/DORA/GDPR obligations and gates merges with a compliance review,
  and a business-planner that maintains the compliance-driven business
  plan in `docs/business/`. The main session delegates to them
  automatically based on their `description` fields, or you can invoke
  them explicitly.
- **`docs/adr/`** — Architecture Decision Records (template included).
- **`docs/prd/`** — Product Requirements Documents.

## Usage

1. Open this directory in Claude Code (`claude` from the repo root).
2. Request a feature, e.g.:

   > Build alert triage: ingest alerts, enrich with threat intel, and
   > present a prioritized queue. Follow the feature lifecycle.

3. The Architect will run the lifecycle: PM requirements → design →
   threat model → parallel implementation → QA → docs → final security
   review → integration.

Explicit invocation also works:

   > Have the security-architect subagent threat-model the ingestion API.
   > Use the qa subagent to write tests for the enrichment pipeline.

## Notes

- Agent files are loaded at session start — restart the session after
  adding or editing agents (or manage them with `/agents`).
- Read-only-ish agents (PM, architects, UX, security) intentionally lack
  Edit/Bash so reviews and specs can't accidentally modify code.
- Tune each agent's `tools:` and add `model:` frontmatter if you want
  per-agent model routing.
