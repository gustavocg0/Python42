# Contract: Alert Priority Score v1 (deterministic, 0–100)

- **Status:** Ratified v1.1 — 2026-07-08 (amended per threat model **B-4/SEC-34**: AI-severity clamp)
- **Owner:** solution-architect, with ai-platform + detection-engineering; security-architect (SEC-34) (resolves PRD OQ-4; satisfies AC-48/50)
- **Consumers:** backend-architect (worker-alerter computes), ai-platform (worker-triager recomputes), frontend-architect (display), qa (test vectors below)

## 1. Inputs

| Input | Source | Values |
|---|---|---|
| `rule_severity` | firing rule (E5) | `low` \| `medium` \| `high` \| `critical` |
| `ai_severity` | AI triage (E7); may be absent | same enum, or absent (`triage.status != completed`) |
| `occurrence_count` | alert dedup counter (AC-42) | int ≥ 1 |
| `agent_status` | affected asset's agent status at computation time | `healthy` \| `enrolled` \| `offline` \| `revoked` \| `none` |

Asset criticality is explicitly OUT for MVP (no criticality field exists yet); the formula reserves headroom via the caps below so criticality can be added in v2 without renormalizing.

## 2. Formula (integer arithmetic, round-half-up)

Severity tiers `T(x)`: `low=0, medium=1, high=2, critical=3`.
Severity points `S(x)`: `low=30, medium=55, high=80, critical=100`.

```
S_rule = S(rule_severity)

# --- B-4 / SEC-34 clamp: AI output may raise, but may lower by at most ONE tier ---
if triage completed:
    ai_tier_eff = max( T(ai_severity), T(rule_severity) - 1 )
    S_ai        = S( severity_at(ai_tier_eff) )
else:
    S_ai        = S_rule                                    # AC-50 fallback

severity_component  = round_half_up( 0.85 * (S_rule + S_ai) / 2 )   # range 26..85

occurrence_component:  count == 1       -> 0
                       2  <= count < 5  -> 4
                       5  <= count < 20 -> 7
                       count >= 20      -> 10

asset_component:       offline | revoked  -> 5    # can't respond/verify; possible tamper
                       none               -> 2    # log-only visibility, no host confirmation
                       healthy | enrolled -> 0

priority_score = min(100, severity_component + occurrence_component + asset_component)
```

`round_half_up(x)` = `floor(x + 0.5)` on the decimal value (i.e., 25.5 → 26). Implementations MUST NOT use banker's rounding.

**Clamp rationale (SEC-34):** triage prompts contain attacker-writable event content (threat model TB-6). Without the clamp, a prompt-injected `ai_severity=low` on a critical rule drops the score 85→61, burying the alert. With the clamp, effective AI severity for *scoring* is at most one tier below rule severity (critical rule ⇒ effective ≥ high), bounding injection damage to ≤11 points. Upward AI influence is intentionally unclamped (inflating surfaces an alert; it cannot bury one). **Display is unchanged:** the raw `ai_severity` is stored on `alert.triage.ai_severity` and shown alongside rule severity per AC-49 — only the score computation uses the clamped value.

## 3. Recompute triggers & ordering

- Computed at alert creation (triage absent ⇒ `S_ai = S_rule`).
- Recomputed when: (a) triage completes (any attempt), (b) `occurrence_count` crosses a tier boundary (2, 5, 20), (c) alert is reopened.
- `agent_status` is read fresh at each (re)computation; it is NOT recomputed on unrelated heartbeat changes (bounded write amplification).
- Queue ordering (AC-44/72): `priority_score DESC, last_seen DESC, id ASC` (deterministic tie-break).
- Score is stored on the alert with `priority_inputs` (the four raw inputs used **plus** the post-clamp effective AI severity), so QA and UI can verify determinism and clamp application.

## 4. Test vectors (QA: exact-match assertions)

`ai_eff` = effective AI severity after the B-4 clamp.

| # | rule_sev | ai_sev | ai_eff | count | agent_status | sev_comp | occ | asset | **score** | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | low | (absent) | =rule | 1 | healthy | round(.85·30)=26 | 0 | 0 | **26** | |
| 2 | medium | (absent) | =rule | 1 | none | round(.85·55)=47 | 0 | 2 | **49** | |
| 3 | medium | high | high | 3 | healthy | round(.85·67.5)=57 | 4 | 0 | **61** | AI raise, no clamp |
| 4 | high | medium | medium | 1 | healthy | round(.85·67.5)=57 | 0 | 0 | **57** | exactly one tier down — allowed |
| 5 | high | high | high | 7 | offline | round(.85·80)=68 | 7 | 5 | **80** | |
| 6 | critical | (absent) | =rule | 1 | healthy | round(.85·100)=85 | 0 | 0 | **85** | |
| 7 | critical | critical | critical | 25 | offline | 85 | 10 | 5 | **100** | |
| 8 | critical | low | **high (clamped)** | 2 | none | round(.85·(100+80)/2)=round(76.5)=77 | 4 | 2 | **83** | **CLAMP: injection cannot bury a critical alert** (unclamped would be 61) |
| 9 | low | critical | critical | 20 | revoked | round(.85·65)=55 | 10 | 5 | **70** | upward unclamped |
| 10 | medium | medium | medium | 5 | enrolled | 47 | 7 | 0 | **54** | |
| 11 | high | low | **medium (clamped)** | 1 | healthy | round(.85·(80+55)/2)=round(57.375)=57 | 0 | 0 | **57** | **CLAMP-specific vector** (unclamped would be 47) |
| 12 | medium | low | low | 1 | healthy | round(.85·(55+30)/2)=round(36.125)=36 | 0 | 0 | **36** | one tier down — clamp is a no-op |

## 5. Properties (QA property tests)

1. Monotonic: raising any single input tier never lowers the score (clamp preserves monotonicity).
2. Bounded: 26 ≤ score ≤ 100 for any valid input.
3. **Clamp bound (SEC-34):** for any AI output, `severity_component ≥ round_half_up(0.85 · (S_rule + S(tier(S_rule)−1)) / 2)` — concretely, a critical-rule alert always has sev_comp ≥ 77, high ≥ 57, medium ≥ 36; AI output can lower the total score by at most 11 points and can never move a critical-rule alert below a one-tier-degraded high-rule alert.
4. Deterministic: same inputs ⇒ same score, no randomness, no wall-clock dependence.

## 6. Versioning

This is `priority_formula_version: 1`, stored on each alert (the B-4 clamp is part of v1; no unclamped version ever ships). Changing weights/tiers/clamp requires a new version + updated test vectors here; old alerts keep their computed score (no retroactive rescoring in MVP).
