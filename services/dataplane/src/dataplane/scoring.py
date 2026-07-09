"""Alert Priority Score v1 — exact implementation of docs/contracts/priority-score.md.

Consumers:
- worker-alerter (this service) computes the score at alert creation and on
  occurrence-tier crossings (2, 5, 20);
- worker-triager (ai-platform) recomputes when triage completes — it imports
  THIS module so the formula exists exactly once;
- qa verifies against the contract's test vectors (§4) and properties (§5).

Pure functions only: no I/O, no wall clock, no randomness (contract §5.4).
Integer arithmetic with round-half-up (never banker's rounding, contract §2).

The B-4/SEC-34 clamp is part of formula v1: for SCORING, the effective AI
severity is at most one tier below the rule severity (prompt injection cannot
bury an alert); upward AI influence is unclamped. Display uses the raw
``ai_severity`` — only scoring uses the clamped value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

PRIORITY_FORMULA_VERSION: Final[int] = 1
"""Stored on every alert inside priority_inputs (contract §6)."""

SEVERITIES: Final[tuple[str, ...]] = ("low", "medium", "high", "critical")

_TIER: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_POINTS: Final[dict[str, int]] = {"low": 30, "medium": 55, "high": 80, "critical": 100}

AGENT_STATUSES: Final[frozenset[str]] = frozenset(
    {"healthy", "enrolled", "offline", "revoked", "none"}
)


def severity_tier(severity: str) -> int:
    """T(x): low=0, medium=1, high=2, critical=3 (contract §2)."""
    try:
        return _TIER[severity]
    except KeyError:
        raise ValueError(f"invalid severity {severity!r}; expected one of {SEVERITIES}") from None


def severity_points(severity: str) -> int:
    """S(x): low=30, medium=55, high=80, critical=100 (contract §2)."""
    severity_tier(severity)  # validate
    return _POINTS[severity]


def effective_ai_severity(rule_severity: str, ai_severity: str) -> str:
    """B-4/SEC-34 clamp: AI may raise freely, may lower by at most ONE tier.

    ai_tier_eff = max(T(ai_severity), T(rule_severity) - 1)
    """
    ai_tier = severity_tier(ai_severity)
    rule_tier = severity_tier(rule_severity)
    return SEVERITIES[max(ai_tier, rule_tier - 1)]


def _severity_component(s_rule: int, s_ai: int) -> int:
    """round_half_up(0.85 * (S_rule + S_ai) / 2) in exact integer arithmetic.

    floor(85*(S_rule+S_ai)/200 + 1/2) == (2*85*(S_rule+S_ai) + 200) // 400 —
    no floats, so no binary-representation rounding surprises (contract §2:
    25.5 -> 26, never banker's rounding).
    """
    return (170 * (s_rule + s_ai) + 200) // 400


def occurrence_component(occurrence_count: int) -> int:
    """Occurrence tiers (contract §2)."""
    if occurrence_count < 1:
        raise ValueError("occurrence_count must be >= 1")
    if occurrence_count == 1:
        return 0
    if occurrence_count < 5:
        return 4
    if occurrence_count < 20:
        return 7
    return 10


def asset_component(agent_status: str) -> int:
    """Asset/agent contribution (contract §2)."""
    if agent_status not in AGENT_STATUSES:
        raise ValueError(
            f"invalid agent_status {agent_status!r}; expected one of {sorted(AGENT_STATUSES)}"
        )
    if agent_status in ("offline", "revoked"):
        return 5
    if agent_status == "none":
        return 2
    return 0  # healthy | enrolled


@dataclass(frozen=True, slots=True)
class PriorityScore:
    """Score plus the raw + derived inputs (contract §3: stored on the alert
    as ``priority_inputs`` so QA/UI can verify determinism and the clamp)."""

    score: int
    severity_component: int
    occurrence_component: int
    asset_component: int
    rule_severity: str
    ai_severity: str | None
    ai_severity_effective: str | None
    occurrence_count: int
    agent_status: str

    @property
    def inputs(self) -> dict[str, Any]:
        """JSON-serializable ``priority_inputs`` payload for the alerts row."""
        return {
            "priority_formula_version": PRIORITY_FORMULA_VERSION,
            "rule_severity": self.rule_severity,
            "ai_severity": self.ai_severity,
            "ai_severity_effective": self.ai_severity_effective,
            "occurrence_count": self.occurrence_count,
            "agent_status": self.agent_status,
            "severity_component": self.severity_component,
            "occurrence_component": self.occurrence_component,
            "asset_component": self.asset_component,
        }


def compute_priority(
    *,
    rule_severity: str,
    ai_severity: str | None = None,
    occurrence_count: int = 1,
    agent_status: str = "none",
) -> PriorityScore:
    """Compute the v1 priority score (contract §2).

    Pass ``ai_severity`` ONLY when triage status is ``completed`` (contract §1:
    absent otherwise). ``ai_severity=None`` is the AC-50 fallback path
    (S_ai = S_rule). ``agent_status`` must be read fresh at each
    (re)computation by the caller (contract §3).
    """
    s_rule = severity_points(rule_severity)
    if ai_severity is not None:
        ai_eff: str | None = effective_ai_severity(rule_severity, ai_severity)
        s_ai = severity_points(ai_eff)  # type: ignore[arg-type]
    else:
        ai_eff = None
        s_ai = s_rule

    sev = _severity_component(s_rule, s_ai)
    occ = occurrence_component(occurrence_count)
    asset = asset_component(agent_status)
    return PriorityScore(
        score=min(100, sev + occ + asset),
        severity_component=sev,
        occurrence_component=occ,
        asset_component=asset,
        rule_severity=rule_severity,
        ai_severity=ai_severity,
        ai_severity_effective=ai_eff,
        occurrence_count=occurrence_count,
        agent_status=agent_status,
    )
