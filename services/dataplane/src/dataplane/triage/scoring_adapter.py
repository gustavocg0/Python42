"""Adapter onto dataplane.scoring (owned by the workers agent).

Contract: docs/contracts/priority-score.md v1.1. Triage passes the RAW
ai_severity; the B-4/SEC-34 clamp (ai_severity_effective) is computed INSIDE
``dataplane.scoring.compute_priority`` and returned via
``PriorityScore.inputs["ai_severity_effective"]`` — the formula exists
exactly once, in that module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class PriorityResult:
    priority_score: int
    priority_inputs: dict[str, Any]

    @property
    def ai_severity_effective(self) -> str:
        try:
            return self.priority_inputs["ai_severity_effective"]
        except KeyError as exc:  # contract §3: inputs MUST include the clamped value
            raise RuntimeError(
                "scoring returned priority_inputs without 'ai_severity_effective' "
                "(required by priority-score.md §3)"
            ) from exc


class PriorityRecompute(Protocol):
    def __call__(
        self,
        *,
        rule_severity: str,
        ai_severity: str | None,
        occurrence_count: int,
        agent_status: str,
    ) -> PriorityResult: ...


def recompute_priority(
    *,
    rule_severity: str,
    ai_severity: str | None,
    occurrence_count: int,
    agent_status: str,
) -> PriorityResult:
    """Recompute the priority score via dataplane.scoring.compute_priority."""
    from dataplane.scoring import compute_priority

    result = compute_priority(
        rule_severity=rule_severity,
        ai_severity=ai_severity,
        occurrence_count=occurrence_count,
        agent_status=agent_status,
    )
    return PriorityResult(priority_score=result.score, priority_inputs=dict(result.inputs))
