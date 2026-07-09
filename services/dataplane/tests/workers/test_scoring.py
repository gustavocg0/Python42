"""dataplane.scoring vs docs/contracts/priority-score.md (§4 vectors, §5 properties)."""

from __future__ import annotations

import itertools

import pytest

from dataplane.scoring import (
    PRIORITY_FORMULA_VERSION,
    SEVERITIES,
    compute_priority,
    effective_ai_severity,
    occurrence_component,
)

# Contract §4 test vectors — exact-match assertions.
# (rule_sev, ai_sev, expected_ai_eff, count, agent_status, expected_score)
VECTORS = [
    ("low", None, None, 1, "healthy", 26),        # 1
    ("medium", None, None, 1, "none", 49),        # 2
    ("medium", "high", "high", 3, "healthy", 61),  # 3  AI raise, no clamp
    ("high", "medium", "medium", 1, "healthy", 57),  # 4  one tier down — allowed
    ("high", "high", "high", 7, "offline", 80),   # 5
    ("critical", None, None, 1, "healthy", 85),   # 6
    ("critical", "critical", "critical", 25, "offline", 100),  # 7
    ("critical", "low", "high", 2, "none", 83),   # 8  CLAMP: cannot bury critical
    ("low", "critical", "critical", 20, "revoked", 70),  # 9  upward unclamped
    ("medium", "medium", "medium", 5, "enrolled", 54),  # 10
    ("high", "low", "medium", 1, "healthy", 57),  # 11 CLAMP-specific vector
    ("medium", "low", "low", 1, "healthy", 36),   # 12 clamp is a no-op
]


@pytest.mark.parametrize(
    ("rule_sev", "ai_sev", "ai_eff", "count", "agent_status", "expected"),
    VECTORS,
    ids=[f"vector-{i}" for i in range(1, len(VECTORS) + 1)],
)
def test_contract_vectors(rule_sev, ai_sev, ai_eff, count, agent_status, expected):
    result = compute_priority(
        rule_severity=rule_sev,
        ai_severity=ai_sev,
        occurrence_count=count,
        agent_status=agent_status,
    )
    assert result.score == expected
    assert result.ai_severity_effective == ai_eff
    assert result.inputs["priority_formula_version"] == PRIORITY_FORMULA_VERSION
    assert result.inputs["ai_severity"] == ai_sev
    assert result.inputs["ai_severity_effective"] == ai_eff
    assert result.inputs["agent_status"] == agent_status


def test_bounded_property():
    """Contract §5.2: 26 <= score <= 100 for any valid input combination."""
    counts = (1, 2, 4, 5, 19, 20, 1000)
    statuses = ("healthy", "enrolled", "offline", "revoked", "none")
    for rule, ai, count, status in itertools.product(
        SEVERITIES, (*SEVERITIES, None), counts, statuses
    ):
        score = compute_priority(
            rule_severity=rule, ai_severity=ai, occurrence_count=count, agent_status=status
        ).score
        assert 26 <= score <= 100, (rule, ai, count, status, score)


def test_clamp_bound_property():
    """Contract §5.3: sev_comp floors — critical >= 77, high >= 57, medium >= 36;
    AI can lower the total by at most 11 points."""
    floors = {"critical": 77, "high": 57, "medium": 36, "low": 26}
    for rule, ai in itertools.product(SEVERITIES, SEVERITIES):
        result = compute_priority(rule_severity=rule, ai_severity=ai)
        assert result.severity_component >= floors[rule], (rule, ai, result)
        baseline = compute_priority(rule_severity=rule).score
        assert baseline - result.score <= 11, (rule, ai)


def test_monotonic_in_occurrence_and_ai():
    """Contract §5.1: raising any single input tier never lowers the score."""
    for rule in SEVERITIES:
        prev = -1
        for count in (1, 2, 5, 20):
            score = compute_priority(rule_severity=rule, occurrence_count=count).score
            assert score >= prev
            prev = score
        prev = -1
        for ai in SEVERITIES:
            score = compute_priority(rule_severity=rule, ai_severity=ai).score
            assert score >= prev
            prev = score


def test_deterministic():
    a = compute_priority(
        rule_severity="high", ai_severity="low", occurrence_count=7, agent_status="offline"
    )
    b = compute_priority(
        rule_severity="high", ai_severity="low", occurrence_count=7, agent_status="offline"
    )
    assert a == b
    assert a.inputs == b.inputs


def test_clamp_helper_and_validation():
    assert effective_ai_severity("critical", "low") == "high"
    assert effective_ai_severity("low", "critical") == "critical"
    assert effective_ai_severity("medium", "low") == "low"
    with pytest.raises(ValueError):
        compute_priority(rule_severity="urgent")
    with pytest.raises(ValueError):
        compute_priority(rule_severity="high", agent_status="unknown")
    with pytest.raises(ValueError):
        occurrence_component(0)
