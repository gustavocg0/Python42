"""Fixture-driven conformance: every rules/tests/cases/<rule-id>.json case
must hold against the REAL compiled engine (FORMAT.md §7 — the QA automation
contract; any failure blocks publish).

CI invocation (also used by qa):
    uv run pytest services/dataplane/tests/detector/test_fixture_conformance.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dataplane.rulepub.packio import load_pack

REPO_ROOT = Path(__file__).resolve().parents[4]
RULES_DIR = REPO_ROOT / "rules"

_VALIDATION = load_pack(RULES_DIR / "pack.yaml", run_fixtures=False)

_CASES: list[pytest.param] = []
for _pack_rule in _VALIDATION.rules:
    _fixture = json.loads(
        (RULES_DIR / "tests" / "cases" / f"{_pack_rule.compiled.rule_id}.json").read_text(
            encoding="utf-8"
        )
    )
    for _section, _expected in (("must_match", True), ("must_not_match", False)):
        for _case in _fixture[_section]:
            _CASES.append(
                pytest.param(
                    _pack_rule.compiled,
                    _case["event"],
                    _expected,
                    id=f"{_pack_rule.compiled.rule_id}::{_section}::{_case['name']}",
                )
            )


def test_pack_validates_cleanly() -> None:
    """SEC-27 gate: the checked-in pack must be publishable as-is."""
    assert _VALIDATION.ok, "\n".join(_VALIDATION.errors)
    assert len(_VALIDATION.rules) == 25


def test_fixture_case_count() -> None:
    """The authoring phase shipped 81 assertions; all must run here."""
    assert len(_CASES) == 81


@pytest.mark.parametrize(("compiled", "event", "expected"), _CASES)
def test_fixture_case(compiled, event, expected) -> None:
    assert compiled.evaluate(event) is expected, (
        f"rule {compiled.rule_id} v{compiled.version}: expected "
        f"{'MATCH' if expected else 'NO MATCH'}"
    )
