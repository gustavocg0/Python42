"""Shared fixtures for detector + rulepub tests.

All tests run against fakes only (fakeredis streams, in-memory rule store) —
no live Postgres/Redis/ES.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence, Set
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from dataplane.rulepub.packio import PackValidation, load_pack
from dataplane.workers.detector_pack import RuleRow

REPO_ROOT = Path(__file__).resolve().parents[4]
RULES_DIR = REPO_ROOT / "rules"
PACK_YAML = RULES_DIR / "pack.yaml"
FIXTURES_DIR = RULES_DIR / "tests" / "cases"
MITRE_DESCRIPTIONS = RULES_DIR / "mitre-descriptions.yaml"


class FakeRuleStore:
    """In-memory RuleStore for engine/worker tests."""

    def __init__(self) -> None:
        self.packs: dict[str, list[RuleRow]] = {}
        self.active_version: str | None = None
        self.runtime_disabled: set[str] = set()
        self.toggles: dict[str, dict[str, bool]] = {}
        self.disable_inserts: list[dict[str, Any]] = []

    async def active_pack_version(self) -> str | None:
        return self.active_version

    async def fetch_rules(self, pack_version: str) -> Sequence[RuleRow]:
        return list(self.packs.get(pack_version, []))

    async def fetch_runtime_disabled(self) -> Set[str]:
        return set(self.runtime_disabled)

    async def fetch_tenant_toggles(self, tenant_id: UUID | str) -> Mapping[str, bool]:
        return dict(self.toggles.get(str(tenant_id), {}))

    async def insert_runtime_disable(
        self, *, rule_id: str, reason: str, error_fraction: float, tenants_affected: int
    ) -> bool:
        newly = rule_id not in self.runtime_disabled
        self.runtime_disabled.add(rule_id)
        self.disable_inserts.append(
            {
                "rule_id": rule_id,
                "reason": reason,
                "error_fraction": error_fraction,
                "tenants_affected": tenants_affected,
            }
        )
        return newly


def rows_from_validation(validation: PackValidation) -> list[RuleRow]:
    """Turn a validated pack into the rows the publish op would write."""
    assert validation.manifest is not None
    return [
        RuleRow(
            pack_version=validation.manifest.pack_version,
            rule_id=pack_rule.compiled.rule_id,
            rule_version=pack_rule.compiled.version,
            definition=pack_rule.compiled.definition,
            enabled_default=pack_rule.entry.enabled,
        )
        for pack_rule in validation.rules
    ]


def load_case_event(rule_id: str, section: str = "must_match", index: int = 0) -> dict[str, Any]:
    fixture = json.loads((FIXTURES_DIR / f"{rule_id}.json").read_text(encoding="utf-8"))
    return fixture[section][index]["event"]


@pytest.fixture(scope="session")
def pack_validation() -> PackValidation:
    validation = load_pack(PACK_YAML, run_fixtures=False)
    assert validation.ok, "\n".join(validation.errors)
    return validation


@pytest.fixture()
def fake_store(pack_validation: PackValidation) -> FakeRuleStore:
    store = FakeRuleStore()
    version = pack_validation.manifest.pack_version
    store.packs[version] = rows_from_validation(pack_validation)
    store.active_version = version
    return store
