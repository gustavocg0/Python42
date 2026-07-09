"""DetectorEngine + enablement overlay + SEC-28 failure-taxonomy tests."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import FakeRuleStore

from dataplane.rulepub.compiler import compile_rule
from dataplane.workers.detector_engine import DetectorEngine, FailureTracker
from dataplane.workers.detector_pack import (
    EnablementCache,
    LoadedPack,
    LoadedRule,
    PackManager,
    RuleRow,
)

TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"
TENANT_C = "33333333-3333-4333-8333-333333333333"


def make_rule_doc(rule_id: str = "test-rule", **overrides: Any) -> dict[str, Any]:
    doc = {
        "id": rule_id,
        "version": "1.0.0",
        "title": f"Rule {rule_id}",
        "description": "test",
        "severity": "low",
        "event_class": "process_activity",
        "min_schema_version": "1.0.0",
        "mitre_technique_ids": ["T1059"],
        "entity": ["host.hostname", "user.name"],
        "detection": {
            "condition": {"field": "process.name", "op": "iequals", "value": "evil.exe"}
        },
        "false_positives": ["none"],
        "references": ["https://attack.mitre.org/techniques/T1059/"],
    }
    doc.update(overrides)
    return doc


def matching_event() -> dict[str, Any]:
    return {
        "event_class": "process_activity",
        "schema_version": "1.0.0",
        "host": {"hostname": "WS-01"},
        "user": {"name": "Sam"},
        "process": {"name": "EVIL.exe"},
    }


def loaded_pack(*rules: LoadedRule, version: str = "1.0.0") -> LoadedPack:
    return LoadedPack(version, list(rules))


def loaded_rule(rule_id: str = "test-rule", *, enabled_default: bool = True) -> LoadedRule:
    return LoadedRule(compiled=compile_rule(make_rule_doc(rule_id)),
                      enabled_default=enabled_default)


class _RaisingCompiled:
    """Duck-typed compiled rule whose predicate always raises (SEC-28b)."""

    def __init__(self, rule_id: str = "raising-rule") -> None:
        self.rule_id = rule_id
        self.version = "1.0.0"
        self.title = "Raising rule"
        self.severity = "low"
        self.event_class = "process_activity"
        self.min_schema = (1, 0, 0)
        self.mitre_technique_ids = ("T1059",)

    def matches_condition(self, event: Any) -> bool:
        raise RuntimeError("boom")

    def entity_key(self, event: Any) -> str:  # pragma: no cover
        return ""


def engine_with(store: FakeRuleStore, **kwargs: Any) -> DetectorEngine:
    return DetectorEngine(enablement=EnablementCache(store), **kwargs)


async def test_hit_carries_rule_metadata_and_entity_key() -> None:
    store = FakeRuleStore()
    engine = engine_with(store)
    pack = loaded_pack(loaded_rule())
    result = await engine.evaluate_event(pack=pack, event=matching_event(), tenant_id=TENANT_A)
    assert len(result.hits) == 1
    hit = result.hits[0]
    assert hit.rule_id == "test-rule"
    assert hit.rule_version == "1.0.0"
    assert hit.severity == "low"
    assert hit.mitre_technique_ids == ("T1059",)
    assert hit.entity_key == "ws-01|sam"  # §5.4 casefolded, declared order
    assert hit.entity_hostname == "WS-01"  # as carried by the event (§5.5)
    assert hit.entity_user == "Sam"  # rule declares user.name in entity
    assert hit.pack_version == "1.0.0"


async def test_hit_entity_fields_absent_when_not_derivable() -> None:
    """§5.5: no host.hostname on the event ⇒ no entity_hostname; rule without
    user.name in its entity list ⇒ no entity_user."""
    store = FakeRuleStore()
    engine = engine_with(store)
    doc = make_rule_doc("no-user-entity", entity=["host.hostname"])
    pack = loaded_pack(LoadedRule(compiled=compile_rule(doc), enabled_default=True))
    event = matching_event()
    del event["host"]
    result = await engine.evaluate_event(pack=pack, event=event, tenant_id=TENANT_A)
    assert len(result.hits) == 1
    assert result.hits[0].entity_hostname is None
    assert result.hits[0].entity_user is None  # user.name not in rule entity


async def test_class_and_schema_gates_skip_rules() -> None:
    store = FakeRuleStore()
    engine = engine_with(store)
    pack = loaded_pack(loaded_rule())
    wrong_class = {**matching_event(), "event_class": "network_activity"}
    result = await engine.evaluate_event(pack=pack, event=wrong_class, tenant_id=TENANT_A)
    assert result.hits == [] and result.rules_evaluated == 0

    wrong_major = {**matching_event(), "schema_version": "2.0.0"}
    result = await engine.evaluate_event(pack=pack, event=wrong_major, tenant_id=TENANT_A)
    assert result.hits == [] and result.rules_evaluated == 0


async def test_tenant_toggle_overlay_ac38() -> None:
    """AC-38: per-tenant toggle overrides enabled_default; other tenants keep it."""
    store = FakeRuleStore()
    store.toggles[TENANT_A] = {"test-rule": False}
    engine = engine_with(store)
    pack = loaded_pack(loaded_rule())
    result_a = await engine.evaluate_event(pack=pack, event=matching_event(),
                                           tenant_id=TENANT_A)
    result_b = await engine.evaluate_event(pack=pack, event=matching_event(),
                                           tenant_id=TENANT_B)
    assert result_a.hits == []
    assert len(result_b.hits) == 1


async def test_toggle_can_enable_a_default_disabled_rule() -> None:
    store = FakeRuleStore()
    store.toggles[TENANT_A] = {"test-rule": True}
    engine = engine_with(store)
    pack = loaded_pack(loaded_rule(enabled_default=False))
    result_a = await engine.evaluate_event(pack=pack, event=matching_event(),
                                           tenant_id=TENANT_A)
    result_b = await engine.evaluate_event(pack=pack, event=matching_event(),
                                           tenant_id=TENANT_B)
    assert len(result_a.hits) == 1
    assert result_b.hits == []


async def test_runtime_disable_beats_tenant_toggle() -> None:
    store = FakeRuleStore()
    store.runtime_disabled.add("test-rule")
    store.toggles[TENANT_A] = {"test-rule": True}
    engine = engine_with(store)
    pack = loaded_pack(loaded_rule())
    result = await engine.evaluate_event(pack=pack, event=matching_event(), tenant_id=TENANT_A)
    assert result.hits == [] and result.rules_evaluated == 0


async def test_overlay_cached_at_most_30s() -> None:
    """AC-38: overlay reads are cached; a toggle lands within the TTL."""
    store = FakeRuleStore()
    now = [0.0]
    cache = EnablementCache(store, ttl_seconds=30.0, clock=lambda: now[0])
    engine = DetectorEngine(enablement=cache)
    pack = loaded_pack(loaded_rule())

    assert len((await engine.evaluate_event(pack=pack, event=matching_event(),
                                            tenant_id=TENANT_A)).hits) == 1
    store.toggles[TENANT_A] = {"test-rule": False}
    now[0] = 10.0  # inside TTL: cached value still used
    assert len((await engine.evaluate_event(pack=pack, event=matching_event(),
                                            tenant_id=TENANT_A)).hits) == 1
    now[0] = 31.0  # TTL expired: toggle takes effect
    assert (await engine.evaluate_event(pack=pack, event=matching_event(),
                                        tenant_id=TENANT_A)).hits == []


async def test_per_event_exception_isolated_rule_stays_enabled() -> None:
    """SEC-28(b): exception caught per (rule, event); other rules unaffected;
    the failing rule is evaluated again on the next event."""
    store = FakeRuleStore()
    errors: list[tuple[str, str, str]] = []
    engine = engine_with(store,
                         on_eval_error=lambda r, t, e: errors.append((r, t, e)))
    raising = LoadedRule(compiled=_RaisingCompiled(), enabled_default=True)
    pack = loaded_pack(raising, loaded_rule())

    for _ in range(2):  # two events: the raising rule keeps being evaluated
        result = await engine.evaluate_event(pack=pack, event=matching_event(),
                                             tenant_id=TENANT_A)
        assert [h.rule_id for h in result.hits] == ["test-rule"]  # healthy rule fires
        assert [e.rule_id for e in result.eval_errors] == ["raising-rule"]
    assert len(errors) == 2
    assert all(r == "raising-rule" and t == TENANT_A for r, t, _ in errors)
    assert store.disable_inserts == []  # never auto-disabled by per-event errors


async def test_auto_disable_requires_multiple_tenants() -> None:
    """SEC-28(c): 100% failure from ONE tenant never disables (attacker-crafted
    events must not kill detection); the same volume across >=3 tenants does."""
    store = FakeRuleStore()
    tracker = FailureTracker(disable_fraction=0.05, min_tenants=3, min_samples=30)
    engine = engine_with(store, tracker=tracker)
    raising = LoadedRule(compiled=_RaisingCompiled(), enabled_default=True)
    pack = loaded_pack(raising)

    decisions = []
    for _ in range(60):  # single tenant, sustained 100% failure
        result = await engine.evaluate_event(pack=pack, event=matching_event(),
                                             tenant_id=TENANT_A)
        decisions.extend(result.disable_decisions)
    assert decisions == []

    for tenant in (TENANT_B, TENANT_C):  # now two more tenants fail
        result = await engine.evaluate_event(pack=pack, event=matching_event(),
                                             tenant_id=tenant)
        decisions.extend(result.disable_decisions)
    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.rule_id == "raising-rule"
    assert decision.tenants_affected == 3
    assert decision.error_fraction >= 0.05


def test_failure_tracker_min_samples_and_fraction() -> None:
    tracker = FailureTracker(disable_fraction=0.5, min_tenants=2, min_samples=10)
    # 9 samples, all errors, 2 tenants: below min_samples ⇒ no decision.
    for i in range(9):
        assert tracker.record("r", TENANT_A if i % 2 else TENANT_B, error=True) is None
    # 10th sample crosses min_samples with fraction 1.0 ⇒ decision, exactly once.
    decision = tracker.record("r", TENANT_A, error=True)
    assert decision is not None and decision.samples == 10
    assert tracker.record("r", TENANT_B, error=True) is None  # fires once


def test_failure_tracker_fraction_below_threshold() -> None:
    tracker = FailureTracker(disable_fraction=0.5, min_tenants=2, min_samples=10)
    for _ in range(20):
        tracker.record("r", TENANT_A, error=False)
    assert tracker.record("r", TENANT_B, error=True) is None  # 1/21 < 0.5


def test_failure_tracker_rejects_single_tenant_config() -> None:
    with pytest.raises(ValueError, match="multi-tenant"):
        FailureTracker(min_tenants=1)


async def test_pack_manager_load_disables_bad_rule_sec28a() -> None:
    """SEC-28(a): a rule that fails to compile at load time is disabled and
    recorded; all other rules keep running."""
    store = FakeRuleStore()
    good = make_rule_doc("good-rule")
    bad = make_rule_doc("bad-rule")
    bad["detection"] = {"condition": {"field": "process.name", "op": "bogus", "value": "x"}}
    store.packs["9.9.9"] = [
        RuleRow(pack_version="9.9.9", rule_id="good-rule", rule_version="1.0.0",
                definition=good, enabled_default=True),
        RuleRow(pack_version="9.9.9", rule_id="bad-rule", rule_version="1.0.0",
                definition=bad, enabled_default=True),
    ]
    store.active_version = "9.9.9"
    manager = PackManager(store)
    pack = await manager.ensure_loaded()
    assert pack is not None
    assert pack.rule_count == 1
    assert "bad-rule" in pack.load_errors
    engine = engine_with(store)
    result = await engine.evaluate_event(
        pack=pack,
        event={**matching_event(), "process": {"name": "evil.exe"}},
        tenant_id=TENANT_A,
    )
    assert [h.rule_id for h in result.hits] == ["good-rule"]
