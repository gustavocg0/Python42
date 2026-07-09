"""Graph behavior: AC-50 resilience, regenerate-once, budget backstop (SEC-37),
metering on success AND failure (AC-51), RAW severity into scoring (SEC-34),
zero tools (SEC-35)."""

from __future__ import annotations

import json
from decimal import Decimal

from triage_fixtures import (
    TENANT_A,
    VALID_SUMMARY,
    DictAlertFetcher,
    DictEventFetcher,
    RecordingMeter,
    RecordingPersister,
    ScriptedLLM,
    contract_recompute,
    make_alert,
    make_error,
    ok_json,
)

from dataplane.triage.budget import TriageBudget, budget_key
from dataplane.triage.config import TriageSettings
from dataplane.triage.graph import TriageRunner
from dataplane.triage.llm import FakeTriageClient
from dataplane.triage.metering import LLMMeter
from dataplane.triage.persist import TriagePersister
from dataplane.triage.validator import validate_summary


def build_runner(
    *,
    client,
    fake_redis,
    settings: TriageSettings | None = None,
    alert=None,
    persister=None,
    meter=None,
    budget_cap: int = 1_000_000,
):
    settings = settings or TriageSettings(backoff_base_s=0.0)
    fetcher = DictAlertFetcher()
    fetcher.add(alert or make_alert())
    persister = persister if persister is not None else RecordingPersister()
    meter = meter if meter is not None else RecordingMeter()
    sleeps: list[float] = []

    async def record_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    runner = TriageRunner(
        settings=settings,
        alerts=fetcher,
        events=DictEventFetcher(),
        client=client,
        budget=TriageBudget(fake_redis, daily_token_cap=budget_cap),
        meter=meter,
        persister=persister,
        sleep=record_sleep,
    )
    return runner, persister, meter, sleeps


async def run(runner):
    return await runner.run(tenant_id=TENANT_A, trace_id="tr-1", alert_id="al_01TEST")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_completes_and_persists_raw_severity(fake_redis):
    llm = ScriptedLLM([ok_json(severity="low")])  # raw LOW on a HIGH rule
    runner, persister, meter, _ = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await run(runner)

    assert outcome.outcome == "completed"
    assert outcome.attempts == 1
    assert len(persister.completed) == 1
    saved = persister.completed[0]
    # RAW model severity is passed through; the clamp is scoring's job (SEC-34)
    assert saved["ai_severity"] == "low"
    assert saved["summary"] == VALID_SUMMARY
    assert saved["model_id"] == "scripted-model"
    assert saved["attempts"] == 1
    # metering: exactly one ok row with cost computed
    assert [m.outcome for m in meter.records] == ["ok"]
    assert meter.records[0].tokens_in == 100
    assert meter.records[0].cost_usd >= Decimal("0")


async def test_zero_tools_ever_passed_to_the_model(fake_redis):
    llm = ScriptedLLM([ok_json()])
    runner, *_ = build_runner(client=llm, fake_redis=fake_redis)
    await run(runner)
    call = llm.calls[0]
    assert "tools" not in call  # SEC-35: prompt-in/JSON-out only
    assert set(call) == {
        "system", "user", "model_id", "max_tokens", "temperature", "timeout_s", "grounding",
    }
    assert call["timeout_s"] == 30.0  # AC-50
    assert call["max_tokens"] == 1024


async def test_budget_is_charged_after_success(fake_redis):
    llm = ScriptedLLM([ok_json()])
    runner, *_ = build_runner(client=llm, fake_redis=fake_redis)
    await run(runner)
    spent = int(await fake_redis.get(budget_key(TENANT_A)))
    assert spent == 150  # 100 in + 50 out


# ---------------------------------------------------------------------------
# Regenerate-once on validation failure (ux §1.8)
# ---------------------------------------------------------------------------


async def test_invalid_then_valid_regenerates_once(fake_redis):
    invalid = ok_json(summary="just one line of **markdown**!")
    llm = ScriptedLLM([invalid, ok_json()])
    runner, _persister, meter, _ = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await run(runner)

    assert outcome.outcome == "completed"
    assert outcome.attempts == 2  # regeneration consumed an attempt (AC-50 budget)
    assert len(llm.calls) == 2
    # the regeneration prompt carries our validator feedback labels
    assert "rejected by the format validator" in llm.calls[1]["user"]
    # both calls consumed tokens => both metered ok
    assert [m.outcome for m in meter.records] == ["ok", "ok"]


async def test_invalid_twice_marks_unavailable_never_a_third_regeneration(fake_redis):
    invalid = ok_json(summary="nope")
    llm = ScriptedLLM([invalid, invalid, invalid])  # third must never be consumed
    runner, persister, _, _ = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await run(runner)

    assert outcome.outcome == "unavailable"
    assert outcome.reason == "validation_failed"
    assert len(llm.calls) == 2  # regenerate ONCE, then give up (§1.8)
    assert len(persister.completed) == 0
    assert persister.unavailable[0]["reason"] == "validation_failed"


# ---------------------------------------------------------------------------
# AC-50: timeout / retry / unavailable — alert delivery never blocked
# ---------------------------------------------------------------------------


async def test_three_timeouts_mark_unavailable_with_metered_failures(fake_redis):
    llm = ScriptedLLM([make_error("timeout")] * 3)
    runner, persister, meter, sleeps = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await run(runner)

    assert outcome.outcome == "unavailable"
    assert outcome.reason == "llm_timeout"
    assert outcome.attempts == 3
    assert len(llm.calls) == 3
    # every failed attempt is metered (AC-51)
    assert [m.outcome for m in meter.records] == ["timeout", "timeout", "timeout"]
    # backoff between attempts (base 0.0 in tests, but the calls happened)
    assert len(sleeps) == 2
    # priority stays rule-derived: only the unavailable update happens
    assert len(persister.completed) == 0
    assert len(persister.unavailable) == 1


async def test_error_then_success_recovers(fake_redis):
    llm = ScriptedLLM([make_error("error"), ok_json()])
    runner, _persister, meter, _ = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await run(runner)
    assert outcome.outcome == "completed"
    assert outcome.attempts == 2
    assert [m.outcome for m in meter.records] == ["error", "ok"]


async def test_backoff_grows_with_attempts(fake_redis):
    llm = ScriptedLLM([make_error("error")] * 3)
    settings = TriageSettings(backoff_base_s=2.0)
    runner, _, _, sleeps = build_runner(client=llm, fake_redis=fake_redis, settings=settings)
    await run(runner)
    assert sleeps == [2.0, 4.0]


# ---------------------------------------------------------------------------
# SEC-37: budget backstop
# ---------------------------------------------------------------------------


async def test_budget_exceeded_skips_llm_and_marks_unavailable(fake_redis):
    await fake_redis.set(budget_key(TENANT_A), 999_999_999)
    llm = ScriptedLLM([])  # any call would blow up the script
    runner, persister, meter, _ = build_runner(client=llm, fake_redis=fake_redis, budget_cap=1000)
    outcome = await run(runner)

    assert outcome.outcome == "unavailable"
    assert outcome.reason == "budget"
    assert llm.calls == []  # no model call at all
    assert [m.outcome for m in meter.records] == ["over_budget"]
    assert meter.records[0].tokens_in == 0 and meter.records[0].cost_usd == Decimal("0")
    assert persister.unavailable[0]["reason"] == "budget"


async def test_under_budget_proceeds(fake_redis):
    await fake_redis.set(budget_key(TENANT_A), 10)
    llm = ScriptedLLM([ok_json()])
    runner, _, _, _ = build_runner(client=llm, fake_redis=fake_redis, budget_cap=1000)
    outcome = await run(runner)
    assert outcome.outcome == "completed"


# ---------------------------------------------------------------------------
# Idempotency / dev mode
# ---------------------------------------------------------------------------


async def test_already_completed_alert_is_skipped(fake_redis):
    alert = make_alert(triage_status="completed")
    llm = ScriptedLLM([])
    runner, persister, meter, _ = build_runner(client=llm, fake_redis=fake_redis, alert=alert)
    outcome = await run(runner)
    assert outcome.outcome == "skipped"
    assert llm.calls == [] and meter.records == [] and persister.completed == []


async def test_missing_alert_is_skipped_not_crashed(fake_redis):
    llm = ScriptedLLM([])
    runner, *_ = build_runner(client=llm, fake_redis=fake_redis)
    outcome = await runner.run(tenant_id=TENANT_A, trace_id="t", alert_id="al_NOPE")
    assert outcome.outcome == "skipped"
    assert outcome.reason == "alert_not_found"


async def test_no_api_key_marks_unavailable_without_any_call(fake_redis):
    runner, persister, meter, _ = build_runner(client=None, fake_redis=fake_redis)
    outcome = await run(runner)
    assert outcome.outcome == "unavailable"
    assert outcome.reason == "no_api_key"
    assert meter.records == []
    assert persister.unavailable[0]["attempts"] == 0


# ---------------------------------------------------------------------------
# TRIAGE_FAKE deterministic mode
# ---------------------------------------------------------------------------


async def test_fake_client_produces_valid_summary_end_to_end(fake_redis):
    runner, persister, meter, _ = build_runner(client=FakeTriageClient(), fake_redis=fake_redis)
    outcome = await run(runner)
    assert outcome.outcome == "completed"
    saved = persister.completed[0]
    result = validate_summary(
        saved["summary"], entity_hostname="fin-laptop-07", entity_user="sam.jones"
    )
    assert result.ok, result.errors
    assert saved["ai_severity"] == "high"  # echoes rule severity deterministically
    assert meter.records[0].cost_usd == Decimal("0")  # fake model costs nothing


async def test_fake_client_handles_missing_entity(fake_redis):
    alert = make_alert(hostname=None, user=None)
    runner, persister, _, _ = build_runner(
        client=FakeTriageClient(), fake_redis=fake_redis, alert=alert
    )
    outcome = await run(runner)
    assert outcome.outcome == "completed"
    saved = persister.completed[0]
    assert "one of your devices" in saved["summary"]
    assert validate_summary(saved["summary"], entity_hostname=None, entity_user=None).ok


# ---------------------------------------------------------------------------
# Persistence SQL layer (FakePool): single transaction, SET LOCAL, history rows
# ---------------------------------------------------------------------------


async def test_persist_completed_sets_tenant_and_writes_history(pool):
    persister = TriagePersister(pool, recompute=contract_recompute)
    alert = make_alert(rule_severity="critical", occurrence_count=2)
    await persister.persist_completed(
        tenant_id=TENANT_A,
        alert=alert,
        summary=VALID_SUMMARY,
        ai_severity="low",  # RAW — clamp must come back from scoring
        model_id="m1",
        attempts=1,
    )
    assert pool.store.tenant_setting == str(TENANT_A)
    updates = pool.store.updates_matching("UPDATE tenantdata.alerts")
    assert len(updates) == 1
    args = updates[0][1]
    # (alert_id, summary, ai_severity, ai_severity_effective, model_id, attempts, score, inputs)
    assert args[2] == "low"
    assert args[3] == "high"  # SEC-34 clamp: critical rule => effective >= high
    assert args[6] == 83  # priority-score.md §4 vector 8 (critical/low/2/none)
    inputs = json.loads(args[7])
    assert inputs["ai_severity"] == "low"
    assert inputs["ai_severity_effective"] == "high"
    history = pool.store.updates_matching("INSERT INTO tenantdata.alert_history")
    assert len(history) == 1
    assert history[0][1][2] == "triage_completed"


async def test_persist_unavailable_keeps_rule_priority(pool):
    persister = TriagePersister(pool, recompute=contract_recompute)
    await persister.persist_unavailable(
        tenant_id=TENANT_A, alert_id="al_01TEST", attempts=3, reason="llm_timeout"
    )
    updates = pool.store.updates_matching("UPDATE tenantdata.alerts")
    assert len(updates) == 1
    assert "priority_score" not in updates[0][0]  # priority untouched (AC-50)
    assert "triage_status = 'unavailable'" in updates[0][0]
    history = pool.store.updates_matching("INSERT INTO tenantdata.alert_history")
    assert history[0][1][2] == "triage_unavailable"
    assert json.loads(history[0][1][3])["reason"] == "llm_timeout"


async def test_metering_row_shape(pool):
    from dataplane.triage.metering import MeterRecord

    meter = LLMMeter(pool)
    await meter.record(
        MeterRecord(
            tenant_id=TENANT_A,
            alert_id="al_01TEST",
            model_id="claude-haiku-4-5-20251001",
            tokens_in=1000,
            tokens_out=200,
            cost_usd=Decimal("0.002"),
            latency_ms=812,
            outcome="ok",
        )
    )
    inserts = pool.store.updates_matching("INSERT INTO tenantdata.llm_metering")
    assert len(inserts) == 1
    args = inserts[0][1]
    assert args[0] == TENANT_A and args[1] == "al_01TEST"
    assert args[4] == 1000 and args[5] == 200
    assert args[8] == "ok"
    assert pool.store.tenant_setting == str(TENANT_A)


# ---------------------------------------------------------------------------
# Real scoring module integration (it landed — use it directly)
# ---------------------------------------------------------------------------


async def test_real_scoring_module_via_adapter():
    from dataplane.triage.scoring_adapter import recompute_priority

    result = recompute_priority(
        rule_severity="critical", ai_severity="low", occurrence_count=2, agent_status="none"
    )
    assert result.priority_score == 83  # contract §4 vector 8
    assert result.ai_severity_effective == "high"
    assert result.priority_inputs["priority_formula_version"] == 1
