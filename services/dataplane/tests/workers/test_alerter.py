"""worker-alerter: dedup upsert incl. conflict race (AC-41/42), window expiry
close-out, correlation (AC-43), priority compute, triage enqueue."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from dataplane.workers.alerter import Alerter
from dataplane.workers.common import Settings
from soc_pipeline import STREAM_ALERTS_TRIAGE, STREAM_DETECTIONS, ReceivedMessage, StreamProducer

TENANT = UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")
NOW = datetime.now(UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql://unused",
        redis_url="redis://unused",
        elasticsearch_url="http://unused",
        consumer_name="test",
    )


def detection(**overrides) -> ReceivedMessage:
    payload = {
        "rule_id": "proc-encoded-powershell",
        "rule_version": "1.0.0",
        "title": "Encoded PowerShell command",
        "severity": "high",
        "mitre_technique_ids": ["T1059.001"],
        "entity_key": "fin-laptop-07|sam.jones",
        "event_id": str(uuid4()),
        "tenant_id": str(TENANT),
        "pack_version": "1.0.0",
        "event_time": NOW.isoformat(),
        "entity_hostname": "fin-laptop-07",
        "entity_user": "sam.jones",
    }
    payload.update(overrides)
    return ReceivedMessage(
        stream=STREAM_DETECTIONS,
        message_id="1-1",
        tenant_id=TENANT,
        trace_id="trace-1",
        payload=payload,
    )


@pytest.fixture
def alerter(pool, redis, metrics):
    return Alerter(
        pool=pool,
        producer=StreamProducer(redis),
        metrics=metrics,
        settings=make_settings(),
        dedup_window_minutes=60,
        correlation_window_minutes=30,
    )


def seed_asset(state, *, hostname="fin-laptop-07", agent_status="healthy", asset_id=None):
    asset_id = asset_id or uuid4()
    state.t["assets"].append(
        {
            "id": asset_id,
            "tenant_id": str(TENANT),
            "hostname": hostname,
            "agent_status": agent_status,
            "state": "active",
            "sources": ["agent"],
            "billable": True,
            "last_seen": NOW,
        }
    )
    return asset_id


async def test_new_alert_created_with_priority_and_triage_enqueue(alerter, state, redis):
    asset_id = seed_asset(state, agent_status="healthy")
    await alerter.handle(detection())

    alerts = state.rows("alerts", TENANT)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["id"].startswith("al_")
    assert alert["state"] == "new"
    assert alert["occurrence_count"] == 1
    assert alert["asset_id"] == str(asset_id)
    # high severity, no triage (S_ai = S_rule), count=1, healthy:
    # sev_comp = round(.85*80) = 68 (contract vector 5's sev_comp), occ 0, asset 0.
    assert alert["priority_score"] == 68
    inputs = json.loads(alert["priority_inputs"])
    assert inputs["priority_formula_version"] == 1
    assert inputs["agent_status"] == "healthy"
    assert inputs["ai_severity"] is None  # rule-severity-only path (AC-50)

    links = state.rows("alert_events", TENANT)
    assert len(links) == 1
    assert links[0]["alert_id"] == alert["id"]
    assert links[0]["es_index"] == f"events-v1-{TENANT}-{NOW:%Y.%m}"

    history = [h["action"] for h in state.rows("alert_history", TENANT)]
    assert history == ["created"]

    triage_entries = await redis.xrange(STREAM_ALERTS_TRIAGE)
    assert len(triage_entries) == 1
    triage_payload = json.loads(triage_entries[0][1][b"payload"])
    assert triage_payload["alert_id"] == alert["id"]
    assert triage_payload["rule_severity"] == "high"
    assert triage_payload["event_refs"][0]["es_index"] == links[0]["es_index"]


async def test_dedup_race_two_hits_one_row_count_two(alerter, state, redis, metrics):
    """Two concurrent hits on the same dedup key: the second INSERT hits the
    unique partial index and takes the DO UPDATE branch (simulated by the fake
    conn's conflict path) => ONE open row, occurrence_count=2 (AC-41/42)."""
    await alerter.handle(detection())
    await alerter.handle(detection(event_id=str(uuid4()), event_time=NOW.isoformat()))

    alerts = [a for a in state.rows("alerts", TENANT) if a["state"] == "new"]
    assert len(alerts) == 1
    assert alerts[0]["occurrence_count"] == 2
    # Both events linked to the same alert (AC-42).
    assert len(state.rows("alert_events", TENANT)) == 2
    actions = [h["action"] for h in state.rows("alert_history", TENANT)]
    assert actions == ["created", "occurrence_added"]
    # Only the NEW alert was enqueued for triage.
    assert len(await redis.xrange(STREAM_ALERTS_TRIAGE)) == 1
    # Tier boundary 2 => recompute happened; occurrence component now 4.
    inputs = json.loads(alerts[0]["priority_inputs"])
    assert inputs["occurrence_count"] == 2
    assert inputs["occurrence_component"] == 4


async def test_redelivered_hit_is_idempotent(alerter, state, redis):
    hit = detection()
    await alerter.handle(hit)
    await alerter.handle(hit)  # same event redelivered (at-least-once)

    assert state.rows("alerts", TENANT)[0]["occurrence_count"] == 1
    assert len(state.rows("alert_events", TENANT)) == 1
    assert len(await redis.xrange(STREAM_ALERTS_TRIAGE)) == 1


async def test_window_expiry_closes_old_and_creates_new(alerter, state, redis):
    """Open alert whose last_seen is outside the 60-min window: close-out
    semantics = new alert (design §5)."""
    await alerter.handle(detection(event_time=(NOW - timedelta(hours=3)).isoformat()))
    old_id = state.rows("alerts", TENANT)[0]["id"]

    await alerter.handle(detection(event_id=str(uuid4()), event_time=NOW.isoformat()))

    alerts = {a["id"]: a for a in state.rows("alerts", TENANT)}
    assert len(alerts) == 2
    old = alerts[old_id]
    assert old["state"] == "closed"
    assert old["close_reason"] == "resolved"
    new = next(a for a in alerts.values() if a["id"] != old_id)
    assert new["state"] == "new"
    assert new["occurrence_count"] == 1
    # History: created(old), closed(old), created(new).
    actions = [(h["alert_id"], h["action"]) for h in state.rows("alert_history", TENANT)]
    assert (old_id, "closed") in actions
    assert (new["id"], "created") in actions
    # Both alerts got a triage enqueue (both were NEW at creation).
    assert len(await redis.xrange(STREAM_ALERTS_TRIAGE)) == 2


async def test_correlation_joins_same_host_different_rule(alerter, state):
    """AC-43: open alerts, same tenant+host, last_seen within 30 min,
    different rules => shared correlation group."""
    await alerter.handle(
        detection(
            rule_id="auth-brute-force",
            entity_key="fin-laptop-07|administrator",
            event_time=(NOW - timedelta(minutes=10)).isoformat(),
        )
    )
    await alerter.handle(detection(event_time=NOW.isoformat()))

    alerts = state.rows("alerts", TENANT)
    assert len(alerts) == 2
    groups = {a["correlation_group_id"] for a in alerts}
    assert len(groups) == 1
    group_id = groups.pop()
    assert group_id is not None and group_id.startswith("cg_")
    group_rows = state.rows("correlation_groups", TENANT)
    assert len(group_rows) == 1
    assert group_rows[0]["alert_count"] == 2
    correlated = [h for h in state.rows("alert_history", TENANT) if h["action"] == "correlated"]
    assert len(correlated) == 2


async def test_no_correlation_outside_window_or_same_rule(alerter, state):
    await alerter.handle(
        detection(
            rule_id="auth-brute-force",
            entity_key="fin-laptop-07|administrator",
            event_time=(NOW - timedelta(hours=2)).isoformat(),
        )
    )
    await alerter.handle(detection(event_time=NOW.isoformat()))
    assert all(a["correlation_group_id"] is None for a in state.rows("alerts", TENANT))
    assert state.rows("correlation_groups", TENANT) == []


async def test_malformed_detection_hit_dead_lettered(alerter, state, metrics):
    bad = detection()
    del bad.payload["rule_id"]
    await alerter.handle(bad)  # must not raise
    dlq = state.rows("dead_letter_events", TENANT)
    assert len(dlq) == 1
    assert dlq[0]["error_code"] == "DETECTION_HIT_MALFORMED"
    assert state.rows("alerts", TENANT) == []


async def test_unknown_asset_scores_agent_status_none(alerter, state):
    await alerter.handle(detection(entity_hostname="never-seen-host"))
    alert = state.rows("alerts", TENANT)[0]
    inputs = json.loads(alert["priority_inputs"])
    assert inputs["agent_status"] == "none"
    # high, triage absent (sev_comp 68) + agent_status none (+2) => 70
    assert alert["priority_score"] == 70
