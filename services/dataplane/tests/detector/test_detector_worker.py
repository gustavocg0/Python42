"""End-to-end worker tests over fakeredis streams: pipe:normalized in,
pipe:detections out (payload per rules/FORMAT.md §5.5), AC-38/39 behavior."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import fakeredis.aioredis
import pytest
from conftest import FakeRuleStore, load_case_event, rows_from_validation

from dataplane.workers.detector import DetectorWorker, detection_payload
from dataplane.workers.detector_engine import DetectionHit
from soc_pipeline import STREAM_DETECTIONS, STREAM_NORMALIZED, StreamProducer


@pytest.fixture()
def redis():
    return fakeredis.aioredis.FakeRedis()


def make_worker(redis: Any, store: FakeRuleStore, name: str = "test-consumer") -> DetectorWorker:
    return DetectorWorker(redis=redis, store=store, consumer_name=name)


async def publish_event(redis: Any, event: dict[str, Any], trace_id: str = "trace-1") -> None:
    producer = StreamProducer(redis)
    await producer.publish(
        STREAM_NORMALIZED,
        tenant_id=event["tenant_id"],
        trace_id=trace_id,
        payload=event,
    )


async def read_detections(redis: Any) -> list[dict[str, Any]]:
    entries = await redis.xrange(STREAM_DETECTIONS)
    out = []
    for _message_id, fields in entries:
        decoded = {k.decode(): v.decode() for k, v in fields.items()}
        payload = json.loads(decoded["payload"])
        payload["_envelope"] = {k: v for k, v in decoded.items() if k != "payload"}
        out.append(payload)
    return out


async def test_matching_event_emits_exact_5_5_payload(redis, fake_store) -> None:
    worker = make_worker(redis, fake_store)
    await worker.consumer.ensure_group()
    event = load_case_event("proc-powershell-encoded-command")
    await publish_event(redis, event, trace_id="trace-abc")
    processed = await worker.consumer.poll_once(block_ms=1)
    assert processed == 1

    detections = await read_detections(redis)
    assert [d["rule_id"] for d in detections] == ["proc-powershell-encoded-command"]
    hit = detections[0]
    envelope = hit.pop("_envelope")
    # FORMAT.md §5.5 canonical FLAT payload: exactly these fields, no more.
    assert set(hit) == {
        "rule_id",
        "rule_version",
        "title",
        "severity",
        "mitre_technique_ids",
        "entity_key",
        "entity_hostname",
        "entity_user",
        "event_id",
        "event_time",
        "es_index",
        "pack_version",
    }
    assert hit["rule_version"] == "1.0.0"
    assert hit["title"] == "PowerShell Encoded Command Execution"
    assert hit["severity"] == "high"
    assert hit["mitre_technique_ids"] == ["T1059.001", "T1027.010"]
    assert hit["entity_key"] == "acme-ws-01|sam.jones"
    assert hit["entity_hostname"] == "acme-ws-01"  # matched event host.hostname
    assert hit["entity_user"] == "sam.jones"  # rule declares user.name in entity
    assert hit["event_id"] == event["event_id"]
    assert hit["event_time"] == event["event_time"]  # REQUIRED (alerter windows)
    # normalizer wrote to events_index(tenant, event_time) — same derivation:
    assert hit["es_index"] == f"events-v1-{event['tenant_id']}-2026.07"
    assert hit["pack_version"] == "1.0.0"
    # tenant_id/trace_id travel ONLY in the envelope (authoritative, SEC-20)
    assert envelope["tenant_id"] == event["tenant_id"]
    assert envelope["trace_id"] == "trace-abc"


async def test_non_matching_event_emits_nothing(redis, fake_store) -> None:
    worker = make_worker(redis, fake_store)
    await worker.consumer.ensure_group()
    event = load_case_event("proc-powershell-encoded-command", "must_not_match")
    await publish_event(redis, event)
    await worker.consumer.poll_once(block_ms=1)
    assert await read_detections(redis) == []


async def test_tenant_toggle_disables_rule_ac38(redis, fake_store) -> None:
    event = load_case_event("proc-powershell-encoded-command")
    fake_store.toggles[event["tenant_id"]] = {"proc-powershell-encoded-command": False}
    worker = make_worker(redis, fake_store)
    await worker.consumer.ensure_group()
    await publish_event(redis, event)
    await worker.consumer.poll_once(block_ms=1)
    assert await read_detections(redis) == []


async def test_runtime_disable_suppresses_rule(redis, fake_store) -> None:
    fake_store.runtime_disabled.add("proc-powershell-encoded-command")
    worker = make_worker(redis, fake_store)
    await worker.consumer.ensure_group()
    await publish_event(redis, load_case_event("proc-powershell-encoded-command"))
    await worker.consumer.poll_once(block_ms=1)
    assert await read_detections(redis) == []


async def test_hot_reload_picks_up_new_pack_without_restart(redis, fake_store,
                                                            pack_validation) -> None:
    """AC-39: version poll swaps the compiled pack in-process."""
    worker = make_worker(redis, fake_store)
    await worker.consumer.ensure_group()
    event = load_case_event("proc-powershell-encoded-command")
    await publish_event(redis, event)
    await worker.consumer.poll_once(block_ms=1)
    assert len(await read_detections(redis)) == 1

    # Publish pack 1.1.0 with the matching rule removed.
    rows_v2 = [
        replace(row, pack_version="1.1.0")
        for row in rows_from_validation(pack_validation)
        if row.rule_id != "proc-powershell-encoded-command"
    ]
    fake_store.packs["1.1.0"] = rows_v2
    fake_store.active_version = "1.1.0"

    changed = await worker.pack_manager.refresh()  # what the 30s poll invokes
    assert changed is True
    assert worker.pack_manager.pack.pack_version == "1.1.0"

    await publish_event(redis, event)
    await worker.consumer.poll_once(block_ms=1)
    assert len(await read_detections(redis)) == 1  # no new hit from 1.1.0


async def test_malformed_envelope_is_dead_lettered_not_crashed(redis, fake_store) -> None:
    dead: list[Any] = []

    async def capture(message: Any) -> None:
        dead.append(message)

    worker = DetectorWorker(
        redis=redis, store=fake_store, consumer_name="dlq-test", dead_letter=capture
    )
    await worker.consumer.ensure_group()
    await redis.xadd(STREAM_NORMALIZED, {"payload": "{}"})  # no tenant_id/trace_id
    await worker.consumer.poll_once(block_ms=1)
    assert len(dead) == 1
    assert dead[0].error_code == "MALFORMED_PIPELINE_MESSAGE"
    assert await read_detections(redis) == []


async def test_eval_error_counts_and_runtime_disable_write(redis, fake_store) -> None:
    """SEC-28(b)+(c) through the worker: errors counted per rule; sustained
    multi-tenant failure writes tenantdata.rule_runtime_disables + local
    enablement takes effect immediately."""
    from dataplane.workers.detector_engine import FailureTracker
    from dataplane.workers.detector_pack import LoadedPack, LoadedRule

    worker = DetectorWorker(
        redis=redis,
        store=fake_store,
        consumer_name="err-test",
        tracker=FailureTracker(disable_fraction=0.05, min_tenants=3, min_samples=3),
    )

    class _Boom:
        rule_id = "boom-rule"
        version = "1.0.0"
        title = "Boom"
        severity = "low"
        event_class = "process_activity"
        min_schema = (1, 0, 0)
        mitre_technique_ids = ("T1059",)

        def matches_condition(self, event):
            raise ValueError("bad shape")

        def entity_key(self, event):  # pragma: no cover
            return ""

    # Pin a pack containing only the failing rule.
    worker.pack_manager._pack = LoadedPack(
        "err-pack", [LoadedRule(compiled=_Boom(), enabled_default=True)]
    )
    await worker.consumer.ensure_group()

    event = load_case_event("proc-powershell-encoded-command")
    tenants = [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    ]
    for tenant in tenants:
        await publish_event(redis, {**event, "tenant_id": tenant})
    for _ in range(3):
        await worker.consumer.poll_once(block_ms=1)

    assert worker.eval_error_counts["boom-rule"] == 3  # rule_eval_errors metric
    assert [d["rule_id"] for d in fake_store.disable_inserts] == ["boom-rule"]
    assert fake_store.disable_inserts[0]["tenants_affected"] == 3
    assert "boom-rule" in fake_store.runtime_disabled  # persisted (SEC-28c)
    assert await read_detections(redis) == []


def test_detection_payload_shape_unit() -> None:
    hit = DetectionHit(
        rule_id="r",
        rule_version="1.0.0",
        title="t",
        severity="low",
        mitre_technique_ids=("T1059",),
        entity_key="h|u",
        pack_version="1.0.0",
        entity_hostname="h",
        entity_user="u",
    )
    payload = detection_payload(
        hit,
        event_id="e-1",
        event_time="2026-07-08T09:14:03.221Z",
        es_index="events-v1-x-2026.07",
    )
    assert payload == {
        "rule_id": "r",
        "rule_version": "1.0.0",
        "title": "t",
        "severity": "low",
        "mitre_technique_ids": ["T1059"],
        "entity_key": "h|u",
        "entity_hostname": "h",
        "entity_user": "u",
        "event_id": "e-1",
        "event_time": "2026-07-08T09:14:03.221Z",
        "es_index": "events-v1-x-2026.07",
        "pack_version": "1.0.0",
    }


def test_detection_payload_omits_absent_entity_fields() -> None:
    """entity_hostname/entity_user are included only when present (§5.5)."""
    hit = DetectionHit(
        rule_id="r",
        rule_version="1.0.0",
        title="t",
        severity="low",
        mitre_technique_ids=("T1059",),
        entity_key="|",
        pack_version="1.0.0",
    )
    payload = detection_payload(
        hit,
        event_id="e-1",
        event_time="2026-07-08T09:14:03.221Z",
        es_index="events-v1-x-2026.07",
    )
    assert "entity_hostname" not in payload
    assert "entity_user" not in payload
