"""worker-normalizer: malformed->DLQ (AC-32), idempotent dup (AC-34),
strip client-assigned fields (SEC-18), downstream fan-out, onboarding (AC-70)."""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from dataplane.workers.common import Settings
from dataplane.workers.normalizer import Normalizer
from soc_pipeline import (
    STREAM_ASSET_OBSERVATIONS,
    STREAM_NORMALIZED,
    STREAM_RAW,
    ReceivedMessage,
    StreamProducer,
)

TENANT = UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql://unused",
        redis_url="redis://unused",
        elasticsearch_url="http://unused",
        consumer_name="test",
    )


def agent_event(**overrides) -> dict:
    event = {
        "event_class": "process_activity",
        "activity": "process_launched",
        "event_time": "2026-07-08T09:14:03.221Z",
        "source_event_id": "etw-4688-000123456",
        "host": {
            "hostname": "FIN-LAPTOP-07",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
            "mac": "A4:BB:6D:12:34:56",
        },
        "process": {
            "pid": 4312,
            "name": "powershell.exe",
            "exe_path": "C:\\Windows\\System32\\powershell.exe",
            "cmd_line": "powershell -enc SQBFAFgA",
        },
        "parent": {"pid": 1180, "name": "winword.exe"},
        "user": {"name": "sam.jones", "domain": "ACME"},
    }
    event.update(overrides)
    return event


def raw_message(events, *, source_type="agent", batch_id=None) -> ReceivedMessage:
    source = (
        {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"}
        if source_type == "agent"
        else {"ingest_key_id": "ik_01J9ZKAB", "vendor": "acme-fw"}
    )
    return ReceivedMessage(
        stream=STREAM_RAW,
        message_id="1-1",
        tenant_id=TENANT,
        trace_id="trace-1",
        payload={
            "batch_id": str(batch_id or uuid4()),
            "source_type": source_type,
            "ingest_time": "2026-07-08T09:14:05.100Z",
            "source": source,
            "events": events,
        },
    )


@pytest.fixture
def normalizer(pool, redis, es, metrics):
    return Normalizer(
        pool=pool,
        redis=redis,
        es=es,
        producer=StreamProducer(redis),
        metrics=metrics,
        settings=make_settings(),
    )


async def test_valid_event_stored_and_fanned_out(normalizer, redis, es, state, metrics):
    await normalizer.handle(raw_message([agent_event()]))

    assert len(es.docs) == 1
    (index, _doc_id), doc = next(iter(es.docs.items()))
    # Monthly per-tenant index derived from event_time (AC-33).
    assert index == f"events-v1-{TENANT}-2026.07"
    assert doc["tenant_id"] == str(TENANT)
    assert doc["host"]["hostname"] == "fin-laptop-07"  # lowercased per contract

    normalized_entries = await redis.xrange(STREAM_NORMALIZED)
    assert len(normalized_entries) == 1
    published = json.loads(normalized_entries[0][1][b"payload"])
    assert published["event_class"] == "process_activity"

    obs_entries = await redis.xrange(STREAM_ASSET_OBSERVATIONS)
    assert len(obs_entries) == 1
    obs = json.loads(obs_entries[0][1][b"payload"])
    assert obs["device_id"] == "dev_01J9ZK3T"
    assert obs["hostname"] == "fin-laptop-07"
    assert obs["source"] == "agent"

    assert metrics.outcomes()["stored"] == 1
    # Onboarding first_event flipped (AC-70): Redis signal + PG row.
    assert await redis.hget(f"onboarding:{TENANT}", "first_event") == b"1"
    assert state.rows("onboarding_steps", TENANT)[0]["state"] == "done"


async def test_malformed_event_dead_lettered_batch_proceeds(normalizer, state, es, metrics, redis):
    bad = agent_event()
    del bad["process"]  # required for process_activity => malformed (AC-32)
    await normalizer.handle(raw_message([bad, agent_event()]))

    dlq = state.rows("dead_letter_events", TENANT)
    assert len(dlq) == 1
    assert dlq[0]["error_code"] == "SCHEMA_VALIDATION_FAILED"
    assert dlq[0]["source_type"] == "agent"
    assert len(dlq[0]["raw_payload"]) <= 65536
    # The valid sibling was still stored — malformed input never stalls (AC-32).
    assert len(es.docs) == 1
    assert metrics.outcomes()["dead_lettered"] == 1
    assert metrics.outcomes()["stored"] == 1
    # Per-tenant events_rejected counter incremented.
    keys = await redis.keys(f"usage:ingest:{TENANT}:*:rejected_events")
    assert len(keys) == 1
    assert int(await redis.get(keys[0])) == 1


async def test_duplicate_delivery_is_dropped_and_counted(normalizer, redis, es, metrics):
    await normalizer.handle(raw_message([agent_event()]))
    await normalizer.handle(raw_message([agent_event()]))  # agent retry, same source_event_id

    assert len(es.docs) == 1  # exactly one stored copy (AC-34)
    assert metrics.outcomes()["duplicate"] == 1
    # Duplicate NOT re-emitted downstream.
    assert len(await redis.xrange(STREAM_NORMALIZED)) == 1
    keys = await redis.keys(f"usage:ingest:{TENANT}:*:duplicates_dropped")
    assert int(await redis.get(keys[0])) == 1


async def test_client_assigned_fields_are_stripped(normalizer, es):
    forged_event_id = str(uuid4())
    forged_tenant = str(uuid4())
    event = agent_event(
        event_id=forged_event_id,
        tenant_id=forged_tenant,
        ingest_time="2020-01-01T00:00:00Z",
        batch_id=str(uuid4()),
        source={"device_id": "dev_EVIL", "ingest_key_id": "ik_EVIL"},
    )
    message = raw_message([event])
    await normalizer.handle(message)

    assert len(es.docs) == 1
    doc = next(iter(es.docs.values()))
    # SEC-18 / contract §5: server-assigned values win, client values ignored.
    assert doc["event_id"] != forged_event_id
    assert doc["tenant_id"] == str(TENANT)
    assert doc["batch_id"] == message.payload["batch_id"]
    assert doc["ingest_time"] != "2020-01-01T00:00:00+00:00"
    assert doc["source"] == {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"}


async def test_generic_arbitrary_json_becomes_generic_event(normalizer, es, redis):
    await normalizer.handle(
        raw_message(
            [{"msg": "Blocked outbound connection", "rule": 17, "src": "10.1.4.23"}],
            source_type="generic",
        )
    )
    assert len(es.docs) == 1
    doc = next(iter(es.docs.values()))
    assert doc["event_class"] == "generic"
    assert doc["message"] == "Blocked outbound connection"
    assert doc["raw"] == {"msg": "Blocked outbound connection", "rule": 17, "src": "10.1.4.23"}
    assert doc["time_inferred"] is True  # no event_time => inferred from ingest_time
    assert doc["source"]["ingest_key_id"] == "ik_01J9ZKAB"
    # No host => no asset observation.
    assert len(await redis.xrange(STREAM_ASSET_OBSERVATIONS)) == 0


async def test_agent_event_with_unknown_class_is_dead_lettered(normalizer, state, es):
    await normalizer.handle(raw_message([agent_event(event_class="weird_class")]))
    dlq = state.rows("dead_letter_events", TENANT)
    assert len(dlq) == 1
    assert dlq[0]["error_code"] == "UNKNOWN_EVENT_CLASS"
    assert len(es.docs) == 0


async def test_malformed_batch_payload_dead_lettered(normalizer, state, metrics):
    message = ReceivedMessage(
        stream=STREAM_RAW,
        message_id="1-2",
        tenant_id=TENANT,
        trace_id="trace-2",
        payload={"events": "not-a-batch"},
    )
    await normalizer.handle(message)  # must not raise (never stall, AC-32)
    dlq = state.rows("dead_letter_events", TENANT)
    assert len(dlq) == 1
    assert dlq[0]["error_code"] == "RAW_BATCH_MALFORMED"


async def test_es_store_failure_raises_for_retry_after_partial_fanout(
    normalizer, es, redis, state
):
    ok = agent_event()
    failing = agent_event(source_event_id="etw-FAIL-1")
    # Precompute the failing doc id by running the batch once against a probe:
    # simpler — mark all ids failing except none, then filter by captured body.
    from soc_schemas import derive_es_document_id

    es.fail_doc_ids.add(derive_es_document_id(TENANT, "dev_01J9ZK3T", "etw-FAIL-1"))

    with pytest.raises(RuntimeError):
        await normalizer.handle(raw_message([ok, failing]))
    # The successful event WAS stored and fanned out before the raise, so a
    # redelivery only retries the failed one (stored one dedups via 409).
    assert len(es.docs) == 1
    assert len(await redis.xrange(STREAM_NORMALIZED)) == 1
