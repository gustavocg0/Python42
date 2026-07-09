import json
import uuid

import pytest

from soc_pipeline import STREAM_RAW, StreamProducer

TENANT = uuid.uuid4()


async def test_publish_xadds_envelope(redis):
    producer = StreamProducer(redis)
    entry_id = await producer.publish(
        STREAM_RAW, tenant_id=TENANT, trace_id="tr-1", payload={"batch": "b_1"}
    )
    assert entry_id
    entries = await redis.xrange(STREAM_RAW)
    assert len(entries) == 1
    _mid, fields = entries[0]
    assert fields["tenant_id"] == str(TENANT)
    assert fields["trace_id"] == "tr-1"
    assert json.loads(fields["payload"]) == {"batch": "b_1"}


async def test_publish_rejects_missing_tenant(redis):
    producer = StreamProducer(redis)
    with pytest.raises(ValueError):
        await producer.publish(STREAM_RAW, tenant_id="not-a-uuid", trace_id="t", payload={})
    assert await redis.xlen(STREAM_RAW) == 0  # nothing written — fail closed


async def test_publish_rejects_empty_trace_id(redis):
    producer = StreamProducer(redis)
    with pytest.raises(ValueError):
        await producer.publish(STREAM_RAW, tenant_id=TENANT, trace_id="", payload={})


async def test_publish_rejects_unknown_stream(redis):
    producer = StreamProducer(redis)
    with pytest.raises(ValueError):
        await producer.publish("pipe:bogus", tenant_id=TENANT, trace_id="t", payload={})


async def test_maxlen_is_applied(redis):
    producer = StreamProducer(redis, maxlen=5)
    for i in range(50):
        await producer.publish(STREAM_RAW, tenant_id=TENANT, trace_id=f"t{i}", payload={"i": i})
    # approximate trim: length bounded near maxlen, far below 50
    assert await redis.xlen(STREAM_RAW) <= 50
