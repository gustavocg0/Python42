import uuid
from contextlib import asynccontextmanager

from soc_pipeline import STREAM_RAW, StreamConsumer, StreamProducer

TENANT = uuid.uuid4()


class Recorder:
    def __init__(self):
        self.handled = []
        self.contexts = []
        self.dead_letters = []
        self.fail_times = 0

    @asynccontextmanager
    async def tenant_context(self, message):
        self.contexts.append(("enter", message.tenant_id))
        try:
            yield
        finally:
            self.contexts.append(("exit", message.tenant_id))

    async def handler(self, message):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("transient failure")
        self.handled.append(message)

    async def dead_letter(self, dlq_message):
        self.dead_letters.append(dlq_message)


def make_consumer(redis, rec, **kwargs):
    return StreamConsumer(
        redis,
        stream=STREAM_RAW,
        group="normalizers",
        consumer_name="c1",
        handler=rec.handler,
        tenant_context=rec.tenant_context,
        dead_letter=rec.dead_letter,
        block_ms=1,
        **kwargs,
    )


async def publish_one(redis, payload=None, trace="tr-1"):
    producer = StreamProducer(redis)
    return await producer.publish(
        STREAM_RAW, tenant_id=TENANT, trace_id=trace, payload=payload or {"k": "v"}
    )


async def test_consume_ack_and_context(redis):
    rec = Recorder()
    consumer = make_consumer(redis, rec)
    await consumer.ensure_group()
    await publish_one(redis)

    assert await consumer.poll_once() == 1
    assert len(rec.handled) == 1
    msg = rec.handled[0]
    assert msg.tenant_id == TENANT
    assert msg.trace_id == "tr-1"
    assert msg.payload == {"k": "v"}
    # SEC-20: handler ran inside the tenant context
    assert rec.contexts == [("enter", TENANT), ("exit", TENANT)]
    # acked: no pending entries left
    pending = await redis.xpending(STREAM_RAW, "normalizers")
    assert pending["pending"] == 0


async def test_ensure_group_idempotent(redis):
    rec = Recorder()
    consumer = make_consumer(redis, rec)
    await consumer.ensure_group()
    await consumer.ensure_group()  # BUSYGROUP swallowed


async def test_failed_handler_leaves_message_pending(redis):
    rec = Recorder()
    rec.fail_times = 1
    consumer = make_consumer(redis, rec)
    await consumer.ensure_group()
    await publish_one(redis)

    await consumer.poll_once()
    assert rec.handled == []
    pending = await redis.xpending(STREAM_RAW, "normalizers")
    assert pending["pending"] == 1  # not acked -> retryable

    # retry via claim (min idle 0 for the test)
    assert await consumer.claim_stuck_once(min_idle_ms=0) == 1
    assert len(rec.handled) == 1
    pending = await redis.xpending(STREAM_RAW, "normalizers")
    assert pending["pending"] == 0


async def test_exhausted_attempts_go_to_dlq(redis):
    rec = Recorder()
    rec.fail_times = 100  # always fail
    consumer = make_consumer(redis, rec, max_delivery_attempts=3)
    await consumer.ensure_group()
    await publish_one(redis)

    await consumer.poll_once()  # attempt 1
    for _ in range(10):  # keep claiming until DLQ fires
        await consumer.claim_stuck_once(min_idle_ms=0)
        if rec.dead_letters:
            break

    assert len(rec.dead_letters) == 1
    dlq = rec.dead_letters[0]
    assert dlq.stream == STREAM_RAW
    assert dlq.tenant_id == str(TENANT)
    assert dlq.delivery_count >= 3
    # DLQ'd message is acked — never reprocessed
    pending = await redis.xpending(STREAM_RAW, "normalizers")
    assert pending["pending"] == 0


async def test_malformed_envelope_dead_lettered_immediately(redis):
    rec = Recorder()
    consumer = make_consumer(redis, rec)
    await consumer.ensure_group()
    # bypass producer (simulates rogue/legacy writer): missing tenant_id
    await redis.xadd(STREAM_RAW, {"trace_id": "t", "payload": "{}"})

    await consumer.poll_once()
    assert rec.handled == []
    assert len(rec.dead_letters) == 1
    assert rec.dead_letters[0].error_code == "MALFORMED_PIPELINE_MESSAGE"
    pending = await redis.xpending(STREAM_RAW, "normalizers")
    assert pending["pending"] == 0
