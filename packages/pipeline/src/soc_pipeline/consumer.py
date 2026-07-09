"""Consumer-group consumer with ack, XAUTOCLAIM reclaim, and DLQ hand-off.

Semantics (ADR-0004, binding):
- at-least-once: ACK only after the handler (side effects) completes;
- handler runs INSIDE the tenant context established from the stream
  envelope — a worker cannot process a message without tenant context
  (SEC-20): both `tenant_context` and `dead_letter` are required arguments;
- stuck messages reclaimed via XAUTOCLAIM (min idle 60s default);
- after `max_delivery_attempts` (default 5) the message is handed to the
  dead-letter callback and ACKed — never dropped silently (AC-91);
- malformed envelopes (missing tenant_id/trace_id/payload) are dead-lettered
  immediately.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from soc_pipeline.messages import (
    MalformedPipelineMessage,
    ReceivedMessage,
    fields_to_message,
)
from soc_pipeline.streams import DEFAULT_MAX_DELIVERY_ATTEMPTS, DEFAULT_MIN_IDLE_MS

logger = logging.getLogger(__name__)

Handler = Callable[[ReceivedMessage], Awaitable[None]]
TenantContextFactory = Callable[[ReceivedMessage], AbstractAsyncContextManager[Any]]


@dataclass(frozen=True, slots=True)
class DeadLetteredMessage:
    """Handed to the dead-letter callback (persisted to PG by the worker)."""

    stream: str
    group: str
    message_id: str
    raw_fields: dict[str, str]
    error_code: str
    error_detail: str
    tenant_id: str | None
    trace_id: str | None
    delivery_count: int


DeadLetterHandler = Callable[[DeadLetteredMessage], Awaitable[None]]


def _decode(value: bytes | str) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _decode_fields(fields: dict[bytes | str, bytes | str]) -> dict[str, str]:
    return {_decode(k): _decode(v) for k, v in fields.items()}


class StreamConsumer:
    """One consumer identity inside a consumer group on one stream."""

    def __init__(
        self,
        redis: Redis,
        *,
        stream: str,
        group: str,
        consumer_name: str,
        handler: Handler,
        tenant_context: TenantContextFactory,
        dead_letter: DeadLetterHandler,
        max_delivery_attempts: int = DEFAULT_MAX_DELIVERY_ATTEMPTS,
        min_idle_ms: int = DEFAULT_MIN_IDLE_MS,
        batch_size: int = 32,
        block_ms: int = 5_000,
    ) -> None:
        if tenant_context is None or dead_letter is None:  # defensive vs None-passing
            raise ValueError("tenant_context and dead_letter are required (SEC-20 / AC-91)")
        self._redis = redis
        self._stream = stream
        self._group = group
        self._consumer_name = consumer_name
        self._handler = handler
        self._tenant_context = tenant_context
        self._dead_letter = dead_letter
        self._max_delivery_attempts = max_delivery_attempts
        self._min_idle_ms = min_idle_ms
        self._batch_size = batch_size
        self._block_ms = block_ms

    async def ensure_group(self) -> None:
        """Create the consumer group (MKSTREAM); idempotent."""
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def poll_once(self, *, block_ms: int | None = None) -> int:
        """Read and process new messages once. Returns number processed."""
        response = await self._redis.xreadgroup(
            groupname=self._group,
            consumername=self._consumer_name,
            streams={self._stream: ">"},
            count=self._batch_size,
            block=block_ms if block_ms is not None else self._block_ms,
        )
        processed = 0
        for _stream_name, entries in response or []:
            for message_id, fields in entries:
                await self._process(_decode(message_id), fields, delivery_count=1)
                processed += 1
        return processed

    async def claim_stuck_once(self, *, min_idle_ms: int | None = None) -> int:
        """Reclaim messages idle past min_idle via XAUTOCLAIM and process them.

        Messages at/over the delivery-attempt limit are dead-lettered and
        ACKed instead of being retried forever (ADR-0004).
        """
        min_idle = min_idle_ms if min_idle_ms is not None else self._min_idle_ms
        result = await self._redis.xautoclaim(
            self._stream,
            self._group,
            self._consumer_name,
            min_idle_time=min_idle,
            start_id="0-0",
            count=self._batch_size,
        )
        # redis-py returns (next_start, messages) or (next_start, messages, deleted)
        entries = result[1] if len(result) >= 2 else []
        processed = 0
        for message_id, fields in entries:
            if fields is None:  # tombstone of a trimmed entry
                continue
            mid = _decode(message_id)
            delivery_count = await self._delivery_count(mid)
            if delivery_count >= self._max_delivery_attempts:
                await self._to_dead_letter(
                    mid,
                    fields,
                    error_code="MAX_DELIVERY_ATTEMPTS_EXCEEDED",
                    error_detail=(
                        f"{delivery_count} delivery attempts "
                        f"(limit {self._max_delivery_attempts})"
                    ),
                    delivery_count=delivery_count,
                )
                await self._ack(mid)
            else:
                await self._process(mid, fields, delivery_count=delivery_count)
            processed += 1
        return processed

    async def run(self, *, stop: asyncio.Event, claim_interval_s: float = 15.0) -> None:
        """Consume until `stop` is set: poll new messages + periodic stuck-claim."""
        await self.ensure_group()
        last_claim = 0.0
        loop = asyncio.get_running_loop()
        while not stop.is_set():
            await self.poll_once()
            now = loop.time()
            if now - last_claim >= claim_interval_s:
                await self.claim_stuck_once()
                last_claim = now

    async def _delivery_count(self, message_id: str) -> int:
        pending = await self._redis.xpending_range(
            self._stream, self._group, min=message_id, max=message_id, count=1
        )
        if not pending:
            return 1
        entry = pending[0]
        return int(entry.get("times_delivered", 1))

    async def _ack(self, message_id: str) -> None:
        await self._redis.xack(self._stream, self._group, message_id)

    async def _to_dead_letter(
        self,
        message_id: str,
        fields: dict[bytes | str, bytes | str],
        *,
        error_code: str,
        error_detail: str,
        delivery_count: int,
    ) -> None:
        decoded = _decode_fields(fields)
        await self._dead_letter(
            DeadLetteredMessage(
                stream=self._stream,
                group=self._group,
                message_id=message_id,
                raw_fields=decoded,
                error_code=error_code,
                error_detail=error_detail,
                tenant_id=decoded.get("tenant_id"),
                trace_id=decoded.get("trace_id"),
                delivery_count=delivery_count,
            )
        )

    async def _process(
        self,
        message_id: str,
        fields: dict[bytes | str, bytes | str],
        *,
        delivery_count: int,
    ) -> None:
        try:
            envelope = fields_to_message(fields)
        except MalformedPipelineMessage as exc:
            # Unprocessable by construction: DLQ immediately, then ACK.
            await self._to_dead_letter(
                message_id,
                fields,
                error_code="MALFORMED_PIPELINE_MESSAGE",
                error_detail=str(exc),
                delivery_count=delivery_count,
            )
            await self._ack(message_id)
            return

        message = ReceivedMessage(
            stream=self._stream,
            message_id=message_id,
            tenant_id=envelope.tenant_id,
            trace_id=envelope.trace_id,
            payload=envelope.payload,
            delivery_count=delivery_count,
        )
        try:
            # SEC-20: tenant context is established from the envelope before —
            # and torn down after — the handler. No context, no processing.
            async with self._tenant_context(message):
                await self._handler(message)
        except Exception as exc:
            if delivery_count >= self._max_delivery_attempts:
                await self._to_dead_letter(
                    message_id,
                    fields,
                    error_code="HANDLER_FAILED",
                    error_detail=f"{type(exc).__name__}: {exc}",
                    delivery_count=delivery_count,
                )
                await self._ack(message_id)
            else:
                # Leave unACKed: XAUTOCLAIM retries it after min_idle.
                logger.warning(
                    "handler failed; message left pending for retry",
                    extra={
                        "stream": self._stream,
                        "message_id": message_id,
                        "delivery_count": delivery_count,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
            return
        await self._ack(message_id)
