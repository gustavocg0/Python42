"""Producer side of the pipeline transport (ADR-0004, SEC-20)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from redis.asyncio import Redis

from soc_pipeline.messages import PipelineMessage, message_to_fields
from soc_pipeline.streams import ALL_STREAMS, DEFAULT_MAXLEN


class StreamProducer:
    """XADD with MAXLEN ~ maxlen; every message MUST carry tenant_id + trace_id.

    tenant_id must come from the producer's authenticated context (SEC-20):
    session, ingest-key identity, or gateway-verified device identity — never
    from a client payload field.
    """

    def __init__(
        self,
        redis: Redis,
        *,
        maxlen: int = DEFAULT_MAXLEN,
        allowed_streams: tuple[str, ...] = ALL_STREAMS,
    ) -> None:
        self._redis = redis
        self._maxlen = maxlen
        self._allowed_streams = allowed_streams

    async def publish(
        self,
        stream: str,
        *,
        tenant_id: UUID | str,
        trace_id: str,
        payload: dict[str, Any],
    ) -> str:
        """Publish one message; returns the stream entry id.

        Raises ValueError before any I/O when the envelope is invalid
        (unknown stream, missing/invalid tenant_id or trace_id) — fail closed.
        """
        if stream not in self._allowed_streams:
            raise ValueError(
                f"unknown stream {stream!r}; pipeline streams are {self._allowed_streams}"
            )
        message = PipelineMessage(
            tenant_id=UUID(str(tenant_id)),
            trace_id=trace_id,
            payload=payload,
        )
        entry_id = await self._redis.xadd(
            stream,
            message_to_fields(message),  # type: ignore[arg-type]
            maxlen=self._maxlen,
            approximate=True,
        )
        return entry_id.decode() if isinstance(entry_id, bytes) else entry_id
