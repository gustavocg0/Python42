"""Pipeline message envelope (SEC-20).

`tenant_id` in the stream envelope is set ONLY by the authenticated producer.
Consumers establish tenant context from THIS envelope, never from fields
inside the event payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

TENANT_ID_FIELD = "tenant_id"
TRACE_ID_FIELD = "trace_id"
PAYLOAD_FIELD = "payload"


class MalformedPipelineMessage(ValueError):
    """A stream entry missing/invalid tenant_id, trace_id, or payload."""


class PipelineMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    trace_id: str = Field(min_length=1)
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ReceivedMessage:
    """A message as delivered to a consumer handler.

    tenant_id/trace_id come from the authenticated stream envelope (SEC-20).
    """

    stream: str
    message_id: str
    tenant_id: UUID
    trace_id: str
    payload: dict[str, Any] = field(hash=False)
    delivery_count: int = 1


def message_to_fields(message: PipelineMessage) -> dict[str, str]:
    """Flatten a message into XADD fields."""
    return {
        TENANT_ID_FIELD: str(message.tenant_id),
        TRACE_ID_FIELD: message.trace_id,
        PAYLOAD_FIELD: json.dumps(message.payload, separators=(",", ":"), default=str),
    }


def _decode(value: bytes | str) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else value


def fields_to_message(fields: dict[bytes | str, bytes | str]) -> PipelineMessage:
    """Parse raw stream fields back into a validated message.

    Raises MalformedPipelineMessage on any missing/invalid part — the consumer
    dead-letters such entries instead of processing them.
    """
    decoded = {_decode(k): _decode(v) for k, v in fields.items()}
    tenant_raw = decoded.get(TENANT_ID_FIELD)
    trace_id = decoded.get(TRACE_ID_FIELD)
    payload_raw = decoded.get(PAYLOAD_FIELD)
    if not tenant_raw or not trace_id or payload_raw is None:
        raise MalformedPipelineMessage(
            "pipeline message must carry tenant_id, trace_id, and payload"
        )
    try:
        tenant_id = UUID(tenant_raw)
    except ValueError as exc:
        raise MalformedPipelineMessage(f"invalid tenant_id in envelope: {tenant_raw!r}") from exc
    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError as exc:
        raise MalformedPipelineMessage("payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise MalformedPipelineMessage("payload must be a JSON object")
    return PipelineMessage(tenant_id=tenant_id, trace_id=trace_id, payload=payload)
