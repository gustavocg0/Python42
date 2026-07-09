"""Normalization/validation helpers for the worker-normalizer and ingest path.

- parse_event: strict validation into the discriminated union (contract §3);
  failures raise MalformedEventError carrying a stable error code + detail
  suitable for the dead-letter record (contract §6, AC-32).
- strip_client_assigned_fields: SEC-18 — server-authoritative identity fields
  are ALWAYS discarded from client payloads.
- move_unknown_to_unmapped: contract §1 — unknown incoming fields are preserved
  under `unmapped`, never dropped silently.
- truncate_generic_raw: contract §3.4 raw ≤32KB with raw_truncated=true.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import TypeAdapter, ValidationError

from soc_schemas.events import (
    MAX_RAW_BYTES,
    AuthenticationEvent,
    Event,
    EventClass,
    GenericEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)

CLIENT_ASSIGNED_FIELDS: frozenset[str] = frozenset(
    {"event_id", "tenant_id", "ingest_time", "batch_id", "source"}
)
"""Contract §5 / SEC-18: platform-assigned fields; client-sent values are ignored."""

_EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)

_CLASS_MODELS: dict[EventClass, type] = {
    EventClass.process_activity: ProcessActivityEvent,
    EventClass.network_activity: NetworkActivityEvent,
    EventClass.authentication: AuthenticationEvent,
    EventClass.generic: GenericEvent,
}


class MalformedEventError(ValueError):
    """Raised when an event fails schema validation — dead-letter it (AC-32).

    Attributes map onto the dead_letter_events record (contract §6):
    `error_code` is stable and machine-readable; `error_detail` is a
    human-readable summary (no stack traces).
    """

    def __init__(self, error_code: str, error_detail: str) -> None:
        super().__init__(f"{error_code}: {error_detail}")
        self.error_code = error_code
        self.error_detail = error_detail


def parse_event(data: Mapping[str, Any]) -> Event:
    """Validate a normalized event dict into its typed model.

    Raises MalformedEventError with a stable error code on any failure.
    """
    event_class = data.get("event_class")
    if event_class not in EventClass.__members__:
        raise MalformedEventError(
            "UNKNOWN_EVENT_CLASS",
            f"event_class must be one of {sorted(EventClass.__members__)}; got {event_class!r}",
        )
    try:
        return _EVENT_ADAPTER.validate_python(dict(data))
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
            for err in exc.errors()[:20]
        )
        raise MalformedEventError("SCHEMA_VALIDATION_FAILED", details) from exc


def strip_client_assigned_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Drop server-authoritative fields from a client payload (SEC-18, contract §5)."""
    return {k: v for k, v in payload.items() if k not in CLIENT_ASSIGNED_FIELDS}


def known_fields_for_class(event_class: EventClass | str) -> frozenset[str]:
    """Top-level field names the schema knows for the given event class."""
    model = _CLASS_MODELS[EventClass(event_class)]
    return frozenset(model.model_fields.keys())


def move_unknown_to_unmapped(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Move unrecognized top-level keys under `unmapped` (contract §1/§2).

    Returns a new dict; existing `unmapped` content is preserved and merged.
    Requires a valid `event_class` key (raise MalformedEventError otherwise).
    """
    event_class = payload.get("event_class")
    if event_class not in EventClass.__members__:
        raise MalformedEventError(
            "UNKNOWN_EVENT_CLASS",
            f"cannot compute unmapped fields without a valid event_class; got {event_class!r}",
        )
    known = known_fields_for_class(EventClass(event_class))
    result: dict[str, Any] = {}
    unmapped: dict[str, Any] = dict(payload.get("unmapped") or {})
    for key, value in payload.items():
        if key == "unmapped":
            continue
        if key in known:
            result[key] = value
        else:
            unmapped[key] = value
    if unmapped:
        result["unmapped"] = unmapped
    return result


def truncate_generic_raw(
    raw: Mapping[str, Any], *, max_bytes: int = MAX_RAW_BYTES
) -> tuple[dict[str, Any], bool]:
    """Cap a generic event's `raw` object at max_bytes (contract §3.4).

    Returns (raw_or_truncated_stand_in, truncated_flag). When over the cap the
    original object is replaced by {"truncated_json": "<prefix>"} so the stored
    value always fits and `raw_truncated=true` must be set by the caller.
    """
    serialized = json.dumps(raw, default=str, separators=(",", ":"))
    if len(serialized.encode("utf-8")) <= max_bytes:
        return dict(raw), False
    # Reserve room for the wrapper object around the JSON-string prefix.
    budget = max_bytes - 64
    prefix = serialized.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
    return {"truncated_json": prefix}, True
