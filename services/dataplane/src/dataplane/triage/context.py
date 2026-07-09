"""Single-tenant context assembly + prompt build (SEC-32/33/36, AC-52).

Rules enforced here:
- every fetcher takes an explicit tenant_id and runs tenant-scoped
  (PG: SET LOCAL RLS GUC; ES: per-tenant alias) — no cross-tenant batching,
  one alert (one tenant) per prompt, no caches, no conversation reuse;
- fetched rows are verified against the requested tenant_id (defense in
  depth on top of RLS);
- event content is trimmed before it can reach a prompt: field-length caps,
  raw/unmapped blobs dropped, base64/hex blobs scrubbed, max N events;
- the prompt places ALL alert/event-derived text inside a fenced untrusted
  block with a random-per-call boundary marker and explicit
  "data, not instructions" framing; the system prompt is static.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from dataplane.triage.prompts import (
    PROMPT_VERSION,
    load_system_prompt,
    load_user_template,
)
from soc_tenancy import events_alias, set_local_tenant, validate_tenant_uuid

_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{64,}|\b[0-9a-fA-F]{40,}\b")
_BLOB_PLACEHOLDER = "[blob-removed]"
_DROPPED_EVENT_KEYS = frozenset({"raw", "unmapped", "batch_id", "tenant_id", "source"})


class TenantMismatchError(RuntimeError):
    """A tenant-scoped fetcher returned a row for a different tenant (SEC-36)."""


@dataclass(frozen=True, slots=True)
class AlertRow:
    """The alert fields triage needs (tenantdata.alerts subset)."""

    id: str
    tenant_id: UUID
    rule_id: str
    rule_version: str
    rule_title: str
    rule_severity: str
    mitre_technique_ids: tuple[str, ...]
    entity_hostname: str | None
    entity_user: str | None
    asset_id: UUID | None
    occurrence_count: int
    first_seen: str
    last_seen: str
    triage_status: str
    triage_attempts: int


@dataclass(frozen=True, slots=True)
class EventRef:
    event_id: str
    es_index: str


@dataclass(frozen=True, slots=True)
class AlertContext:
    """Everything the prompt may contain, for exactly one tenant."""

    tenant_id: UUID
    alert: AlertRow
    events: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class BuiltPrompt:
    system: str
    user: str
    boundary: str
    prompt_version: str = PROMPT_VERSION


class AlertFetcher(Protocol):
    async def fetch_alert(self, tenant_id: UUID, alert_id: str) -> AlertRow | None: ...

    async def fetch_event_refs(
        self, tenant_id: UUID, alert_id: str, *, limit: int
    ) -> list[EventRef]: ...


class EventFetcher(Protocol):
    async def fetch_events(
        self, tenant_id: UUID, refs: list[EventRef]
    ) -> list[dict[str, Any]]: ...


# --------------------------------------------------------------------------
# Production fetchers
# --------------------------------------------------------------------------

_ALERT_SQL = """
SELECT id, tenant_id, rule_id, rule_version, rule_title, rule_severity,
       mitre_technique_ids, entity_hostname, entity_user, asset_id,
       occurrence_count, first_seen, last_seen, triage_status, triage_attempts
FROM tenantdata.alerts WHERE id = $1
"""

_EVENT_REFS_SQL = """
SELECT event_id, es_index FROM tenantdata.alert_events
WHERE alert_id = $1 ORDER BY created_at LIMIT $2
"""


class PGAlertFetcher:
    """Tenant-scoped alert/event-ref reads: RLS via SET LOCAL per transaction."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def fetch_alert(self, tenant_id: UUID, alert_id: str) -> AlertRow | None:
        tenant = validate_tenant_uuid(tenant_id)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant)
                row = await conn.fetchrow(_ALERT_SQL, alert_id)
        if row is None:
            return None
        alert = AlertRow(
            id=row["id"],
            tenant_id=validate_tenant_uuid(row["tenant_id"]),
            rule_id=row["rule_id"],
            rule_version=row["rule_version"],
            rule_title=row["rule_title"],
            rule_severity=row["rule_severity"],
            mitre_technique_ids=tuple(row["mitre_technique_ids"] or ()),
            entity_hostname=row["entity_hostname"],
            entity_user=row["entity_user"],
            asset_id=row["asset_id"],
            occurrence_count=row["occurrence_count"],
            first_seen=str(row["first_seen"]),
            last_seen=str(row["last_seen"]),
            triage_status=row["triage_status"],
            triage_attempts=row["triage_attempts"],
        )
        if alert.tenant_id != tenant:  # defense in depth over RLS
            raise TenantMismatchError(f"alert {alert_id} is not in tenant {tenant}")
        return alert

    async def fetch_event_refs(
        self, tenant_id: UUID, alert_id: str, *, limit: int
    ) -> list[EventRef]:
        tenant = validate_tenant_uuid(tenant_id)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant)
                rows = await conn.fetch(_EVENT_REFS_SQL, alert_id, limit)
        return [EventRef(event_id=str(r["event_id"]), es_index=r["es_index"]) for r in rows]


class ESEventFetcher:
    """Reads normalized event bodies via the per-tenant alias only (SEC-24)."""

    def __init__(self, es_client: Any) -> None:
        self._es = es_client

    async def fetch_events(
        self, tenant_id: UUID, refs: list[EventRef]
    ) -> list[dict[str, Any]]:
        if not refs:
            return []
        alias = events_alias(tenant_id)  # raises before I/O on bad tenant (fail closed)
        response = await self._es.mget(index=alias, ids=[r.event_id for r in refs])
        docs = response.get("docs", []) if isinstance(response, dict) else response.body["docs"]
        return [d["_source"] for d in docs if d.get("found")]


class NullEventFetcher:
    """Degraded mode (no ES reachable/configured): alert-only context."""

    async def fetch_events(
        self, tenant_id: UUID, refs: list[EventRef]
    ) -> list[dict[str, Any]]:
        return []


# --------------------------------------------------------------------------
# Trimming (SEC-33 input side)
# --------------------------------------------------------------------------


def _trim_value(value: Any, max_chars: int) -> Any:
    if isinstance(value, str):
        scrubbed = _BLOB_RE.sub(_BLOB_PLACEHOLDER, value)
        if len(scrubbed) > max_chars:
            scrubbed = scrubbed[:max_chars] + "…[truncated]"
        return scrubbed
    if isinstance(value, dict):
        return {
            k: _trim_value(v, max_chars)
            for k, v in value.items()
            if k not in _DROPPED_EVENT_KEYS
        }
    if isinstance(value, list):
        return [_trim_value(v, max_chars) for v in value[:16]]
    return value


def trim_event(event: dict[str, Any], *, max_chars: int) -> dict[str, Any]:
    """Bound one normalized event before it may enter a prompt (SEC-33)."""
    trimmed = _trim_value(event, max_chars)
    assert isinstance(trimmed, dict)
    return trimmed


# --------------------------------------------------------------------------
# Assembly + prompt build
# --------------------------------------------------------------------------


async def assemble_context(
    *,
    tenant_id: UUID,
    alert_id: str,
    alerts: AlertFetcher,
    events: EventFetcher,
    max_events: int,
    max_field_chars: int,
) -> AlertContext | None:
    """Build the single-tenant context for one alert (SEC-36).

    Returns None when the alert does not exist in this tenant (stale message).
    """
    tenant = validate_tenant_uuid(tenant_id)
    alert = await alerts.fetch_alert(tenant, alert_id)
    if alert is None:
        return None
    refs = await alerts.fetch_event_refs(tenant, alert_id, limit=max_events)
    bodies = await events.fetch_events(tenant, refs)
    trimmed = tuple(trim_event(e, max_chars=max_field_chars) for e in bodies[:max_events])
    return AlertContext(tenant_id=tenant, alert=alert, events=trimmed)


def _context_as_json(ctx: AlertContext) -> str:
    alert = ctx.alert
    data = {
        "alert": {
            "rule_title": alert.rule_title,
            "rule_severity": alert.rule_severity,
            "mitre_technique_ids": list(alert.mitre_technique_ids),
            "entity": {"hostname": alert.entity_hostname, "user": alert.entity_user},
            "occurrence_count": alert.occurrence_count,
            "first_seen": alert.first_seen,
            "last_seen": alert.last_seen,
        },
        "events": list(ctx.events),
    }
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


def build_prompt(ctx: AlertContext, *, correction: str | None = None) -> BuiltPrompt:
    """Fixed system prompt + fenced untrusted data block (SEC-32).

    The boundary marker is random per call; if (absurdly) the data contains
    the marker, a fresh one is drawn. `correction` is OUR validator feedback
    (error labels only, never model/telemetry text) appended to the
    instruction section for the single regeneration pass.
    """
    data = _context_as_json(ctx)
    boundary = secrets.token_hex(8)
    while boundary in data:  # pragma: no cover - 2^-64 event
        boundary = secrets.token_hex(8)
    correction_text = ""
    if correction:
        correction_text = (
            "\nYour previous reply was rejected by the format validator for these"
            f" reasons: {correction}. Produce a new reply that fixes every issue"
            " while following all rules."
        )
    user = load_user_template().substitute(
        boundary=boundary, data=data, correction=correction_text
    )
    return BuiltPrompt(system=load_system_prompt(), user=user, boundary=boundary)
