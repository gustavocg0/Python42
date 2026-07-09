"""Ingestion endpoints (contract §6) + ingest-key console CRUD + usage.

Check order on the batch path (design §4.3, BINDING):
identity/allowlist (401/503) -> tenant status (402/403) -> size (413) ->
quota (429, never 202-then-drop) -> XADD pipe:raw -> 202 {batch_id, accepted}.
p95 <= 300ms: no event parsing beyond count/size (normalization is async).
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response
from opentelemetry import trace
from redis.exceptions import RedisError

from dataplane.api.deps import (
    DeviceIdentity,
    IngestKeyIdentity,
    agent_auth,
    get_resources,
    ingest_key_auth,
    not_found,
    session_auth,
)
from dataplane.api.models import IngestKeyCreateRequest
from dataplane.core.ids import new_id
from dataplane.core.onboarding import signal_step
from dataplane.core.resources import AppResources
from dataplane.core.sessions import SessionPrincipal
from dataplane.core.tokens import mint_secret
from soc_audit import Actor, Target, write_audit
from soc_pipeline import StreamProducer
from soc_pipeline.streams import STREAM_RAW
from soc_schemas import ApiError, ErrorCode
from soc_telemetry import PipelineOutcome, PipelineStage

router = APIRouter()

_INSERT_KEY_SQL = (
    "INSERT INTO tenantdata.ingest_keys (id, tenant_id, name, key_hash, created_by) "
    "VALUES ($1, $2, $3, $4, $5)"
)
_LIST_KEYS_SQL = (
    "SELECT id, name, created_at, last_used_at FROM tenantdata.ingest_keys "
    "WHERE revoked_at IS NULL ORDER BY created_at DESC"
)
_REVOKE_KEY_SQL = (
    "UPDATE tenantdata.ingest_keys SET revoked_at = now(), revoked_by = $2 "
    "WHERE id = $1 AND revoked_at IS NULL RETURNING id"
)


def _trace_id() -> str:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else uuid4().hex


async def _read_batch(request: Request, resources: AppResources) -> list[Any]:
    """Size/count checks only — no schema validation on the hot path (AC-30)."""
    settings = resources.settings
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > settings.ingest_max_bytes:
                raise ApiError(
                    ErrorCode.BATCH_TOO_LARGE,
                    f"Batch exceeds {settings.ingest_max_bytes} bytes.",
                    details={"max_bytes": settings.ingest_max_bytes},
                )
        except ValueError:
            pass
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > settings.ingest_max_bytes:
            raise ApiError(
                ErrorCode.BATCH_TOO_LARGE,
                f"Batch exceeds {settings.ingest_max_bytes} bytes.",
                details={"max_bytes": settings.ingest_max_bytes},
            )
    try:
        payload = json.loads(bytes(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, "Body must be JSON: {\"events\": [...]}."
        ) from None
    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        raise ApiError(ErrorCode.VALIDATION_ERROR, "Body must contain an 'events' array.")
    if len(events) > settings.ingest_max_events:
        raise ApiError(
            ErrorCode.BATCH_TOO_LARGE,
            f"Batch exceeds {settings.ingest_max_events} events.",
            details={"max_events": settings.ingest_max_events},
        )
    return events


async def _handle_batch(
    request: Request,
    resources: AppResources,
    tenant_id: UUID,
    *,
    source_type: str,
    source_ctx: dict[str, str],
) -> dict[str, Any]:
    started = time.perf_counter()
    # 2. tenant status (402 TRIAL_EXPIRED / 403 TENANT_FROZEN cause=abuse)
    await resources.status_stores.require_ingest_allowed(tenant_id)
    # 3. size / count (413)
    events = await _read_batch(request, resources)
    batch_uuid = uuid4()
    batch_id = f"b_{batch_uuid.hex}"  # opaque wire id (contract §6)
    if not events:
        return {"batch_id": batch_id, "accepted": 0}
    # 4. quota (429 + Retry-After; 503 ENTITLEMENTS_UNAVAILABLE on cold cache)
    snapshot = await resources.entitlements.get(tenant_id)
    limit = int(snapshot.entitlements.ingest_events_per_min)
    try:
        await resources.quotas.check_and_consume_ingest(tenant_id, len(events), limit)
    except ApiError as err:
        if err.code == ErrorCode.INGEST_QUOTA_EXCEEDED:
            await resources.quotas.bump_usage(tenant_id, "throttled_batches", 1)
            await resources.quotas.bump_usage(tenant_id, "rejected_events", len(events))
            resources.metrics.record(
                tenant_id=tenant_id,
                stage=PipelineStage.ingest,
                outcome=PipelineOutcome.rejected,
                count=len(events),
                duration_seconds=time.perf_counter() - started,
            )
        raise
    # 5. XADD pipe:raw — payload shape is BINDING for worker-normalizer
    #    (Architect-ratified): {batch_id: uuid, source_type, ingest_time,
    #    source: {device_id|ingest_key_id, ...}, events}.
    producer: StreamProducer = resources.producer
    try:
        await producer.publish(
            STREAM_RAW,
            tenant_id=tenant_id,
            trace_id=_trace_id(),
            payload={
                "batch_id": str(batch_uuid),
                "source_type": source_type,
                "ingest_time": datetime.now(UTC).isoformat(),
                "source": dict(source_ctx),
                "events": events,
            },
        )
    except RedisError:
        resources.metrics.record(
            tenant_id=tenant_id, stage=PipelineStage.ingest, outcome=PipelineOutcome.error
        )
        raise ApiError(
            ErrorCode.SERVICE_UNAVAILABLE,
            "Ingest pipeline unavailable; buffer and retry.",
            retry_after_seconds=30,
        ) from None
    await resources.quotas.bump_usage(tenant_id, "events_accepted", len(events))
    await signal_step(resources.redis, tenant_id, "first_event")
    resources.metrics.record(
        tenant_id=tenant_id,
        stage=PipelineStage.ingest,
        outcome=PipelineOutcome.ok,
        count=len(events),
        duration_seconds=time.perf_counter() - started,
    )
    return {"batch_id": batch_id, "accepted": len(events)}


@router.post("/v1/agent/events", status_code=202)
async def agent_events(
    request: Request,
    device: Annotated[DeviceIdentity, Depends(agent_auth)],
) -> dict[str, Any]:
    resources = get_resources(request)
    return await _handle_batch(
        request,
        resources,
        device.tenant_id,
        source_type="agent",
        source_ctx={"device_id": device.device_id},
    )


@router.post("/v1/ingest/events", status_code=202)
async def generic_events(
    request: Request,
    key: Annotated[IngestKeyIdentity, Depends(ingest_key_auth)],
) -> dict[str, Any]:
    resources = get_resources(request)
    return await _handle_batch(
        request,
        resources,
        key.tenant_id,
        source_type="generic",
        source_ctx={"ingest_key_id": key.key_id},
    )


# ------------------------------------------------------- console: ingest keys
@router.post("/v1/ingest-keys", status_code=201)
async def create_ingest_key(
    body: IngestKeyCreateRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    key_id = new_id("ik")
    minted = mint_secret(key_id, principal.tenant_id)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        await conn.execute(
            _INSERT_KEY_SQL,
            key_id,
            principal.tenant_id,
            body.name,
            minted.secret_hash,
            principal.user_id,
        )
        row = await conn.fetchrow(
            "SELECT created_at FROM tenantdata.ingest_keys WHERE id = $1", key_id
        )
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="ingest_key.create",
            target=Target(type="ingest_key", id=key_id),
            after={"name": body.name},
        )
    await signal_step(resources.redis, principal.tenant_id, "create_ingest_key")
    return {
        "id": key_id,
        "name": body.name,
        "key": minted.wire_token,  # shown once (SEC-16)
        "created_at": row["created_at"] if row else None,
    }


@router.get("/v1/ingest-keys")
async def list_ingest_keys(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        rows = await conn.fetch(_LIST_KEYS_SQL)
    items = [
        {
            "id": r["id"],
            "name": r["name"],
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
        }
        for r in rows
    ]
    return {"items": items, "next_cursor": None, "total_estimate": len(items)}


@router.delete("/v1/ingest-keys/{key_id}", status_code=204)
async def revoke_ingest_key(
    key_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> Response:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        row = await conn.fetchrow(_REVOKE_KEY_SQL, key_id, principal.user_id)
        if row is None:
            not_found("ingest_key", key_id, principal.tenant_id)
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="ingest_key.revoke",
            target=Target(type="ingest_key", id=key_id),
        )
    # Delete-on-change: <=60s propagation is the TTL worst case (SEC-17).
    await resources.status_stores.invalidate_ingest_key(principal.tenant_id, key_id)
    return Response(status_code=204)


# ------------------------------------------------------------- usage (AC-88)
@router.get("/v1/tenant/usage/ingest")
async def ingest_usage(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    snapshot = await resources.entitlements.get(principal.tenant_id)
    limit = int(snapshot.entitlements.ingest_events_per_min)
    current = await resources.quotas.current_ingest_rate(principal.tenant_id)
    throttled = await resources.quotas.usage_24h(principal.tenant_id, "throttled_batches")
    rejected = await resources.quotas.usage_24h(principal.tenant_id, "rejected_events")
    return {
        "events_per_min_current": current,
        "events_per_min_limit": limit,
        "throttled_batches_24h": throttled,
        "rejected_events_24h": rejected,
        "warning_active": limit > 0 and current >= int(limit * 0.8),
    }
