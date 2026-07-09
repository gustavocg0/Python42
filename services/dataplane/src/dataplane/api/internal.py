"""Internal APIs (contract §13) — mounted ONLY on the internal listener
(dataplane.internal_main), never exposed via the gateway (SEC-30/40).

Auth: HMAC-signed short-lived service tokens (design §5.1 item 2).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict

from dataplane.api.deps import get_resources, service_token_auth
from dataplane.core.db import from_jsonb
from dataplane.core.onboarding import STEP_IDS
from soc_schemas import ApiError, ErrorCode
from soc_tenancy import events_alias, events_index, validate_tenant_uuid

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(service_token_auth)])


def _tenant_uuid(raw: str) -> UUID:
    try:
        return validate_tenant_uuid(raw)
    except Exception:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "tenant_id must be a UUID.",
            details={"fields": ["tenant_id"]},
        ) from None


def _parse_time(value: str | None, field: str, default: datetime) -> datetime:
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            f"{field} must be RFC3339.",
            details={"fields": [field]},
        ) from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class ProvisionRequest(BaseModel):
    """Saga body: {"tenant_id": "<uuid>"} — must match the path when sent."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID | None = None


# ---------------------------------------------------------------- provision
@router.put("/internal/v1/tenants/{tenant_id}/provision")
async def provision_tenant(
    tenant_id: str, request: Request, body: ProvisionRequest | None = None
) -> dict[str, Any]:
    """Ratified §13 addition: IDEMPOTENT data-plane provisioning step called
    by the controlplane saga (service token "controlplane", body tenant_id
    mirrors the path) — first monthly ES index + events-{tenant} alias +
    onboarding_steps seed. ES ownership stays in the data plane
    (ADR-0001/0003). Success is always 200 (idempotent retries included)."""
    resources = get_resources(request)
    tenant = _tenant_uuid(tenant_id)
    if body is not None and body.tenant_id is not None and body.tenant_id != tenant:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "body tenant_id must match the path tenant_id.",
            details={"fields": ["tenant_id"]},
        )
    index_name = events_index(tenant, datetime.now(UTC))
    alias = events_alias(tenant)
    index_created = False
    try:
        await resources.es.indices.create(index=index_name, aliases={alias: {}})
        index_created = True
    except Exception as exc:
        if "resource_already_exists" not in str(exc):
            logger.exception("provision: ES index create failed for %s", tenant)
            raise ApiError(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Event store unavailable; retry provisioning.",
                retry_after_seconds=15,
            ) from None
        # Index already there (idempotent retry) — make sure the alias is too.
        try:
            await resources.es.indices.put_alias(index=index_name, name=alias)
        except Exception:
            logger.exception("provision: ES alias ensure failed for %s", tenant)
            raise ApiError(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Event store unavailable; retry provisioning.",
                retry_after_seconds=15,
            ) from None
    async with resources.db.tenant_transaction(tenant) as conn:
        for step_id in STEP_IDS:
            await conn.execute(
                "INSERT INTO tenantdata.onboarding_steps (tenant_id, step_id) "
                "VALUES ($1, $2) ON CONFLICT (tenant_id, step_id) DO NOTHING",
                tenant,
                step_id,
            )
    return {
        "tenant_id": str(tenant),
        "es_index": index_name,
        "es_alias": alias,
        "index_created": index_created,
        "onboarding_seeded": True,
    }


# ----------------------------------------------------------------- metering
@router.get("/internal/v1/metering/llm")
async def metering_llm(
    request: Request,
    tenant_id: Annotated[str, Query()],
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    tenant = _tenant_uuid(tenant_id)
    now = datetime.now(UTC)
    start = _parse_time(from_, "from", now.replace(hour=0, minute=0, second=0, microsecond=0))
    end = _parse_time(to, "to", now)
    async with resources.db.tenant_transaction(tenant) as conn:
        rows = await conn.fetch(
            "SELECT date_trunc('day', created_at)::date AS day, model_id, "
            "sum(tokens_in) AS tokens_in, sum(tokens_out) AS tokens_out, "
            "count(*) AS calls, sum(cost_usd) AS cost_usd, "
            "percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_ms_p95 "
            "FROM tenantdata.llm_metering "
            "WHERE created_at >= $1 AND created_at <= $2 "
            "GROUP BY 1, 2 ORDER BY 1, 2",
            start,
            end,
        )
    items = [
        {
            "day": str(r["day"]),
            "model_id": r["model_id"],
            "tokens_in": int(r["tokens_in"]),
            "tokens_out": int(r["tokens_out"]),
            "calls": int(r["calls"]),
            "cost_usd": float(r["cost_usd"]),
            "latency_ms_p95": float(r["latency_ms_p95"]) if r["latency_ms_p95"] else None,
        }
        for r in rows
    ]
    return {"tenant_id": str(tenant), "items": items}


@router.get("/internal/v1/metering/deep-investigation")
async def metering_deep_investigation(
    request: Request,
    tenant_id: Annotated[str, Query()],
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    tenant = _tenant_uuid(tenant_id)
    now = datetime.now(UTC)
    start = _parse_time(from_, "from", now.replace(hour=0, minute=0, second=0, microsecond=0))
    end = _parse_time(to, "to", now)
    async with resources.db.tenant_transaction(tenant) as conn:
        rows = await conn.fetch(
            "SELECT id, alert_id, status, is_stub, engine_version, requested_by, "
            "requested_at, completed_at, quota_limit, quota_remaining "
            "FROM tenantdata.deep_investigation_runs "
            "WHERE requested_at >= $1 AND requested_at <= $2 ORDER BY requested_at",
            start,
            end,
        )
    items = [
        {
            "investigation_id": r["id"],
            "alert_id": r["alert_id"],
            "status": r["status"],
            "is_stub": r["is_stub"],
            "engine_version": r["engine_version"],
            "requested_by": str(r["requested_by"]),
            "requested_at": r["requested_at"],
            "completed_at": r["completed_at"],
            "quota_limit": r["quota_limit"],
            "quota_remaining": r["quota_remaining"],
        }
        for r in rows
    ]
    return {"tenant_id": str(tenant), "items": items}


# -------------------------------------------------------------- fp feedback
@router.get("/internal/v1/fp-feedback")
async def fp_feedback(
    request: Request,
    rule_id: Annotated[str | None, Query()] = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
    tenant_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """AC-46 export for detection-engineering: false_positive closes.

    Optional tenant_id narrows to one tenant; otherwise all tenants are
    iterated (tenant-pinned RLS reads per tenant — RLS is never bypassed).
    """
    resources = get_resources(request)
    now = datetime.now(UTC)
    start = _parse_time(from_, "from", now.replace(hour=0, minute=0, second=0, microsecond=0))
    end = _parse_time(to, "to", now)
    if tenant_id:
        tenants = [_tenant_uuid(tenant_id)]
    else:
        async with resources.db.system_transaction() as conn:
            tenant_rows = await conn.fetch("SELECT id FROM control.tenants ORDER BY id")
        tenants = [r["id"] for r in tenant_rows]
    where = "close_reason = 'false_positive' AND closed_at >= $1 AND closed_at <= $2"
    args: list[Any] = [start, end]
    if rule_id:
        where += " AND rule_id = $3"
        args.append(rule_id)
    items: list[dict[str, Any]] = []
    for tenant in tenants:
        async with resources.db.tenant_transaction(tenant) as conn:
            rows = await conn.fetch(
                "SELECT id, rule_id, entity_hostname, entity_user, close_reason, "
                "close_comment, closed_at, priority_inputs "
                f"FROM tenantdata.alerts WHERE {where} ORDER BY closed_at",
                *args,
            )
        for r in rows:
            items.append(
                {
                    "tenant_id": str(tenant),
                    "alert_id": r["id"],
                    "rule_id": r["rule_id"],
                    "entity": {"hostname": r["entity_hostname"], "user": r["entity_user"]},
                    "reason": r["close_reason"],
                    "comment": r["close_comment"],
                    "at": r["closed_at"],
                    "priority_inputs": from_jsonb(r["priority_inputs"]) or {},
                }
            )
    return {"items": items}
