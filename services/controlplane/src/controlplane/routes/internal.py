"""Internal operator/service APIs (contract §5/§13; SEC-30/39/40).

Mounted ONLY on the internal app/listener (controlplane.internal_app) —
NEVER on the public app. Auth: HMAC-signed short-lived service tokens
(design §5.1); plan and abuse-freeze changes additionally require the
`X-Operator-Id` identity claim, recorded with old+new values in the audit
entry, in the same transaction as the change (SEC-43).

On every plan/abuse-freeze change: update PG, then DELETE `ent:{t}` and
`tenantstatus:{t}` — delete-on-change makes propagation <=60s (SEC-39) /
<=5min (AC-11/15).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request

from controlplane import queries
from controlplane.ids import rfc3339
from controlplane.models import AbuseFreezeRequest, PlanChangeRequest
from controlplane.security.service_auth import ServiceCaller, require_service_auth
from soc_audit import Actor, Target, write_audit
from soc_schemas.errors import ApiError, ErrorCode
from soc_tenancy import set_local_tenant

router = APIRouter()

service_auth = require_service_auth()
operator_auth = require_service_auth(operator_required=True)


def _tenant_uuid(tenant_id: str) -> UUID:
    try:
        return UUID(tenant_id)
    except ValueError:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.") from None


@router.get("/internal/v1/tenants/{tenant_id}/entitlements")
async def internal_entitlements(
    tenant_id: str, request: Request, caller: ServiceCaller = Depends(service_auth)
) -> dict:
    """Entitlements-client source (ADR-0005). Same shape as the public §5 payload."""
    services = request.app.state.services
    payload = await services.entitlements.get(_tenant_uuid(tenant_id))
    if payload is None:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    return payload


@router.put("/internal/v1/tenants/{tenant_id}/plan")
async def change_plan(
    tenant_id: str,
    body: PlanChangeRequest,
    request: Request,
    caller: ServiceCaller = Depends(operator_auth),
) -> dict:
    """[A] Operator plan change (AC-11/15, SEC-40): audit stores old+new values
    plus the operator identity, in the same transaction as the update."""
    services = request.app.state.services
    tenant = _tenant_uuid(tenant_id)
    now = services.clock()
    async with services.db.acquire() as conn:
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            before = await conn.fetchrow(queries.SELECT_TENANT_BY_ID, tenant)
            if before is None:
                raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
            after = await conn.fetchrow(queries.UPDATE_TENANT_PLAN, tenant, body.plan, now)
            await write_audit(
                conn,
                tenant_id=tenant,
                actor=Actor(type="user", id=caller.operator_id or "unknown"),
                action_type="tenant.plan_changed",
                target=Target(type="tenant", id=str(tenant)),
                before={
                    "plan": before["plan_id"],
                    "status": str(before["status"]),
                    "trial_expires_at": (
                        rfc3339(before["trial_expires_at"])
                        if before["trial_expires_at"]
                        else None
                    ),
                },
                after={
                    "plan": after["plan_id"],
                    "status": str(after["status"]),
                    "trial_expires_at": (
                        rfc3339(after["trial_expires_at"]) if after["trial_expires_at"] else None
                    ),
                },
                reason_code="operator_plan_change",
            )
    # Delete-on-change: entitlement cache + tenant-status key (AC-15/SEC-39).
    await services.entitlements.invalidate(tenant)
    return {"tenant_id": str(tenant), "plan": after["plan_id"]}


@router.put("/internal/v1/tenants/{tenant_id}/abuse-freeze")
async def abuse_freeze(
    tenant_id: str,
    body: AbuseFreezeRequest,
    request: Request,
    caller: ServiceCaller = Depends(operator_auth),
) -> dict:
    """[A] Set/clear tenant.abuse_frozen (G-1/SEC-39). Effective <=60s via the
    tenant-status store path — never the entitlements cache."""
    services = request.app.state.services
    tenant = _tenant_uuid(tenant_id)
    now = services.clock()
    async with services.db.acquire() as conn:
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            before = await conn.fetchrow(queries.SELECT_TENANT_BY_ID, tenant)
            if before is None:
                raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
            await conn.fetchrow(
                queries.UPDATE_TENANT_ABUSE_FREEZE,
                tenant,
                body.frozen,
                body.reason,
                now,
            )
            await write_audit(
                conn,
                tenant_id=tenant,
                actor=Actor(type="user", id=caller.operator_id or "unknown"),
                action_type="tenant.abuse_freeze_changed",
                target=Target(type="tenant", id=str(tenant)),
                before={
                    "abuse_frozen": bool(before["abuse_frozen"]),
                    "reason": before["abuse_frozen_reason"],
                },
                after={"abuse_frozen": body.frozen, "reason": body.reason},
                reason_code="operator_abuse_freeze",
            )
    # SEC-39: tenant-status key deleted => enforcement flips <=60s everywhere.
    await services.entitlements.invalidate(tenant)
    return {"tenant_id": str(tenant), "abuse_frozen": body.frozen}
