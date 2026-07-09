"""GET /v1/tenant/entitlements (contract §5) — any role, read-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from controlplane.authz import SessionPrincipal, require_roles
from soc_schemas.errors import ApiError, ErrorCode

router = APIRouter()

any_role = require_roles("admin", "analyst")


@router.get("/v1/tenant/entitlements")
async def tenant_entitlements(
    request: Request, principal: SessionPrincipal = Depends(any_role)
) -> dict:
    services = request.app.state.services
    payload = await services.entitlements.get(principal.tenant_id)
    if payload is None:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    return payload
