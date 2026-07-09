"""/healthz and /readyz (contract §13, AC-90) — mounted on BOTH listeners."""

from __future__ import annotations

from fastapi import APIRouter, Request

from controlplane.authz import public
from controlplane.queries import SELECT_ONE
from soc_schemas.errors import ApiError, ErrorCode

router = APIRouter()


@router.get("/healthz")
@public
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
@public
async def readyz(request: Request) -> dict:
    services = request.app.state.services
    try:
        async with services.db.acquire() as conn:
            await conn.fetchval(SELECT_ONE)
        await services.redis.ping()
    except Exception:
        raise ApiError(
            ErrorCode.SERVICE_UNAVAILABLE,
            "Dependencies not ready.",
            retry_after_seconds=5,
        ) from None
    return {"status": "ready"}
