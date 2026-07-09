"""Deep-investigation stub + quota flow (contract §9, AC-53..55, SEC-35).

MVP: synchronous stub, NO model call. The response shape is the PERMANENT
contract — the real engine later fills the arrays without breaking clients.
Quota: atomic check-and-DECR on quota:di:{t}:{yyyymmdd} (denial consumes
nothing; -1 = unlimited skips the key entirely)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from dataplane.api.deps import get_resources, not_found, session_auth
from dataplane.core.db import from_jsonb, to_jsonb
from dataplane.core.ids import new_id
from dataplane.core.pagination import clamp_limit, decode_cursor, encode_cursor, page
from dataplane.core.quotas import next_utc_midnight
from dataplane.core.sessions import SessionPrincipal
from soc_audit import Actor, Target, write_audit
from soc_schemas import ApiError, ErrorCode

router = APIRouter()

STUB_SUMMARY = (
    "Deep investigation is coming soon. This placeholder confirms your "
    "entitlement and quota flow."
)
ENGINE_VERSION = "stub-1"

_INSERT_RUN_SQL = (
    "INSERT INTO tenantdata.deep_investigation_runs "
    "(id, tenant_id, alert_id, status, is_stub, engine_version, requested_by, "
    " requested_at, completed_at, summary, confidence, findings, timeline, "
    " evidence_graph, recommended_actions, quota_limit, quota_remaining) "
    "VALUES ($1, $2, $3, 'completed', true, $4, $5, $6, $7, $8, NULL, '[]'::jsonb, "
    "        '[]'::jsonb, $9::jsonb, '[]'::jsonb, $10, $11)"
)
_METER_SQL = (
    "INSERT INTO tenantdata.llm_metering "
    "(tenant_id, call_type, alert_id, model_id, tokens_in, tokens_out, cost_usd, "
    " latency_ms, outcome) "
    "VALUES ($1, 'deep_investigation', $2, $3, 0, 0, 0, 0, 'ok')"
)


def _run_response(
    *,
    investigation_id: str,
    alert_id: str,
    requested_by: str,
    requested_at: datetime,
    completed_at: datetime,
    quota_limit: int,
    quota_remaining: int,
    resets_at: datetime,
) -> dict[str, Any]:
    """EXACT contract §9 stub shape (permanent)."""
    return {
        "investigation_id": investigation_id,
        "alert_id": alert_id,
        "status": "completed",
        "is_stub": True,
        "engine_version": ENGINE_VERSION,
        "requested_at": requested_at,
        "completed_at": completed_at,
        "requested_by": requested_by,
        "summary": STUB_SUMMARY,
        "confidence": None,
        "findings": [],
        "timeline": [],
        "evidence_graph": {"nodes": [], "edges": []},
        "recommended_actions": [],
        "quota": {
            "limit": quota_limit,
            "remaining": quota_remaining,
            "resets_at": resets_at,
        },
    }


async def _daily_limit(resources, tenant_id) -> int:
    snapshot = await resources.entitlements.get(tenant_id)
    limit = getattr(snapshot.entitlements, "deep_investigation_daily_quota", None)
    if limit is None or int(limit) == 0:
        raise ApiError(
            ErrorCode.ENTITLEMENT_DENIED,
            "Deep investigation is not included in this plan.",
            details={"entitlement": "deep_investigation"},
        )
    return int(limit)


@router.post("/v1/alerts/{alert_id}/deep-investigation")
async def run_deep_investigation(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin", "analyst"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    tenant_id = principal.tenant_id
    async with resources.db.tenant_transaction(tenant_id) as conn:
        exists = await conn.fetchval("SELECT 1 FROM tenantdata.alerts WHERE id = $1", alert_id)
    if exists is None:
        not_found("alert", alert_id, tenant_id)
    limit = await _daily_limit(resources, tenant_id)
    result = await resources.quotas.consume_deep_investigation(tenant_id, limit)
    if not result.allowed:
        # AC-54: no quota consumed on denial.
        raise ApiError(
            ErrorCode.QUOTA_EXCEEDED_DEEP_INVESTIGATION,
            "Daily deep-investigation quota exhausted.",
            details={"remaining": 0, "resets_at": result.resets_at.isoformat()},
        )
    now = datetime.now(UTC)
    investigation_id = new_id("inv")
    async with resources.db.tenant_transaction(tenant_id) as conn:
        await conn.execute(
            _INSERT_RUN_SQL,
            investigation_id,
            tenant_id,
            alert_id,
            ENGINE_VERSION,
            principal.user_id,
            now,
            now,
            STUB_SUMMARY,
            to_jsonb({"nodes": [], "edges": []}),
            result.limit,
            result.remaining,
        )
        await conn.execute(_METER_SQL, tenant_id, alert_id, ENGINE_VERSION)
        await write_audit(
            conn,
            tenant_id=tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="alert.deep_investigation",
            target=Target(type="alert", id=alert_id),
            after={
                "investigation_id": investigation_id,
                "engine_version": ENGINE_VERSION,
                "quota_remaining": result.remaining,
            },
        )
    return _run_response(
        investigation_id=investigation_id,
        alert_id=alert_id,
        requested_by=str(principal.user_id),
        requested_at=now,
        completed_at=now,
        quota_limit=result.limit,
        quota_remaining=result.remaining,
        resets_at=result.resets_at,
    )


@router.get("/v1/alerts/{alert_id}/deep-investigations")
async def list_deep_investigations(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    page_limit = clamp_limit(limit)
    offset = 0
    if cursor:
        try:
            offset = max(0, int(decode_cursor(cursor).get("o", 0)))
        except (TypeError, ValueError):
            raise ApiError(ErrorCode.VALIDATION_ERROR, "cursor is invalid.") from None
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        exists = await conn.fetchval("SELECT 1 FROM tenantdata.alerts WHERE id = $1", alert_id)
        if exists is None:
            not_found("alert", alert_id, principal.tenant_id)
        rows = await conn.fetch(
            "SELECT id, alert_id, status, is_stub, engine_version, requested_by, "
            "requested_at, completed_at, summary, confidence, findings, timeline, "
            "evidence_graph, recommended_actions, quota_limit, quota_remaining "
            "FROM tenantdata.deep_investigation_runs WHERE alert_id = $1 "
            f"ORDER BY requested_at DESC, id LIMIT {page_limit + 1} OFFSET {offset}",
            alert_id,
        )
        total = await conn.fetchval(
            "SELECT count(*) FROM tenantdata.deep_investigation_runs WHERE alert_id = $1",
            alert_id,
        )
    page_rows = rows[:page_limit]
    items = [
        {
            "investigation_id": r["id"],
            "alert_id": r["alert_id"],
            "status": r["status"],
            "is_stub": r["is_stub"],
            "engine_version": r["engine_version"],
            "requested_at": r["requested_at"],
            "completed_at": r["completed_at"],
            "requested_by": str(r["requested_by"]),
            "summary": r["summary"],
            "confidence": float(r["confidence"]) if r["confidence"] is not None else None,
            "findings": from_jsonb(r["findings"]),
            "timeline": from_jsonb(r["timeline"]),
            "evidence_graph": from_jsonb(r["evidence_graph"]),
            "recommended_actions": from_jsonb(r["recommended_actions"]),
            "quota": {
                "limit": r["quota_limit"],
                "remaining": r["quota_remaining"],
                "resets_at": None,
            },
        }
        for r in page_rows
    ]
    next_cursor = (
        encode_cursor({"o": offset + page_limit}) if len(rows) > page_limit else None
    )
    return page(items, next_cursor, int(total or 0))


@router.get("/v1/tenant/quotas/deep-investigation")
async def deep_investigation_quota(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    snapshot = await resources.entitlements.get(principal.tenant_id)
    limit = int(getattr(snapshot.entitlements, "deep_investigation_daily_quota", 0))
    remaining = await resources.quotas.deep_investigation_remaining(principal.tenant_id, limit)
    return {"limit": limit, "remaining": remaining, "resets_at": next_utc_midnight()}
