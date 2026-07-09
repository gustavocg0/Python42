"""Audit query (contract §12, AC-83..85) + onboarding status (AC-70)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request

from dataplane.api.deps import get_resources, session_auth
from dataplane.core.db import from_jsonb
from dataplane.core.onboarding import STEP_IDS, clear_signals, read_signals
from dataplane.core.pagination import clamp_limit, decode_cursor, encode_cursor, page
from dataplane.core.sessions import SessionPrincipal
from soc_schemas import ApiError, ErrorCode

router = APIRouter()


def _parse_rfc3339(value: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            f"{field} must be RFC3339.",
            details={"fields": [field]},
        ) from None


@router.get("/v1/audit-logs")
async def list_audit_logs(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
    actor: str | None = None,
    action_type: str | None = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    page_limit = clamp_limit(limit)
    where: list[str] = ["true"]
    args: list[Any] = []

    def bind(value: Any) -> str:
        args.append(value)
        return f"${len(args)}"

    if actor:
        where.append(f"actor_id = {bind(actor)}")
    if action_type:
        where.append(f"action_type = {bind(action_type)}")
    if from_:
        where.append(f"created_at >= {bind(_parse_rfc3339(from_, 'from'))}")
    if to:
        where.append(f"created_at <= {bind(_parse_rfc3339(to, 'to'))}")
    count_where = " AND ".join(where)
    count_args = list(args)
    if cursor:
        payload = decode_cursor(cursor)
        try:
            key_at = datetime.fromisoformat(str(payload["at"]))
            key_id = int(payload["id"])
        except (KeyError, ValueError):
            raise ApiError(ErrorCode.VALIDATION_ERROR, "cursor is invalid.") from None
        where.append(
            f"(created_at < {bind(key_at)} OR "
            f"(created_at = ${len(args)} AND id < {bind(key_id)}))"
        )
    where_sql = " AND ".join(where)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        rows = await conn.fetch(
            "SELECT id, created_at, tenant_id, actor_type, actor_id, action_type, "
            "target_type, target_id, before, after, reason_code "
            f"FROM tenantdata.audit_log WHERE {where_sql} "
            f"ORDER BY created_at DESC, id DESC LIMIT {page_limit + 1}",
            *args,
        )
        total = await conn.fetchval(
            f"SELECT count(*) FROM tenantdata.audit_log WHERE {count_where}", *count_args
        )
    page_rows = rows[:page_limit]
    items = []
    for r in page_rows:
        record: dict[str, Any] = {
            "id": r["id"],
            "at": r["created_at"],
            "tenant_id": str(r["tenant_id"]),
            "actor": {"type": r["actor_type"], "id": r["actor_id"]},
            "action_type": r["action_type"],
            "target": (
                {"type": r["target_type"], "id": r["target_id"]}
                if r["target_type"]
                else None
            ),
        }
        if r["before"] is not None:
            record["before"] = from_jsonb(r["before"])
        if r["after"] is not None:
            record["after"] = from_jsonb(r["after"])
        if r["reason_code"] is not None:
            record["reason_code"] = r["reason_code"]
        items.append(record)
    next_cursor = None
    if len(rows) > page_limit and page_rows:
        tail = page_rows[-1]
        next_cursor = encode_cursor({"at": tail["created_at"].isoformat(), "id": tail["id"]})
    return page(items, next_cursor, int(total or 0))


@router.get("/v1/onboarding/status")
async def onboarding_status(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    """PG onboarding_steps is truth; Redis signals auto-complete steps
    (first_event on first ingested batch, AC-70)."""
    resources = get_resources(request)
    tenant_id = principal.tenant_id
    signals = await read_signals(resources.redis, tenant_id)
    async with resources.db.tenant_transaction(tenant_id) as conn:
        rows = await conn.fetch(
            "SELECT step_id, state, completed_at FROM tenantdata.onboarding_steps"
        )
        steps = {r["step_id"]: dict(id=r["step_id"], state=r["state"],
                                    completed_at=r["completed_at"]) for r in rows}
        for step_id in signals:
            current = steps.get(step_id)
            if current is None or current["state"] == "todo":
                row = await conn.fetchrow(
                    "UPDATE tenantdata.onboarding_steps SET state = 'done', "
                    "completed_at = now() WHERE step_id = $1 AND state = 'todo' "
                    "RETURNING completed_at",
                    step_id,
                )
                if row is not None:
                    steps[step_id] = {
                        "id": step_id,
                        "state": "done",
                        "completed_at": row["completed_at"],
                    }
    ordered = []
    for step_id in STEP_IDS:
        entry = steps.get(step_id, {"id": step_id, "state": "todo", "completed_at": None})
        item: dict[str, Any] = {"id": entry["id"], "state": entry["state"]}
        if entry.get("completed_at") is not None:
            item["completed_at"] = entry["completed_at"]
        ordered.append(item)
    if all(s["state"] == "done" for s in ordered):
        await clear_signals(resources.redis, tenant_id)
    return {"steps": ordered}
