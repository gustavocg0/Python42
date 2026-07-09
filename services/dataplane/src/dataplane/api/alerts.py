"""Alert queue APIs (contract §8): list/get, state machine (atomic CAS),
bulk partial success, and normalized event bodies via the tenant-scoped ES
alias (SEC-24). Queue list uses keyset pagination on the dictated
alerts_queue_idx ordering (AC-44 p95 <= 500ms @10k)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request

from dataplane.api.deps import get_resources, not_found, session_auth
from dataplane.api.models import AlertBulkRequest, AlertCloseRequest
from dataplane.core.db import ConnectionLike, from_jsonb
from dataplane.core.onboarding import signal_step
from dataplane.core.pagination import clamp_limit, decode_cursor, encode_cursor
from dataplane.core.resources import AppResources
from dataplane.core.sessions import SessionPrincipal
from soc_audit import Actor, Target, write_audit
from soc_schemas import ApiError, ErrorCode
from soc_tenancy import events_alias

router = APIRouter()

_ALERT_COLUMNS = (
    "id, tenant_id, state, rule_id, rule_version, rule_title, rule_severity, "
    "mitre_technique_ids, entity_hostname, entity_user, asset_id, occurrence_count, "
    "first_seen, last_seen, correlation_group_id, priority_score, priority_inputs, "
    "triage_status, triage_summary, ai_severity, ai_severity_effective, triage_model_id, "
    "triage_completed_at, triage_attempts, close_reason, close_comment, closed_by, "
    "closed_at, acknowledged_by, acknowledged_at, created_at"
)

_SORTS = {
    "-priority": (
        "priority_score DESC, last_seen DESC, id",
        "(priority_score < {p1} OR (priority_score = {p1} AND last_seen < {p2}) "
        "OR (priority_score = {p1} AND last_seen = {p2} AND id > {p3}))",
    ),
    "priority": (
        "priority_score ASC, last_seen DESC, id",
        "(priority_score > {p1} OR (priority_score = {p1} AND last_seen < {p2}) "
        "OR (priority_score = {p1} AND last_seen = {p2} AND id > {p3}))",
    ),
    "-last_seen": (
        "last_seen DESC, id",
        "(last_seen < {p2} OR (last_seen = {p2} AND id > {p3}))",
    ),
    "last_seen": (
        "last_seen ASC, id",
        "(last_seen > {p2} OR (last_seen = {p2} AND id > {p3}))",
    ),
}

_TRANSITIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "acknowledge": (("new",), "acknowledged"),
    "close": (("new", "acknowledged"), "closed"),
    "reopen": (("closed",), "new"),
}


def _alert_dict(row: Any, event_refs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenant_id": str(row["tenant_id"]),
        "state": row["state"],
        "rule": {
            "id": row["rule_id"],
            "version": row["rule_version"],
            "title": row["rule_title"],
            "severity": row["rule_severity"],
            "mitre_technique_ids": list(row["mitre_technique_ids"] or []),
        },
        "entity": {
            "hostname": row["entity_hostname"],
            "user": row["entity_user"],
            "asset_id": str(row["asset_id"]) if row["asset_id"] else None,
        },
        "occurrence_count": row["occurrence_count"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "correlation_group_id": row["correlation_group_id"],
        "priority_score": row["priority_score"],
        "priority_inputs": from_jsonb(row["priority_inputs"]) or {},
        "triage": {
            "status": row["triage_status"],
            "summary": row["triage_summary"],
            "ai_severity": row["ai_severity"],  # RAW model output (AC-49)
            "model_id": row["triage_model_id"],
            "completed_at": row["triage_completed_at"],
            "attempts": row["triage_attempts"],
        },
        "event_refs": event_refs,
        "close_reason": row["close_reason"],
        "close_comment": row["close_comment"],
        "closed_by": str(row["closed_by"]) if row["closed_by"] else None,
        "closed_at": row["closed_at"],
        "acknowledged_by": str(row["acknowledged_by"]) if row["acknowledged_by"] else None,
        "acknowledged_at": row["acknowledged_at"],
        "created_at": row["created_at"],
    }


async def _event_refs_for(
    conn: ConnectionLike, alert_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    if not alert_ids:
        return {}
    rows = await conn.fetch(
        "SELECT alert_id, event_id, es_index FROM tenantdata.alert_events "
        "WHERE alert_id = ANY($1::text[]) ORDER BY alert_id, event_id",
        alert_ids,
    )
    refs: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        refs.setdefault(r["alert_id"], []).append(
            {"event_id": str(r["event_id"]), "es_index": r["es_index"]}
        )
    return refs


def _parse_rfc3339(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            f"{field} must be RFC3339.",
            details={"fields": [field]},
        ) from None
    return parsed


# --------------------------------------------------------------------- list
@router.get("/v1/alerts")
async def list_alerts(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
    state: Annotated[list[str] | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    ai_severity: Annotated[list[str] | None, Query()] = None,
    rule_id: str | None = None,
    host: str | None = None,
    correlation_group_id: str | None = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: str | None = None,
    sort: str = "-priority",
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    if sort not in _SORTS:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            f"sort must be one of {sorted(_SORTS)}.",
            details={"fields": ["sort"]},
        )
    page_limit = clamp_limit(limit)
    order_sql, keyset_template = _SORTS[sort]
    where: list[str] = ["true"]
    args: list[Any] = []

    def bind(value: Any) -> str:
        args.append(value)
        return f"${len(args)}"

    valid_states = {"new", "acknowledged", "closed"}
    valid_sev = {"low", "medium", "high", "critical"}
    if state:
        if not set(state) <= valid_states:
            raise ApiError(ErrorCode.VALIDATION_ERROR, "invalid state filter.")
        where.append(f"state = ANY({bind(state)}::text[])")
    if severity:
        if not set(severity) <= valid_sev:
            raise ApiError(ErrorCode.VALIDATION_ERROR, "invalid severity filter.")
        where.append(f"rule_severity = ANY({bind(severity)}::text[])")
    if ai_severity:
        if not set(ai_severity) <= valid_sev:
            raise ApiError(ErrorCode.VALIDATION_ERROR, "invalid ai_severity filter.")
        where.append(f"ai_severity = ANY({bind(ai_severity)}::text[])")
    if rule_id:
        where.append(f"rule_id = {bind(rule_id)}")
    if host:
        where.append(f"entity_hostname = {bind(host.lower())}")
    if correlation_group_id:
        where.append(f"correlation_group_id = {bind(correlation_group_id)}")
    if from_:
        where.append(f"last_seen >= {bind(_parse_rfc3339(from_, 'from'))}")
    if to:
        where.append(f"last_seen <= {bind(_parse_rfc3339(to, 'to'))}")
    count_where = " AND ".join(where)
    count_args = list(args)
    if cursor:
        payload = decode_cursor(cursor)
        try:
            if payload.get("s") != sort:
                raise ValueError("sort mismatch")
            key_ps = int(payload.get("ps", 0))
            key_ls = datetime.fromisoformat(str(payload["ls"]))
            key_id = str(payload["id"])
        except (KeyError, ValueError):
            raise ApiError(ErrorCode.VALIDATION_ERROR, "cursor is invalid.") from None
        where.append(
            keyset_template.format(p1=bind(key_ps), p2=bind(key_ls), p3=bind(key_id))
        )
    where_sql = " AND ".join(where)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        rows = await conn.fetch(
            f"SELECT {_ALERT_COLUMNS} FROM tenantdata.alerts WHERE {where_sql} "
            f"ORDER BY {order_sql} LIMIT {page_limit + 1}",
            *args,
        )
        page_rows = rows[:page_limit]
        total = await conn.fetchval(
            f"SELECT count(*) FROM tenantdata.alerts WHERE {count_where}", *count_args
        )
        refs = await _event_refs_for(conn, [r["id"] for r in page_rows])
    items = [_alert_dict(r, refs.get(r["id"], [])) for r in page_rows]
    next_cursor = None
    if len(rows) > page_limit and page_rows:
        tail = page_rows[-1]
        next_cursor = encode_cursor(
            {
                "s": sort,
                "ps": tail["priority_score"],
                "ls": tail["last_seen"].isoformat(),
                "id": tail["id"],
            }
        )
    await signal_step(resources.redis, principal.tenant_id, "view_queue")
    return {"items": items, "next_cursor": next_cursor, "total_estimate": int(total or 0)}


# ---------------------------------------------------------------------- get
@router.get("/v1/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        row = await conn.fetchrow(
            f"SELECT {_ALERT_COLUMNS} FROM tenantdata.alerts WHERE id = $1", alert_id
        )
        if row is None:
            not_found("alert", alert_id, principal.tenant_id)
        refs = await _event_refs_for(conn, [alert_id])
        siblings_rows = []
        if row["correlation_group_id"]:
            siblings_rows = await conn.fetch(
                f"SELECT {_ALERT_COLUMNS} FROM tenantdata.alerts "
                "WHERE correlation_group_id = $1 AND id <> $2 "
                "ORDER BY priority_score DESC, last_seen DESC, id",
                row["correlation_group_id"],
                alert_id,
            )
        history_rows = await conn.fetch(
            "SELECT at, actor_type, actor_id, action, from_state, to_state, reason, comment "
            "FROM tenantdata.alert_history WHERE alert_id = $1 ORDER BY at, id",
            alert_id,
        )
        sibling_refs = await _event_refs_for(conn, [s["id"] for s in siblings_rows])
    alert = _alert_dict(row, refs.get(alert_id, []))
    alert["siblings"] = [_alert_dict(s, sibling_refs.get(s["id"], [])) for s in siblings_rows]
    alert["history"] = [
        {
            "at": h["at"],
            "actor": {"type": h["actor_type"], "id": h["actor_id"]},
            "action": h["action"],
            "from_state": h["from_state"],
            "to_state": h["to_state"],
            "reason": h["reason"],
            "comment": h["comment"],
        }
        for h in history_rows
    ]
    return alert


# ------------------------------------------------------------------- events
@router.get("/v1/alerts/{alert_id}/events")
async def alert_events(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Ratified §8 addition: normalized event bodies for the alert's
    event_refs via the tenant-scoped alias; purged events are reported in
    missing_event_ids (retention, AC-16)."""
    resources = get_resources(request)
    page_limit = clamp_limit(limit)
    after = ""
    if cursor:
        after = str(decode_cursor(cursor).get("eid", ""))
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM tenantdata.alerts WHERE id = $1", alert_id
        )
        if exists is None:
            not_found("alert", alert_id, principal.tenant_id)
        ref_rows = await conn.fetch(
            "SELECT event_id, es_index FROM tenantdata.alert_events "
            "WHERE alert_id = $1 AND event_id::text > $2 ORDER BY event_id::text "
            f"LIMIT {page_limit + 1}",
            alert_id,
            after,
        )
        total = await conn.fetchval(
            "SELECT count(*) FROM tenantdata.alert_events WHERE alert_id = $1", alert_id
        )
    page_refs = ref_rows[:page_limit]
    wanted = [str(r["event_id"]) for r in page_refs]
    items: list[dict[str, Any]] = []
    found: set[str] = set()
    if wanted:
        alias = events_alias(principal.tenant_id)  # SEC-24 fail-closed naming
        try:
            response = await resources.es.search(
                index=alias,
                query={"terms": {"event_id": wanted}},
                size=len(wanted),
                ignore_unavailable=True,
            )
        except Exception:
            raise ApiError(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Event store unavailable; retry.",
                retry_after_seconds=15,
            ) from None
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            event_id = str(source.get("event_id", ""))
            if event_id in wanted and event_id not in found:
                found.add(event_id)
                items.append(source)
    missing = [event_id for event_id in wanted if event_id not in found]
    next_cursor = None
    if len(ref_rows) > page_limit and page_refs:
        next_cursor = encode_cursor({"eid": str(page_refs[-1]["event_id"])})
    return {
        "items": items,
        "next_cursor": next_cursor,
        "total_estimate": int(total or 0),
        "missing_event_ids": missing,
    }


# -------------------------------------------------------------- transitions
async def _transition(
    conn: ConnectionLike,
    principal: SessionPrincipal,
    alert_id: str,
    action: str,
    *,
    reason: str | None = None,
    comment: str | None = None,
) -> Any:
    """Atomic compare-and-set (AC-47); returns the updated row."""
    valid_from, to_state = _TRANSITIONS[action]
    if action == "acknowledge":
        row = await conn.fetchrow(
            f"UPDATE tenantdata.alerts SET state = 'acknowledged', acknowledged_by = $2, "
            f"acknowledged_at = now(), updated_at = now() "
            f"WHERE id = $1 AND state = 'new' RETURNING {_ALERT_COLUMNS}",
            alert_id,
            principal.user_id,
        )
    elif action == "close":
        row = await conn.fetchrow(
            f"UPDATE tenantdata.alerts SET state = 'closed', close_reason = $2, "
            f"close_comment = $3, closed_by = $4, closed_at = now(), updated_at = now() "
            f"WHERE id = $1 AND state IN ('new', 'acknowledged') RETURNING {_ALERT_COLUMNS}",
            alert_id,
            reason,
            comment,
            principal.user_id,
        )
    else:  # reopen
        row = await conn.fetchrow(
            f"UPDATE tenantdata.alerts SET state = 'new', close_reason = NULL, "
            f"close_comment = NULL, closed_by = NULL, closed_at = NULL, "
            f"acknowledged_by = NULL, acknowledged_at = NULL, updated_at = now() "
            f"WHERE id = $1 AND state = 'closed' RETURNING {_ALERT_COLUMNS}",
            alert_id,
        )
    if row is None:
        current = await conn.fetchval(
            "SELECT state FROM tenantdata.alerts WHERE id = $1", alert_id
        )
        if current is None:
            not_found("alert", alert_id, principal.tenant_id)
        raise ApiError(
            ErrorCode.INVALID_STATE_TRANSITION,
            f"Cannot {action} an alert in state '{current}'.",
            details={"current_state": current, "valid_from": list(valid_from)},
        )
    await conn.execute(
        "INSERT INTO tenantdata.alert_history "
        "(tenant_id, alert_id, actor_type, actor_id, action, from_state, to_state, "
        " reason, comment) VALUES ($1, $2, 'user', $3, $4, $5, $6, $7, $8)",
        principal.tenant_id,
        alert_id,
        str(principal.user_id),
        {"acknowledge": "acknowledged", "close": "closed", "reopen": "reopened"}[action],
        valid_from[0] if len(valid_from) == 1 else None,
        to_state,
        reason,
        comment,
    )
    await write_audit(
        conn,
        tenant_id=principal.tenant_id,
        actor=Actor(type="user", id=str(principal.user_id)),
        action_type=f"alert.{action}",
        target=Target(type="alert", id=alert_id),
        after={"state": to_state, "reason": reason} if reason else {"state": to_state},
        reason_code=reason,
    )
    return row


async def _run_transition(
    resources: AppResources,
    principal: SessionPrincipal,
    alert_id: str,
    action: str,
    *,
    reason: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        row = await _transition(
            conn, principal, alert_id, action, reason=reason, comment=comment
        )
        refs = await _event_refs_for(conn, [alert_id])
    return _alert_dict(row, refs.get(alert_id, []))


@router.post("/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin", "analyst"))],
) -> dict[str, Any]:
    return await _run_transition(get_resources(request), principal, alert_id, "acknowledge")


@router.post("/v1/alerts/{alert_id}/close")
async def close_alert(
    alert_id: str,
    body: AlertCloseRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin", "analyst"))],
) -> dict[str, Any]:
    return await _run_transition(
        get_resources(request),
        principal,
        alert_id,
        "close",
        reason=body.reason,
        comment=body.comment,
    )


@router.post("/v1/alerts/{alert_id}/reopen")
async def reopen_alert(
    alert_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin", "analyst"))],
) -> dict[str, Any]:
    return await _run_transition(get_resources(request), principal, alert_id, "reopen")


@router.post("/v1/alerts/bulk")
async def bulk_alerts(
    body: AlertBulkRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin", "analyst"))],
) -> dict[str, Any]:
    """AC-73: partial success; each item atomic in its own transaction."""
    if body.action == "close" and body.reason is None:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "reason is required for bulk close.",
            details={"fields": ["reason"]},
        )
    resources = get_resources(request)
    succeeded: list[str] = []
    failed: list[dict[str, str]] = []
    for alert_id in dict.fromkeys(body.alert_ids):
        try:
            await _run_transition(
                resources,
                principal,
                alert_id,
                body.action,
                reason=body.reason if body.action == "close" else None,
            )
        except ApiError as err:
            failed.append({"id": alert_id, "code": str(err.code)})
        else:
            succeeded.append(alert_id)
    return {"succeeded": succeeded, "failed": failed}
