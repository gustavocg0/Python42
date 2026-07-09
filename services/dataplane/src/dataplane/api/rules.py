"""Rules (contract §11, AC-36/38): tenant-effective list + per-tenant toggle.

Effective enabled = NOT runtime-disabled (SEC-28c) AND (tenant toggle if a
row exists, else pack enabled_default). rule_packs/rules/rule_runtime_disables
are GLOBAL (no RLS); rule_toggles is the RLS-scoped tenant overlay."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from dataplane.api.deps import get_resources, not_found, session_auth
from dataplane.api.models import RuleToggleRequest
from dataplane.core.pagination import clamp_limit, decode_cursor, encode_cursor, page
from dataplane.core.sessions import SessionPrincipal
from soc_audit import Actor, Target, write_audit
from soc_schemas import ApiError, ErrorCode

router = APIRouter()

_ACTIVE_PACK_SQL = (
    "SELECT version FROM tenantdata.rule_packs WHERE status = 'active' "
    "ORDER BY published_at DESC LIMIT 1"
)
_RULES_SQL = (
    "SELECT r.rule_id, r.rule_version, r.title, r.severity, r.mitre_technique_ids, "
    "r.event_classes, r.description, r.enabled_default, "
    "(d.rule_id IS NOT NULL) AS runtime_disabled "
    "FROM tenantdata.rules r "
    "LEFT JOIN tenantdata.rule_runtime_disables d ON d.rule_id = r.rule_id "
    "WHERE r.pack_version = $1 AND r.rule_id > $2 ORDER BY r.rule_id LIMIT $3"
)
_RULE_COUNT_SQL = "SELECT count(*) FROM tenantdata.rules WHERE pack_version = $1"
_RULE_EXISTS_SQL = (
    "SELECT 1 FROM tenantdata.rules WHERE pack_version = $1 AND rule_id = $2"
)
_TOGGLES_SQL = (
    "SELECT rule_id, enabled FROM tenantdata.rule_toggles WHERE rule_id = ANY($1::text[])"
)
_UPSERT_TOGGLE_SQL = (
    "INSERT INTO tenantdata.rule_toggles (tenant_id, rule_id, enabled, updated_by) "
    "VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, rule_id) DO UPDATE SET "
    "enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()"
)


async def _active_pack(conn) -> str | None:
    return await conn.fetchval(_ACTIVE_PACK_SQL)


@router.get("/v1/rules")
async def list_rules(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    page_limit = clamp_limit(limit)
    after = str(decode_cursor(cursor).get("rid", "")) if cursor else ""
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        pack_version = await _active_pack(conn)
        if pack_version is None:
            return page([], None, 0)
        rows = await conn.fetch(_RULES_SQL, pack_version, after, page_limit + 1)
        total = await conn.fetchval(_RULE_COUNT_SQL, pack_version)
        page_rows = rows[:page_limit]
        toggles_rows = await conn.fetch(_TOGGLES_SQL, [r["rule_id"] for r in page_rows])
    toggles = {t["rule_id"]: t["enabled"] for t in toggles_rows}
    items = []
    for r in page_rows:
        base = toggles.get(r["rule_id"], r["enabled_default"])
        items.append(
            {
                "id": r["rule_id"],
                "version": r["rule_version"],
                "title": r["title"],
                "severity": r["severity"],
                "mitre_technique_ids": list(r["mitre_technique_ids"] or []),
                "event_classes": list(r["event_classes"] or []),
                "enabled": bool(base) and not r["runtime_disabled"],
                "description": r["description"],
            }
        )
    next_cursor = (
        encode_cursor({"rid": page_rows[-1]["rule_id"]}) if len(rows) > page_limit else None
    )
    return page(items, next_cursor, int(total or 0))


@router.put("/v1/rules/{rule_id}/enabled")
async def toggle_rule(
    rule_id: str,
    body: RuleToggleRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        pack_version = await _active_pack(conn)
        if pack_version is None:
            raise ApiError(
                ErrorCode.SERVICE_UNAVAILABLE, "No active rule pack published yet."
            )
        exists = await conn.fetchval(_RULE_EXISTS_SQL, pack_version, rule_id)
        if exists is None:
            not_found("rule", rule_id, principal.tenant_id)
        await conn.execute(
            _UPSERT_TOGGLE_SQL, principal.tenant_id, rule_id, body.enabled, principal.user_id
        )
        runtime_disabled = await conn.fetchval(
            "SELECT 1 FROM tenantdata.rule_runtime_disables WHERE rule_id = $1", rule_id
        )
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="rule.toggle",
            target=Target(type="rule", id=rule_id),
            after={"enabled": body.enabled},
        )
    return {
        "id": rule_id,
        "enabled": body.enabled and runtime_disabled is None,
        "toggle": body.enabled,
    }
