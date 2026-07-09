"""Asset inventory (contract §7): list/get/billable-count + manual merge/split
with correction pins (AC-21..27). Merge/split are forward-looking only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from dataplane.api.deps import get_resources, not_found, session_auth
from dataplane.api.models import AssetMergeRequest, AssetSplitRequest
from dataplane.core.db import ConnectionLike, to_jsonb
from dataplane.core.pagination import clamp_limit, decode_cursor, encode_cursor, page
from dataplane.core.sessions import SessionPrincipal
from soc_audit import Actor, Target, write_audit
from soc_schemas import ApiError, ErrorCode

router = APIRouter()

_BILLABLE_COUNT_SQL = (
    "SELECT count(*) FROM tenantdata.assets WHERE state = 'active' "
    "AND agent_status <> 'revoked' AND last_seen >= now() - make_interval(days => $1)"
)
_ASSET_COLUMNS = (
    "id, hostname, os_family, os_name, os_version, ip, mac, sources, agent_status, "
    "billable, state, merged_into_asset_id, created_via, first_seen, last_seen, created_at"
)


def _uuid_or_404(value: str, resource: str, tenant_id) -> UUID:
    try:
        return UUID(value)
    except ValueError:
        not_found(resource, value, tenant_id)


def _asset_summary(row: Any, agent: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "hostname": row["hostname"],
        "os_family": row["os_family"],
        "os_name": row["os_name"],
        "os_version": row["os_version"],
        "sources": list(row["sources"] or []),
        "agent_status": row["agent_status"],
        "agent": agent,
        "billable": row["billable"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "created_via": row["created_via"],
    }


async def _agents_by_asset(
    conn: ConnectionLike, asset_ids: list[UUID]
) -> dict[UUID, dict[str, Any]]:
    if not asset_ids:
        return {}
    rows = await conn.fetch(
        "SELECT DISTINCT ON (asset_id) asset_id, id, agent_version, last_heartbeat_at "
        "FROM tenantdata.devices WHERE asset_id = ANY($1::uuid[]) "
        "ORDER BY asset_id, created_at DESC",
        asset_ids,
    )
    return {
        r["asset_id"]: {
            "device_id": r["id"],
            "version": r["agent_version"],
            "last_heartbeat_at": r["last_heartbeat_at"],
        }
        for r in rows
    }


async def _asset_detail(
    conn: ConnectionLike, tenant_id: UUID, asset_id: UUID
) -> dict[str, Any]:
    row = await conn.fetchrow(
        f"SELECT {_ASSET_COLUMNS} FROM tenantdata.assets WHERE id = $1", asset_id
    )
    if row is None:
        not_found("asset", str(asset_id), tenant_id)
    identities = await conn.fetch(
        "SELECT id, source, identifier_type, value, first_seen, last_seen "
        "FROM tenantdata.asset_identities WHERE asset_id = $1 ORDER BY first_seen",
        asset_id,
    )
    merge_audit = await conn.fetch(
        "SELECT at, rule, actor_type, actor_id, details "
        "FROM tenantdata.asset_merge_audit WHERE asset_id = $1 ORDER BY at",
        asset_id,
    )
    agents = await _agents_by_asset(conn, [row["id"]])
    detail = _asset_summary(row, agents.get(row["id"]))
    detail["identities"] = [
        {
            "id": str(i["id"]),
            "source": i["source"],
            "identifier_type": i["identifier_type"],
            "value": i["value"],
            "first_seen": i["first_seen"],
            "last_seen": i["last_seen"],
        }
        for i in identities
    ]
    detail["merge_audit"] = [
        {
            "at": m["at"],
            "rule": m["rule"],
            "actor": {"type": m["actor_type"], "id": m["actor_id"]},
            "details": _details(m["details"]),
        }
        for m in merge_audit
    ]
    detail["state"] = row["state"]
    if row["merged_into_asset_id"]:
        detail["merged_into_asset_id"] = str(row["merged_into_asset_id"])
    return detail


def _details(value: Any) -> Any:
    from dataplane.core.db import from_jsonb

    return from_jsonb(value) if value is not None else {}


# ------------------------------------------------------------------- routes
@router.get("/v1/assets/billable-count")
async def billable_count(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    window_days = resources.settings.billable_window_days
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        count = await conn.fetchval(_BILLABLE_COUNT_SQL, window_days)
    snapshot = await resources.entitlements.get(principal.tenant_id)
    return {
        "billable_count": int(count or 0),
        "endpoint_cap": int(snapshot.entitlements.endpoint_cap),
        "window_days": window_days,
        "computed_at": datetime.now(UTC),
    }


@router.get("/v1/assets")
async def list_assets(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
    source: str | None = Query(default=None, pattern="^(agent|log_ingest)$"),
    agent_status: str | None = Query(
        default=None, pattern="^(enrolled|healthy|offline|revoked|none)$"
    ),
    billable: bool | None = None,
    q: str | None = Query(default=None, max_length=253),
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    resources = get_resources(request)
    page_limit = clamp_limit(limit)
    where = ["state = 'active'"]
    args: list[Any] = []

    def bind(value: Any) -> str:
        args.append(value)
        return f"${len(args)}"

    if source:
        where.append(f"{bind(source)} = ANY(sources)")
    if agent_status:
        where.append(f"agent_status = {bind(agent_status)}")
    if billable is not None:
        where.append(f"billable = {bind(billable)}")
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append(f"hostname ILIKE {bind('%' + escaped + '%')}")
    if cursor:
        payload = decode_cursor(cursor)
        try:
            last_seen = datetime.fromisoformat(str(payload["ls"]))
            last_id = UUID(str(payload["id"]))
        except (KeyError, ValueError):
            raise ApiError(ErrorCode.VALIDATION_ERROR, "cursor is invalid.") from None
        where.append(
            f"(last_seen < {bind(last_seen)} OR "
            f"(last_seen = ${len(args)} AND id > {bind(last_id)}))"
        )
    where_sql = " AND ".join(where)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        rows = await conn.fetch(
            f"SELECT {_ASSET_COLUMNS} FROM tenantdata.assets WHERE {where_sql} "
            f"ORDER BY last_seen DESC, id LIMIT {page_limit + 1}",
            *args,
        )
        total = await conn.fetchval(
            f"SELECT count(*) FROM tenantdata.assets WHERE {where_sql}", *args
        )
        page_rows = rows[:page_limit]
        agents = await _agents_by_asset(conn, [r["id"] for r in page_rows])
    items = [_asset_summary(r, agents.get(r["id"])) for r in page_rows]
    next_cursor = None
    if len(rows) > page_limit and page_rows:
        tail = page_rows[-1]
        next_cursor = encode_cursor({"ls": tail["last_seen"].isoformat(), "id": str(tail["id"])})
    return page(items, next_cursor, int(total or 0))


@router.get("/v1/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    asset_uuid = _uuid_or_404(asset_id, "asset", principal.tenant_id)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        return await _asset_detail(conn, principal.tenant_id, asset_uuid)


@router.post("/v1/assets/merge")
async def merge_assets(
    body: AssetMergeRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    tenant_id = principal.tenant_id
    ids = [_uuid_or_404(a, "asset", tenant_id) for a in dict.fromkeys(body.asset_ids)]
    if len(ids) < 2:
        raise ApiError(ErrorCode.VALIDATION_ERROR, "merge requires >=2 distinct asset_ids.")
    survivor_id, other_ids = ids[0], ids[1:]
    async with resources.db.tenant_transaction(tenant_id) as conn:
        rows = await conn.fetch(
            "SELECT id, sources, agent_status, first_seen, last_seen, state "
            "FROM tenantdata.assets WHERE id = ANY($1::uuid[]) FOR UPDATE",
            ids,
        )
        found = {r["id"]: r for r in rows}
        for asset_uuid in ids:
            if asset_uuid not in found:
                not_found("asset", str(asset_uuid), tenant_id)
            if found[asset_uuid]["state"] != "active":
                raise ApiError(
                    ErrorCode.VALIDATION_ERROR,
                    "Only active assets can be merged.",
                    details={"asset_id": str(asset_uuid)},
                )
        moved = await conn.fetch(
            "UPDATE tenantdata.asset_identities SET asset_id = $1 "
            "WHERE asset_id = ANY($2::uuid[]) RETURNING id, identifier_type, value, source",
            survivor_id,
            other_ids,
        )
        for identity in moved:
            await conn.execute(
                "INSERT INTO tenantdata.asset_identity_pins "
                "(tenant_id, identifier_type, value, pinned_asset_id, origin, reason, created_by) "
                "VALUES ($1, $2, $3, $4, 'merge', $5, $6) "
                "ON CONFLICT (tenant_id, identifier_type, value) DO UPDATE SET "
                "pinned_asset_id = EXCLUDED.pinned_asset_id, origin = 'merge', "
                "reason = EXCLUDED.reason, created_by = EXCLUDED.created_by",
                tenant_id,
                identity["identifier_type"],
                identity["value"],
                survivor_id,
                body.reason,
                principal.user_id,
            )
        await conn.execute(
            "UPDATE tenantdata.devices SET asset_id = $1, updated_at = now() "
            "WHERE asset_id = ANY($2::uuid[])",
            survivor_id,
            other_ids,
        )
        sources = sorted(
            {s for r in rows for s in (r["sources"] or [])}
        )
        survivor = found[survivor_id]
        agent_status = survivor["agent_status"]
        if agent_status == "none":
            for other in other_ids:
                if found[other]["agent_status"] != "none":
                    agent_status = found[other]["agent_status"]
                    break
        await conn.execute(
            "UPDATE tenantdata.assets SET sources = $2::text[], agent_status = $3, "
            "first_seen = LEAST(first_seen, $4), last_seen = GREATEST(last_seen, $5), "
            "dedup_rule = 'manual_merge', updated_at = now() WHERE id = $1",
            survivor_id,
            sources,
            agent_status,
            min(r["first_seen"] for r in rows),
            max(r["last_seen"] for r in rows),
        )
        await conn.execute(
            "UPDATE tenantdata.assets SET state = 'merged', merged_into_asset_id = $1, "
            "billable = false, updated_at = now() WHERE id = ANY($2::uuid[])",
            survivor_id,
            other_ids,
        )
        await conn.execute(
            "INSERT INTO tenantdata.asset_merge_audit "
            "(tenant_id, asset_id, rule, actor_type, actor_id, details) "
            "VALUES ($1, $2, 'manual_merge', 'user', $3, $4::jsonb)",
            tenant_id,
            survivor_id,
            str(principal.user_id),
            to_jsonb(
                {
                    "merged_asset_ids": [str(a) for a in other_ids],
                    "moved_identities": [str(m["id"]) for m in moved],
                    "reason": body.reason,
                }
            ),
        )
        await write_audit(
            conn,
            tenant_id=tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="asset.merge",
            target=Target(type="asset", id=str(survivor_id)),
            after={"merged_asset_ids": [str(a) for a in other_ids], "reason": body.reason},
        )
        return await _asset_detail(conn, tenant_id, survivor_id)


@router.post("/v1/assets/{asset_id}/split")
async def split_asset(
    asset_id: str,
    body: AssetSplitRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    tenant_id = principal.tenant_id
    asset_uuid = _uuid_or_404(asset_id, "asset", tenant_id)
    identity_ids: list[UUID] = []
    for identity_id in dict.fromkeys(body.identity_ids):
        try:
            identity_ids.append(UUID(identity_id))
        except ValueError:
            raise ApiError(
                ErrorCode.VALIDATION_ERROR,
                "identity_ids must be identity UUIDs from the asset's identities[].",
            ) from None
    async with resources.db.tenant_transaction(tenant_id) as conn:
        original = await conn.fetchrow(
            f"SELECT {_ASSET_COLUMNS} FROM tenantdata.assets WHERE id = $1 "
            "AND state = 'active' FOR UPDATE",
            asset_uuid,
        )
        if original is None:
            not_found("asset", asset_id, tenant_id)
        identities = await conn.fetch(
            "SELECT id, source, identifier_type, value, first_seen, last_seen "
            "FROM tenantdata.asset_identities WHERE id = ANY($1::uuid[]) AND asset_id = $2",
            identity_ids,
            asset_uuid,
        )
        if len(identities) != len(identity_ids):
            raise ApiError(
                ErrorCode.VALIDATION_ERROR,
                "All identity_ids must belong to the asset being split.",
                details={"fields": ["identity_ids"]},
            )
        moved_device_ids = [
            i["value"] for i in identities if i["identifier_type"] == "device_id"
        ]
        hostname = original["hostname"]
        for identity in identities:
            if identity["identifier_type"] == "hostname_os" and "|" in identity["value"]:
                hostname = identity["value"].split("|", 1)[0]
        new_agent_status = original["agent_status"] if moved_device_ids else "none"
        new_sources = sorted({i["source"] for i in identities})
        new_asset_id = await conn.fetchval(
            "INSERT INTO tenantdata.assets "
            "(tenant_id, hostname, os_family, os_name, os_version, sources, agent_status, "
            " created_via, dedup_rule, first_seen, last_seen) "
            "VALUES ($1, $2, $3, $4, $5, $6::text[], $7, 'manual_split', 'manual_split', "
            "        $8, $9) RETURNING id",
            tenant_id,
            hostname,
            original["os_family"],
            original["os_name"],
            original["os_version"],
            new_sources,
            new_agent_status,
            min(i["first_seen"] for i in identities),
            max(i["last_seen"] for i in identities),
        )
        await conn.execute(
            "UPDATE tenantdata.asset_identities SET asset_id = $1 WHERE id = ANY($2::uuid[])",
            new_asset_id,
            identity_ids,
        )
        for identity in identities:
            await conn.execute(
                "INSERT INTO tenantdata.asset_identity_pins "
                "(tenant_id, identifier_type, value, pinned_asset_id, origin, reason, created_by) "
                "VALUES ($1, $2, $3, $4, 'split', $5, $6) "
                "ON CONFLICT (tenant_id, identifier_type, value) DO UPDATE SET "
                "pinned_asset_id = EXCLUDED.pinned_asset_id, origin = 'split', "
                "reason = EXCLUDED.reason, created_by = EXCLUDED.created_by",
                tenant_id,
                identity["identifier_type"],
                identity["value"],
                new_asset_id,
                body.reason,
                principal.user_id,
            )
        if moved_device_ids:
            await conn.execute(
                "UPDATE tenantdata.devices SET asset_id = $1, updated_at = now() "
                "WHERE id = ANY($2::text[])",
                new_asset_id,
                moved_device_ids,
            )
            await conn.execute(
                "UPDATE tenantdata.assets SET agent_status = 'none', updated_at = now() "
                "WHERE id = $1",
                asset_uuid,
            )
        for target_asset, detail in ((asset_uuid, "split_from"), (new_asset_id, "split_to")):
            await conn.execute(
                "INSERT INTO tenantdata.asset_merge_audit "
                "(tenant_id, asset_id, rule, actor_type, actor_id, details) "
                "VALUES ($1, $2, 'manual_split', 'user', $3, $4::jsonb)",
                tenant_id,
                target_asset,
                str(principal.user_id),
                to_jsonb(
                    {
                        "direction": detail,
                        "counterpart_asset_id": str(
                            new_asset_id if target_asset == asset_uuid else asset_uuid
                        ),
                        "identity_ids": [str(i) for i in identity_ids],
                        "reason": body.reason,
                    }
                ),
            )
        await write_audit(
            conn,
            tenant_id=tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="asset.split",
            target=Target(type="asset", id=str(asset_uuid)),
            after={
                "new_asset_id": str(new_asset_id),
                "identity_ids": [str(i) for i in identity_ids],
                "reason": body.reason,
            },
        )
        original_detail = await _asset_detail(conn, tenant_id, asset_uuid)
        new_detail = await _asset_detail(conn, tenant_id, new_asset_id)
    return {"assets": [original_detail, new_detail]}
