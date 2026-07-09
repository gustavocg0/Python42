"""Entitlements composition + shared Redis cache (contract §5, ADR-0005, SEC-41).

Composition: `control.plan_config[plan]` base values overlaid with
`control.entitlement_overrides` (non-expired). `-1` means unlimited and
passes through untouched. The payload shape is validated against
soc_entitlements.TenantEntitlements — the same model the dataplane client
consumes (single contract, both sides).

Cache: `ent:{t}` (300s TTL). This service is the ONLY writer (SEC-41).
Plan/abuse/override changes DELETE `ent:{t}` AND `tenantstatus:{t}` —
delete-on-change makes the TTL the worst-case propagation (SEC-39 <=60s for
status, AC-11/15 <=5min for plan values).

NOTE (contract §5): this payload is informational for `abuse_frozen` — the
tenant-status store is the enforcement source, never this cache.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from controlplane import redis_keys
from controlplane.ids import rfc3339
from controlplane.queries import (
    SELECT_ENTITLEMENT_OVERRIDES,
    SELECT_PLAN_CONFIG,
    SELECT_TENANT_BY_ID,
)
from soc_entitlements import TenantEntitlements

ENT_CACHE_TTL_SECONDS = 300

# Plan-meta keys that are configuration, not tenant-facing entitlements.
_NON_ENTITLEMENT_KEYS = frozenset({"trial_duration_days"})


class EntitlementsService:
    def __init__(self, *, db: Any, redis: Any, clock) -> None:
        self._db = db
        self._redis = redis
        self._clock = clock

    async def compose(self, tenant_id: UUID) -> dict[str, Any] | None:
        """Fresh composition from PG. None => unknown tenant."""
        now = self._clock()
        async with self._db.acquire() as conn:
            tenant = await conn.fetchrow(SELECT_TENANT_BY_ID, tenant_id)
            if tenant is None:
                return None
            plan_rows = await conn.fetch(SELECT_PLAN_CONFIG, tenant["plan_id"])
            override_rows = await conn.fetch(SELECT_ENTITLEMENT_OVERRIDES, tenant_id, now)

        values: dict[str, Any] = {
            row["key"]: json.loads(row["value"])
            for row in plan_rows
            if row["key"] not in _NON_ENTITLEMENT_KEYS
        }
        for row in override_rows:
            values[row["key"]] = json.loads(row["value"])

        payload: dict[str, Any] = {
            "plan": tenant["plan_id"],
            "tenant_status": str(tenant["status"]),
            "abuse_frozen": bool(tenant["abuse_frozen"]),
            "entitlements": values,
            "as_of": rfc3339(now),
        }
        if tenant["trial_expires_at"] is not None:
            payload["trial_expires_at"] = rfc3339(tenant["trial_expires_at"])
        # Shape guard: same model the dataplane entitlements client validates.
        TenantEntitlements.model_validate(payload)
        return payload

    async def get(self, tenant_id: UUID) -> dict[str, Any] | None:
        """Read-through: `ent:{t}` hit, else compose + cache (SEC-41 writer path)."""
        cached = await self._redis.get(redis_keys.ent(tenant_id))
        if cached:
            return json.loads(cached)
        payload = await self.compose(tenant_id)
        if payload is not None:
            await self._redis.set(
                redis_keys.ent(tenant_id), json.dumps(payload), ex=ENT_CACHE_TTL_SECONDS
            )
        return payload

    async def warm(self, tenant_id: UUID) -> dict[str, Any]:
        """Compose + cache, raising if the plan config is unusable (saga step)."""
        payload = await self.compose(tenant_id)
        if payload is None:
            raise RuntimeError(f"tenant {tenant_id} not found while warming entitlements")
        await self._redis.set(
            redis_keys.ent(tenant_id), json.dumps(payload), ex=ENT_CACHE_TTL_SECONDS
        )
        return payload

    async def invalidate(self, tenant_id: UUID) -> None:
        """Delete-on-change: entitlements cache AND tenant-status key (SEC-39)."""
        await self._redis.delete(redis_keys.ent(tenant_id))
        await self._redis.delete(redis_keys.tenantstatus(tenant_id))
