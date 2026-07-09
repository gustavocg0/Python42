"""Tenant-status allowlist cache (SEC-39 path — NOT the entitlements cache).

`tenantstatus:{t}` per db/redis-conventions.md: HASH {status, abuse_frozen},
60s TTL, PG `control.tenants` is the source of truth, controlplane writes and
DELETES the key on any status/abuse change so the TTL is worst-case
propagation (<=60s), never the mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from controlplane import redis_keys
from controlplane.queries import SELECT_TENANT_BY_ID

TENANT_STATUS_TTL_SECONDS = 60


@dataclass(frozen=True, slots=True)
class TenantStatus:
    status: str
    abuse_frozen: bool


class TenantStatusStore:
    def __init__(self, *, db: Any, redis: Any) -> None:
        self._db = db
        self._redis = redis

    async def get(self, tenant_id: UUID) -> TenantStatus | None:
        """Redis first; miss => PG read + backfill; unknown tenant => None (deny)."""
        key = redis_keys.tenantstatus(tenant_id)
        cached = await self._redis.hgetall(key)
        if cached:
            return TenantStatus(
                status=cached["status"], abuse_frozen=cached["abuse_frozen"] == "1"
            )
        async with self._db.acquire() as conn:
            row = await conn.fetchrow(SELECT_TENANT_BY_ID, tenant_id)
        if row is None:
            return None
        status = TenantStatus(status=str(row["status"]), abuse_frozen=bool(row["abuse_frozen"]))
        await self._redis.hset(
            key,
            mapping={"status": status.status, "abuse_frozen": "1" if status.abuse_frozen else "0"},
        )
        await self._redis.expire(key, TENANT_STATUS_TTL_SECONDS)
        return status

    async def invalidate(self, tenant_id: UUID) -> None:
        """Delete-on-change (SEC-39: effective <=60s)."""
        await self._redis.delete(redis_keys.tenantstatus(tenant_id))
