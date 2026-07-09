"""asyncpg pool wrapper with tenant-pinned transactions (SEC-23).

Every tenant-scoped statement runs inside `tenant_transaction(tenant_id)`,
which sets the RLS GUC via soc_tenancy.set_local_tenant (SET LOCAL — clears
at commit/rollback, pool-safe). `system_transaction()` is for GLOBAL tables
only (control.platform_config/control.tenants reads, tenantdata.rule_packs/
rules/rule_runtime_disables) — RLS-protected tables return zero rows there
by design (deny-by-default).

The `workers`/`jobs` modules may import and reuse `Database` +
`create_database` (binding module contract for the workers agent).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol
from uuid import UUID

import asyncpg

from soc_tenancy import set_local_tenant


class ConnectionLike(Protocol):
    """Duck type shared by asyncpg.Connection and test fakes."""

    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


class Database:
    """Thin pool wrapper; the ONLY place transactions/GUC pinning happen."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    @asynccontextmanager
    async def tenant_transaction(self, tenant_id: UUID | str) -> AsyncIterator[ConnectionLike]:
        async with self._pool.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            try:
                await set_local_tenant(conn, tenant_id)
                yield conn
            except BaseException:
                await tx.rollback()
                raise
            else:
                await tx.commit()

    @asynccontextmanager
    async def system_transaction(self) -> AsyncIterator[ConnectionLike]:
        """No tenant GUC: for global (non-RLS) tables only."""
        async with self._pool.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            try:
                yield conn
            except BaseException:
                await tx.rollback()
                raise
            else:
                await tx.commit()

    async def close(self) -> None:
        await self._pool.close()


async def create_database(dsn: str) -> Database:
    pool = await asyncpg.create_pool(dsn=dsn, min_size=2, max_size=10)
    return Database(pool)


def to_jsonb(value: Any) -> str | None:
    """Serialize a param for a `$n::jsonb` placeholder (no jsonb codec is
    registered on purpose — soc_audit passes pre-serialized strings)."""
    if value is None:
        return None
    return json.dumps(value, separators=(",", ":"), default=str)


def from_jsonb(value: Any) -> Any:
    """Read a jsonb column (asyncpg returns str without a codec; fakes may
    return structured values directly)."""
    if isinstance(value, str | bytes):
        return json.loads(value)
    return value
