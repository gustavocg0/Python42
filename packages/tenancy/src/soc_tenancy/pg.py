"""Postgres RLS tenant GUC helper (SEC-23, threat model §4.1).

`SET LOCAL app.tenant_id = '<uuid>'` inside each request/message transaction:
auto-clears at commit/rollback, so pooled connections never bleed tenant
context (safe with PgBouncer transaction pooling). Policies use
current_setting('app.tenant_id', true)::uuid — missing/empty GUC => zero rows
(deny-by-default).

This module is the ONLY place that sets the GUC (threat model §4.1).
"""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from soc_tenancy.es import validate_tenant_uuid

SET_TENANT_GUC_SQL = "SELECT set_config('app.tenant_id', $1, true)"
"""Parameterized form (asyncpg placeholders). set_config(..., true) == SET LOCAL."""


class _AsyncExecutor(Protocol):
    """Duck type for asyncpg Connection / any conn exposing execute(sql, *args)."""

    async def execute(self, query: str, *args: Any) -> Any: ...


def set_local_tenant_sql(tenant_id: UUID | str) -> str:
    """Literal `SET LOCAL` statement for drivers without parameterized SET.

    Safe by construction: the value is a canonicalized UUID, so no injection
    surface. For SQLAlchemy: `await conn.execute(text(set_local_tenant_sql(tid)))`.
    """
    return f"SET LOCAL app.tenant_id = '{validate_tenant_uuid(tenant_id)}'"


async def set_local_tenant(conn: _AsyncExecutor, tenant_id: UUID | str) -> UUID:
    """Set the RLS GUC for the CURRENT TRANSACTION on an asyncpg-style connection.

    Must be called inside an open transaction; SET LOCAL outside a transaction
    is a silent no-op in Postgres — callers own the transaction scope.
    Raises InvalidTenantError before any I/O on a bad tenant_id (fail closed).
    """
    tenant = validate_tenant_uuid(tenant_id)
    await conn.execute(SET_TENANT_GUC_SQL, str(tenant))
    return tenant
