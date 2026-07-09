"""Audit helpers: soc_audit writes with tenant RLS context (SEC-42..45).

Two entry points:
- `write_audit_in_tx(conn, ...)` — for callers already inside the transaction
  that performs the audited state change (SEC-43 same-transaction rule);
  callers must have pinned the tenant GUC.
- `audit_standalone(db, ...)` — opens its own transaction (used for pure audit
  events like failed authz, where there is no accompanying state change).

`tenantdata.audit_log` is RLS-protected, so every write pins
`app.tenant_id` via soc_tenancy (the only sanctioned way).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from soc_audit import Actor, Target, write_audit
from soc_tenancy import set_local_tenant

PLATFORM_TENANT_ID = UUID("00000000-0000-0000-0000-000000000000")
"""Reserved tenant id for platform-scope entries (db/README.md)."""


async def write_audit_in_tx(
    conn: Any,
    *,
    tenant_id: UUID,
    actor: Actor,
    action_type: str,
    target: Target,
    before: Mapping[str, Any] | None = None,
    after: Mapping[str, Any] | None = None,
    reason_code: str | None = None,
) -> None:
    await write_audit(
        conn,
        tenant_id=tenant_id,
        actor=actor,
        action_type=action_type,
        target=target,
        before=before,
        after=after,
        reason_code=reason_code,
    )


async def audit_standalone(
    db: Any,
    *,
    tenant_id: UUID,
    actor: Actor,
    action_type: str,
    target: Target,
    before: Mapping[str, Any] | None = None,
    after: Mapping[str, Any] | None = None,
    reason_code: str | None = None,
) -> None:
    async with db.acquire() as conn:
        async with conn.transaction():
            await set_local_tenant(conn, tenant_id)
            await write_audit(
                conn,
                tenant_id=tenant_id,
                actor=actor,
                action_type=action_type,
                target=target,
                before=before,
                after=after,
                reason_code=reason_code,
            )
