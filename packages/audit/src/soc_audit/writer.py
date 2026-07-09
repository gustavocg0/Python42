"""Append-only audit writer (AC-83..85, SEC-42..45)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from soc_audit.redact import serialize_audit_value

AUDIT_INSERT_SQL = """\
INSERT INTO audit_log
    (tenant_id, actor_type, actor_id, action_type,
     target_type, target_id, before, after, reason_code, created_at)
VALUES
    ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, now())\
"""
"""created_at comes from the DB clock — never actor-supplied (SEC-45).
Column contract for database-architect's audit_log migration."""


class Actor(BaseModel):
    """Fixed actor taxonomy (SEC-45 / contract §12): user | system | device."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["user", "system", "device"]
    id: str = Field(min_length=1)


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str = Field(min_length=1)
    id: str = Field(min_length=1)


class _AsyncExecutor(Protocol):
    """Duck type for asyncpg Connection (or compatible) — execute(sql, *args)."""

    async def execute(self, query: str, *args: Any) -> Any: ...


async def write_audit(
    conn: _AsyncExecutor,
    *,
    tenant_id: UUID | str,
    actor: Actor,
    action_type: str,
    target: Target,
    before: Mapping[str, Any] | None = None,
    after: Mapping[str, Any] | None = None,
    reason_code: str | None = None,
) -> None:
    """INSERT one audit record on the caller's connection/transaction (SEC-43).

    Call this INSIDE the transaction that performs the audited state change:
    if this INSERT fails, the surrounding action must fail with it. There is
    deliberately no argument that accepts secret material or raw event
    payloads (SEC-44): before/after are structured dicts, redacted and
    size-capped before storage.
    """
    tenant = UUID(str(tenant_id))
    if not isinstance(actor, Actor):
        raise TypeError("actor must be a soc_audit.Actor")
    if not isinstance(target, Target):
        raise TypeError("target must be a soc_audit.Target")
    if not action_type or not action_type.strip():
        raise ValueError("action_type must be non-empty")

    before_json = serialize_audit_value(before)
    after_json = serialize_audit_value(after)

    await conn.execute(
        AUDIT_INSERT_SQL,
        str(tenant),
        actor.type,
        actor.id,
        action_type,
        target.type,
        target.id,
        before_json,
        after_json,
        reason_code,
    )
