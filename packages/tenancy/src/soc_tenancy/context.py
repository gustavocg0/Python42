"""Tenant contextvar — one tenant per request / per pipeline message (SEC-20/23)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar, Token
from uuid import UUID

from soc_tenancy.errors import InvalidTenantError, TenantContextError

_current_tenant: ContextVar[UUID | None] = ContextVar("soc_current_tenant", default=None)


def _coerce_tenant(tenant_id: UUID | str) -> UUID:
    try:
        return UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidTenantError(f"invalid tenant_id: {tenant_id!r}") from exc


def set_current_tenant(tenant_id: UUID | str) -> Token[UUID | None]:
    """Set the current tenant; returns a token for reset_current_tenant()."""
    return _current_tenant.set(_coerce_tenant(tenant_id))


def reset_current_tenant(token: Token[UUID | None]) -> None:
    _current_tenant.reset(token)


def get_current_tenant() -> UUID | None:
    return _current_tenant.get()


def require_current_tenant() -> UUID:
    """Return the current tenant or raise — never proceed without one (fail closed)."""
    tenant = _current_tenant.get()
    if tenant is None:
        raise TenantContextError("no tenant context established")
    return tenant


@asynccontextmanager
async def tenant_context(tenant_id: UUID | str) -> AsyncIterator[UUID]:
    """Scoped tenant context.

    Also usable as the `tenant_context` factory for soc_pipeline consumers:

        StreamConsumer(..., tenant_context=lambda msg: tenant_context(msg.tenant_id))

    (the envelope tenant_id, never a payload field — SEC-20).
    """
    token = set_current_tenant(tenant_id)
    try:
        yield require_current_tenant()
    finally:
        reset_current_tenant(token)
