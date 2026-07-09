"""Pluggable tenant resolvers + FastAPI dependency (design §2, AC-82).

Tenant is ALWAYS derived from the credential (api-contracts.md §1):
(a) session cookie, (b) ingest-key identity, (c) gateway-verified device
headers. Services supply the credential lookups (they own the stores); this
module owns the resolution order, contextvar wiring, and fail-closed default.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from uuid import UUID

from fastapi import Request

from soc_schemas.errors import ApiError, ErrorCode
from soc_tenancy.context import set_current_tenant
from soc_tenancy.errors import InvalidTenantError
from soc_tenancy.es import validate_tenant_uuid
from soc_tenancy.gateway import GATEWAY_AUTHENTICATED_STATE_KEY, IDENTITY_HEADERS

PrincipalType = Literal["session", "ingest_key", "device"]


@dataclass(frozen=True, slots=True)
class ResolvedTenant:
    """Outcome of tenant resolution — the ONLY source of request tenant context."""

    tenant_id: UUID
    principal_type: PrincipalType
    principal_id: str
    extra: dict[str, Any] = field(default_factory=dict, hash=False)


class TenantResolver(Protocol):
    """One credential-type resolver. Return None to fall through (not my credential);
    raise ApiError to reject outright (my credential, but invalid)."""

    async def resolve(self, request: Request) -> ResolvedTenant | None: ...


class SessionTenantResolver:
    """(a) session -> tenant. `lookup` maps a session id to ResolvedTenant | None."""

    def __init__(
        self,
        lookup: Callable[[str], Awaitable[ResolvedTenant | None]],
        *,
        cookie_name: str = "sid",
    ) -> None:
        self._lookup = lookup
        self._cookie_name = cookie_name

    async def resolve(self, request: Request) -> ResolvedTenant | None:
        session_id = request.cookies.get(self._cookie_name)
        if not session_id:
            return None
        return await self._lookup(session_id)


class IngestKeyTenantResolver:
    """(b) ingest key -> tenant. `lookup` verifies the presented key against the
    hashed store (SEC-16, constant-time) and returns ResolvedTenant | None.
    Unknown/foreign/revoked keys: raise ApiError(INGEST_KEY_INVALID/REVOKED)
    inside `lookup` — indistinguishability is the service's contract duty."""

    def __init__(
        self,
        lookup: Callable[[str], Awaitable[ResolvedTenant | None]],
        *,
        header_name: str = "X-Ingest-Key",
    ) -> None:
        self._lookup = lookup
        self._header_name = header_name

    async def resolve(self, request: Request) -> ResolvedTenant | None:
        presented = request.headers.get(self._header_name)
        if not presented:
            return None
        return await self._lookup(presented)


class GatewayDeviceTenantResolver:
    """(c) gateway-verified device headers -> tenant (SEC-14).

    Only trusts X-Device-Id / X-Device-Tenant when GatewayAuthMiddleware marked
    the request gateway-authenticated; otherwise the headers were already
    stripped and this resolver returns None. The device allowlist check
    (SEC-10: status + cert serial, 503 when stores are down) is `verify`'s job
    — it MUST raise ApiError on revoked/unknown/unavailable, never fall through.
    """

    def __init__(
        self,
        verify: Callable[[UUID, str], Awaitable[ResolvedTenant]],
    ) -> None:
        self._verify = verify

    async def resolve(self, request: Request) -> ResolvedTenant | None:
        state = getattr(request, "state", None)
        if not state or not getattr(state, GATEWAY_AUTHENTICATED_STATE_KEY, False):
            return None
        device_id = request.headers.get(IDENTITY_HEADERS[0])
        device_tenant = request.headers.get(IDENTITY_HEADERS[1])
        if not device_id or not device_tenant:
            return None
        try:
            tenant_id = validate_tenant_uuid(device_tenant)
        except InvalidTenantError:
            raise ApiError(
                ErrorCode.DEVICE_IDENTITY_INVALID,
                "Device identity could not be established.",
            ) from None
        return await self._verify(tenant_id, device_id)


def tenant_dependency(
    resolvers: Sequence[TenantResolver],
    *,
    failure_code: ErrorCode = ErrorCode.AUTH_REQUIRED,
) -> Callable[[Request], Awaitable[ResolvedTenant]]:
    """Build the FastAPI dependency that resolves + pins tenant context.

    Resolvers are tried in order; the first non-None wins. The tenant
    contextvar is set before returning. No resolver matching => ApiError
    (fail closed, 401 by default). Usage:

        resolve_tenant = tenant_dependency([session_resolver, key_resolver])

        @router.get("/v1/assets")
        async def list_assets(tenant: ResolvedTenant = Depends(resolve_tenant)): ...
    """
    resolver_chain = tuple(resolvers)
    if not resolver_chain:
        raise ValueError("tenant_dependency requires at least one resolver")

    async def resolve_tenant(request: Request) -> ResolvedTenant:
        for resolver in resolver_chain:
            resolved = await resolver.resolve(request)
            if resolved is not None:
                set_current_tenant(resolved.tenant_id)
                return resolved
        raise ApiError(failure_code, "Authentication required.")

    return resolve_tenant
