"""Authentication/authorization dependencies (deny-by-default, SEC-30).

Every route MUST declare exactly one auth dependency from this module; the
app factory asserts it at startup (`assert_routes_declared`). Markers:
- session_auth(...roles): console cookie (`sid` -> Redis sess:{sid}); CSRF
  double-submit + tenant-frozen write guard on mutating methods.
- agent_auth: gateway-verified device identity headers + SEC-10 allowlist
  (status + cert serial) — only meaningful behind GatewayAuthMiddleware.
- ingest_key_auth: X-Ingest-Key (SEC-16/17).
- enrollment_route: POST /v1/agent/enroll authenticates via the token in the
  body (handler-enforced) — marker only.
- service_token_auth: internal listener HMAC service tokens (SEC-40).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, NoReturn
from uuid import UUID

from fastapi import Request

from dataplane.core.resources import AppResources
from dataplane.core.seclog import log_security_event
from dataplane.core.sessions import CSRF_HEADER, MUTATING_METHODS, SessionPrincipal
from soc_entitlements import ServiceTokenError, verify_service_token
from soc_schemas import ApiError, ErrorCode
from soc_tenancy import (
    IDENTITY_HEADERS,
    InvalidTenantError,
    set_current_tenant,
    validate_tenant_uuid,
)

AUTH_MARKER = "__soc_auth__"
CERT_SERIAL_HEADER = "X-Client-Cert-Serial"
ROLES_ANY = ("admin", "analyst")
_GATEWAY_STATE_KEY = "gateway_authenticated"


def get_resources(request: Request) -> AppResources:
    return request.app.state.resources


def _mark(dep: Callable, kind: str) -> Callable:
    setattr(dep, AUTH_MARKER, kind)
    return dep


def not_found(resource_type: str, resource_id: str, tenant_id: UUID | None = None) -> NoReturn:
    """AC-81: missing OR foreign-tenant => identical 404 + security log."""
    log_security_event(
        "resource_not_found",
        resource_type=resource_type,
        resource_id=resource_id,
        tenant_id=str(tenant_id) if tenant_id else None,
    )
    raise ApiError(
        ErrorCode.NOT_FOUND,
        f"{resource_type} not found.",
        details={"resource_type": resource_type},
    )


# ------------------------------------------------------------------ console
def session_auth(*roles: str) -> Callable[[Request], Awaitable[SessionPrincipal]]:
    """Dependency factory: cookie session + role check (+CSRF/frozen-guard on
    writes). Empty roles = any authenticated console role."""
    allowed = frozenset(roles) if roles else frozenset(ROLES_ANY)

    async def resolve_session(request: Request) -> SessionPrincipal:
        resources = get_resources(request)
        session_id = request.cookies.get("sid")
        if not session_id:
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")
        principal = await resources.sessions.validate(session_id)
        if principal.role not in allowed:
            log_security_event(
                "role_denied",
                tenant_id=str(principal.tenant_id),
                user_id=str(principal.user_id),
                role=principal.role,
                path=request.url.path,
            )
            raise ApiError(
                ErrorCode.FORBIDDEN_ROLE,
                "Your role does not permit this action.",
                details={"required_role": sorted(allowed)},
            )
        if request.method in MUTATING_METHODS:
            resources.sessions.check_csrf(principal, request.headers.get(CSRF_HEADER))
            await resources.status_stores.require_writes_allowed(principal.tenant_id)
        set_current_tenant(principal.tenant_id)
        return principal

    return _mark(resolve_session, "session")


# -------------------------------------------------------------------- agent
@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    tenant_id: UUID
    device_id: str


async def agent_auth(request: Request) -> DeviceIdentity:
    """Gateway-injected identity headers + SEC-10 allowlist verification.

    GatewayAuthMiddleware already rejected agent routes lacking gateway auth
    (401 AUTH_REQUIRED) and stripped identity headers from unauthenticated
    hops; this dependency re-checks the state flag as defense in depth.
    """
    state = request.scope.get("state") or {}
    if not state.get(_GATEWAY_STATE_KEY, False):
        raise ApiError(ErrorCode.AUTH_REQUIRED, "Agent routes require the ingest gateway.")
    device_id = request.headers.get(IDENTITY_HEADERS[0])
    device_tenant = request.headers.get(IDENTITY_HEADERS[1])
    if not device_id or not device_tenant:
        raise ApiError(
            ErrorCode.DEVICE_IDENTITY_INVALID, "Device identity could not be established."
        )
    try:
        tenant_id = validate_tenant_uuid(device_tenant)
    except InvalidTenantError:
        raise ApiError(
            ErrorCode.DEVICE_IDENTITY_INVALID, "Device identity could not be established."
        ) from None
    resources = get_resources(request)
    await resources.status_stores.verify_device(
        tenant_id, device_id, request.headers.get(CERT_SERIAL_HEADER)
    )
    set_current_tenant(tenant_id)
    return DeviceIdentity(tenant_id=tenant_id, device_id=device_id)


_mark(agent_auth, "device")


# ------------------------------------------------------------------- ingest
@dataclass(frozen=True, slots=True)
class IngestKeyIdentity:
    tenant_id: UUID
    key_id: str


async def ingest_key_auth(request: Request) -> IngestKeyIdentity:
    presented = request.headers.get("X-Ingest-Key")
    if not presented:
        raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")
    resources = get_resources(request)
    verified = await resources.status_stores.verify_ingest_key(presented)
    set_current_tenant(verified.tenant_id)
    return IngestKeyIdentity(tenant_id=verified.tenant_id, key_id=verified.key_id)


_mark(ingest_key_auth, "ingest_key")


# --------------------------------------------------------------- enrollment
async def enrollment_route(request: Request) -> None:
    """Marker: authentication happens via the enrollment token in the body."""
    return None


_mark(enrollment_route, "enrollment_token")


# ----------------------------------------------------------------- internal
async def service_token_auth(request: Request) -> str:
    """Internal listener auth (design §5.1 item 2): HMAC service tokens."""
    resources = get_resources(request)
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError(ErrorCode.AUTH_REQUIRED, "Service authentication required.")
    try:
        return verify_service_token(
            header.removeprefix("Bearer ").strip(),
            keys=resources.settings.internal_service_keys,
        )
    except ServiceTokenError:
        log_security_event("service_token_rejected", path=request.url.path)
        raise ApiError(ErrorCode.AUTH_REQUIRED, "Service authentication required.") from None


_mark(service_token_auth, "service_token")


# ------------------------------------------------------------ SEC-30 gate
_PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})


def assert_routes_declared(app: Any) -> None:
    """Startup assertion: every route carries exactly one auth marker
    (deny-by-default route declarations, AC-78/SEC-30)."""
    from fastapi.routing import APIRoute

    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in _PUBLIC_PATHS:
            continue
        if not _dependant_has_marker(route.dependant):
            raise RuntimeError(
                f"route {route.path} has no auth declaration (SEC-30 deny-by-default)"
            )


def _dependant_has_marker(dependant: Any) -> bool:
    call = getattr(dependant, "call", None)
    if call is not None and getattr(call, AUTH_MARKER, None):
        return True
    return any(_dependant_has_marker(sub) for sub in getattr(dependant, "dependencies", []))
