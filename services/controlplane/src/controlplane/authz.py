"""Deny-by-default authorization (SEC-30) + session auth + CSRF (SEC-3/§14).

Every route MUST carry an explicit declaration:
- `@public` on the endpoint function (unauthenticated routes: signup, login,
  health probes), or
- a `require_roles(...)` dependency (cookie-session routes), or
- a `require_service_auth(...)` dependency (internal routes).

`assert_all_routes_declared(app)` runs at app construction and raises on any
undeclared route — a route without a declaration NEVER ships (fail closed).

The session dependency enforces, in order:
1. session validity (Redis `sess:{sid}`; idle/absolute timeouts),
2. tenant reachability: `purged`/`provisioning_failed`/`provisioning` tenants
   are blocked entirely (session revoked, 401),
3. CSRF double-submit on every mutating request (`X-CSRF-Token` header vs the
   per-session token; cookie `csrf_token` per contract §14),
4. role membership (403 FORBIDDEN_ROLE),
5. frozen-tenant write block: mutating requests on trial-frozen or
   abuse-frozen tenants => 403 TENANT_FROZEN with details.cause (contract §1),
   except routes flagged `allow_frozen_write` — logout and change-password
   (Architect-ratified 2026-07-08: account-security operations must work on
   frozen tenants).

Failed authorization writes an audit record with a reason_code (AC-85).
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.routing import APIRoute

from controlplane.auditing import audit_standalone
from controlplane.sessions import SESSION_COOKIE_NAME, SessionData, SessionExpiredError
from soc_audit import Actor, Target
from soc_schemas.errors import ApiError, ErrorCode
from soc_tenancy import set_current_tenant

logger = logging.getLogger(__name__)

CSRF_HEADER_NAME = "X-CSRF-Token"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_BLOCKED_TENANT_STATUSES = frozenset({"purged", "provisioning_failed", "provisioning"})

AUTHZ_ATTR = "__soc_authz__"


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    session_id: str
    user_id: UUID
    tenant_id: UUID
    role: str
    csrf_token: str
    tenant_status: str
    abuse_frozen: bool


def public(endpoint):
    """Explicitly declare an endpoint as unauthenticated (SEC-30)."""
    setattr(endpoint, AUTHZ_ATTR, "public")
    return endpoint


def client_ip(request: Request) -> str | None:
    settings = getattr(request.app.state, "settings", None)
    if settings is not None and settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def _audit_denial(
    request: Request,
    session: SessionData,
    *,
    reason_code: str,
) -> None:
    """AC-85: failed authz => audit record with reason_code. Best effort —
    the denial stands even if the audit write fails (logged)."""
    services = request.app.state.services
    try:
        await audit_standalone(
            services.db,
            tenant_id=session.tenant_id,
            actor=Actor(type="user", id=f"usr_{session.user_id}"),
            action_type="authz.denied",
            target=Target(type="route", id=f"{request.method} {request.url.path}"),
            reason_code=reason_code,
        )
    except Exception:
        logger.exception("failed to audit authz denial")


def require_roles(*roles: str, allow_frozen_write: bool = False):
    """Session-auth dependency requiring one of the declared roles (SEC-30).

    Returns the SessionPrincipal; also pins the tenant contextvar via
    soc_tenancy so downstream code inherits tenant context.
    """
    if not roles:
        raise ValueError("require_roles needs at least one role (deny-by-default)")
    allowed = frozenset(roles)

    async def dependency(request: Request) -> SessionPrincipal:
        services = request.app.state.services
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")
        try:
            session = await services.sessions.get(session_id)
        except SessionExpiredError:
            raise ApiError(ErrorCode.SESSION_EXPIRED, "Session expired.") from None
        if session is None:
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")

        set_current_tenant(session.tenant_id)

        # Tenant reachability (design §5: no access for non-live tenants).
        status = await services.tenant_status.get(session.tenant_id)
        if status is None or status.status in _BLOCKED_TENANT_STATUSES:
            await services.sessions.revoke(session.session_id, reason="tenant_unavailable")
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")

        mutating = request.method.upper() in MUTATING_METHODS
        if mutating:
            presented = request.headers.get(CSRF_HEADER_NAME, "")
            if not presented or not hmac.compare_digest(presented, session.csrf_token):
                await _audit_denial(request, session, reason_code="csrf_failed")
                raise ApiError(ErrorCode.AUTH_REQUIRED, "CSRF token missing or invalid.")

        if session.role not in allowed:
            await _audit_denial(request, session, reason_code="role_forbidden")
            raise ApiError(
                ErrorCode.FORBIDDEN_ROLE,
                "Your role does not permit this action.",
                details={"required_roles": sorted(allowed)},
            )

        if mutating and not allow_frozen_write:
            if status.abuse_frozen:
                await _audit_denial(request, session, reason_code="tenant_frozen_abuse")
                raise ApiError(
                    ErrorCode.TENANT_FROZEN,
                    "This tenant is frozen.",
                    details={"cause": "abuse"},
                )
            if status.status == "frozen":
                await _audit_denial(request, session, reason_code="tenant_frozen_trial")
                raise ApiError(
                    ErrorCode.TENANT_FROZEN,
                    "This tenant's trial has expired.",
                    details={"cause": "trial"},
                )

        return SessionPrincipal(
            session_id=session.session_id,
            user_id=session.user_id,
            tenant_id=session.tenant_id,
            role=session.role,
            csrf_token=session.csrf_token,
            tenant_status=status.status,
            abuse_frozen=status.abuse_frozen,
        )

    setattr(
        dependency,
        AUTHZ_ATTR,
        {"roles": tuple(sorted(allowed)), "allow_frozen_write": allow_frozen_write},
    )
    return dependency


def _iter_dependency_calls(dependant: Any):
    yield dependant.call
    for sub in dependant.dependencies:
        yield from _iter_dependency_calls(sub)


def iter_api_routes(app_or_router: Any):
    """Yield every APIRoute, flattening lazily-included routers.

    FastAPI >= 0.139 keeps included routers as `_IncludedRouter` entries in
    `app.routes` (with the concrete APIRoutes on `original_router.routes`);
    older versions flatten to APIRoute directly. Handle both — the SEC-30
    gate must never silently skip routes."""
    for route in app_or_router.routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from iter_api_routes(original)
        elif hasattr(route, "routes"):  # generic nested router/mount with routes
            yield from iter_api_routes(route)


def assert_all_routes_declared(app: FastAPI) -> None:
    """Startup gate (SEC-30): every APIRoute must carry an authz declaration."""
    undeclared: list[str] = []
    seen_any = False
    for route in iter_api_routes(app):
        seen_any = True
        module = getattr(route.endpoint, "__module__", "") or ""
        if module.startswith(("fastapi.", "starlette.")):
            continue  # framework-internal (docs) endpoints
        declared = any(
            getattr(call, AUTHZ_ATTR, None) is not None
            for call in _iter_dependency_calls(route.dependant)
            if call is not None
        )
        if not declared:
            undeclared.append(f"{sorted(route.methods or set())} {route.path}")
    if not seen_any:
        raise RuntimeError(
            "SEC-30 check found no API routes — route flattening is broken; failing closed"
        )
    if undeclared:
        raise RuntimeError(
            "SEC-30 deny-by-default violation: routes without an explicit "
            f"authorization declaration: {', '.join(undeclared)}"
        )
