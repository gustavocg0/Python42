"""dataplane-api PUBLIC app (console/agent/generic-ingest routes).

Assembly order (outermost first at runtime):
  CORS (console origin, credentials) ->
  GatewayAuthMiddleware (SEC-14: strips identity headers on unauthenticated
  hops; 401 AUTH_REQUIRED on agent routes without X-Gateway-Auth) ->
  routers (every route carries a deny-by-default auth declaration, SEC-30).

Internal (/internal/v1/...) routes are NOT here — see
dataplane.internal_main (separate listener, SEC-40).

Run: uvicorn --factory dataplane.main:build_app
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from dataplane.api import alerts, assets, audit, enrollment, ingest, investigation, rules
from dataplane.api.deps import assert_routes_declared
from dataplane.core.errors import install_error_handlers
from dataplane.core.resources import AppResources, build_resources
from dataplane.core.settings import Settings
from soc_telemetry import configure_json_logging, init_telemetry
from soc_tenancy import GatewayAuthMiddleware

_ROUTERS = (
    ingest.router,
    enrollment.router,
    assets.router,
    alerts.router,
    investigation.router,
    rules.router,
    audit.router,
)


def create_app(settings: Settings, resources: AppResources | None = None) -> FastAPI:
    """Public app factory. Tests inject `resources` built from fakes;
    production leaves it None and the lifespan builds real clients."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owns_resources = app.state.resources is None
        if owns_resources:
            app.state.resources = await build_resources(settings)
        try:
            yield
        finally:
            if owns_resources:
                await app.state.resources.aclose()
                app.state.resources = None

    app = FastAPI(
        title="dataplane-api",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.resources = resources
    install_error_handlers(app)
    for router in _ROUTERS:
        app.include_router(router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ok"}

    assert_routes_declared(app)  # SEC-30 deny-by-default gate

    # Middleware added last runs first: Gateway auth wraps routes; CORS wraps
    # everything (contract §14.2: console origin + credentials + CSRF header).
    app.add_middleware(
        GatewayAuthMiddleware,
        secret=settings.gateway_auth_secret,
        agent_route_prefixes=("/v1/agent",),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.console_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["X-CSRF-Token", "Content-Type"],
    )
    return app


def build_app() -> FastAPI:
    """uvicorn --factory entrypoint (production)."""
    configure_json_logging()
    init_telemetry("dataplane-api")
    return create_app(Settings.from_env())
