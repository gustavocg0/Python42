"""Internal controlplane app factory (contract §13; SEC-30/40).

Separate FastAPI app on a separate listener (default 127.0.0.1:8101,
network-restricted in compose/K8s). No CORS, no docs, no public routes —
only /internal/v1 (HMAC service-token auth) and health probes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from controlplane.authz import assert_all_routes_declared
from controlplane.config import Settings
from controlplane.errors import install_error_handlers
from controlplane.routes import health, internal
from controlplane.services import AppServices
from controlplane.telemetry_middleware import install_request_spans

SERVICE_NAME = "controlplane-internal"


def create_internal_app(settings: Settings, services: AppServices | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        created_here = False
        if app.state.services is None:
            from controlplane.runtime import build_runtime_services

            app.state.services = await build_runtime_services(settings)
            created_here = True
        yield
        if created_here:
            from controlplane.runtime import shutdown_runtime_services

            await shutdown_runtime_services(app.state.services)

    app = FastAPI(
        title=SERVICE_NAME,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.services = services

    install_error_handlers(app)
    install_request_spans(app, SERVICE_NAME)

    app.include_router(health.router)
    app.include_router(internal.router)

    assert_all_routes_declared(app)
    return app
