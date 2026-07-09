"""Public controlplane-api app factory (contract §3/§4/§5 public surface).

The internal router is NEVER mounted here — it lives on a separate app and
listener (controlplane.internal_app / internal_main, SEC-30/40).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from controlplane.authz import CSRF_HEADER_NAME, assert_all_routes_declared
from controlplane.config import Settings
from controlplane.errors import install_error_handlers
from controlplane.routes import auth, entitlements_public, health, signup, users
from controlplane.services import AppServices
from controlplane.telemetry_middleware import install_request_spans

SERVICE_NAME = "controlplane-api"


def create_public_app(settings: Settings, services: AppServices | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        created_here = False
        if app.state.services is None:
            from controlplane.runtime import build_runtime_services

            app.state.services = await build_runtime_services(settings)
            created_here = True
        # Restart recovery: resume in-flight provisioning sagas (AC-5).
        for task in await app.state.services.saga.resume_running():
            app.state.services.background_tasks.add(task)
            task.add_done_callback(app.state.services.background_tasks.discard)
        yield
        if created_here:
            from controlplane.runtime import shutdown_runtime_services

            await shutdown_runtime_services(app.state.services)

    app = FastAPI(
        title=SERVICE_NAME,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.services = services

    install_error_handlers(app)
    install_request_spans(app, SERVICE_NAME)
    # CORS per contract §14: console origin, credentials, CSRF header.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.console_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", CSRF_HEADER_NAME],
    )

    app.include_router(health.router)
    app.include_router(signup.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(entitlements_public.router)

    # SEC-30: refuse to construct an app with an undeclared route.
    assert_all_routes_declared(app)
    return app
