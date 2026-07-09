"""dataplane-api INTERNAL app (/internal/v1/... — contract §13).

Separate ASGI app bound to an internal-only listener (compose internal
network / K8s NetworkPolicy); NEVER routed by the ingest gateway or any
public listener (SEC-30/40). Auth: HMAC-signed short-lived service tokens
(design §5.1 item 2) on every route.

Run: uvicorn --factory dataplane.internal_main:build_app --port 8091
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from dataplane.api import internal
from dataplane.api.deps import assert_routes_declared
from dataplane.core.errors import install_error_handlers
from dataplane.core.resources import AppResources, build_resources
from dataplane.core.settings import Settings
from soc_telemetry import configure_json_logging, init_telemetry


def create_internal_app(
    settings: Settings, resources: AppResources | None = None
) -> FastAPI:
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
        title="dataplane-internal",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.resources = resources
    install_error_handlers(app)
    app.include_router(internal.router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ok"}

    assert_routes_declared(app)
    return app


def build_app() -> FastAPI:
    """uvicorn --factory entrypoint (production, internal listener)."""
    configure_json_logging()
    init_telemetry("dataplane-internal")
    return create_internal_app(Settings.from_env())
