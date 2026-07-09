"""SEC-30 deny-by-default route declarations + listener separation (SEC-40)."""

from __future__ import annotations

import pytest
from cp_env import DEFAULT_PASSWORD, create_active_user, login, provision_tenant
from fastapi import FastAPI

from controlplane.authz import assert_all_routes_declared, iter_api_routes


def test_undeclared_route_fails_closed():
    app = FastAPI()

    @app.get("/v1/oops")
    async def oops():  # no @public, no role/service dependency
        return {}

    with pytest.raises(RuntimeError, match="SEC-30"):
        assert_all_routes_declared(app)


async def test_shipped_apps_construct_with_all_routes_declared(env):
    # Construction already runs assert_all_routes_declared; reaching here means
    # every shipped route carries an explicit declaration. Sanity-check that
    # the flattener actually sees the mounted routes (guards against FastAPI
    # routing internals changing under us).
    public_paths = {r.path for r in iter_api_routes(env.public_app)}
    internal_paths = {r.path for r in iter_api_routes(env.internal_app)}
    assert {"/v1/signup", "/v1/auth/login", "/v1/users", "/healthz"} <= public_paths
    assert "/internal/v1/tenants/{tenant_id}/plan" in internal_paths


async def test_adding_undeclared_route_to_public_app_is_caught(env):
    app = env.public_app

    @app.get("/v1/forgotten")
    async def forgotten():
        return {}

    with pytest.raises(RuntimeError, match="forgotten"):
        assert_all_routes_declared(app)


async def test_internal_routes_never_on_public_listener(env):
    for route in iter_api_routes(env.public_app):
        assert not route.path.startswith("/internal"), route.path
    # And hitting an internal path on the public app is a plain 404.
    response = await env.public.get("/internal/v1/tenants/x/entitlements")
    assert response.status_code == 404


async def test_public_routes_never_on_internal_listener(env):
    internal_paths = {r.path for r in iter_api_routes(env.internal_app)}
    assert internal_paths
    assert not any(p.startswith("/v1/") for p in internal_paths)
    response = await env.internal.post(
        "/v1/auth/login", json={"email": "a@b.co", "password": "x" * 12}
    )
    assert response.status_code == 404


async def test_role_denial_is_audited_with_reason_code(env):
    tenant_id = await provision_tenant(env)
    await create_active_user(env, tenant_id, email="analyst@acme.example", role="analyst")
    response = await login(env, email="analyst@acme.example", password=DEFAULT_PASSWORD)
    assert response.status_code == 200

    denied = await env.public.get("/v1/users")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "FORBIDDEN_ROLE"

    denials = [a for a in env.db.audit_log if a["action_type"] == "authz.denied"]
    assert denials and denials[-1]["reason_code"] == "role_forbidden"
