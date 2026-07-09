"""Entitlements composition, overrides, -1 unlimited, cache invalidation (§5)."""

from __future__ import annotations

import time

from cp_env import SVC_KEY_DATAPLANE, login, provision_tenant

from soc_entitlements import generate_service_token


def _svc_headers(service: str = "dataplane", key: str = SVC_KEY_DATAPLANE) -> dict:
    token = generate_service_token(service_name=service, key=key)
    return {"Authorization": f"Bearer {token}"}


async def test_public_entitlements_shape_matches_contract(env):
    tenant_id = await provision_tenant(env)
    await login(env)
    response = await env.public.get("/v1/tenant/entitlements")
    assert response.status_code == 200
    body = response.json()
    assert body["plan"] == "trial"
    assert body["tenant_status"] == "active"
    assert body["abuse_frozen"] is False
    assert body["trial_expires_at"].endswith("Z")
    assert body["as_of"].endswith("Z")
    assert body["entitlements"] == {
        "endpoint_cap": 100,
        "retention_days": 14,
        "deep_investigation_daily_quota": 5,
        "response_mode": "recommend_only",
        "ingest_events_per_min": 5000,
    }
    # Cached in ent:{t} with a bounded TTL (<=5 min, AC-13).
    ttl = await env.redis.ttl(f"ent:{tenant_id}")
    assert 0 < ttl <= 300


async def test_internal_entitlements_same_shape(env):
    tenant_id = await provision_tenant(env)
    internal = await env.internal.get(
        f"/internal/v1/tenants/{tenant_id}/entitlements", headers=_svc_headers()
    )
    assert internal.status_code == 200
    assert internal.json()["entitlements"]["endpoint_cap"] == 100

    unknown = await env.internal.get(
        "/internal/v1/tenants/00000000-0000-0000-0000-00000000dead/entitlements",
        headers=_svc_headers(),
    )
    assert unknown.status_code == 404


async def test_overrides_apply_and_expire(env):
    tenant_id = await provision_tenant(env)
    env.db.overrides[(tenant_id, "endpoint_cap")] = {"value": "500", "expires_at": None}
    env.db.overrides[(tenant_id, "retention_days")] = {
        "value": "90",
        "expires_at": env.clock(),  # already expired => ignored
    }
    await env.redis.delete(f"ent:{tenant_id}")

    await login(env)
    body = (await env.public.get("/v1/tenant/entitlements")).json()
    assert body["entitlements"]["endpoint_cap"] == 500  # override wins
    assert body["entitlements"]["retention_days"] == 14  # expired override ignored


async def test_minus_one_means_unlimited_passthrough(env):
    tenant_id = await provision_tenant(env)
    env.db.overrides[(tenant_id, "deep_investigation_daily_quota")] = {
        "value": "-1",
        "expires_at": None,
    }
    await env.redis.delete(f"ent:{tenant_id}")
    await login(env)
    body = (await env.public.get("/v1/tenant/entitlements")).json()
    assert body["entitlements"]["deep_investigation_daily_quota"] == -1


async def test_cached_payload_served_until_invalidated(env):
    tenant_id = await provision_tenant(env)
    await login(env)
    first = (await env.public.get("/v1/tenant/entitlements")).json()

    # Change the DB directly: the cached payload keeps serving (TTL <= 5 min)...
    env.db.plan_config[("trial", "endpoint_cap")] = "111"
    second = (await env.public.get("/v1/tenant/entitlements")).json()
    assert second["entitlements"]["endpoint_cap"] == first["entitlements"]["endpoint_cap"]

    # ...until delete-on-change invalidation.
    await env.services.entitlements.invalidate(tenant_id)
    third = (await env.public.get("/v1/tenant/entitlements")).json()
    assert third["entitlements"]["endpoint_cap"] == 111


async def test_expired_service_token_rejected(env):
    tenant_id = await provision_tenant(env)
    stale = generate_service_token(
        service_name="dataplane", key=SVC_KEY_DATAPLANE, now=int(time.time()) - 400
    )
    response = await env.internal.get(
        f"/internal/v1/tenants/{tenant_id}/entitlements",
        headers={"Authorization": f"Bearer {stale}"},
    )
    assert response.status_code == 401
