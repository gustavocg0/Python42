"""Internal API auth (HMAC, SEC-40), plan change, abuse freeze (SEC-39)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

from cp_env import SVC_KEY_DATAPLANE, SVC_KEY_OPS, login, provision_tenant

from soc_entitlements import generate_service_token


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _ops_headers(operator: str = "ops:alice@vendor.example") -> dict:
    token = generate_service_token(service_name="opsconsole", key=SVC_KEY_OPS)
    return {**_bearer(token), "X-Operator-Id": operator}


def _forge_token(service: str, key: str, expires: int) -> str:
    signing_input = f"v1.{service}.{expires}"
    sig = hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).hexdigest()
    return f"{signing_input}.{sig}"


async def test_hmac_auth_rejections(env):
    tenant_id = await provision_tenant(env)
    url = f"/internal/v1/tenants/{tenant_id}/entitlements"

    assert (await env.internal.get(url)).status_code == 401  # no header
    assert (
        await env.internal.get(url, headers=_bearer("v1.malformed"))
    ).status_code == 401
    # Wrong key => bad signature.
    bad_sig = generate_service_token(service_name="dataplane", key="x" * 32)
    assert (await env.internal.get(url, headers=_bearer(bad_sig))).status_code == 401
    # Unknown service name (no key configured).
    rogue = generate_service_token(service_name="rogue", key="r" * 32)
    assert (await env.internal.get(url, headers=_bearer(rogue))).status_code == 401
    # Expired beyond the +/-30s skew.
    expired = generate_service_token(
        service_name="dataplane", key=SVC_KEY_DATAPLANE, now=int(time.time()) - 400
    )
    assert (await env.internal.get(url, headers=_bearer(expired))).status_code == 401
    # Lifetime over the 300s ceiling is invalid even with a valid signature.
    too_long = _forge_token("dataplane", SVC_KEY_DATAPLANE, int(time.time()) + 100_000)
    assert (await env.internal.get(url, headers=_bearer(too_long))).status_code == 401

    error = (await env.internal.get(url)).json()["error"]
    assert error["code"] == "AUTH_REQUIRED"


async def test_plan_change_requires_operator_identity(env):
    tenant_id = await provision_tenant(env)
    url = f"/internal/v1/tenants/{tenant_id}/plan"
    token = generate_service_token(service_name="opsconsole", key=SVC_KEY_OPS)

    missing = await env.internal.put(url, json={"plan": "core"}, headers=_bearer(token))
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "VALIDATION_ERROR"
    assert env.db.tenants[tenant_id]["plan_id"] == "trial"  # unchanged


async def test_plan_change_audits_and_invalidates_caches(env):
    tenant_id = await provision_tenant(env)
    await login(env)
    await env.public.get("/v1/tenant/entitlements")  # warm ent + tenantstatus
    await env.services.tenant_status.get(tenant_id)
    assert await env.redis.get(f"ent:{tenant_id}") is not None
    assert await env.redis.hgetall(f"tenantstatus:{tenant_id}")

    response = await env.internal.put(
        f"/internal/v1/tenants/{tenant_id}/plan",
        json={"plan": "core"},
        headers=_ops_headers("ops:alice@vendor.example"),
    )
    assert response.status_code == 200
    assert response.json() == {"tenant_id": str(tenant_id), "plan": "core"}

    # Delete-on-change (AC-15/SEC-39): both keys gone.
    assert await env.redis.get(f"ent:{tenant_id}") is None
    assert not await env.redis.hgetall(f"tenantstatus:{tenant_id}")

    # Audit: operator identity + old/new values (SEC-40).
    audit = next(a for a in env.db.audit_log if a["action_type"] == "tenant.plan_changed")
    assert audit["actor_id"] == "ops:alice@vendor.example"
    assert '"trial"' in audit["before"] and '"core"' in audit["after"]

    # Next read recomposes with the new plan; paid plan drops trial expiry.
    body = (await env.public.get("/v1/tenant/entitlements")).json()
    assert body["plan"] == "core"
    assert body["entitlements"]["endpoint_cap"] == 250
    assert "trial_expires_at" not in body

    unknown = await env.internal.put(
        "/internal/v1/tenants/00000000-0000-0000-0000-00000000dead/plan",
        json={"plan": "core"},
        headers=_ops_headers(),
    )
    assert unknown.status_code == 404


async def test_abuse_freeze_flow(env):
    tenant_id = await provision_tenant(env)
    await login(env)
    await env.services.tenant_status.get(tenant_id)  # warm the status cache

    frozen = await env.internal.put(
        f"/internal/v1/tenants/{tenant_id}/abuse-freeze",
        json={"frozen": True, "reason": "spam ingest from tenant"},
        headers=_ops_headers("ops:bob@vendor.example"),
    )
    assert frozen.status_code == 200
    assert env.db.tenants[tenant_id]["abuse_frozen"] is True
    # tenantstatus:{t} deleted => next read backfills the new state (<=60s SLO).
    assert not await env.redis.hgetall(f"tenantstatus:{tenant_id}")

    audit = next(
        a for a in env.db.audit_log if a["action_type"] == "tenant.abuse_freeze_changed"
    )
    assert audit["actor_id"] == "ops:bob@vendor.example"
    assert json.loads(audit["before"])["abuse_frozen"] is False
    after = json.loads(audit["after"])
    assert after["abuse_frozen"] is True and "spam ingest" in after["reason"]

    # Console: writes blocked with cause=abuse, reads remain (SEC-39).
    write = await env.public.post(
        "/v1/users",
        json={"email": "x@acme.example", "role": "analyst"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert write.status_code == 403
    error = write.json()["error"]
    assert error["code"] == "TENANT_FROZEN" and error["details"]["cause"] == "abuse"
    assert (await env.public.get("/v1/users")).status_code == 200
    me = await env.public.get("/v1/me")
    assert me.json()["tenant"]["abuse_frozen"] is True

    # Unfreeze restores writes.
    unfrozen = await env.internal.put(
        f"/internal/v1/tenants/{tenant_id}/abuse-freeze",
        json={"frozen": False, "reason": "resolved with customer"},
        headers=_ops_headers("ops:bob@vendor.example"),
    )
    assert unfrozen.status_code == 200
    write_again = await env.public.post(
        "/v1/users",
        json={"email": "x@acme.example", "role": "analyst"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert write_again.status_code == 201


async def test_abuse_freeze_requires_reason_and_operator(env):
    tenant_id = await provision_tenant(env)
    token = generate_service_token(service_name="opsconsole", key=SVC_KEY_OPS)
    no_operator = await env.internal.put(
        f"/internal/v1/tenants/{tenant_id}/abuse-freeze",
        json={"frozen": True, "reason": "x"},
        headers=_bearer(token),
    )
    assert no_operator.status_code == 400

    no_reason = await env.internal.put(
        f"/internal/v1/tenants/{tenant_id}/abuse-freeze",
        json={"frozen": True, "reason": ""},
        headers=_ops_headers(),
    )
    assert no_reason.status_code == 400
    assert env.db.tenants[tenant_id]["abuse_frozen"] is False
