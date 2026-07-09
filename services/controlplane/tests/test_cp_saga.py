"""Provisioning saga: verify flow, idempotency, retries, terminal failure (AC-2/3/5)."""

from __future__ import annotations

import json

from cp_env import DEFAULT_PASSWORD, OUTBOUND_KEY, do_signup, login, provision_tenant

from soc_entitlements import verify_service_token


async def test_full_provisioning_flow(env):
    tenant_id = await provision_tenant(env)

    tenant = env.db.tenants[tenant_id]
    assert tenant["status"] == "active"
    assert tenant["trial_expires_at"] is not None
    assert (tenant["trial_expires_at"] - env.clock()).days == 14

    # Saga persisted and complete, all six steps done.
    saga = next(iter(env.db.sagas.values()))
    assert saga["state"] == "succeeded"
    steps = {s["step"]: s["status"] for (sid, _), s in env.db.saga_steps.items()}
    assert steps == {
        "tenant_row": "done",
        "rls_context": "done",
        "es_index": "done",
        "entitlements": "done",
        "admin_user": "done",
        "trial_expiry": "done",
    }

    # Dataplane provision call (contract §13): exact path, HMAC token, payload.
    assert len(env.dataplane.requests) == 1
    request = env.dataplane.requests[0]
    assert request.method == "PUT"
    assert request.url.path == f"/internal/v1/tenants/{tenant_id}/provision"
    assert json.loads(request.content) == {"tenant_id": str(tenant_id)}
    token = request.headers["Authorization"].removeprefix("Bearer ")
    assert verify_service_token(token, keys={"controlplane": OUTBOUND_KEY}) == "controlplane"

    # Admin user created from the signup account.
    admins = [u for u in env.db.users.values() if u["tenant_id"] == tenant_id]
    assert len(admins) == 1 and admins[0]["role"] == "admin"

    # Entitlements compose cleanly for the activated tenant (cache was
    # invalidated by the status change; read-through rebuilds it).
    payload = await env.services.entitlements.get(tenant_id)
    assert payload["tenant_status"] == "active" and payload["plan"] == "trial"
    assert await env.redis.get(f"ent:{tenant_id}") is not None

    # Status endpoint: ready + console_url (AC-3/5).
    account_id = next(iter(env.db.accounts))
    status = await env.public.get(
        "/v1/signup/provisioning-status", params={"account_id": f"acc_{account_id}"}
    )
    assert status.json() == {"state": "ready", "console_url": "https://console.test"}

    # Audit trail: verification + activation.
    actions = [a["action_type"] for a in env.db.audit_log]
    assert "signup.verified" in actions and "tenant.provisioned" in actions


async def test_verification_token_single_use_and_expiry(env):
    await do_signup(env)
    token = env.mailer.last_token()

    first = await env.public.post("/v1/signup/verify", json={"token": token})
    assert first.status_code == 200
    await env.drain_background()

    again = await env.public.post("/v1/signup/verify", json={"token": token})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "VERIFICATION_ALREADY_USED"

    unknown = await env.public.post("/v1/signup/verify", json={"token": "nope"})
    assert unknown.status_code == 410
    assert unknown.json()["error"]["code"] == "VERIFICATION_EXPIRED"


async def test_expired_verification_token(env):
    await do_signup(env)
    token = env.mailer.last_token()
    env.clock.advance(hours=25)
    response = await env.public.post("/v1/signup/verify", json={"token": token})
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "VERIFICATION_EXPIRED"


async def test_saga_retries_transient_dataplane_failure(env):
    env.dataplane.status_queue = [500]  # first call fails, retry succeeds
    tenant_id = await provision_tenant(env)
    assert env.db.tenants[tenant_id]["status"] == "active"
    assert len(env.dataplane.requests) == 2
    assert len(env.db.tenants) == 1  # no duplicate tenant rows on retry


async def test_saga_terminal_failure_marks_tenant_and_blocks_login(env):
    env.dataplane.status_queue = [500, 500]  # max_attempts=2 => terminal
    await do_signup(env)
    token = env.mailer.last_token()
    verified = await env.public.post("/v1/signup/verify", json={"token": token})
    assert verified.status_code == 200
    await env.drain_background()

    tenant = next(iter(env.db.tenants.values()))
    assert tenant["status"] == "provisioning_failed"
    saga = next(iter(env.db.sagas.values()))
    assert saga["state"] == "failed"
    assert "es_index" in saga["last_error"]

    # Status endpoint surfaces the failure (AC-5).
    account_id = next(iter(env.db.accounts))
    status = await env.public.get(
        "/v1/signup/provisioning-status", params={"account_id": f"acc_{account_id}"}
    )
    assert status.json()["state"] == "provisioning_failed"

    # No session issuable: admin user was never created; login is a uniform 401.
    response = await login(env)
    assert response.status_code == 401

    # Audited + terminal state is sticky on re-run.
    assert any(a["action_type"] == "tenant.provisioning_failed" for a in env.db.audit_log)
    assert await env.services.saga.run(saga["id"]) == "failed"
    assert len(env.dataplane.requests) == 2  # no further calls after terminal failure


async def test_saga_run_is_idempotent_after_success(env):
    tenant_id = await provision_tenant(env)
    saga = next(iter(env.db.sagas.values()))
    assert await env.services.saga.run(saga["id"]) == "succeeded"
    assert len(env.dataplane.requests) == 1  # completed steps never re-execute
    assert env.db.tenants[tenant_id]["status"] == "active"


async def test_resume_running_sagas_after_restart(env):
    await do_signup(env)
    account_id = next(iter(env.db.accounts))
    saga_id, tenant_id = await env.services.saga.ensure_started(
        account_id, env.db.accounts[account_id]["org_name"]
    )
    assert env.db.tenants[tenant_id]["status"] == "provisioning"

    tasks = await env.services.saga.resume_running()
    assert len(tasks) == 1
    for task in tasks:
        await task
    assert env.db.sagas[saga_id]["state"] == "succeeded"
    assert env.db.tenants[tenant_id]["status"] == "active"


async def test_provisioning_status_pending_before_verify(env):
    response = await do_signup(env)
    account_id = response.json()["account_id"]
    status = await env.public.get(
        "/v1/signup/provisioning-status", params={"account_id": account_id}
    )
    assert status.json() == {"state": "pending_verification"}

    missing = await env.public.get(
        "/v1/signup/provisioning-status",
        params={"account_id": "acc_00000000-0000-0000-0000-00000000abcd"},
    )
    assert missing.status_code == 404


async def test_login_password_matches_signup_password(env):
    await provision_tenant(env)
    response = await login(env, password=DEFAULT_PASSWORD)
    assert response.status_code == 200
