"""User CRUD: admin-only, tenant scoping, session invalidation (contract §4)."""

from __future__ import annotations

import uuid

from cp_env import (
    DEFAULT_PASSWORD,
    create_active_user,
    login,
    make_second_tenant,
    provision_tenant,
)


async def _admin_session(env):
    tenant_id = await provision_tenant(env)
    assert (await login(env)).status_code == 200
    return tenant_id


def _csrf_headers(env):
    return {"X-CSRF-Token": env.csrf()}


async def test_list_and_create_user_with_invite(env):
    await _admin_session(env)
    listed = await env.public.get("/v1/users")
    assert listed.status_code == 200
    assert listed.json()["total_estimate"] == 1  # the signup admin

    created = await env.public.post(
        "/v1/users",
        json={"email": "analyst@acme.example", "role": "analyst"},
        headers=_csrf_headers(env),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["id"].startswith("usr_") and body["state"] == "invited"

    invite = env.mailer.outbox[-1]
    assert invite["to"] == "analyst@acme.example"
    assert "token=" in invite["body"]

    duplicate = await env.public.post(
        "/v1/users",
        json={"email": "analyst@acme.example", "role": "analyst"},
        headers=_csrf_headers(env),
    )
    assert duplicate.status_code == 400

    assert any(a["action_type"] == "user.created" for a in env.db.audit_log)
    assert (await env.public.get("/v1/users")).json()["total_estimate"] == 2


async def test_role_change_invalidates_target_sessions(env):
    tenant_id = await _admin_session(env)
    await create_active_user(env, tenant_id, email="analyst@acme.example", role="analyst")

    analyst_client = env.new_client()
    assert (
        await login(env, email="analyst@acme.example", client=analyst_client)
    ).status_code == 200
    analyst_id = next(
        u["id"] for u in env.db.users.values() if u["email"] == "analyst@acme.example"
    )

    patched = await env.public.patch(
        f"/v1/users/usr_{analyst_id}", json={"role": "admin"}, headers=_csrf_headers(env)
    )
    assert patched.status_code == 200
    assert patched.json()["role"] == "admin"

    # Target's sessions are gone (SEC-3); a fresh login gets the new role.
    assert (await analyst_client.get("/v1/me")).status_code == 401
    audit = next(a for a in env.db.audit_log if a["action_type"] == "user.role_changed")
    assert '"analyst"' in audit["before"] and '"admin"' in audit["after"]


async def test_delete_user_invalidates_sessions(env):
    tenant_id = await _admin_session(env)
    await create_active_user(env, tenant_id, email="analyst@acme.example", role="analyst")
    analyst_client = env.new_client()
    await login(env, email="analyst@acme.example", client=analyst_client)
    analyst_id = next(
        u["id"] for u in env.db.users.values() if u["email"] == "analyst@acme.example"
    )

    deleted = await env.public.delete(
        f"/v1/users/usr_{analyst_id}", headers=_csrf_headers(env)
    )
    assert deleted.status_code == 204
    assert (await analyst_client.get("/v1/me")).status_code == 401
    assert (
        await login(env, email="analyst@acme.example", client=env.new_client())
    ).status_code == 401
    assert any(a["action_type"] == "user.deleted" for a in env.db.audit_log)


async def test_foreign_tenant_user_is_404(env):
    await _admin_session(env)
    other_tenant = make_second_tenant(env)
    foreign_id = await create_active_user(
        env, other_tenant, email="victim@other.example", role="admin"
    )

    response = await env.public.patch(
        f"/v1/users/usr_{foreign_id}", json={"role": "analyst"}, headers=_csrf_headers(env)
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert env.db.users[foreign_id]["role"] == "admin"  # untouched

    unknown = await env.public.delete(
        f"/v1/users/usr_{uuid.uuid4()}", headers=_csrf_headers(env)
    )
    assert unknown.status_code == 404  # indistinguishable from foreign (AC-81)


async def test_self_delete_and_self_role_change_blocked(env):
    await _admin_session(env)
    me = await env.public.get("/v1/me")
    my_id = me.json()["user"]["id"]

    self_delete = await env.public.delete(f"/v1/users/{my_id}", headers=_csrf_headers(env))
    assert self_delete.status_code == 400

    self_demote = await env.public.patch(
        f"/v1/users/{my_id}", json={"role": "analyst"}, headers=_csrf_headers(env)
    )
    assert self_demote.status_code == 400


async def test_analyst_cannot_manage_users(env):
    tenant_id = await provision_tenant(env)
    await create_active_user(env, tenant_id, email="analyst@acme.example", role="analyst")
    assert (
        await login(env, email="analyst@acme.example", password=DEFAULT_PASSWORD)
    ).status_code == 200

    assert (await env.public.get("/v1/users")).status_code == 403
    create = await env.public.post(
        "/v1/users",
        json={"email": "x@acme.example", "role": "analyst"},
        headers=_csrf_headers(env),
    )
    assert create.status_code == 403
    assert create.json()["error"]["code"] == "FORBIDDEN_ROLE"
