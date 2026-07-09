"""Sessions, cookies, CSRF, lockout/throttle, enumeration (SEC-3/4/6, AC-77)."""

from __future__ import annotations

from cp_env import DEFAULT_PASSWORD, login, provision_tenant


def _set_cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


async def test_login_sets_cookies_and_returns_contract_shape(env):
    tenant_id = await provision_tenant(env)
    response = await login(env)
    assert response.status_code == 200

    body = response.json()
    assert set(body) == {"user", "tenant"}
    assert set(body["user"]) == {"id", "email", "role"}
    assert body["user"]["id"].startswith("usr_")
    assert body["user"]["role"] == "admin"
    assert body["tenant"]["id"] == f"tn_{tenant_id}"
    assert body["tenant"]["status"] == "active"
    assert body["tenant"]["abuse_frozen"] is False
    assert body["tenant"]["trial_expires_at"].endswith("Z")

    cookies = _set_cookie_headers(response)
    sid_cookie = next(c for c in cookies if c.startswith("sid="))
    csrf_cookie = next(c for c in cookies if c.startswith("csrf_token="))
    assert "HttpOnly" in sid_cookie and "Secure" in sid_cookie and "SameSite=lax" in sid_cookie.replace("Lax", "lax")
    assert "HttpOnly" not in csrf_cookie and "Secure" in csrf_cookie

    me = await env.public.get("/v1/me")
    assert me.status_code == 200
    assert me.json() == body


async def test_login_errors_are_uniform_for_unknown_email_and_bad_password(env):
    await provision_tenant(env)
    unknown = await login(env, email="ghost@acme.example", password="whatever-12345")
    wrong = await login(env, email="admin@acme.example", password="wrong-password-1")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert unknown.json()["error"]["code"] == "AUTH_REQUIRED"


async def test_account_lockout_after_10_failures(env):
    await provision_tenant(env)
    for _ in range(10):
        response = await login(env, password="wrong-password-1")
        assert response.status_code == 401
    # Correct password is now also rejected: 429 RATE_LIMITED + Retry-After.
    locked = await login(env, password=DEFAULT_PASSWORD)
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "RATE_LIMITED"
    assert int(locked.headers["Retry-After"]) > 0
    assert env.db.users and next(iter(env.db.users.values()))["failed_login_count"] == 10


async def test_per_ip_throttle(env_factory):
    env = await env_factory(login_ip_threshold=3)
    await provision_tenant(env)
    for _ in range(3):
        await login(env, email="nobody@nowhere.example", password="wrong-password-1")
    blocked = await login(env, password=DEFAULT_PASSWORD)  # even valid creds
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMITED"


async def test_csrf_required_on_mutating_routes(env):
    await provision_tenant(env)
    await login(env)
    payload = {"email": "new@acme.example", "role": "analyst"}

    missing = await env.public.post("/v1/users", json=payload)
    assert missing.status_code == 401

    wrong = await env.public.post(
        "/v1/users", json=payload, headers={"X-CSRF-Token": "forged"}
    )
    assert wrong.status_code == 401

    ok = await env.public.post(
        "/v1/users", json=payload, headers={"X-CSRF-Token": env.csrf()}
    )
    assert ok.status_code == 201
    assert any(a["reason_code"] == "csrf_failed" for a in env.db.audit_log)


async def test_logout_revokes_session(env):
    await provision_tenant(env)
    await login(env)
    response = await env.public.post(
        "/v1/auth/logout", headers={"X-CSRF-Token": env.csrf()}
    )
    assert response.status_code == 204
    assert (await env.public.get("/v1/me")).status_code == 401
    assert any(a["action_type"] == "auth.logout" for a in env.db.audit_log)


async def test_absolute_session_lifetime(env):
    await provision_tenant(env)
    await login(env)
    env.clock.advance(days=8)  # beyond the 7d absolute lifetime
    response = await env.public.get("/v1/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_EXPIRED"


async def test_change_password_invalidates_other_sessions(env):
    await provision_tenant(env)
    await login(env)
    other = env.new_client()
    assert (await login(env, client=other)).status_code == 200

    wrong = await env.public.post(
        "/v1/auth/change-password",
        json={"current_password": "not-my-password", "new_password": "brand-new-pw-123"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert wrong.status_code == 400

    changed = await env.public.post(
        "/v1/auth/change-password",
        json={"current_password": DEFAULT_PASSWORD, "new_password": "brand-new-pw-123"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert changed.status_code == 204

    assert (await env.public.get("/v1/me")).status_code == 200  # current session survives
    assert (await other.get("/v1/me")).status_code == 401  # other session revoked

    fresh = env.new_client()
    assert (await login(env, client=fresh, password="brand-new-pw-123")).status_code == 200


async def test_frozen_tenant_login_reads_ok_writes_blocked(env):
    tenant_id = await provision_tenant(env)
    env.db.tenants[tenant_id]["status"] = "frozen"
    await env.services.tenant_status.invalidate(tenant_id)

    assert (await login(env)).status_code == 200
    me = await env.public.get("/v1/me")
    assert me.status_code == 200
    assert me.json()["tenant"]["status"] == "frozen"  # console signals read-only

    blocked = await env.public.post(
        "/v1/users",
        json={"email": "x@acme.example", "role": "analyst"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert blocked.status_code == 403
    error = blocked.json()["error"]
    assert error["code"] == "TENANT_FROZEN" and error["details"]["cause"] == "trial"

    assert (await env.public.get("/v1/users")).status_code == 200  # reads remain

    # Account-security operations stay available on frozen tenants
    # (Architect-ratified 2026-07-08): change-password and logout.
    changed = await env.public.post(
        "/v1/auth/change-password",
        json={"current_password": DEFAULT_PASSWORD, "new_password": "rotated-on-freeze-9"},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert changed.status_code == 204
    logout = await env.public.post("/v1/auth/logout", headers={"X-CSRF-Token": env.csrf()})
    assert logout.status_code == 204  # logout always possible
    fresh = env.new_client()
    assert (
        await login(env, client=fresh, password="rotated-on-freeze-9")
    ).status_code == 200


async def test_unhandled_errors_return_internal_error_code(env):
    """Contract §2 (ratified 2026-07-08): unhandled 500s carry INTERNAL_ERROR,
    never SERVICE_UNAVAILABLE (reserved for fail-closed dependency denials)."""
    import httpx

    from controlplane import queries

    env.db.inject_failure(queries.SELECT_ACCOUNT_BY_ID, times=1)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env.public_app, raise_app_exceptions=False),
        base_url="https://testserver",
    )
    try:
        response = await client.get(
            "/v1/signup/provisioning-status",
            params={"account_id": "acc_00000000-0000-0000-0000-0000000000aa"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 500
    body = response.json()["error"]
    assert body["code"] == "INTERNAL_ERROR"
    assert body["message"] == "Internal server error."  # no stack traces / details


async def test_purged_tenant_blocked_entirely(env):
    tenant_id = await provision_tenant(env)
    assert (await login(env)).status_code == 200
    env.db.tenants[tenant_id]["status"] = "purged"
    await env.services.tenant_status.invalidate(tenant_id)

    assert (await env.public.get("/v1/me")).status_code == 401
    fresh = env.new_client()
    assert (await login(env, client=fresh)).status_code == 401  # no new session either
