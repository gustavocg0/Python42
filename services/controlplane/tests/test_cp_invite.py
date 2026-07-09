"""POST /v1/auth/accept-invite (contract §4, Architect-ratified 2026-07-08)."""

from __future__ import annotations

from cp_env import login, provision_tenant


async def _invite_user(env, email: str = "analyst@acme.example", role: str = "analyst") -> str:
    """Admin invites a user; returns the invite token from the email."""
    await provision_tenant(env)
    assert (await login(env)).status_code == 200
    created = await env.public.post(
        "/v1/users",
        json={"email": email, "role": role},
        headers={"X-CSRF-Token": env.csrf()},
    )
    assert created.status_code == 201, created.text
    return env.mailer.last_token()


async def test_accept_invite_activates_user_and_enables_login(env):
    token = await _invite_user(env)
    response = await env.public.post(
        "/v1/auth/accept-invite",
        json={"token": token, "password": "fresh-invitee-pw-77"},
    )
    assert response.status_code == 204

    user = next(u for u in env.db.users.values() if u["email"] == "analyst@acme.example")
    assert user["state"] == "active" and user["password_hash"]

    fresh = env.new_client()
    logged_in = await login(
        env, email="analyst@acme.example", password="fresh-invitee-pw-77", client=fresh
    )
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["role"] == "analyst"

    audit = next(a for a in env.db.audit_log if a["action_type"] == "user.invite_accepted")
    assert audit["actor_id"] == f"usr_{user['id']}"


async def test_accept_invite_single_use(env):
    token = await _invite_user(env)
    first = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "fresh-invitee-pw-77"}
    )
    assert first.status_code == 204
    again = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "another-good-pw-88"}
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "VERIFICATION_ALREADY_USED"


async def test_accept_invite_expiry_and_unknown_token(env):
    token = await _invite_user(env)
    env.clock.advance(hours=25)
    expired = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "fresh-invitee-pw-77"}
    )
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "VERIFICATION_EXPIRED"

    unknown = await env.public.post(
        "/v1/auth/accept-invite", json={"token": "bogus", "password": "fresh-invitee-pw-77"}
    )
    assert unknown.status_code == 410  # indistinguishable from expired (SEC-6)


async def test_rejected_password_does_not_burn_the_invite(env):
    token = await _invite_user(env)

    weak = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "elevenchars"}
    )
    assert weak.status_code == 400
    assert weak.json()["error"]["code"] == "PASSWORD_POLICY_VIOLATION"

    breached = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "password12345"}
    )
    assert breached.status_code == 400
    assert breached.json()["error"]["code"] == "PASSWORD_BREACHED"

    # Token survived both rejections — a good password still works.
    retry = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "fresh-invitee-pw-77"}
    )
    assert retry.status_code == 204


async def test_signup_verification_token_not_valid_for_invite(env):
    from cp_env import do_signup

    await do_signup(env)
    signup_token = env.mailer.last_token()
    response = await env.public.post(
        "/v1/auth/accept-invite",
        json={"token": signup_token, "password": "fresh-invitee-pw-77"},
    )
    assert response.status_code == 410  # wrong purpose == unknown (SEC-6)
    # And the signup token was NOT consumed by the failed attempt.
    verified = await env.public.post("/v1/signup/verify", json={"token": signup_token})
    assert verified.status_code == 200
    await env.drain_background()


async def test_deleted_user_invite_cannot_be_accepted(env):
    token = await _invite_user(env)
    invited_id = next(
        u["id"] for u in env.db.users.values() if u["email"] == "analyst@acme.example"
    )
    deleted = await env.public.delete(
        f"/v1/users/usr_{invited_id}", headers={"X-CSRF-Token": env.csrf()}
    )
    assert deleted.status_code == 204

    response = await env.public.post(
        "/v1/auth/accept-invite", json={"token": token, "password": "fresh-invitee-pw-77"}
    )
    assert response.status_code == 410
