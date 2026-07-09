"""Signup: password policy, breached check, AC-4 domain 409, AC-8 abuse, SEC-6."""

from __future__ import annotations

from cp_env import CHALLENGE_TOKEN, DEFAULT_PASSWORD, do_signup


async def test_signup_happy_path_sends_verification_link(env):
    response = await do_signup(env, email="admin@acme.example")
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "pending_verification"
    assert body["account_id"].startswith("acc_")

    mail = env.mailer.outbox[-1]
    assert mail["to"] == "admin@acme.example"
    # Contract §14 item 5: /signup/verify?token=...&account_id=acc_... on the console origin.
    assert "https://console.test/signup/verify?token=" in mail["body"]
    assert f"account_id={body['account_id']}" in mail["body"]


async def test_password_policy_minimum_12_chars(env):
    response = await do_signup(env, password="short-pw-11c")
    assert response.status_code == 202  # exactly 12 chars passes

    response = await do_signup(
        env, email="x@other.example", org="Other", password="elevenchars"
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "PASSWORD_POLICY_VIOLATION"


async def test_breached_password_rejected(env):
    response = await do_signup(env, password="password12345")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "PASSWORD_BREACHED"
    assert env.db.accounts == {}


async def test_domain_already_registered_reveals_nothing(env):
    assert (await do_signup(env, email="admin@acme.example")).status_code == 202
    dup = await do_signup(env, email="someone.else@acme.example", org="Impostor")
    assert dup.status_code == 409
    body = dup.json()["error"]
    assert body["code"] == "DOMAIN_ALREADY_REGISTERED"
    # AC-4: no org name, email, or account detail beyond "domain has an account".
    assert "acme" not in body["message"].lower()
    assert "admin@" not in body["message"]
    assert body.get("details") is None


async def test_ip_velocity_triggers_challenge_and_logs(env):
    env.db.platform_config["signup_per_ip_hourly_threshold"] = "1"
    assert (await do_signup(env, email="a@one.example", org="One")).status_code == 202

    held = await do_signup(env, email="b@two.example", org="Two")
    assert held.status_code == 400
    error = held.json()["error"]
    assert error["code"] == "SIGNUP_CHALLENGE_REQUIRED"
    assert error["details"]["challenge"]["status"] == "required"
    assert env.db.abuse_log[-1]["outcome"] == "challenged"
    assert env.db.abuse_log[-1]["reason"] == "ip_velocity"


async def test_challenge_response_pass_and_fail(env):
    env.db.platform_config["signup_per_ip_hourly_threshold"] = "0"

    failed = await env.public.post(
        "/v1/signup",
        json={
            "org_name": "Two",
            "email": "b@two.example",
            "password": DEFAULT_PASSWORD,
            "challenge_response": "wrong",
        },
    )
    assert failed.status_code == 400
    assert failed.json()["error"]["code"] == "SIGNUP_CHALLENGE_REQUIRED"
    assert env.db.abuse_log[-1]["outcome"] == "blocked"
    assert env.db.abuse_log[-1]["reason"] == "challenge_failed"

    passed = await env.public.post(
        "/v1/signup",
        json={
            "org_name": "Three",
            "email": "c@three.example",
            "password": DEFAULT_PASSWORD,
            "challenge_response": CHALLENGE_TOKEN,
        },
    )
    assert passed.status_code == 202
    assert any(
        row["outcome"] == "allowed" and row["reason"] == "challenge_passed"
        for row in env.db.abuse_log
    )


async def test_disposable_domain_requires_challenge(env):
    response = await do_signup(env, email="fraud@mailinator.com", org="Fraudsters")
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "SIGNUP_CHALLENGE_REQUIRED"
    assert "disposable_domain" in error["details"]["challenge"]["reason"]


async def test_resend_verification_never_enumerates(env):
    unknown = await env.public.post(
        "/v1/signup/resend-verification", json={"email": "ghost@nowhere.example"}
    )
    assert unknown.status_code == 202
    assert env.mailer.outbox == []

    await do_signup(env, email="admin@acme.example")
    sent_before = len(env.mailer.outbox)
    known = await env.public.post(
        "/v1/signup/resend-verification", json={"email": "admin@acme.example"}
    )
    assert known.status_code == 202
    assert len(env.mailer.outbox) == sent_before + 1
    # Identical status for both cases — no enumeration channel (SEC-6).
    assert unknown.status_code == known.status_code
