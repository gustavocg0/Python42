"""Console auth: roles deny-by-default, CSRF double-submit, frozen-tenant
write guard, session expiry, SEC-30 route declaration gate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from dp_api_testkit import (
    TENANT_ID,
    alert_row,
    make_session,
    seed_tenant_status,
    session_kwargs,
)

from dataplane.api.deps import assert_routes_declared


async def test_no_cookie_is_401(client):
    response = await client.get("/v1/assets")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


async def test_expired_session_is_401_session_expired(client, fake_redis):
    sid = f"sid-{uuid4().hex}"
    now = datetime.now(UTC)
    await fake_redis.hset(
        f"sess:{sid}",
        mapping={
            "user_id": str(uuid4()),
            "tenant_id": str(TENANT_ID),
            "role": "admin",
            "csrf_token": "c",
            "created_at": (now - timedelta(days=8)).isoformat(),
            "absolute_expires_at": (now - timedelta(days=1)).isoformat(),
        },
    )
    response = await client.get("/v1/assets", cookies={"sid": sid})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_EXPIRED"


async def test_analyst_denied_on_admin_route(client, fake_redis):
    sid, csrf = await make_session(fake_redis, role="analyst")
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/ingest-keys", json={"name": "x"}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN_ROLE"


async def test_analyst_can_triage_alerts(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis, role="analyst")
    await seed_tenant_status(fake_redis)
    sql.on(
        r"UPDATE tenantdata\.alerts SET state = 'acknowledged'",
        rows=[alert_row(state="acknowledged")],
    )
    response = await client.post(
        "/v1/alerts/al_X/acknowledge", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 200


async def test_csrf_missing_on_write_is_401(client, fake_redis):
    sid, _ = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/ingest-keys", json={"name": "x"}, **session_kwargs(sid)
    )
    assert response.status_code == 401


async def test_csrf_wrong_token_is_401(client, fake_redis):
    sid, _ = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/ingest-keys",
        json={"name": "x"},
        cookies={"sid": sid},
        headers={"X-CSRF-Token": "wrong"},
    )
    assert response.status_code == 401


async def test_reads_do_not_require_csrf(client, fake_redis):
    sid, _ = await make_session(fake_redis)
    response = await client.get("/v1/assets", **session_kwargs(sid))
    assert response.status_code == 200


async def test_trial_frozen_blocks_writes_with_cause_trial(client, fake_redis):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis, status="frozen")
    response = await client.post(
        "/v1/ingest-keys", json={"name": "x"}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "TENANT_FROZEN"
    assert error["details"]["cause"] == "trial"


async def test_trial_frozen_reads_still_work(client, fake_redis):
    sid, _ = await make_session(fake_redis)
    await seed_tenant_status(fake_redis, status="frozen")
    response = await client.get("/v1/assets", **session_kwargs(sid))
    assert response.status_code == 200


async def test_abuse_frozen_blocks_writes_with_cause_abuse(client, fake_redis):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis, abuse_frozen=True)
    response = await client.post(
        "/v1/ingest-keys", json={"name": "x"}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 403
    assert response.json()["error"]["details"]["cause"] == "abuse"


async def test_all_routes_declare_auth(app, internal_app):
    """SEC-30: deny-by-default declarations — factories already assert this;
    re-run explicitly so a regression fails here too."""
    assert_routes_declared(app)
    assert_routes_declared(internal_app)


async def test_undeclared_route_is_rejected_at_startup(app):
    @app.get("/v1/oops")
    async def oops():  # pragma: no cover - never invoked
        return {}

    with pytest.raises(RuntimeError, match="deny-by-default"):
        assert_routes_declared(app)


async def test_unhandled_error_is_500_internal_error_envelope(
    app, fake_redis, sql, monkeypatch
):
    """Ratified taxonomy: unhandled => 500 INTERNAL_ERROR (never
    SERVICE_UNAVAILABLE); envelope only, no stack trace."""
    import httpx

    sid, _ = await make_session(fake_redis)

    def boom(*args, **kwargs):
        raise RuntimeError("secret stack detail")

    monkeypatch.setattr("dataplane.api.assets.clamp_limit", boom)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://dp.test") as client:
        response = await client.get("/v1/assets", **session_kwargs(sid))
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert "secret stack detail" not in response.text


async def test_session_store_down_is_503(client, fake_redis, monkeypatch):
    async def broken(*args, **kwargs):
        raise ConnectionError("redis down")

    monkeypatch.setattr(fake_redis, "hgetall", broken)
    response = await client.get("/v1/assets", cookies={"sid": "sid-x"})
    assert response.status_code == 503


# ------------------------------------------------------- misc console routes
async def test_rules_toggle_unknown_rule_404(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(r"FROM tenantdata\.rule_packs WHERE status = 'active'", value="1.0.0")
    sql.on(r"SELECT 1 FROM tenantdata\.rules WHERE pack_version", rows=[])
    response = await client.put(
        "/v1/rules/nope/enabled", json={"enabled": False}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 404


async def test_rules_list_effective_enabled(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    sql.on(r"FROM tenantdata\.rule_packs WHERE status = 'active'", value="1.0.0")
    sql.on(
        r"FROM tenantdata\.rules r LEFT JOIN tenantdata\.rule_runtime_disables",
        rows=[
            {
                "rule_id": "r_default_on",
                "rule_version": "1.0.0",
                "title": "A",
                "severity": "low",
                "mitre_technique_ids": [],
                "event_classes": ["process_activity"],
                "description": None,
                "enabled_default": True,
                "runtime_disabled": False,
            },
            {
                "rule_id": "r_toggled_off",
                "rule_version": "1.0.0",
                "title": "B",
                "severity": "high",
                "mitre_technique_ids": ["T1059"],
                "event_classes": [],
                "description": "d",
                "enabled_default": True,
                "runtime_disabled": False,
            },
            {
                "rule_id": "r_runtime_disabled",
                "rule_version": "1.0.0",
                "title": "C",
                "severity": "medium",
                "mitre_technique_ids": [],
                "event_classes": [],
                "description": None,
                "enabled_default": True,
                "runtime_disabled": True,
            },
        ],
    )
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.rules", value=3)
    sql.on(
        r"FROM tenantdata\.rule_toggles",
        rows=[{"rule_id": "r_toggled_off", "enabled": False}],
    )
    response = await client.get("/v1/rules", **session_kwargs(sid))
    assert response.status_code == 200
    enabled = {i["id"]: i["enabled"] for i in response.json()["items"]}
    assert enabled == {
        "r_default_on": True,
        "r_toggled_off": False,  # tenant toggle overrides pack default
        "r_runtime_disabled": False,  # runtime disable wins over everything
    }


async def test_onboarding_status_reconciles_signals(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    await fake_redis.hset(f"onboarding:{TENANT_ID}", "first_event", "1")
    sql.on(
        r"SELECT step_id, state, completed_at FROM tenantdata\.onboarding_steps",
        rows=[
            {"step_id": "install_agent", "state": "done", "completed_at": "2026-07-08T09:00:00+00:00"},
            {"step_id": "create_ingest_key", "state": "todo", "completed_at": None},
            {"step_id": "first_event", "state": "todo", "completed_at": None},
            {"step_id": "view_queue", "state": "todo", "completed_at": None},
        ],
    )
    sql.on(
        r"UPDATE tenantdata\.onboarding_steps SET state = 'done'",
        rows=[{"completed_at": "2026-07-08T10:00:00+00:00"}],
    )
    response = await client.get("/v1/onboarding/status", **session_kwargs(sid))
    assert response.status_code == 200
    steps = {s["id"]: s["state"] for s in response.json()["steps"]}
    assert steps == {
        "install_agent": "done",
        "create_ingest_key": "todo",
        "first_event": "done",  # auto-completed from the redis signal (AC-70)
        "view_queue": "todo",
    }


async def test_audit_logs_admin_only_and_shape(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis, role="analyst")
    denied = await client.get("/v1/audit-logs", **session_kwargs(sid))
    assert denied.status_code == 403

    sid_admin, _ = await make_session(fake_redis, role="admin")
    sql.on(
        r"FROM tenantdata\.audit_log WHERE",
        rows=[
            {
                "id": 7,
                "created_at": datetime.now(UTC),
                "tenant_id": TENANT_ID,
                "actor_type": "user",
                "actor_id": "u1",
                "action_type": "alert.close",
                "target_type": "alert",
                "target_id": "al_1",
                "before": None,
                "after": {"state": "closed"},
                "reason_code": "false_positive",
            }
        ],
    )
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.audit_log", value=1)
    response = await client.get("/v1/audit-logs", **session_kwargs(sid_admin))
    assert response.status_code == 200
    record = response.json()["items"][0]
    assert record["actor"] == {"type": "user", "id": "u1"}
    assert record["target"] == {"type": "alert", "id": "al_1"}
    assert record["after"] == {"state": "closed"}
    assert record["reason_code"] == "false_positive"


async def test_assets_billable_count_shape(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.assets", value=7)
    response = await client.get("/v1/assets/billable-count", **session_kwargs(sid))
    assert response.status_code == 200
    body = response.json()
    assert body["billable_count"] == 7
    assert body["endpoint_cap"] == 100
    assert body["window_days"] == 30
    assert "computed_at" in body
