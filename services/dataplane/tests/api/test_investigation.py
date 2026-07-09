"""Deep-investigation stub: exact contract shape, quota atomicity (AC-53..55)."""

from __future__ import annotations

import asyncio

from dp_api_testkit import TENANT_ID, make_session, seed_tenant_status, session_kwargs

from dataplane.core.quotas import QuotaService


def _register_alert(sql) -> None:
    sql.on(r"SELECT 1 FROM tenantdata\.alerts WHERE id", value=1)


async def test_stub_response_exact_contract_shape(client, fake_redis, sql):
    """Contract §9: the stub shape is the PERMANENT contract."""
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    _register_alert(sql)
    response = await client.post(
        "/v1/alerts/al_X/deep-investigation", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "investigation_id",
        "alert_id",
        "status",
        "is_stub",
        "engine_version",
        "requested_at",
        "completed_at",
        "requested_by",
        "summary",
        "confidence",
        "findings",
        "timeline",
        "evidence_graph",
        "recommended_actions",
        "quota",
    }
    assert body["investigation_id"].startswith("inv_")
    assert body["alert_id"] == "al_X"
    assert body["status"] == "completed"
    assert body["is_stub"] is True
    assert body["engine_version"] == "stub-1"
    assert body["summary"] == (
        "Deep investigation is coming soon. This placeholder confirms your "
        "entitlement and quota flow."
    )
    assert body["confidence"] is None
    assert body["findings"] == []
    assert body["timeline"] == []
    assert body["evidence_graph"] == {"nodes": [], "edges": []}
    assert body["recommended_actions"] == []
    assert set(body["quota"]) == {"limit", "remaining", "resets_at"}
    assert body["quota"]["limit"] == 5
    assert body["quota"]["remaining"] == 4
    # run + metering + audit rows persisted
    assert sql.executed(r"INSERT INTO tenantdata\.deep_investigation_runs")
    assert sql.executed(r"INSERT INTO tenantdata\.llm_metering")
    assert sql.executed(r"INSERT INTO audit_log")


async def test_quota_exhaustion_403_and_no_consumption(client, fake_redis, sql, entitlements):
    entitlements.values["deep_investigation_daily_quota"] = 2
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    _register_alert(sql)
    kwargs = session_kwargs(sid, csrf)
    first = await client.post("/v1/alerts/al_X/deep-investigation", **kwargs)
    second = await client.post("/v1/alerts/al_X/deep-investigation", **kwargs)
    assert first.status_code == second.status_code == 200
    assert first.json()["quota"]["remaining"] == 1
    assert second.json()["quota"]["remaining"] == 0
    third = await client.post("/v1/alerts/al_X/deep-investigation", **kwargs)
    assert third.status_code == 403
    error = third.json()["error"]
    assert error["code"] == "QUOTA_EXCEEDED_DEEP_INVESTIGATION"
    assert error["details"]["remaining"] == 0
    assert "resets_at" in error["details"]
    # AC-54: denial consumed nothing — counter still 0, not negative.
    keys = await fake_redis.keys(f"quota:di:{TENANT_ID}:*")
    assert len(keys) == 1
    assert int(await fake_redis.get(keys[0])) == 0


async def test_entitlement_denied_when_quota_zero(client, fake_redis, sql, entitlements):
    entitlements.values["deep_investigation_daily_quota"] = 0
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    _register_alert(sql)
    response = await client.post(
        "/v1/alerts/al_X/deep-investigation", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "ENTITLEMENT_DENIED"
    assert error["details"]["entitlement"] == "deep_investigation"


async def test_unlimited_quota_skips_redis_key(client, fake_redis, sql, entitlements):
    entitlements.values["deep_investigation_daily_quota"] = -1
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    _register_alert(sql)
    response = await client.post(
        "/v1/alerts/al_X/deep-investigation", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 200
    assert response.json()["quota"] == {
        "limit": -1,
        "remaining": -1,
        "resets_at": response.json()["quota"]["resets_at"],
    }
    assert await fake_redis.keys(f"quota:di:{TENANT_ID}:*") == []


async def test_unknown_alert_404_before_quota(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(r"SELECT 1 FROM tenantdata\.alerts WHERE id", rows=[])
    response = await client.post(
        "/v1/alerts/al_NOPE/deep-investigation", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 404
    assert await fake_redis.keys(f"quota:di:{TENANT_ID}:*") == []


async def test_concurrent_consumption_never_oversubscribes(fake_redis):
    """AC-55: 20 concurrent requests against limit 5 => exactly 5 succeed."""
    quotas = QuotaService(fake_redis)
    results = await asyncio.gather(
        *(quotas.consume_deep_investigation(TENANT_ID, 5) for _ in range(20))
    )
    allowed = [r for r in results if r.allowed]
    denied = [r for r in results if not r.allowed]
    assert len(allowed) == 5
    assert len(denied) == 15
    assert sorted(r.remaining for r in allowed) == [0, 1, 2, 3, 4]
    keys = await fake_redis.keys(f"quota:di:{TENANT_ID}:*")
    assert int(await fake_redis.get(keys[0])) == 0  # never negative


async def test_quota_status_endpoint(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    response = await client.get(
        "/v1/tenant/quotas/deep-investigation", **session_kwargs(sid)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 5
    assert body["remaining"] == 5  # untouched today
    assert "resets_at" in body


async def test_list_runs_paginated(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    _register_alert(sql)
    sql.on(
        r"FROM tenantdata\.deep_investigation_runs WHERE alert_id = \$1 ORDER BY",
        rows=[
            {
                "id": "inv_1",
                "alert_id": "al_X",
                "status": "completed",
                "is_stub": True,
                "engine_version": "stub-1",
                "requested_by": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "requested_at": "2026-07-08T10:00:00+00:00",
                "completed_at": "2026-07-08T10:00:00+00:00",
                "summary": "s",
                "confidence": None,
                "findings": [],
                "timeline": [],
                "evidence_graph": {"nodes": [], "edges": []},
                "recommended_actions": [],
                "quota_limit": 5,
                "quota_remaining": 4,
            }
        ],
    )
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.deep_investigation_runs", value=1)
    response = await client.get(
        "/v1/alerts/al_X/deep-investigations", **session_kwargs(sid)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"][0]["investigation_id"] == "inv_1"
    assert body["items"][0]["is_stub"] is True
