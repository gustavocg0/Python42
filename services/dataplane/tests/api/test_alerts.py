"""Alert state machine, bulk partial success, AC-81 404-vs-403, events via ES."""

from __future__ import annotations

from uuid import uuid4

from dp_api_testkit import (
    TENANT_ID,
    alert_row,
    make_session,
    seed_tenant_status,
    session_kwargs,
)

from soc_tenancy import events_alias


async def test_list_alerts_shape_and_default_sort(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis, role="analyst")
    rows = [alert_row(id="al_A", priority_score=90), alert_row(id="al_B", priority_score=80)]
    sql.on(r"SELECT .* FROM tenantdata\.alerts WHERE .* ORDER BY", rows=rows)
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.alerts", value=2)
    response = await client.get("/v1/alerts", **session_kwargs(sid))
    assert response.status_code == 200
    body = response.json()
    assert body["total_estimate"] == 2
    first = body["items"][0]
    assert first["id"] == "al_A"
    assert first["rule"]["severity"] == "high"
    assert first["triage"]["status"] == "completed"
    assert first["priority_score"] == 90
    # queue view signals onboarding (AC-70)
    assert await fake_redis.hget(f"onboarding:{TENANT_ID}", "view_queue") == "1"
    # default sort matches the queue index ordering
    list_sql = sql.executed(r"ORDER BY priority_score DESC, last_seen DESC, id")
    assert list_sql


async def test_list_alerts_rejects_bad_sort(client, fake_redis):
    sid, _ = await make_session(fake_redis)
    response = await client.get("/v1/alerts?sort=hostname", **session_kwargs(sid))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_acknowledge_happy_path_writes_history_and_audit(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis, role="analyst")
    await seed_tenant_status(fake_redis)
    sql.on(
        r"UPDATE tenantdata\.alerts SET state = 'acknowledged'",
        rows=[alert_row(id="al_X", state="acknowledged")],
    )
    response = await client.post("/v1/alerts/al_X/acknowledge", **session_kwargs(sid, csrf))
    assert response.status_code == 200
    assert response.json()["state"] == "acknowledged"
    assert sql.executed(r"INSERT INTO tenantdata\.alert_history")
    assert sql.executed(r"INSERT INTO audit_log")


async def test_invalid_transition_409_with_current_state(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(r"UPDATE tenantdata\.alerts SET state = 'acknowledged'", rows=[])
    sql.on(r"SELECT state FROM tenantdata\.alerts WHERE id", value="closed")
    response = await client.post("/v1/alerts/al_X/acknowledge", **session_kwargs(sid, csrf))
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "INVALID_STATE_TRANSITION"
    assert error["details"]["current_state"] == "closed"


async def test_unknown_or_foreign_alert_is_404_not_403(client, fake_redis, sql):
    """AC-81: RLS makes foreign == missing; both 404 NOT_FOUND."""
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(r"UPDATE tenantdata\.alerts SET state", rows=[])
    sql.on(r"SELECT state FROM tenantdata\.alerts WHERE id", rows=[])
    response = await client.post(
        "/v1/alerts/al_FOREIGN/acknowledge", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_close_requires_reason(client, fake_redis):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/alerts/al_X/close", json={}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_close_with_fp_reason_recorded(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(
        r"UPDATE tenantdata\.alerts SET state = 'closed'",
        rows=[alert_row(id="al_X", state="closed", close_reason="false_positive")],
    )
    response = await client.post(
        "/v1/alerts/al_X/close",
        json={"reason": "false_positive", "comment": "known admin script"},
        **session_kwargs(sid, csrf),
    )
    assert response.status_code == 200
    assert response.json()["close_reason"] == "false_positive"
    close_args = sql.executed(r"UPDATE tenantdata\.alerts SET state = 'closed'")[0][1]
    assert "false_positive" in close_args


async def test_reopen_only_from_closed(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    sql.on(r"UPDATE tenantdata\.alerts SET state = 'new'", rows=[alert_row(state="new")])
    response = await client.post("/v1/alerts/al_X/reopen", **session_kwargs(sid, csrf))
    assert response.status_code == 200
    assert response.json()["state"] == "new"


async def test_bulk_partial_success(client, fake_redis, sql):
    """AC-73: per-item atomicity, partial success reported."""
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)

    def ack_responder(args):
        if args[0] == "al_OK":
            return [alert_row(id="al_OK", state="acknowledged")]
        return []

    sql.on(r"UPDATE tenantdata\.alerts SET state = 'acknowledged'", rows=ack_responder)
    sql.on(r"SELECT state FROM tenantdata\.alerts WHERE id", value="closed")
    response = await client.post(
        "/v1/alerts/bulk",
        json={"action": "acknowledge", "alert_ids": ["al_OK", "al_BAD"]},
        **session_kwargs(sid, csrf),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["succeeded"] == ["al_OK"]
    assert body["failed"] == [{"id": "al_BAD", "code": "INVALID_STATE_TRANSITION"}]


async def test_bulk_rejects_more_than_50(client, fake_redis):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/alerts/bulk",
        json={"action": "acknowledge", "alert_ids": [f"al_{i}" for i in range(51)]},
        **session_kwargs(sid, csrf),
    )
    assert response.status_code == 400


async def test_bulk_close_requires_reason(client, fake_redis):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/alerts/bulk",
        json={"action": "close", "alert_ids": ["al_X"]},
        **session_kwargs(sid, csrf),
    )
    assert response.status_code == 400


# ------------------------------------------------------------- alert events
async def test_alert_events_from_es_with_missing_ids(client, fake_redis, sql, fake_es):
    """Ratified GET /v1/alerts/{id}/events: bodies via the tenant alias;
    purged events land in missing_event_ids."""
    sid, _ = await make_session(fake_redis)
    kept, purged = str(uuid4()), str(uuid4())
    sql.on(r"SELECT 1 FROM tenantdata\.alerts WHERE id", value=1)
    sql.on(
        r"SELECT event_id, es_index FROM tenantdata\.alert_events",
        rows=[
            {"event_id": kept, "es_index": "events-v1-x-2026.07"},
            {"event_id": purged, "es_index": "events-v1-x-2026.06"},
        ],
    )
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.alert_events", value=2)
    fake_es.docs[events_alias(TENANT_ID)] = [
        {"event_id": kept, "event_class": "process_activity", "activity": "process_launched"}
    ]
    response = await client.get("/v1/alerts/al_X/events", **session_kwargs(sid))
    assert response.status_code == 200
    body = response.json()
    assert [item["event_id"] for item in body["items"]] == [kept]
    assert body["missing_event_ids"] == [purged]
    assert body["total_estimate"] == 2


async def test_alert_events_unknown_alert_404(client, fake_redis, sql):
    sid, _ = await make_session(fake_redis)
    sql.on(r"SELECT 1 FROM tenantdata\.alerts WHERE id", rows=[])
    response = await client.get("/v1/alerts/al_NOPE/events", **session_kwargs(sid))
    assert response.status_code == 404


async def test_alert_events_es_down_503(client, fake_redis, sql, fake_es):
    sid, _ = await make_session(fake_redis)
    sql.on(r"SELECT 1 FROM tenantdata\.alerts WHERE id", value=1)
    sql.on(
        r"SELECT event_id, es_index FROM tenantdata\.alert_events",
        rows=[{"event_id": str(uuid4()), "es_index": "i"}],
    )
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.alert_events", value=1)
    fake_es.fail = True
    response = await client.get("/v1/alerts/al_X/events", **session_kwargs(sid))
    assert response.status_code == 503
