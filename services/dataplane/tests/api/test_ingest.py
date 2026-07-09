"""Ingest path tests: check order, SEC-14 negative, fail-closed 503, quota 429."""

from __future__ import annotations

import httpx
from dp_api_testkit import (
    GATEWAY_HEADERS,
    TENANT_ID,
    agent_headers,
    make_session,
    mint_ingest_key,
    seed_device,
    seed_tenant_status,
    session_kwargs,
    settings_with,
)

from dataplane.main import create_app
from soc_pipeline.streams import STREAM_RAW


def batch(n: int = 2) -> dict:
    return {"events": [{"event_class": "generic", "activity": "log"} for _ in range(n)]}


async def test_agent_ingest_happy_path(client, fake_redis):
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post("/v1/agent/events", json=batch(3), headers=agent_headers())
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 3
    assert body["batch_id"].startswith("b_")
    entries = await fake_redis.xrange(STREAM_RAW)
    assert len(entries) == 1
    # usage counter updated (AC-88)
    keys = await fake_redis.keys(f"usage:ingest:{TENANT_ID}:*:events_accepted")
    assert len(keys) == 1 and int(await fake_redis.get(keys[0])) == 3
    # onboarding first_event signal
    assert await fake_redis.hget(f"onboarding:{TENANT_ID}", "first_event") == "1"


async def test_header_injection_without_gateway_auth_is_401(client):
    """SEC-14 negative: identity headers from outside the gateway are useless."""
    headers = {
        "X-Device-Id": "dev_TEST",
        "X-Device-Tenant": str(TENANT_ID),
        "X-Client-Cert-Serial": "serial1",
    }
    response = await client.post("/v1/agent/events", json=batch(), headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


async def test_agent_route_with_gateway_auth_but_no_identity_is_401(client, fake_redis):
    response = await client.post("/v1/agent/events", json=batch(), headers=GATEWAY_HEADERS)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_IDENTITY_INVALID"


async def test_revoked_device_is_401_device_revoked(client, fake_redis):
    await seed_device(fake_redis, status="revoked")
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_REVOKED"


async def test_serial_mismatch_is_401_identity_invalid(client, fake_redis):
    await seed_device(fake_redis, cert_serial="other")
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_IDENTITY_INVALID"


async def test_unknown_device_cache_miss_pg_miss_is_401(client, fake_redis, sql):
    # Redis up (miss), PG reachable, row absent => allowlist deny (B-1).
    sql.on(r"FROM tenantdata\.devices WHERE id", rows=[])
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_IDENTITY_INVALID"


async def test_both_stores_down_is_503_fail_closed(client, fake_redis, sql, monkeypatch):
    """B-1/SEC-10: BOTH stores down => 503 deny, never accept."""

    async def broken_hgetall(*args, **kwargs):
        raise ConnectionError("redis down")

    monkeypatch.setattr(fake_redis, "hgetall", broken_hgetall)
    sql.on(r"FROM tenantdata\.devices WHERE id", raises=ConnectionError("pg down"))
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert "Retry-After" in response.headers


async def test_pg_down_on_cache_miss_is_503(client, fake_redis, sql):
    sql.on(r"FROM tenantdata\.devices WHERE id", raises=ConnectionError("pg down"))
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 503


async def test_trial_frozen_is_402_before_size_check(client, fake_redis, settings, resources):
    """Check order: tenant status (402) runs BEFORE the size check (413)."""
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis, status="frozen")
    oversized = batch(2000)  # would be 413 if size ran first
    response = await client.post("/v1/agent/events", json=oversized, headers=agent_headers())
    assert response.status_code == 402
    assert response.json()["error"]["code"] == "TRIAL_EXPIRED"


async def test_abuse_frozen_is_403_with_cause(client, fake_redis):
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis, abuse_frozen=True)
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "TENANT_FROZEN"
    assert error["details"]["cause"] == "abuse"


async def test_batch_too_many_events_is_413(client, fake_redis):
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/agent/events", json=batch(1001), headers=agent_headers()
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "BATCH_TOO_LARGE"


async def test_batch_too_many_bytes_is_413(settings, resources, fake_redis):
    small = settings_with(settings, ingest_max_bytes=200)
    app = create_app(small, resources)
    resources.settings = small
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://dp.test") as client:
        response = await client.post(
            "/v1/agent/events", json=batch(50), headers=agent_headers()
        )
    assert response.status_code == 413


async def test_quota_429_with_retry_after_and_no_stream_write(
    client, fake_redis, entitlements
):
    """AC-86: 429 + Retry-After; never 202-then-drop."""
    entitlements.values["ingest_events_per_min"] = 10
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post("/v1/agent/events", json=batch(11), headers=agent_headers())
    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "INGEST_QUOTA_EXCEEDED"
    assert error["retry_after_seconds"] >= 1
    assert int(response.headers["Retry-After"]) >= 1
    assert await fake_redis.xrange(STREAM_RAW) == []
    keys = await fake_redis.keys(f"usage:ingest:{TENANT_ID}:*:throttled_batches")
    assert len(keys) == 1


async def test_quota_allows_within_limit_then_blocks(client, fake_redis, entitlements):
    entitlements.values["ingest_events_per_min"] = 10
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    first = await client.post("/v1/agent/events", json=batch(8), headers=agent_headers())
    assert first.status_code == 202
    second = await client.post("/v1/agent/events", json=batch(5), headers=agent_headers())
    assert second.status_code == 429


async def test_entitlements_unavailable_is_503(client, fake_redis, entitlements):
    entitlements.unavailable = True
    await seed_device(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post("/v1/agent/events", json=batch(), headers=agent_headers())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ENTITLEMENTS_UNAVAILABLE"


# ------------------------------------------------------------ generic ingest
async def test_ingest_key_happy_path(client, fake_redis):
    wire, secret_hash = mint_ingest_key()
    await fake_redis.hset(
        f"ingestkey:{TENANT_ID}:ik_TEST",
        mapping={"status": "active", "key_hash": secret_hash},
    )
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/ingest/events", json=batch(2), headers={"X-Ingest-Key": wire}
    )
    assert response.status_code == 202
    assert response.json()["accepted"] == 2


async def test_ingest_key_missing_is_401_auth_required(client):
    response = await client.post("/v1/ingest/events", json=batch())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


async def test_ingest_key_wrong_secret_is_invalid(client, fake_redis):
    _, secret_hash = mint_ingest_key()
    await fake_redis.hset(
        f"ingestkey:{TENANT_ID}:ik_TEST",
        mapping={"status": "active", "key_hash": secret_hash},
    )
    wrong_wire, _ = mint_ingest_key(TENANT_ID, "ik_TEST")  # same id, new secret
    response = await client.post(
        "/v1/ingest/events", json=batch(), headers={"X-Ingest-Key": wrong_wire}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INGEST_KEY_INVALID"


async def test_ingest_key_revoked(client, fake_redis):
    wire, secret_hash = mint_ingest_key()
    await fake_redis.hset(
        f"ingestkey:{TENANT_ID}:ik_TEST",
        mapping={"status": "revoked", "key_hash": secret_hash},
    )
    response = await client.post(
        "/v1/ingest/events", json=batch(), headers={"X-Ingest-Key": wire}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INGEST_KEY_REVOKED"


async def test_ingest_key_malformed_is_invalid(client):
    response = await client.post(
        "/v1/ingest/events", json=batch(), headers={"X-Ingest-Key": "not-a-key"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INGEST_KEY_INVALID"


# ------------------------------------------------------- console: ingest keys
async def test_create_ingest_key_shows_key_once_and_signals_onboarding(
    client, fake_redis, sql
):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/ingest-keys", json={"name": "firewall"}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 201
    body = response.json()
    assert body["key"].startswith(body["id"] + ".")
    assert sql.executed(r"INSERT INTO tenantdata\.ingest_keys")
    assert sql.executed(r"INSERT INTO audit_log")
    assert await fake_redis.hget(f"onboarding:{TENANT_ID}", "create_ingest_key") == "1"


async def test_revoke_ingest_key_deletes_allowlist_cache(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    await fake_redis.hset(
        f"ingestkey:{TENANT_ID}:ik_GONE", mapping={"status": "active", "key_hash": "h"}
    )
    sql.on(r"UPDATE tenantdata\.ingest_keys SET revoked_at", rows=[{"id": "ik_GONE"}])
    response = await client.delete("/v1/ingest-keys/ik_GONE", **session_kwargs(sid, csrf))
    assert response.status_code == 204
    assert await fake_redis.hgetall(f"ingestkey:{TENANT_ID}:ik_GONE") == {}


async def test_usage_endpoint_shape(client, fake_redis):
    sid, _ = await make_session(fake_redis, role="analyst")
    response = await client.get("/v1/tenant/usage/ingest", **session_kwargs(sid))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "events_per_min_current",
        "events_per_min_limit",
        "throttled_batches_24h",
        "rejected_events_24h",
        "warning_active",
    }
