"""EntitlementsClient fail-closed / LKG tests (ADR-0005, SEC-39)."""

import uuid

import httpx
import pytest

from soc_entitlements import (
    EntitlementsClient,
    EntitlementsUnavailable,
    NeverGracedFieldStale,
    verify_service_token,
)

TENANT = uuid.UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")
KEY = b"s" * 32

PAYLOAD = {
    "plan": "trial",
    "tenant_status": "active",
    "abuse_frozen": False,
    "trial_expires_at": "2026-07-22T09:00:00Z",
    "entitlements": {
        "endpoint_cap": 100,
        "retention_days": 14,
        "deep_investigation_daily_quota": 5,
        "response_mode": "recommend_only",
        "ingest_events_per_min": 5000,
    },
    "as_of": "2026-07-08T10:00:00Z",
}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Upstream:
    """Scriptable fake controlplane behind httpx.MockTransport."""

    def __init__(self):
        self.requests = []
        self.mode = "ok"  # ok | error_503 | error_403 | down

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.mode == "down":
            raise httpx.ConnectError("connection refused", request=request)
        if self.mode == "error_503":
            return httpx.Response(503)
        if self.mode == "error_403":
            return httpx.Response(403)
        return httpx.Response(200, json=PAYLOAD)


def make_client(upstream, clock, **kwargs):
    http = httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler))
    stale_events = []
    client = EntitlementsClient(
        base_url="http://controlplane",
        service_name="dataplane",
        signing_key=KEY,
        http_client=http,
        clock=clock,
        on_stale_served=lambda tid, age: stale_events.append((tid, age)),
        **kwargs,
    )
    return client, stale_events


async def test_fetch_sends_hmac_service_token():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    snapshot = await client.get(TENANT)
    assert snapshot.entitlements.endpoint_cap == 100
    assert snapshot.stale is False
    assert snapshot.abuse_frozen is False  # readable when fresh (informational)
    request = upstream.requests[0]
    assert request.url.path == f"/internal/v1/tenants/{TENANT}/entitlements"
    scheme, _, token = request.headers["Authorization"].partition(" ")
    assert scheme == "Bearer"
    assert verify_service_token(token, keys={"dataplane": KEY}) == "dataplane"


async def test_cache_hit_within_ttl_no_second_request():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 299
    await client.get(TENANT)
    assert len(upstream.requests) == 1


async def test_refetch_after_ttl():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 301
    await client.get(TENANT)
    assert len(upstream.requests) == 2


async def test_lkg_served_on_outage_with_staleness_signal():
    upstream, clock = Upstream(), FakeClock()
    client, stale_events = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 600  # 300 past TTL
    upstream.mode = "down"
    snapshot = await client.get(TENANT)
    assert snapshot.stale is True
    assert snapshot.staleness_seconds == pytest.approx(300)
    assert snapshot.entitlements.ingest_events_per_min == 5000  # quantitative: graced
    assert stale_events == [(TENANT, pytest.approx(300))]


async def test_never_graced_abuse_frozen_raises_when_stale():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 600
    upstream.mode = "error_503"
    snapshot = await client.get(TENANT)
    with pytest.raises(NeverGracedFieldStale):
        _ = snapshot.abuse_frozen


async def test_lkg_beyond_hard_ceiling_denies():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 300 + 1800 + 1  # past TTL + 30-min ceiling
    upstream.mode = "down"
    with pytest.raises(EntitlementsUnavailable):
        await client.get(TENANT)


async def test_cold_cache_plus_outage_denies():
    upstream, clock = Upstream(), FakeClock()
    upstream.mode = "down"
    client, _ = make_client(upstream, clock)
    with pytest.raises(EntitlementsUnavailable) as exc:
        await client.get(TENANT)
    assert exc.value.retry_after_seconds > 0


async def test_4xx_is_not_graced():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    clock.now += 301
    upstream.mode = "error_403"  # config/auth problem, not an outage
    with pytest.raises(EntitlementsUnavailable):
        await client.get(TENANT)


async def test_invalidate_forces_refetch():
    upstream, clock = Upstream(), FakeClock()
    client, _ = make_client(upstream, clock)
    await client.get(TENANT)
    client.invalidate(TENANT)
    await client.get(TENANT)
    assert len(upstream.requests) == 2


def test_constructor_enforces_adr_bounds():
    with pytest.raises(ValueError):
        EntitlementsClient(
            base_url="http://c", service_name="d", signing_key=KEY, cache_ttl_seconds=301
        )
    with pytest.raises(ValueError):
        EntitlementsClient(
            base_url="http://c", service_name="d", signing_key=KEY, lkg_grace_seconds=1801
        )
