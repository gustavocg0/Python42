"""Internal listener: HMAC service-token auth (SEC-40) + provision idempotency."""

from __future__ import annotations

from dp_api_testkit import INTERNAL_KEY, TENANT_ID

from soc_entitlements import generate_service_token
from soc_tenancy import events_alias


def service_headers() -> dict[str, str]:
    token = generate_service_token(service_name="controlplane", key=INTERNAL_KEY)
    return {"Authorization": f"Bearer {token}"}


async def test_internal_requires_service_token(internal_client):
    response = await internal_client.put(f"/internal/v1/tenants/{TENANT_ID}/provision")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


async def test_internal_rejects_bad_token(internal_client):
    response = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision",
        headers={"Authorization": "Bearer v1.controlplane.9999999999.deadbeef"},
    )
    assert response.status_code == 401


async def test_internal_rejects_unknown_service(internal_client):
    token = generate_service_token(service_name="rogue", key=INTERNAL_KEY)
    response = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


async def test_provision_creates_index_alias_and_seeds_onboarding(
    internal_client, fake_es, sql
):
    response = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision", headers=service_headers()
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == str(TENANT_ID)
    assert body["es_alias"] == events_alias(TENANT_ID)
    assert body["es_index"].startswith(f"events-v1-{TENANT_ID}-")
    assert body["index_created"] is True
    assert body["onboarding_seeded"] is True
    assert fake_es.indices.created == [body["es_index"]]
    assert events_alias(TENANT_ID) in fake_es.indices.aliases[body["es_index"]]
    seeds = sql.executed(r"INSERT INTO tenantdata\.onboarding_steps")
    assert len(seeds) == 4  # install_agent, create_ingest_key, first_event, view_queue
    assert all("ON CONFLICT" in s for s, _ in seeds)


async def test_provision_is_idempotent(internal_client, fake_es, sql):
    first = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision", headers=service_headers()
    )
    second = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision", headers=service_headers()
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["index_created"] is True
    assert second.json()["index_created"] is False
    # alias still ensured on the retry path
    index = first.json()["es_index"]
    assert events_alias(TENANT_ID) in fake_es.indices.aliases[index]
    assert fake_es.indices.created.count(index) == 1


async def test_provision_accepts_matching_body_and_rejects_mismatch(
    internal_client, fake_es
):
    ok = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision",
        json={"tenant_id": str(TENANT_ID)},
        headers=service_headers(),
    )
    assert ok.status_code == 200
    mismatch = await internal_client.put(
        f"/internal/v1/tenants/{TENANT_ID}/provision",
        json={"tenant_id": "99999999-8888-7777-6666-555555555555"},
        headers=service_headers(),
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_provision_invalid_tenant_400(internal_client):
    response = await internal_client.put(
        "/internal/v1/tenants/not-a-uuid/provision", headers=service_headers()
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_fp_feedback_single_tenant(internal_client, sql):
    sql.on(
        r"FROM tenantdata\.alerts WHERE close_reason = 'false_positive'",
        rows=[
            {
                "id": "al_1",
                "rule_id": "rule_a",
                "entity_hostname": "h1",
                "entity_user": "u1",
                "close_reason": "false_positive",
                "close_comment": "expected",
                "closed_at": "2026-07-08T10:00:00+00:00",
                "priority_inputs": {},
            }
        ],
    )
    response = await internal_client.get(
        f"/internal/v1/fp-feedback?tenant_id={TENANT_ID}&rule_id=rule_a",
        headers=service_headers(),
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert items[0]["rule_id"] == "rule_a"
    assert items[0]["entity"] == {"hostname": "h1", "user": "u1"}
    assert items[0]["reason"] == "false_positive"


async def test_metering_llm_aggregates(internal_client, sql):
    sql.on(
        r"FROM tenantdata\.llm_metering",
        rows=[
            {
                "day": "2026-07-08",
                "model_id": "fast-1",
                "tokens_in": 1000,
                "tokens_out": 200,
                "calls": 10,
                "cost_usd": 0.05,
                "latency_ms_p95": 850.0,
            }
        ],
    )
    response = await internal_client.get(
        f"/internal/v1/metering/llm?tenant_id={TENANT_ID}", headers=service_headers()
    )
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["model_id"] == "fast-1"
    assert item["tokens_in"] == 1000
    assert item["latency_ms_p95"] == 850.0
