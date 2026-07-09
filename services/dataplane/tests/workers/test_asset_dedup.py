"""worker-asset-dedup: deterministic match order (AC-22), pins win (AC-25),
agent identity beats hostname (AC-23), cross-source merge + audit (AC-24)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from dataplane.workers.asset_dedup import AssetDeduper
from soc_pipeline import STREAM_ASSET_OBSERVATIONS, ReceivedMessage

TENANT = UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")
NOW = datetime.now(UTC)


def observation(**overrides) -> ReceivedMessage:
    payload = {
        "observed_at": NOW.isoformat(),
        "source": "agent",
        "hostname": "fin-laptop-07",
        "os_family": "windows",
        "os_name": "Windows 11 Pro",
        "os_version": "10.0.26100",
        "device_id": "dev_A",
    }
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    return ReceivedMessage(
        stream=STREAM_ASSET_OBSERVATIONS,
        message_id="1-1",
        tenant_id=TENANT,
        trace_id="trace-1",
        payload=payload,
    )


@pytest.fixture
def deduper(pool, metrics):
    return AssetDeduper(pool=pool, metrics=metrics)


def seed_asset(state, *, hostname=None, sources=("agent",), agent_status="enrolled"):
    asset_id = uuid4()
    state.t["assets"].append(
        {
            "id": asset_id,
            "tenant_id": str(TENANT),
            "hostname": hostname,
            "os_family": "windows" if hostname else None,
            "os_name": None,
            "os_version": None,
            "ip": None,
            "mac": None,
            "sources": list(sources),
            "agent_status": agent_status,
            "billable": True,
            "state": "active",
            "dedup_rule": None,
            "first_seen": NOW - timedelta(days=1),
            "last_seen": NOW - timedelta(days=1),
        }
    )
    return asset_id


def seed_identity(state, asset_id, identifier_type, value, source="agent"):
    state.t["asset_identities"].append(
        {
            "tenant_id": str(TENANT),
            "asset_id": asset_id,
            "source": source,
            "identifier_type": identifier_type,
            "value": value,
            "first_seen": NOW - timedelta(days=1),
            "last_seen": NOW - timedelta(days=1),
        }
    )


def seed_pin(state, identifier_type, value, asset_id):
    state.t["asset_identity_pins"].append(
        {
            "tenant_id": str(TENANT),
            "identifier_type": identifier_type,
            "value": value,
            "pinned_asset_id": asset_id,
        }
    )


async def test_new_asset_created_from_first_observation(deduper, state):
    await deduper.handle(observation())
    assets = state.rows("assets", TENANT)
    assert len(assets) == 1
    asset = assets[0]
    assert asset["created_via"] == "agent_enrollment"
    assert asset["sources"] == ["agent"]
    assert asset["billable"] is True
    identities = state.rows("asset_identities", TENANT)
    assert {(i["identifier_type"], i["value"]) for i in identities} == {
        ("device_id", "dev_A"),
        ("hostname_os", "fin-laptop-07|windows"),
    }


async def test_match_order_device_id_wins_over_hostname(deduper, state):
    """AC-22 order: device_id match beats a hostname_os match pointing elsewhere."""
    asset_dev = seed_asset(state, hostname="old-name")
    seed_identity(state, asset_dev, "device_id", "dev_A")
    asset_host = seed_asset(state, hostname="fin-laptop-07", sources=("log_ingest",))
    seed_identity(state, asset_host, "hostname_os", "fin-laptop-07|windows", source="log_ingest")

    await deduper.handle(observation())  # device dev_A + hostname fin-laptop-07

    assets = {str(a["id"]): a for a in state.rows("assets", TENANT)}
    assert len(assets) == 2  # no new asset created
    updated = assets[str(asset_dev)]
    assert updated["last_seen"] == NOW
    assert updated["dedup_rule"] == "device_id_match"
    # The hostname identity binding stays with its original asset (unique
    # binding, never stolen).
    binding = next(
        i for i in state.rows("asset_identities", TENANT) if i["identifier_type"] == "hostname_os"
    )
    assert str(binding["asset_id"]) == str(asset_host)


async def test_pins_always_win_over_automatic_identity(deduper, state):
    """AC-25: a manual pin beats the automatic identity binding."""
    asset_auto = seed_asset(state, hostname="fin-laptop-07", sources=("log_ingest",))
    seed_identity(state, asset_auto, "hostname_os", "fin-laptop-07|windows")
    asset_pinned = seed_asset(state, hostname="fin-laptop-07")
    seed_pin(state, "hostname_os", "fin-laptop-07|windows", asset_pinned)

    await deduper.handle(observation(device_id=None, source="log_ingest"))

    assets = {str(a["id"]): a for a in state.rows("assets", TENANT)}
    assert assets[str(asset_pinned)]["last_seen"] == NOW  # pin target updated
    assert assets[str(asset_auto)]["last_seen"] == NOW - timedelta(days=1)


async def test_ac23_differing_device_ids_stay_separate_assets(deduper, state):
    """AC-23: same hostname, different agent device ids => two assets; the
    hostname match is skipped because agent identity wins."""
    asset_one = seed_asset(state, hostname="fin-laptop-07")
    seed_identity(state, asset_one, "device_id", "dev_A")
    seed_identity(state, asset_one, "hostname_os", "fin-laptop-07|windows")

    await deduper.handle(observation(device_id="dev_B"))  # re-imaged machine

    assets = state.rows("assets", TENANT)
    assert len(assets) == 2
    new_asset = next(a for a in assets if str(a["id"]) != str(asset_one))
    identities = state.rows("asset_identities", TENANT)
    dev_b = next(i for i in identities if i["value"] == "dev_B")
    assert str(dev_b["asset_id"]) == str(new_asset["id"])
    # Shared hostname identity remains bound to the FIRST asset.
    host_binding = next(i for i in identities if i["identifier_type"] == "hostname_os")
    assert str(host_binding["asset_id"]) == str(asset_one)


async def test_cross_source_merge_updates_sources_and_audit(deduper, state):
    """AC-22/24: agent asset + agent observation adds the hostname identity
    (merge_audit row); later log_ingest observation merges by hostname and
    unions sources => ONE billable asset."""
    asset_id = seed_asset(state, hostname=None)
    seed_identity(state, asset_id, "device_id", "dev_A")

    await deduper.handle(observation())  # agent: binds hostname_os to the asset
    merge_rows = state.rows("asset_merge_audit", TENANT)
    assert len(merge_rows) == 1
    assert merge_rows[0]["rule"] == "device_id_match"
    assert json.loads(merge_rows[0]["details"])["identifier_type"] == "hostname_os"

    await deduper.handle(observation(device_id=None, source="log_ingest"))

    assets = state.rows("assets", TENANT)
    assert len(assets) == 1
    assert sorted(assets[0]["sources"]) == ["agent", "log_ingest"]
    assert assets[0]["hostname"] == "fin-laptop-07"


async def test_revoked_asset_not_re_marked_billable(deduper, state):
    asset_id = seed_asset(state, hostname="fin-laptop-07", agent_status="revoked")
    seed_identity(state, asset_id, "device_id", "dev_A")
    for a in state.t["assets"]:
        a["billable"] = False

    await deduper.handle(observation())
    asset = state.rows("assets", TENANT)[0]
    assert asset["billable"] is False  # AC-26/27: revoked never billable


async def test_observation_without_identifiers_dead_lettered(deduper, state, metrics):
    await deduper.handle(observation(device_id=None, hostname=None, os_family=None))
    dlq = state.rows("dead_letter_events", TENANT)
    assert len(dlq) == 1
    assert dlq[0]["error_code"] == "ASSET_OBSERVATION_MALFORMED"
    assert state.rows("assets", TENANT) == []
