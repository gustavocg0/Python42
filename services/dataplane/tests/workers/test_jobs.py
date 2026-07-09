"""jobs-scheduler: trial freeze/purge (AC-9/10, SEC-46), retention index
selection (AC-16), billable window (AC-26), agent offline (AC-61), DLQ cleanup."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from dataplane.jobs.runner import acquire_job_lock, build_jobs
from dataplane.jobs.tasks import (
    JobContext,
    job_agent_offline,
    job_billable_window,
    job_dlq_cleanup,
    job_retention_purge,
    job_trial_freeze,
    job_trial_purge,
    ordered_purge_tables,
    select_expired_indices,
)
from dataplane.workers.common import Settings

TENANT = UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")
OTHER_TENANT = UUID("11111111-2222-4333-8444-555555555555")
NOW = datetime.now(UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql://unused",
        redis_url="redis://unused",
        elasticsearch_url="http://unused",
        consumer_name="test",
    )


@pytest.fixture
def ctx(pool, redis, es) -> JobContext:
    return JobContext(pool=pool, redis=redis, es=es, settings=make_settings(), config={})


def seed_tenant(state, tenant_id, *, status="active", plan_id="trial", **extra):
    state.tenants[str(tenant_id)] = {
        "id": tenant_id,
        "status": status,
        "plan_id": plan_id,
        "trial_expires_at": None,
        "frozen_at": None,
        "purged_at": None,
        **extra,
    }


DEFAULT_REGISTRY = [
    {"schema_name": "tenantdata", "table_name": "assets", "purge_action": "delete"},
    {"schema_name": "tenantdata", "table_name": "alert_events", "purge_action": "delete"},
    {"schema_name": "tenantdata", "table_name": "alerts", "purge_action": "delete"},
    {"schema_name": "tenantdata", "table_name": "dead_letter_events", "purge_action": "delete"},
    {"schema_name": "tenantdata", "table_name": "llm_metering", "purge_action": "retain"},
    {"schema_name": "tenantdata", "table_name": "audit_log", "purge_action": "retain"},
]


# ---------------------------------------------------------------------------
# trial freeze (AC-9, SEC-46)
# ---------------------------------------------------------------------------


async def test_trial_freeze_flips_status_and_invalidates_cache(ctx, state, redis):
    seed_tenant(state, TENANT, trial_expires_at=NOW - timedelta(hours=1))
    seed_tenant(state, OTHER_TENANT, trial_expires_at=NOW + timedelta(days=3))
    paid = uuid4()
    seed_tenant(state, paid, plan_id="core")
    await redis.hset(f"tenantstatus:{TENANT}", mapping={"status": "active"})

    await job_trial_freeze(ctx)

    assert state.tenants[str(TENANT)]["status"] == "frozen"
    assert state.tenants[str(TENANT)]["frozen_at"] is not None
    assert state.tenants[str(OTHER_TENANT)]["status"] == "active"
    assert state.tenants[str(paid)]["status"] == "active"
    # SEC-39/redis rule 4: delete-on-change so the 60s TTL is worst case.
    assert await redis.exists(f"tenantstatus:{TENANT}") == 0
    audits = state.rows("audit_log", TENANT)
    assert [a["action_type"] for a in audits] == ["tenant.trial_frozen"]


# ---------------------------------------------------------------------------
# trial purge (AC-10, SEC-46/48)
# ---------------------------------------------------------------------------


async def test_trial_purge_honors_registry_and_retain(ctx, state, redis, es):
    seed_tenant(state, TENANT, status="frozen", frozen_at=NOW - timedelta(days=40))
    seed_tenant(state, OTHER_TENANT, status="active")
    state.purge_registry = list(DEFAULT_REGISTRY)
    for tenant in (TENANT, OTHER_TENANT):
        t = str(tenant)
        state.t["assets"].append({"tenant_id": t, "id": uuid4()})
        state.t["alerts"].append({"tenant_id": t, "id": "al_X", "state": "new"})
        state.t["alert_events"].append({"tenant_id": t, "alert_id": "al_X"})
        state.t["dead_letter_events"].append({"tenant_id": t, "received_at": NOW})
        state.t["llm_metering"].append({"tenant_id": t, "tokens_in": 10})
        state.t["audit_log"].append({"tenant_id": t, "action_type": "old.entry"})
    es.index_names.update(
        {
            f"events-v1-{TENANT}-2026.06",
            f"events-v1-{TENANT}-2026.07",
            f"events-v1-{OTHER_TENANT}-2026.07",
        }
    )
    await redis.set(f"onboarding:{TENANT}", "x")
    await redis.set(f"tenantstatus:{TENANT}", "x")
    await redis.set(f"quota:ingest:{TENANT}:123", "1")
    await redis.set(f"quota:ingest:{OTHER_TENANT}:123", "1")

    await job_trial_purge(ctx)

    # PG: delete-action tables emptied for the purged tenant only (AC-10).
    for table in ("assets", "alerts", "alert_events", "dead_letter_events"):
        assert state.rows(table, TENANT) == [], table
        assert len(state.rows(table, OTHER_TENANT)) == 1, table
    # 'retain' rows survive (SEC-48): metering + audit, and the purge itself
    # is recorded in the audit log.
    assert len(state.rows("llm_metering", TENANT)) == 1
    audit_actions = [a["action_type"] for a in state.rows("audit_log", TENANT)]
    assert "old.entry" in audit_actions
    assert "tenant.purged" in audit_actions
    # ES: only the purged tenant's indices deleted.
    assert es.index_names == {f"events-v1-{OTHER_TENANT}-2026.07"}
    # Redis: tenant-prefixed keys purged; other tenant untouched.
    assert await redis.exists(f"onboarding:{TENANT}") == 0
    assert await redis.exists(f"quota:ingest:{TENANT}:123") == 0
    assert await redis.exists(f"quota:ingest:{OTHER_TENANT}:123") == 1
    # Tenant marked purged.
    assert state.tenants[str(TENANT)]["status"] == "purged"
    assert state.tenants[str(TENANT)]["purged_at"] is not None
    assert state.tenants[str(OTHER_TENANT)]["status"] == "active"


async def test_trial_purge_skips_recently_frozen(ctx, state):
    seed_tenant(state, TENANT, status="frozen", frozen_at=NOW - timedelta(days=5))
    state.purge_registry = list(DEFAULT_REGISTRY)
    state.t["assets"].append({"tenant_id": str(TENANT), "id": uuid4()})

    await job_trial_purge(ctx)

    assert state.tenants[str(TENANT)]["status"] == "frozen"
    assert len(state.rows("assets", TENANT)) == 1


def test_ordered_purge_tables_orders_children_first_and_drops_retain():
    tables = ordered_purge_tables(DEFAULT_REGISTRY)
    assert "audit_log" not in tables
    assert "llm_metering" not in tables
    assert tables.index("alert_events") < tables.index("alerts")
    assert tables.index("alerts") < tables.index("assets")


# ---------------------------------------------------------------------------
# retention purge (AC-16)
# ---------------------------------------------------------------------------


def test_select_expired_indices_selection():
    now = datetime(2026, 7, 8, tzinfo=UTC)
    names = [
        f"events-v1-{TENANT}-2026.03",  # month ends 04-01 => 98d old
        f"events-v1-{TENANT}-2026.06",  # month ends 07-01 => 7d old
        f"events-v1-{TENANT}-2026.07",  # current month
        f"events-v1-{OTHER_TENANT}-2026.01",  # other tenant: never touched
        f"events-v1-{TENANT}-garbage",  # unparseable: skipped
    ]
    expired = select_expired_indices(names, TENANT, 14, now)
    assert expired == [f"events-v1-{TENANT}-2026.03"]
    # 1-day retention (AC-16 QA knob): 2026.06 becomes deletable too.
    expired_short = select_expired_indices(names, TENANT, 1, now)
    assert expired_short == [
        f"events-v1-{TENANT}-2026.03",
        f"events-v1-{TENANT}-2026.06",
    ]


async def test_retention_job_deletes_expired_indices_and_audits(ctx, state, es):
    seed_tenant(state, TENANT, plan_id="trial")
    state.plan_config[("trial", "retention_days")] = 14
    old_month = (NOW.replace(day=1) - timedelta(days=200)).strftime("%Y.%m")
    current_month = NOW.strftime("%Y.%m")
    es.index_names.update(
        {
            f"events-v1-{TENANT}-{old_month}",
            f"events-v1-{TENANT}-{current_month}",
        }
    )

    await job_retention_purge(ctx)

    assert es.index_names == {f"events-v1-{TENANT}-{current_month}"}
    audits = state.rows("audit_log", TENANT)
    assert [a["action_type"] for a in audits] == ["retention.es_index_deleted"]
    assert audits[0]["target_id"] == f"events-v1-{TENANT}-{old_month}"


async def test_retention_override_beats_plan_default(ctx, state, es):
    seed_tenant(state, TENANT, plan_id="trial")
    state.plan_config[("trial", "retention_days")] = 14
    state.entitlement_overrides.append(
        {"tenant_id": str(TENANT), "key": "retention_days", "value": 3650, "expires_at": None}
    )
    old_month = (NOW.replace(day=1) - timedelta(days=200)).strftime("%Y.%m")
    es.index_names.add(f"events-v1-{TENANT}-{old_month}")

    await job_retention_purge(ctx)

    assert f"events-v1-{TENANT}-{old_month}" in es.index_names  # kept by override


# ---------------------------------------------------------------------------
# billable window (AC-26), agent offline (AC-61), DLQ cleanup
# ---------------------------------------------------------------------------


async def test_billable_window_marks_stale_assets_non_billable(ctx, state):
    seed_tenant(state, TENANT)
    state.t["assets"].append(
        {"tenant_id": str(TENANT), "id": uuid4(), "billable": True,
         "last_seen": NOW - timedelta(days=45), "agent_status": "none"}
    )
    state.t["assets"].append(
        {"tenant_id": str(TENANT), "id": uuid4(), "billable": True,
         "last_seen": NOW - timedelta(days=2), "agent_status": "none"}
    )

    await job_billable_window(ctx)

    flags = sorted(a["billable"] for a in state.rows("assets", TENANT))
    assert flags == [False, True]


async def test_agent_offline_after_three_missed_heartbeats(ctx, state):
    seed_tenant(state, TENANT)
    stale_asset, fresh_asset = uuid4(), uuid4()
    state.t["assets"].append(
        {"tenant_id": str(TENANT), "id": stale_asset, "agent_status": "healthy",
         "billable": True, "last_seen": NOW}
    )
    state.t["assets"].append(
        {"tenant_id": str(TENANT), "id": fresh_asset, "agent_status": "healthy",
         "billable": True, "last_seen": NOW}
    )
    state.t["devices"].append(
        {"tenant_id": str(TENANT), "id": "dev_stale", "asset_id": stale_asset,
         "status": "active", "last_heartbeat_at": NOW - timedelta(seconds=600)}
    )
    state.t["devices"].append(
        {"tenant_id": str(TENANT), "id": "dev_fresh", "asset_id": fresh_asset,
         "status": "active", "last_heartbeat_at": NOW - timedelta(seconds=30)}
    )

    await job_agent_offline(ctx)  # threshold = 60s * 3 = 180s

    by_id = {str(a["id"]): a for a in state.rows("assets", TENANT)}
    assert by_id[str(stale_asset)]["agent_status"] == "offline"
    assert by_id[str(fresh_asset)]["agent_status"] == "healthy"


async def test_dlq_cleanup_deletes_rows_older_than_seven_days(ctx, state):
    seed_tenant(state, TENANT)
    state.t["dead_letter_events"].append(
        {"tenant_id": str(TENANT), "received_at": NOW - timedelta(days=9), "error_code": "X"}
    )
    state.t["dead_letter_events"].append(
        {"tenant_id": str(TENANT), "received_at": NOW - timedelta(days=1), "error_code": "Y"}
    )

    await job_dlq_cleanup(ctx)

    remaining = state.rows("dead_letter_events", TENANT)
    assert [r["error_code"] for r in remaining] == ["Y"]


# ---------------------------------------------------------------------------
# runner: singleton lock
# ---------------------------------------------------------------------------


async def test_job_lock_is_exclusive(redis):
    job = next(j for j in build_jobs() if j.name == "trial_freeze")
    token = await acquire_job_lock(redis, job)
    assert token is not None
    assert await acquire_job_lock(redis, job) is None  # second holder rejected


def test_registered_job_names_match_lock_convention():
    names = {job.name for job in build_jobs()}
    assert names == {
        "agent_offline",
        "trial_freeze",
        "billable_window",
        "dlq_cleanup",
        "trial_purge",
        "retention_purge",
    }
