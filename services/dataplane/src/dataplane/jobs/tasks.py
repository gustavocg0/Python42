"""Job implementations for the data-plane jobs-scheduler.

All PG access runs as the ``system_jobs`` role (db/README.md grant matrix):
- control schema: tenants SELECT + UPDATE(status/frozen_at/purged_at/updated_at),
  plans/plan_config/platform_config/entitlement_overrides SELECT,
  purge_registry SELECT;
- tenantdata schema: full DML, always under a tenant-pinned RLS GUC;
- audit rows via ``audit_writer`` membership (same-transaction, SEC-43).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from dataplane.workers.common import Settings, tenant_transaction
from soc_audit import Actor, Target, write_audit
from soc_tenancy.es import EVENTS_INDEX_PREFIX

logger = logging.getLogger(__name__)

JOB_ACTOR = Actor(type="system", id="jobs-scheduler")

# --- SQL ----------------------------------------------------------------------

ACTIVE_TENANTS_SQL = """\
SELECT id, plan_id, status FROM control.tenants WHERE status IN ('active', 'frozen')\
"""

RETENTION_OVERRIDE_SQL = """\
SELECT value FROM control.entitlement_overrides
WHERE tenant_id = $1 AND key = 'retention_days'
  AND (expires_at IS NULL OR expires_at > now())\
"""

PLAN_RETENTION_SQL = """\
SELECT value FROM control.plan_config WHERE plan_id = $1 AND key = 'retention_days'\
"""

FREEZE_EXPIRED_TRIALS_SQL = """\
UPDATE control.tenants
SET status = 'frozen', frozen_at = now(), updated_at = now()
WHERE status = 'active' AND plan_id = 'trial'
  AND trial_expires_at IS NOT NULL AND trial_expires_at < now()
RETURNING id\
"""

PURGE_DUE_TENANTS_SQL = """\
SELECT id FROM control.tenants
WHERE status = 'frozen' AND frozen_at IS NOT NULL
  AND frozen_at < now() - make_interval(days => $1)\
"""

PURGE_REGISTRY_SQL = """\
SELECT schema_name, table_name, purge_action FROM control.purge_registry\
"""

MARK_TENANT_PURGED_SQL = """\
UPDATE control.tenants
SET status = 'purged', purged_at = now(), updated_at = now()
WHERE id = $1 AND status = 'frozen'\
"""

BILLABLE_WINDOW_SQL = """\
UPDATE tenantdata.assets
SET billable = false, billable_computed_at = now(), updated_at = now()
WHERE billable AND last_seen < now() - make_interval(days => $1)
RETURNING id\
"""

AGENT_OFFLINE_SQL = """\
UPDATE tenantdata.assets a
SET agent_status = 'offline', updated_at = now()
FROM tenantdata.devices d
WHERE d.tenant_id = a.tenant_id AND d.asset_id = a.id AND d.status = 'active'
  AND a.agent_status IN ('enrolled', 'healthy')
  AND d.last_heartbeat_at IS NOT NULL
  AND d.last_heartbeat_at < now() - make_interval(secs => $1)
RETURNING a.id\
"""

DLQ_CLEANUP_SQL = """\
DELETE FROM tenantdata.dead_letter_events
WHERE received_at < now() - make_interval(days => $1)\
"""

# FK-safe deletion order for the purge (children before parents). Tables found
# in the registry but not listed here are deleted FIRST (best-effort: new
# tables are usually leaves; database-architect owns registry ordering).
PURGE_TABLE_ORDER: tuple[str, ...] = (
    "deep_investigation_runs",
    "alert_events",
    "alert_history",
    "alerts",
    "correlation_groups",
    "devices",
    "asset_merge_audit",
    "asset_identity_pins",
    "asset_identities",
    "enrollment_tokens",
    "ingest_keys",
    "assets",
    "rule_toggles",
    "dead_letter_events",
    "onboarding_steps",
    "usage_counters",
)

# Redis prefixes deleted at tenant purge (db/redis-conventions.md §Tenant purge;
# sess:* is controlplane-owned and handled there).
PURGE_REDIS_PATTERNS: tuple[str, ...] = (
    "device:{t}:*",
    "ingestkey:{t}:*",
    "tenantstatus:{t}",
    "ent:{t}",
    "quota:ingest:{t}:*",
    "quota:di:{t}:*",
    "budget:triage:{t}:*",
    "usage:ingest:{t}:*",
    "onboarding:{t}",
    "rl:enroll:token:{t}:*",
)


@dataclass(slots=True)
class JobContext:
    """Live clients + effective platform config for one scheduler process."""

    pool: Any
    redis: Any
    es: Any
    settings: Settings
    config: dict[str, Any]

    def int_config(self, key: str, fallback: int) -> int:
        try:
            return int(self.config.get(key, fallback))
        except (TypeError, ValueError):
            return fallback


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def _tenant_rows(ctx: JobContext) -> list[Any]:
    async with ctx.pool.acquire() as conn:
        return await conn.fetch(ACTIVE_TENANTS_SQL)


# ---------------------------------------------------------------------------
# retention_purge (AC-16)
# ---------------------------------------------------------------------------


def _month_end_utc(suffix: str) -> datetime:
    """First instant AFTER month 'yyyy.MM' — the latest possible event_time in
    that monthly index."""
    year, month = suffix.split(".")
    y, m = int(year), int(month)
    if m == 12:
        return datetime(y + 1, 1, 1, tzinfo=UTC)
    return datetime(y, m + 1, 1, tzinfo=UTC)


def select_expired_indices(
    index_names: list[str], tenant_id: UUID | str, retention_days: int, now: datetime
) -> list[str]:
    """Monthly indices whose ENTIRE content is past retention (pure, testable)."""
    prefix = f"{EVENTS_INDEX_PREFIX}{tenant_id}-"
    expired: list[str] = []
    for name in index_names:
        if not name.startswith(prefix):
            continue
        suffix = name[len(prefix):]
        try:
            month_end = _month_end_utc(suffix)
        except (ValueError, IndexError):
            logger.warning("skipping unparseable index name %s", name)
            continue
        age_days = (now - month_end).total_seconds() / 86_400
        if age_days > retention_days:
            expired.append(name)
    return expired


async def _retention_days_for(ctx: JobContext, tenant_id: UUID, plan_id: str) -> int:
    async with ctx.pool.acquire() as conn:
        override = await conn.fetchval(RETENTION_OVERRIDE_SQL, tenant_id)
        if override is not None:
            return int(_json_value(override))
        plan_value = await conn.fetchval(PLAN_RETENTION_SQL, plan_id)
    if plan_value is not None:
        return int(_json_value(plan_value))
    return ctx.settings.default_retention_days


async def job_retention_purge(ctx: JobContext) -> None:
    """Delete expired monthly ES indices per tenant retention (AC-16)."""
    now = datetime.now(UTC)
    for tenant in await _tenant_rows(ctx):
        tenant_id = tenant["id"]
        retention_days = await _retention_days_for(ctx, tenant_id, tenant["plan_id"])
        try:
            existing = await ctx.es.indices.get(index=f"{EVENTS_INDEX_PREFIX}{tenant_id}-*")
        except Exception as exc:  # per-tenant isolation: one bad tenant never stops the sweep
            logger.warning("retention: index listing failed for %s: %s", tenant_id, exc)
            continue
        expired = select_expired_indices(list(existing), tenant_id, retention_days, now)
        for index_name in expired:
            await ctx.es.indices.delete(index=index_name)
            async with tenant_transaction(ctx.pool, tenant_id) as conn:
                await write_audit(
                    conn,
                    tenant_id=tenant_id,
                    actor=JOB_ACTOR,
                    action_type="retention.es_index_deleted",
                    target=Target(type="es_index", id=index_name),
                    after={"retention_days": retention_days},
                    reason_code="retention_expired",
                )
            logger.info("retention: deleted %s (tenant %s)", index_name, tenant_id)


# ---------------------------------------------------------------------------
# trial_freeze (AC-9, SEC-46) + trial_purge (AC-10)
# ---------------------------------------------------------------------------


async def job_trial_freeze(ctx: JobContext) -> None:
    """Freeze trial tenants past trial_expires_at; invalidate the tenant-status
    cache so enforcement propagates ≤60s (redis-conventions rule 4)."""
    async with ctx.pool.acquire() as conn:
        rows = await conn.fetch(FREEZE_EXPIRED_TRIALS_SQL)
    for row in rows:
        tenant_id = row["id"]
        await ctx.redis.delete(f"tenantstatus:{tenant_id}")
        async with tenant_transaction(ctx.pool, tenant_id) as conn:
            await write_audit(
                conn,
                tenant_id=tenant_id,
                actor=JOB_ACTOR,
                action_type="tenant.trial_frozen",
                target=Target(type="tenant", id=str(tenant_id)),
                before={"status": "active"},
                after={"status": "frozen"},
                reason_code="trial_expired",
            )
        logger.info("trial_freeze: tenant %s frozen", tenant_id)


def ordered_purge_tables(registry_rows: list[Any]) -> list[str]:
    """Delete-action tenantdata tables in FK-safe order; 'retain' rows are
    honored (never deleted — e.g. audit_log, llm_metering per SEC-48)."""
    deletable = [
        r["table_name"]
        for r in registry_rows
        if r["schema_name"] == "tenantdata" and r["purge_action"] == "delete"
    ]
    order = {name: i for i, name in enumerate(PURGE_TABLE_ORDER)}
    return sorted(deletable, key=lambda t: order.get(t, -1))


_TABLE_NAME_OK = re.compile(r"^[a-z_][a-z0-9_]*$")


async def _purge_tenant_pg(ctx: JobContext, tenant_id: UUID, tables: list[str]) -> None:
    async with tenant_transaction(ctx.pool, tenant_id) as conn:
        for table in tables:
            if not _TABLE_NAME_OK.match(table):
                raise ValueError(f"refusing to purge suspicious table name {table!r}")
            # Identifier is validated + sourced from control.purge_registry
            # (operator-managed); tenant scoping is enforced by BOTH the RLS
            # GUC and the explicit predicate.
            await conn.execute(
                f'DELETE FROM tenantdata."{table}" WHERE tenant_id = $1',
                tenant_id,
            )
        # Audit row written in the SAME transaction; audit_log is 'retain' and
        # survives the purge (SEC-48).
        await write_audit(
            conn,
            tenant_id=tenant_id,
            actor=JOB_ACTOR,
            action_type="tenant.purged",
            target=Target(type="tenant", id=str(tenant_id)),
            after={"tables_purged": len(tables)},
            reason_code="trial_purge_30d",
        )


async def _purge_tenant_redis(ctx: JobContext, tenant_id: UUID) -> None:
    """Tenant-pinned key deletion (SCAN on a single tenant's prefixes is
    explicitly allowed in the purge job — redis-conventions rule 2)."""
    for pattern in PURGE_REDIS_PATTERNS:
        concrete = pattern.replace("{t}", str(tenant_id))
        if "*" not in concrete:
            await ctx.redis.delete(concrete)
            continue
        cursor = 0
        while True:
            cursor, keys = await ctx.redis.scan(cursor=cursor, match=concrete, count=500)
            if keys:
                await ctx.redis.delete(*keys)
            if cursor == 0:
                break


async def job_trial_purge(ctx: JobContext) -> None:
    """Purge tenants frozen ≥30 days: PG via purge_registry, ES indices,
    Redis keys; then mark the tenant purged (AC-10, SEC-46)."""
    purge_after_days = ctx.int_config(
        "trial_purge_after_days", ctx.settings.trial_purge_after_days
    )
    async with ctx.pool.acquire() as conn:
        due = await conn.fetch(PURGE_DUE_TENANTS_SQL, purge_after_days)
        registry = await conn.fetch(PURGE_REGISTRY_SQL)
    tables = ordered_purge_tables(list(registry))
    for row in due:
        tenant_id = row["id"]
        await _purge_tenant_pg(ctx, tenant_id, tables)
        await ctx.es.indices.delete(index=f"{EVENTS_INDEX_PREFIX}{tenant_id}-*")
        await _purge_tenant_redis(ctx, tenant_id)
        async with ctx.pool.acquire() as conn:
            await conn.execute(MARK_TENANT_PURGED_SQL, tenant_id)
        await ctx.redis.delete(f"tenantstatus:{tenant_id}")
        logger.info("trial_purge: tenant %s purged (%d tables)", tenant_id, len(tables))


# ---------------------------------------------------------------------------
# billable_window (AC-26), agent_offline (AC-61), dlq_cleanup (AC-32)
# ---------------------------------------------------------------------------


async def job_billable_window(ctx: JobContext) -> None:
    """Assets not seen within the 30-day window become non-billable (AC-26)."""
    window_days = ctx.int_config("billable_window_days", ctx.settings.billable_window_days)
    for tenant in await _tenant_rows(ctx):
        async with tenant_transaction(ctx.pool, tenant["id"]) as conn:
            changed = await conn.fetch(BILLABLE_WINDOW_SQL, window_days)
        if changed:
            logger.info(
                "billable_window: %d asset(s) -> non-billable (tenant %s)",
                len(changed),
                tenant["id"],
            )


async def job_agent_offline(ctx: JobContext) -> None:
    """3 missed heartbeats => asset agent_status='offline' within 1 min (AC-61).
    A resumed heartbeat flips it back via the heartbeat API (not this job)."""
    interval = ctx.int_config(
        "heartbeat_interval_seconds", ctx.settings.heartbeat_interval_seconds
    )
    missed = ctx.int_config(
        "agent_offline_after_missed_heartbeats",
        ctx.settings.agent_offline_after_missed_heartbeats,
    )
    threshold_seconds = interval * missed
    for tenant in await _tenant_rows(ctx):
        async with tenant_transaction(ctx.pool, tenant["id"]) as conn:
            changed = await conn.fetch(AGENT_OFFLINE_SQL, threshold_seconds)
        if changed:
            logger.info(
                "agent_offline: %d asset(s) marked offline (tenant %s)",
                len(changed),
                tenant["id"],
            )


async def job_dlq_cleanup(ctx: JobContext) -> None:
    """Dead-letter retention: 7 days (AC-32/SEC-21)."""
    retention_days = ctx.int_config("dlq_retention_days", ctx.settings.dlq_retention_days)
    for tenant in await _tenant_rows(ctx):
        async with tenant_transaction(ctx.pool, tenant["id"]) as conn:
            await conn.execute(DLQ_CLEANUP_SQL, retention_days)
