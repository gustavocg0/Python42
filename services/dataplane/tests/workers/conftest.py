"""Fakes for worker/job tests — no live Postgres/Redis/Elasticsearch.

- FakePool/FakeConn implement the asyncpg surface the workers use and
  interpret the workers' exact SQL constants against in-memory tables,
  including the alerts dedup-upsert conflict semantics (partial unique index
  alerts_open_dedup_uq) so concurrency/window paths are exercised for real.
- FakeES captures bulk bodies and emulates op_type=create idempotency (409 on
  duplicate _id) plus index listing/deletion for the jobs.
- Redis is fakeredis (streams included), so StreamProducer runs unmodified.
"""

from __future__ import annotations

import fnmatch
import json
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import fakeredis.aioredis
import pytest

from dataplane.jobs import tasks as tasks_mod
from dataplane.workers import alerter as alerter_mod
from dataplane.workers import asset_dedup as asset_mod
from dataplane.workers import normalizer as normalizer_mod
from dataplane.workers.common import DLQ_INSERT_SQL, PLATFORM_CONFIG_SQL
from soc_audit import AUDIT_INSERT_SQL
from soc_tenancy.pg import SET_TENANT_GUC_SQL


def utcnow() -> datetime:
    return datetime.now(UTC)


def _s(value: Any) -> str | None:
    return None if value is None else str(value)


class FakeState:
    """Shared in-memory database state."""

    def __init__(self) -> None:
        self.t: dict[str, list[dict[str, Any]]] = defaultdict(list)  # tenantdata tables
        self.tenants: dict[str, dict[str, Any]] = {}  # control.tenants by str(id)
        self.plan_config: dict[tuple[str, str], Any] = {}
        self.platform_config: dict[str, Any] = {}
        self.entitlement_overrides: list[dict[str, Any]] = []
        self.purge_registry: list[dict[str, Any]] = []

    # convenience for assertions
    def rows(self, table: str, tenant_id: Any = None) -> list[dict[str, Any]]:
        rows = self.t[table]
        if tenant_id is None:
            return rows
        return [r for r in rows if r.get("tenant_id") == _s(tenant_id)]


class FakeConn:
    def __init__(self, state: FakeState) -> None:
        self.state = state
        self.tenant: str | None = None

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def execute(self, sql: str, *args: Any) -> str:
        self._dispatch(sql, args)
        return "OK"

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return self._dispatch(sql, args)

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        rows = self._dispatch(sql, args)
        return rows[0] if rows else None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        rows = self._dispatch(sql, args)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    # -- dispatcher ---------------------------------------------------------

    def _dispatch(self, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        s = self.state
        now = utcnow()

        if sql == SET_TENANT_GUC_SQL:
            self.tenant = str(UUID(args[0]))
            return []

        if sql == DLQ_INSERT_SQL:
            s.t["dead_letter_events"].append(
                {
                    "tenant_id": _s(args[0]),
                    "batch_id": _s(args[1]),
                    "source_type": args[2],
                    "raw_payload": args[3],
                    "error_code": args[4],
                    "error_detail": args[5],
                    "received_at": now,
                }
            )
            return []

        if sql == PLATFORM_CONFIG_SQL:
            return [
                {"key": k, "value": json.dumps(v)}
                for k, v in s.platform_config.items()
                if k in args[0]
            ]

        if sql == AUDIT_INSERT_SQL:
            s.t["audit_log"].append(
                {
                    "tenant_id": _s(args[0]),
                    "actor_type": args[1],
                    "actor_id": args[2],
                    "action_type": args[3],
                    "target_type": args[4],
                    "target_id": args[5],
                    "before": args[6],
                    "after": args[7],
                    "reason_code": args[8],
                    "created_at": now,
                }
            )
            return []

        if sql == normalizer_mod.ONBOARDING_FIRST_EVENT_SQL:
            for row in s.t["onboarding_steps"]:
                if row["tenant_id"] == _s(args[0]) and row["step_id"] == "first_event":
                    row["state"] = "done"
                    return []
            s.t["onboarding_steps"].append(
                {
                    "tenant_id": _s(args[0]),
                    "step_id": "first_event",
                    "state": "done",
                    "completed_at": now,
                }
            )
            return []

        # ---- alerter -------------------------------------------------------

        if sql == alerter_mod.ALERT_EVENT_LINKED_SQL:
            tenant, event_id, rule_id = _s(args[0]), _s(args[1]), args[2]
            alerts_by_id = {a["id"]: a for a in s.t["alerts"]}
            for link in s.t["alert_events"]:
                if link["tenant_id"] != tenant or link["event_id"] != event_id:
                    continue
                alert = alerts_by_id.get(link["alert_id"])
                if alert and alert["rule_id"] == rule_id:
                    return [{"ok": 1}]
            return []

        if sql == alerter_mod.RESOLVE_ASSET_SQL:
            tenant, hostname = _s(args[0]), args[1]
            matches = [
                a
                for a in s.t["assets"]
                if a["tenant_id"] == tenant
                and a.get("hostname") == hostname
                and a.get("state", "active") == "active"
            ]
            matches.sort(key=lambda a: a["last_seen"], reverse=True)
            return [{"id": m["id"], "agent_status": m["agent_status"]} for m in matches[:1]]

        if sql == alerter_mod.ALERT_UPSERT_SQL:
            (
                new_id, tenant, rule_id, rule_version, title, severity, mitre,
                entity_key, hostname, user, asset_id, event_time, score,
                inputs_json, window,
            ) = args
            tenant = _s(tenant)
            open_rows = [
                a
                for a in s.t["alerts"]
                if a["tenant_id"] == tenant
                and a["rule_id"] == rule_id
                and a["entity_key"] == entity_key
                and a["state"] in ("new", "acknowledged")
            ]
            if not open_rows:
                row = {
                    "id": new_id,
                    "tenant_id": tenant,
                    "state": "new",
                    "rule_id": rule_id,
                    "rule_version": rule_version,
                    "rule_title": title,
                    "rule_severity": severity,
                    "mitre_technique_ids": list(mitre),
                    "entity_key": entity_key,
                    "entity_hostname": hostname,
                    "entity_user": user,
                    "asset_id": _s(asset_id),
                    "occurrence_count": 1,
                    "first_seen": event_time,
                    "last_seen": event_time,
                    "correlation_group_id": None,
                    "priority_score": score,
                    "priority_inputs": inputs_json,
                    "triage_status": "pending",
                    "ai_severity": None,
                    "close_reason": None,
                    "created_at": now,
                    "updated_at": now,
                }
                s.t["alerts"].append(row)
                return [{**row, "inserted": True}]
            existing = open_rows[0]
            if existing["last_seen"] >= event_time - timedelta(minutes=window):
                existing["occurrence_count"] += 1
                existing["last_seen"] = max(existing["last_seen"], event_time)
                existing["updated_at"] = now
                return [{**existing, "inserted": False}]
            return []  # conflict outside the window: DO UPDATE WHERE failed

        if sql == alerter_mod.CLOSE_EXPIRED_OPEN_ALERT_SQL:
            tenant, rule_id, entity_key, event_time, window = args
            tenant = _s(tenant)
            closed = []
            for a in s.t["alerts"]:
                if (
                    a["tenant_id"] == tenant
                    and a["rule_id"] == rule_id
                    and a["entity_key"] == entity_key
                    and a["state"] in ("new", "acknowledged")
                    and a["last_seen"] < event_time - timedelta(minutes=window)
                ):
                    a["state"] = "closed"
                    a["close_reason"] = "resolved"
                    a["closed_at"] = now
                    closed.append({"id": a["id"]})
            return closed

        if sql == alerter_mod.LINK_EVENT_SQL:
            tenant, alert_id, event_id, es_index = _s(args[0]), args[1], _s(args[2]), args[3]
            for link in s.t["alert_events"]:
                if (
                    link["tenant_id"] == tenant
                    and link["alert_id"] == alert_id
                    and link["event_id"] == event_id
                ):
                    return []
            s.t["alert_events"].append(
                {
                    "tenant_id": tenant,
                    "alert_id": alert_id,
                    "event_id": event_id,
                    "es_index": es_index,
                }
            )
            return []

        if sql == alerter_mod.INSERT_HISTORY_SQL:
            s.t["alert_history"].append(
                {
                    "tenant_id": _s(args[0]),
                    "alert_id": args[1],
                    "actor_type": args[2],
                    "actor_id": args[3],
                    "action": args[4],
                    "from_state": args[5],
                    "to_state": args[6],
                    "details": args[7],
                    "at": now,
                }
            )
            return []

        if sql == alerter_mod.CORRELATION_CANDIDATES_SQL:
            tenant, hostname, rule_id, alert_id, event_time, window = args
            tenant = _s(tenant)
            rows = [
                a
                for a in s.t["alerts"]
                if a["tenant_id"] == tenant
                and a.get("entity_hostname") == hostname
                and a["state"] in ("new", "acknowledged")
                and a["rule_id"] != rule_id
                and a["id"] != alert_id
                and a["last_seen"] >= event_time - timedelta(minutes=window)
            ]
            rows.sort(key=lambda a: a["last_seen"], reverse=True)
            return [
                {"id": a["id"], "correlation_group_id": a["correlation_group_id"]} for a in rows
            ]

        if sql == alerter_mod.CREATE_CORRELATION_GROUP_SQL:
            s.t["correlation_groups"].append(
                {
                    "id": args[0],
                    "tenant_id": _s(args[1]),
                    "entity_hostname": args[2],
                    "alert_count": 0,
                    "last_alert_at": args[3],
                }
            )
            return []

        if sql == alerter_mod.ASSIGN_CORRELATION_GROUP_SQL:
            tenant, ids, group_id = _s(args[0]), list(args[1]), args[2]
            assigned = []
            for a in s.t["alerts"]:
                if (
                    a["tenant_id"] == tenant
                    and a["id"] in ids
                    and a["correlation_group_id"] is None
                ):
                    a["correlation_group_id"] = group_id
                    assigned.append({"id": a["id"]})
            return assigned

        if sql == alerter_mod.UPDATE_CORRELATION_GROUP_STATS_SQL:
            tenant, group_id, ts = _s(args[0]), args[1], args[2]
            count = sum(
                1
                for a in s.t["alerts"]
                if a["tenant_id"] == tenant and a["correlation_group_id"] == group_id
            )
            for g in s.t["correlation_groups"]:
                if g["tenant_id"] == tenant and g["id"] == group_id:
                    g["alert_count"] = count
                    g["last_alert_at"] = max(g["last_alert_at"], ts)
            return []

        if sql == alerter_mod.UPDATE_PRIORITY_SQL:
            tenant, alert_id, score, inputs = _s(args[0]), args[1], args[2], args[3]
            for a in s.t["alerts"]:
                if a["tenant_id"] == tenant and a["id"] == alert_id:
                    a["priority_score"] = score
                    a["priority_inputs"] = inputs
            return []

        # ---- asset dedup -----------------------------------------------------

        if sql == asset_mod.PIN_LOOKUP_SQL:
            tenant, itype, value = _s(args[0]), args[1], args[2]
            return [
                {"pinned_asset_id": p["pinned_asset_id"]}
                for p in s.t["asset_identity_pins"]
                if p["tenant_id"] == tenant
                and p["identifier_type"] == itype
                and p["value"] == value
            ]

        if sql == asset_mod.IDENTITY_LOOKUP_SQL:
            tenant, itype, value = _s(args[0]), args[1], args[2]
            return [
                {"asset_id": i["asset_id"]}
                for i in s.t["asset_identities"]
                if i["tenant_id"] == tenant
                and i["identifier_type"] == itype
                and i["value"] == value
            ]

        if sql == asset_mod.ASSET_DEVICE_IDENTITY_SQL:
            tenant, asset_id = _s(args[0]), _s(args[1])
            return [
                {"value": i["value"]}
                for i in s.t["asset_identities"]
                if i["tenant_id"] == tenant
                and _s(i["asset_id"]) == asset_id
                and i["identifier_type"] == "device_id"
            ][:1]

        if sql == asset_mod.UPDATE_ASSET_SQL:
            (
                tenant, asset_id, hostname, os_family, os_name, os_version,
                ip, mac, source, observed_at, dedup_rule,
            ) = args
            for a in s.t["assets"]:
                if a["tenant_id"] == _s(tenant) and _s(a["id"]) == _s(asset_id):
                    a["hostname"] = hostname or a.get("hostname")
                    a["os_family"] = os_family or a.get("os_family")
                    a["os_name"] = os_name or a.get("os_name")
                    a["os_version"] = os_version or a.get("os_version")
                    a["ip"] = ip or a.get("ip")
                    a["mac"] = mac or a.get("mac")
                    if source not in a["sources"]:
                        a["sources"] = [*a["sources"], source]
                    a["last_seen"] = max(a["last_seen"], observed_at)
                    if a["agent_status"] != "revoked":
                        a["billable"] = True
                    a["billable_computed_at"] = now
                    a["dedup_rule"] = dedup_rule or a.get("dedup_rule")
                    a["updated_at"] = now
            return []

        if sql == asset_mod.INSERT_ASSET_SQL:
            (
                asset_id, tenant, hostname, os_family, os_name, os_version,
                ip, mac, sources, agent_status, created_via, observed_at,
            ) = args
            s.t["assets"].append(
                {
                    "id": asset_id,
                    "tenant_id": _s(tenant),
                    "hostname": hostname,
                    "os_family": os_family,
                    "os_name": os_name,
                    "os_version": os_version,
                    "ip": ip,
                    "mac": mac,
                    "sources": list(sources),
                    "agent_status": agent_status,
                    "billable": True,
                    "billable_computed_at": now,
                    "state": "active",
                    "dedup_rule": None,
                    "created_via": created_via,
                    "first_seen": observed_at,
                    "last_seen": observed_at,
                    "updated_at": now,
                }
            )
            return []

        if sql == asset_mod.UPSERT_IDENTITY_SQL:
            tenant, asset_id, source, itype, value, observed_at = args
            tenant = _s(tenant)
            for i in s.t["asset_identities"]:
                if (
                    i["tenant_id"] == tenant
                    and i["identifier_type"] == itype
                    and i["value"] == value
                ):
                    if _s(i["asset_id"]) == _s(asset_id):
                        i["last_seen"] = max(i["last_seen"], observed_at)
                        return [{"inserted": False}]
                    return []  # bound to another asset: DO UPDATE WHERE failed
            s.t["asset_identities"].append(
                {
                    "tenant_id": tenant,
                    "asset_id": asset_id,
                    "source": source,
                    "identifier_type": itype,
                    "value": value,
                    "first_seen": observed_at,
                    "last_seen": observed_at,
                }
            )
            return [{"inserted": True}]

        if sql == asset_mod.INSERT_MERGE_AUDIT_SQL:
            s.t["asset_merge_audit"].append(
                {
                    "tenant_id": _s(args[0]),
                    "asset_id": args[1],
                    "rule": args[2],
                    "actor_id": args[3],
                    "details": args[4],
                    "at": now,
                }
            )
            return []

        # ---- jobs ------------------------------------------------------------

        if sql == tasks_mod.ACTIVE_TENANTS_SQL:
            return [
                {"id": t["id"], "plan_id": t["plan_id"], "status": t["status"]}
                for t in s.tenants.values()
                if t["status"] in ("active", "frozen")
            ]

        if sql == tasks_mod.RETENTION_OVERRIDE_SQL:
            tenant = _s(args[0])
            return [
                {"value": json.dumps(o["value"])}
                for o in s.entitlement_overrides
                if o["tenant_id"] == tenant
                and o["key"] == "retention_days"
                and (o.get("expires_at") is None or o["expires_at"] > now)
            ]

        if sql == tasks_mod.PLAN_RETENTION_SQL:
            value = s.plan_config.get((args[0], "retention_days"))
            return [] if value is None else [{"value": json.dumps(value)}]

        if sql == tasks_mod.FREEZE_EXPIRED_TRIALS_SQL:
            frozen = []
            for t in s.tenants.values():
                if (
                    t["status"] == "active"
                    and t["plan_id"] == "trial"
                    and t.get("trial_expires_at") is not None
                    and t["trial_expires_at"] < now
                ):
                    t["status"] = "frozen"
                    t["frozen_at"] = now
                    frozen.append({"id": t["id"]})
            return frozen

        if sql == tasks_mod.PURGE_DUE_TENANTS_SQL:
            days = args[0]
            return [
                {"id": t["id"]}
                for t in s.tenants.values()
                if t["status"] == "frozen"
                and t.get("frozen_at") is not None
                and t["frozen_at"] < now - timedelta(days=days)
            ]

        if sql == tasks_mod.PURGE_REGISTRY_SQL:
            return [dict(r) for r in s.purge_registry]

        if sql == tasks_mod.MARK_TENANT_PURGED_SQL:
            t = s.tenants.get(_s(args[0]))
            if t is not None and t["status"] == "frozen":
                t["status"] = "purged"
                t["purged_at"] = now
            return []

        if sql == tasks_mod.BILLABLE_WINDOW_SQL:
            days = args[0]
            changed = []
            for a in s.t["assets"]:
                if (
                    a["tenant_id"] == self.tenant
                    and a["billable"]
                    and a["last_seen"] < now - timedelta(days=days)
                ):
                    a["billable"] = False
                    a["billable_computed_at"] = now
                    changed.append({"id": a["id"]})
            return changed

        if sql == tasks_mod.AGENT_OFFLINE_SQL:
            secs = args[0]
            assets_by_id = {_s(a["id"]): a for a in s.t["assets"]}
            changed = []
            for d in s.t["devices"]:
                if d["tenant_id"] != self.tenant or d["status"] != "active":
                    continue
                hb = d.get("last_heartbeat_at")
                if hb is None or hb >= now - timedelta(seconds=secs):
                    continue
                asset = assets_by_id.get(_s(d["asset_id"]))
                if asset and asset["agent_status"] in ("enrolled", "healthy"):
                    asset["agent_status"] = "offline"
                    changed.append({"id": asset["id"]})
            return changed

        if sql == tasks_mod.DLQ_CLEANUP_SQL:
            days = args[0]
            s.t["dead_letter_events"] = [
                r
                for r in s.t["dead_letter_events"]
                if not (
                    r["tenant_id"] == self.tenant
                    and r["received_at"] < now - timedelta(days=days)
                )
            ]
            return []

        if sql.startswith('DELETE FROM tenantdata."'):
            table = sql.split('"')[1]
            tenant = _s(args[0])
            s.t[table] = [r for r in s.t[table] if r.get("tenant_id") != tenant]
            return []

        raise AssertionError(f"FakeConn: unhandled SQL:\n{sql}")


class FakePool:
    def __init__(self, state: FakeState) -> None:
        self.state = state

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.state)

    async def close(self) -> None:  # pragma: no cover - parity with asyncpg
        return None


class _FakeESIndices:
    def __init__(self, parent: FakeES) -> None:
        self._parent = parent
        self.deleted: list[str] = []

    async def get(self, index: str) -> dict[str, Any]:
        return {
            name: {} for name in sorted(self._parent.index_names) if fnmatch.fnmatch(name, index)
        }

    async def delete(self, index: str) -> dict[str, Any]:
        matching = {n for n in self._parent.index_names if fnmatch.fnmatch(n, index)}
        self._parent.index_names -= matching
        self._parent.docs = {
            (idx, _id): doc for (idx, _id), doc in self._parent.docs.items() if idx not in matching
        }
        self.deleted.extend(sorted(matching))
        return {"acknowledged": True}


class FakeES:
    """Captures bulk bodies; emulates op_type=create idempotency (AC-34)."""

    def __init__(self) -> None:
        self.docs: dict[tuple[str, str], dict[str, Any]] = {}
        self.index_names: set[str] = set()
        self.bulk_bodies: list[list[dict[str, Any]]] = []
        self.fail_doc_ids: set[str] = set()
        self.indices = _FakeESIndices(self)

    async def bulk(self, *, operations: list[dict[str, Any]]) -> dict[str, Any]:
        self.bulk_bodies.append(operations)
        items: list[dict[str, Any]] = []
        errors = False
        for action, doc in zip(operations[0::2], operations[1::2], strict=True):
            meta = action["create"]
            index, doc_id = meta["_index"], meta["_id"]
            if doc_id in self.fail_doc_ids:
                items.append({"create": {"_id": doc_id, "status": 503, "error": {"type": "boom"}}})
                errors = True
            elif (index, doc_id) in self.docs:
                items.append(
                    {
                        "create": {
                            "_id": doc_id,
                            "status": 409,
                            "error": {"type": "version_conflict_engine_exception"},
                        }
                    }
                )
                errors = True
            else:
                self.docs[(index, doc_id)] = doc
                self.index_names.add(index)
                items.append({"create": {"_id": doc_id, "status": 201}})
        return {"errors": errors, "items": items}

    async def close(self) -> None:  # pragma: no cover
        return None


class CapturingMetrics:
    """Duck-typed PipelineMetrics capturing {tenant_id, stage, outcome}."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, str]] = []

    def record(self, *, tenant_id, stage, outcome, count=1, duration_seconds=None) -> None:
        for _ in range(count):
            self.records.append((str(tenant_id), str(stage), str(outcome)))

    def outcomes(self, stage: str | None = None) -> Counter[str]:
        return Counter(o for _t, s, o in self.records if stage is None or s == stage)


@pytest.fixture
def state() -> FakeState:
    return FakeState()


@pytest.fixture
def pool(state: FakeState) -> FakePool:
    return FakePool(state)


@pytest.fixture
def es() -> FakeES:
    return FakeES()


@pytest.fixture
def metrics() -> CapturingMetrics:
    return CapturingMetrics()


@pytest.fixture
async def redis():
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.aclose()
