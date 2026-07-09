"""Shared fakes for triage tests.

NO network anywhere: LLM clients are in-memory fakes, Redis is fakeredis,
Postgres is a duck-typed fake pool implementing the small surface the triage
modules use (acquire/transaction/execute/fetchrow/fetch).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from dataplane.triage.context import AlertRow, EventRef
from dataplane.triage.llm import LLMResult, TriageLLMError, TriageLLMTimeout
from dataplane.triage.scoring_adapter import PriorityResult
from soc_tenancy.pg import SET_TENANT_GUC_SQL

TENANT_A = UUID("11111111-1111-4111-8111-111111111111")
TENANT_B = UUID("22222222-2222-4222-8222-222222222222")

VALID_SUMMARY = (
    "What happened: The computer fin-laptop-07 ran a PowerShell command at 09:42 UTC "
    "under the account sam.jones. The command was disguised so its contents could "
    "not be read directly, which is a common way to hide malicious activity.\n"
    "Why it matters: Normal software rarely hides its commands this way. If an "
    "attacker ran this, they may already have remote control of this computer.\n"
    "Do this next: Ask sam.jones whether they or your IT tools ran a script around "
    "09:42 UTC. If not, disconnect fin-laptop-07 from the network now and change "
    "sam.jones's password."
)


def make_alert(
    *,
    tenant_id: UUID = TENANT_A,
    alert_id: str = "al_01TEST",
    hostname: str | None = "fin-laptop-07",
    user: str | None = "sam.jones",
    rule_severity: str = "high",
    triage_status: str = "pending",
    occurrence_count: int = 1,
    asset_id: UUID | None = None,
) -> AlertRow:
    return AlertRow(
        id=alert_id,
        tenant_id=tenant_id,
        rule_id="win_susp_encoded_powershell",
        rule_version="1.2.0",
        rule_title="Suspicious encoded PowerShell",
        rule_severity=rule_severity,
        mitre_technique_ids=("T1059.001",),
        entity_hostname=hostname,
        entity_user=user,
        asset_id=asset_id,
        occurrence_count=occurrence_count,
        first_seen="2026-07-08 09:42:03+00:00",
        last_seen="2026-07-08 09:42:03+00:00",
        triage_status=triage_status,
        triage_attempts=0,
    )


# ---------------------------------------------------------------------------
# Fake Postgres pool
# ---------------------------------------------------------------------------


class FakeConn:
    """Duck-typed asyncpg connection: records every execute; routes reads."""

    def __init__(self, store: FakeStore) -> None:
        self._store = store

    @asynccontextmanager
    async def _tx(self):
        yield self

    def transaction(self):
        return self._tx()

    async def execute(self, query: str, *args: Any) -> str:
        self._store.executed.append((query, args))
        if query == SET_TENANT_GUC_SQL:
            self._store.tenant_setting = args[0]
        return "OK"

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        self._store.executed.append((query, args))
        if "FROM tenantdata.alerts" in query:
            return self._store.alert_rows.get(args[0])
        if "FROM tenantdata.assets" in query:
            return self._store.asset_rows.get(args[0])
        raise AssertionError(f"unexpected fetchrow: {query}")

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        self._store.executed.append((query, args))
        if "FROM tenantdata.alert_events" in query:
            return self._store.event_ref_rows.get(args[0], [])
        if "FROM control.platform_config" in query:
            return []
        raise AssertionError(f"unexpected fetch: {query}")


class FakeStore:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.tenant_setting: str | None = None
        self.alert_rows: dict[str, dict[str, Any]] = {}
        self.asset_rows: dict[UUID, dict[str, Any]] = {}
        self.event_ref_rows: dict[str, list[dict[str, Any]]] = {}

    def add_alert(self, alert: AlertRow) -> None:
        self.alert_rows[alert.id] = {
            "id": alert.id,
            "tenant_id": alert.tenant_id,
            "rule_id": alert.rule_id,
            "rule_version": alert.rule_version,
            "rule_title": alert.rule_title,
            "rule_severity": alert.rule_severity,
            "mitre_technique_ids": list(alert.mitre_technique_ids),
            "entity_hostname": alert.entity_hostname,
            "entity_user": alert.entity_user,
            "asset_id": alert.asset_id,
            "occurrence_count": alert.occurrence_count,
            "first_seen": alert.first_seen,
            "last_seen": alert.last_seen,
            "triage_status": alert.triage_status,
            "triage_attempts": alert.triage_attempts,
        }

    def updates_matching(self, fragment: str) -> list[tuple[str, tuple[Any, ...]]]:
        return [(q, a) for q, a in self.executed if fragment in q]


class FakePool:
    def __init__(self, store: FakeStore) -> None:
        self.store = store

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.store)


# ---------------------------------------------------------------------------
# Fake fetchers / LLM / metering / persistence collaborators
# ---------------------------------------------------------------------------


class DictAlertFetcher:
    """In-memory tenant-scoped alert fetcher: data keyed by (tenant, alert)."""

    def __init__(self) -> None:
        self.alerts: dict[tuple[UUID, str], AlertRow] = {}
        self.refs: dict[tuple[UUID, str], list[EventRef]] = {}

    def add(self, alert: AlertRow, refs: list[EventRef] | None = None) -> None:
        self.alerts[(alert.tenant_id, alert.id)] = alert
        self.refs[(alert.tenant_id, alert.id)] = refs or []

    async def fetch_alert(self, tenant_id: UUID, alert_id: str) -> AlertRow | None:
        return self.alerts.get((tenant_id, alert_id))

    async def fetch_event_refs(
        self, tenant_id: UUID, alert_id: str, *, limit: int
    ) -> list[EventRef]:
        return self.refs.get((tenant_id, alert_id), [])[:limit]


class DictEventFetcher:
    """In-memory tenant-scoped event fetcher (bodies keyed by tenant)."""

    def __init__(self) -> None:
        self.bodies: dict[UUID, list[dict[str, Any]]] = {}

    async def fetch_events(self, tenant_id: UUID, refs: list[EventRef]) -> list[dict[str, Any]]:
        return list(self.bodies.get(tenant_id, []))[: len(refs)] if refs else []


class ScriptedLLM:
    """Returns queued results/exceptions in order; records every call."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    async def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        if not self.script:
            raise AssertionError("ScriptedLLM exhausted")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, str):
            return LLMResult(
                text=item, model_id="scripted-model", tokens_in=100, tokens_out=50, latency_ms=5
            )
        return item


def ok_json(summary: str = VALID_SUMMARY, severity: str = "high") -> str:
    import json

    return json.dumps({"summary": summary, "ai_severity": severity})


class RecordingMeter:
    def __init__(self) -> None:
        self.records: list[Any] = []

    async def record(self, rec: Any) -> None:
        self.records.append(rec)


class RecordingPersister:
    def __init__(self) -> None:
        self.completed: list[dict[str, Any]] = []
        self.unavailable: list[dict[str, Any]] = []

    async def persist_completed(self, **kwargs: Any) -> None:
        self.completed.append(kwargs)

    async def persist_unavailable(self, **kwargs: Any) -> None:
        self.unavailable.append(kwargs)


def contract_recompute(
    *, rule_severity: str, ai_severity: str | None, occurrence_count: int, agent_status: str
) -> PriorityResult:
    """Mock of dataplane.scoring against docs/contracts/priority-score.md
    (used where the real module is not the unit under test)."""
    tiers = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    points = {"low": 30, "medium": 55, "high": 80, "critical": 100}
    names = ("low", "medium", "high", "critical")
    s_rule = points[rule_severity]
    if ai_severity is not None:
        eff = names[max(tiers[ai_severity], tiers[rule_severity] - 1)]
        s_ai = points[eff]
    else:
        eff, s_ai = None, s_rule
    sev = (170 * (s_rule + s_ai) + 200) // 400
    occ = 0 if occurrence_count == 1 else 4 if occurrence_count < 5 else 7 if occurrence_count < 20 else 10
    asset = 5 if agent_status in ("offline", "revoked") else 2 if agent_status == "none" else 0
    return PriorityResult(
        priority_score=min(100, sev + occ + asset),
        priority_inputs={
            "priority_formula_version": 1,
            "rule_severity": rule_severity,
            "ai_severity": ai_severity,
            "ai_severity_effective": eff,
            "occurrence_count": occurrence_count,
            "agent_status": agent_status,
        },
    )


def make_error(kind: str) -> Exception:
    return TriageLLMTimeout("30s") if kind == "timeout" else TriageLLMError("boom")


def new_trace() -> str:
    return f"tr-{uuid4().hex[:12]}"
