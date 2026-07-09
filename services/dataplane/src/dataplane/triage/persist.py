"""Persistence for triage results — single tenant-scoped transaction each.

Completed: triage fields (RAW ai_severity per AC-49) + priority recompute via
dataplane.scoring (clamped ai_severity_effective comes back inside
priority_inputs, SEC-34) + alert_history 'triage_completed' — one transaction,
SET LOCAL tenant (SEC-23).

Unavailable: triage_status only; priority stays rule-derived (AC-50) — the
alert was delivered when it was created, we only UPDATE.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from dataplane.triage.context import AlertRow
from dataplane.triage.scoring_adapter import PriorityRecompute, recompute_priority
from soc_tenancy import set_local_tenant

_AGENT_STATUS_SQL = "SELECT agent_status FROM tenantdata.assets WHERE id = $1"

_UPDATE_COMPLETED_SQL = """
UPDATE tenantdata.alerts SET
  triage_status = 'completed',
  triage_summary = $2,
  ai_severity = $3,
  ai_severity_effective = $4,
  triage_model_id = $5,
  triage_completed_at = now(),
  triage_attempts = $6,
  priority_score = $7,
  priority_inputs = $8::jsonb,
  updated_at = now()
WHERE id = $1
"""

_UPDATE_UNAVAILABLE_SQL = """
UPDATE tenantdata.alerts SET
  triage_status = 'unavailable',
  triage_attempts = $2,
  updated_at = now()
WHERE id = $1
"""

_HISTORY_SQL = """
INSERT INTO tenantdata.alert_history
  (tenant_id, alert_id, actor_type, actor_id, action, details)
VALUES ($1, $2, 'system', 'worker-triager', $3, $4::jsonb)
"""


class TriagePersister:
    def __init__(self, pool: Any, *, recompute: PriorityRecompute | None = None) -> None:
        self._pool = pool
        self._recompute = recompute or recompute_priority

    async def _agent_status(self, conn: Any, asset_id: UUID | None) -> str:
        """Fresh agent_status at recompute time (priority-score.md §3)."""
        if asset_id is None:
            return "none"
        row = await conn.fetchrow(_AGENT_STATUS_SQL, asset_id)
        return row["agent_status"] if row else "none"

    async def persist_completed(
        self,
        *,
        tenant_id: UUID,
        alert: AlertRow,
        summary: str,
        ai_severity: str,  # RAW model output — clamp happens inside scoring
        model_id: str,
        attempts: int,
    ) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant_id)
                agent_status = await self._agent_status(conn, alert.asset_id)
                priority = self._recompute(
                    rule_severity=alert.rule_severity,
                    ai_severity=ai_severity,
                    occurrence_count=alert.occurrence_count,
                    agent_status=agent_status,
                )
                await conn.execute(
                    _UPDATE_COMPLETED_SQL,
                    alert.id,
                    summary,
                    ai_severity,
                    priority.ai_severity_effective,
                    model_id,
                    attempts,
                    priority.priority_score,
                    json.dumps(priority.priority_inputs, default=str),
                )
                await conn.execute(
                    _HISTORY_SQL,
                    tenant_id,
                    alert.id,
                    "triage_completed",
                    json.dumps(
                        {
                            "ai_severity": ai_severity,
                            "ai_severity_effective": priority.ai_severity_effective,
                            "priority_score": priority.priority_score,
                            "model_id": model_id,
                            "attempts": attempts,
                        }
                    ),
                )

    async def persist_unavailable(
        self,
        *,
        tenant_id: UUID,
        alert_id: str,
        attempts: int,
        reason: str,
    ) -> None:
        """AC-50 terminal failure: alert keeps its rule-derived priority."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant_id)
                await conn.execute(_UPDATE_UNAVAILABLE_SQL, alert_id, attempts)
                await conn.execute(
                    _HISTORY_SQL,
                    tenant_id,
                    alert_id,
                    "triage_unavailable",
                    json.dumps({"reason": reason, "attempts": attempts}),
                )
