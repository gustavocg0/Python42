"""LLM metering: one tenantdata.llm_metering row per model-call attempt (AC-51).

Rows are written for successes AND failures (error/timeout) and for budget
skips (outcome=over_budget, zero tokens). Rows contain reference ids and
aggregates only — never prompt or completion content (SEC-38/48).

Outcome mapping (column CHECK: ok|error|timeout|over_budget):
- ok          -> the API call completed (tokens were consumed), even if the
                 output later failed validation — metering tracks spend;
- error       -> API/transport error;
- timeout     -> per-call 30s timeout (AC-50);
- over_budget -> call skipped by the SEC-37 budget backstop.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from soc_tenancy import set_local_tenant

Outcome = Literal["ok", "error", "timeout", "over_budget"]

_INSERT_SQL = """
INSERT INTO tenantdata.llm_metering
  (tenant_id, call_type, alert_id, model_id, endpoint_region,
   tokens_in, tokens_out, cost_usd, latency_ms, outcome)
VALUES ($1, 'triage', $2, $3, $4, $5, $6, $7, $8, $9)
"""


@dataclass(frozen=True, slots=True)
class MeterRecord:
    tenant_id: UUID
    alert_id: str
    model_id: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int | None
    outcome: Outcome
    endpoint_region: str | None = None


class LLMMeter:
    """Writes metering rows in their own short tenant-scoped transaction.

    Separate from the alert-persist transaction on purpose: failed attempts
    must be metered even when triage never completes (AC-51).
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def record(self, rec: MeterRecord) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, rec.tenant_id)
                await conn.execute(
                    _INSERT_SQL,
                    rec.tenant_id,
                    rec.alert_id,
                    rec.model_id,
                    rec.endpoint_region,
                    rec.tokens_in,
                    rec.tokens_out,
                    rec.cost_usd,
                    rec.latency_ms,
                    rec.outcome,
                )
