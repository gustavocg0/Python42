"""Per-tenant daily triage budget backstop (SEC-37).

Key: `budget:triage:{t}:{yyyymmdd}` (db/redis-conventions.md) — a counter of
triage tokens (in+out) spent today, TTL 48h. Over the cap => skip the model
call, mark triage unavailable (reason=budget), meter outcome=over_budget,
emit an ops-alert log. LLM spend can never be unbounded by a single tenant.

Fail-open note: if Redis is unreachable the pipeline is already broken (the
message arrived via Redis streams), so no separate degraded path is needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

_TTL_SECONDS = 48 * 3600


def budget_key(tenant_id: UUID, *, now: datetime | None = None) -> str:
    day = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%d")
    return f"budget:triage:{tenant_id}:{day}"


@dataclass(frozen=True, slots=True)
class BudgetState:
    spent_tokens: int
    cap_tokens: int

    @property
    def exceeded(self) -> bool:
        return self.spent_tokens >= self.cap_tokens


class TriageBudget:
    def __init__(self, redis: object, *, daily_token_cap: int) -> None:
        self._redis = redis
        self._cap = daily_token_cap

    async def state(self, tenant_id: UUID) -> BudgetState:
        raw = await self._redis.get(budget_key(tenant_id))  # type: ignore[attr-defined]
        spent = int(raw) if raw else 0
        return BudgetState(spent_tokens=spent, cap_tokens=self._cap)

    async def add(self, tenant_id: UUID, tokens: int) -> int:
        """Record spend after a completed call; returns the new day total."""
        key = budget_key(tenant_id)
        total = await self._redis.incrby(key, tokens)  # type: ignore[attr-defined]
        if total == tokens:  # first write today -> set the TTL once
            await self._redis.expire(key, _TTL_SECONDS)  # type: ignore[attr-defined]
        return int(total)
