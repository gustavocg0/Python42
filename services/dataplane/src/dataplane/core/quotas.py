"""Quotas + rate limits + usage counters (Redis keys per db/redis-conventions.md).

- Ingest: sliding window, 60s in 10 x 6s buckets (`quota:ingest:{t}:{bucket}`,
  bucket = floor(unix/6)) — checked BEFORE XADD; over => 429 + Retry-After,
  never 202-then-drop (AC-86).
- Deep investigation: atomic check-and-DECR on `quota:di:{t}:{yyyymmdd}`
  (AC-55). Primary path is the Lua script from design §5; when the Redis
  runtime lacks scripting (test fakes without lupa) an equivalent atomic
  DECR/compensate fallback preserves the no-oversubscription guarantee.
- Enrollment rate limits: `rl:enroll:token:{t}:{id}`, `rl:enroll:ip:{ip}`
  fixed 60s windows (SEC-12).
- Usage counters: `usage:ingest:{t}:{yyyymmdd}:{metric}` 48h TTL (AC-88).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from redis.exceptions import RedisError

from soc_schemas import ApiError, ErrorCode

BUCKET_SECONDS = 6
WINDOW_BUCKETS = 10
_BUCKET_TTL = 120
_USAGE_TTL = 48 * 3600
_DI_TTL = 48 * 3600

DI_CONSUME_LUA = """
local v = redis.call('GET', KEYS[1])
if not v then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  v = ARGV[1]
end
v = tonumber(v)
if v <= 0 then return -1 end
return redis.call('DECR', KEYS[1])
"""


def _redis_unavailable() -> ApiError:
    return ApiError(
        ErrorCode.SERVICE_UNAVAILABLE,
        "Quota store unavailable; retry with backoff.",
        retry_after_seconds=30,
    )


def utc_day(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y%m%d")


def next_utc_midnight(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)


@dataclass(frozen=True, slots=True)
class DiQuotaResult:
    allowed: bool
    remaining: int  # remaining AFTER consumption when allowed; 0 when denied
    limit: int
    resets_at: datetime


class QuotaService:
    def __init__(self, redis) -> None:
        self._redis = redis

    # ---------------------------------------------------------- ingest window
    async def current_ingest_rate(self, tenant_id: UUID, now: float | None = None) -> int:
        bucket = int((now or time.time()) // BUCKET_SECONDS)
        keys = [f"quota:ingest:{tenant_id}:{bucket - i}" for i in range(WINDOW_BUCKETS)]
        try:
            values = await self._redis.mget(keys)
        except RedisError:
            raise _redis_unavailable() from None
        return sum(int(v) for v in values if v)

    async def check_and_consume_ingest(
        self, tenant_id: UUID, event_count: int, limit_per_min: int
    ) -> None:
        """429 INGEST_QUOTA_EXCEEDED (+Retry-After) when the batch would
        exceed the per-minute limit; otherwise consume."""
        now = time.time()
        used = await self.current_ingest_rate(tenant_id, now)
        if used + event_count > limit_per_min:
            retry_after = max(1, BUCKET_SECONDS - int(now) % BUCKET_SECONDS)
            raise ApiError(
                ErrorCode.INGEST_QUOTA_EXCEEDED,
                "Ingest quota exceeded for this tenant; retry after the window slides.",
                details={"events_per_min_limit": limit_per_min},
                retry_after_seconds=retry_after,
            )
        bucket_key = f"quota:ingest:{tenant_id}:{int(now // BUCKET_SECONDS)}"
        try:
            await self._redis.incrby(bucket_key, event_count)
            await self._redis.expire(bucket_key, _BUCKET_TTL)
        except RedisError:
            raise _redis_unavailable() from None

    # ------------------------------------------------------- deep investigation
    async def consume_deep_investigation(
        self, tenant_id: UUID, daily_limit: int, now: datetime | None = None
    ) -> DiQuotaResult:
        """Atomic seed-and-DECR (AC-54/55). daily_limit == -1 => unlimited,
        key untouched. Denial consumes nothing."""
        now = now or datetime.now(UTC)
        resets_at = next_utc_midnight(now)
        if daily_limit == -1:
            return DiQuotaResult(allowed=True, remaining=-1, limit=-1, resets_at=resets_at)
        if daily_limit <= 0:
            return DiQuotaResult(allowed=False, remaining=0, limit=daily_limit, resets_at=resets_at)
        key = f"quota:di:{tenant_id}:{utc_day(now)}"
        try:
            remaining = await self._eval_di(key, daily_limit)
        except RedisError:
            raise _redis_unavailable() from None
        if remaining < 0:
            return DiQuotaResult(allowed=False, remaining=0, limit=daily_limit, resets_at=resets_at)
        return DiQuotaResult(
            allowed=True, remaining=remaining, limit=daily_limit, resets_at=resets_at
        )

    async def _eval_di(self, key: str, limit: int) -> int:
        try:
            result = await self._redis.eval(DI_CONSUME_LUA, 1, key, str(limit), str(_DI_TTL))
            return int(result)
        except RedisError as exc:
            # Real Redis always has scripting; fall through only when the
            # runtime reports scripting is unsupported (fakes without lupa
            # raise "unknown command 'eval'" / lupa import errors).
            message = str(exc).lower()
            if not any(marker in message for marker in ("lupa", "script", "unknown command")):
                raise
        except NotImplementedError:
            pass
        # Equivalent atomic fallback: DECR then compensate — a successful
        # consume always lands >= 0, so the limit can never oversubscribe.
        await self._redis.set(key, limit, ex=_DI_TTL, nx=True)
        remaining = await self._redis.decr(key)
        if remaining < 0:
            await self._redis.incr(key)
            return -1
        return int(remaining)

    async def deep_investigation_remaining(
        self, tenant_id: UUID, daily_limit: int, now: datetime | None = None
    ) -> int:
        if daily_limit == -1:
            return -1
        key = f"quota:di:{tenant_id}:{utc_day(now)}"
        try:
            value = await self._redis.get(key)
        except RedisError:
            raise _redis_unavailable() from None
        if value is None:
            return max(daily_limit, 0)
        return max(int(value), 0)

    # ------------------------------------------------------------ rate limits
    async def check_rate_limit(self, key: str, per_minute: int) -> None:
        """Fixed 60s window counter; over => 429 RATE_LIMITED (SEC-12)."""
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, 60)
        except RedisError:
            raise _redis_unavailable() from None
        if count > per_minute:
            raise ApiError(
                ErrorCode.RATE_LIMITED,
                "Rate limit exceeded; retry later.",
                retry_after_seconds=60,
            )

    # ---------------------------------------------------------- usage counters
    async def bump_usage(self, tenant_id: UUID, metric: str, count: int = 1) -> None:
        """Best-effort AC-88 counters — never fails the request."""
        key = f"usage:ingest:{tenant_id}:{utc_day()}:{metric}"
        try:
            await self._redis.incrby(key, count)
            await self._redis.expire(key, _USAGE_TTL)
        except Exception:
            pass

    async def usage_24h(self, tenant_id: UUID, metric: str) -> int:
        today = datetime.now(UTC)
        keys = [
            f"usage:ingest:{tenant_id}:{utc_day(today)}:{metric}",
            f"usage:ingest:{tenant_id}:{utc_day(today - timedelta(days=1))}:{metric}",
        ]
        try:
            values = await self._redis.mget(keys)
        except RedisError:
            raise _redis_unavailable() from None
        return sum(int(v) for v in values if v)
