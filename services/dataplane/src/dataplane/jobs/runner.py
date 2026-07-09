"""Cron-style job runner with Redis singleton locks (design §2 jobs-scheduler).

Each job acquires ``lock:job:{name}`` (SET NX PX, redis-conventions.md) before
running so multiple scheduler replicas never run the same job concurrently.
Locks are released with a compare-and-delete script — a slow job that outlives
its lock TTL can never delete a lock that another replica has since acquired.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from dataplane.jobs.tasks import (
    JobContext,
    job_agent_offline,
    job_billable_window,
    job_dlq_cleanup,
    job_retention_purge,
    job_trial_freeze,
    job_trial_purge,
)

logger = logging.getLogger(__name__)

JobFunc = Callable[[JobContext], Awaitable[None]]

RELEASE_LOCK_LUA = """\
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end\
"""


@dataclass(frozen=True, slots=True)
class Job:
    name: str
    interval_seconds: int
    func: JobFunc

    @property
    def lock_key(self) -> str:
        return f"lock:job:{self.name}"


def build_jobs() -> tuple[Job, ...]:
    """Registered jobs. Intervals sized against their ACs:
    agent_offline ≤60s (AC-61 "within 1 minute"), retention every 6h (≤24h
    after expiry, AC-16), freeze every 5 min, purge/billable/dlq hourly."""
    return (
        Job("agent_offline", 30, job_agent_offline),
        Job("trial_freeze", 300, job_trial_freeze),
        Job("billable_window", 3_600, job_billable_window),
        Job("dlq_cleanup", 3_600, job_dlq_cleanup),
        Job("trial_purge", 3_600, job_trial_purge),
        Job("retention_purge", 6 * 3_600, job_retention_purge),
    )


async def acquire_job_lock(redis: Any, job: Job, *, ttl_ms: int | None = None) -> str | None:
    """SET NX PX on lock:job:{name}; returns the owner token or None."""
    token = secrets.token_hex(16)
    ttl = ttl_ms if ttl_ms is not None else max(job.interval_seconds, 60) * 1000
    acquired = await redis.set(job.lock_key, token, nx=True, px=ttl)
    return token if acquired else None


async def release_job_lock(redis: Any, job: Job, token: str) -> None:
    await redis.eval(RELEASE_LOCK_LUA, 1, job.lock_key, token)


async def run_job_once(ctx: JobContext, job: Job) -> bool:
    """Run one job under its lock. Returns True when it actually ran."""
    token = await acquire_job_lock(ctx.redis, job)
    if token is None:
        logger.debug("job %s: lock held elsewhere, skipping", job.name)
        return False
    try:
        logger.info("job %s: starting", job.name)
        await job.func(ctx)
        logger.info("job %s: done", job.name)
    finally:
        await release_job_lock(ctx.redis, job, token)
    return True


async def run_loop(
    ctx: JobContext,
    jobs: tuple[Job, ...],
    stop: asyncio.Event,
    *,
    tick_seconds: float = 5.0,
) -> None:
    """Run due jobs until `stop` is set. One failing job never kills the loop
    (logged + retried next interval); jobs run sequentially per process."""
    loop = asyncio.get_running_loop()
    next_run: dict[str, float] = {job.name: 0.0 for job in jobs}
    while not stop.is_set():
        now = loop.time()
        for job in jobs:
            if now < next_run[job.name]:
                continue
            try:
                await run_job_once(ctx, job)
            except Exception:
                logger.exception("job %s failed; retrying next interval", job.name)
            next_run[job.name] = loop.time() + job.interval_seconds
        try:
            await asyncio.wait_for(stop.wait(), timeout=tick_seconds)
        except TimeoutError:
            continue
