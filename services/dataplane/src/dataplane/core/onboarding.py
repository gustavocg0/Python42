"""Onboarding step signals (AC-70).

PG `tenantdata.onboarding_steps` is the source of truth (seeded by the
internal provision endpoint); Redis `onboarding:{t}` carries transient
"step happened" signals set by whichever module observes the step. The
status endpoint reconciles signals into PG and deletes the hash when all
steps are done (db/redis-conventions.md).
"""

from __future__ import annotations

import logging
from uuid import UUID

logger = logging.getLogger(__name__)

STEP_IDS = ("install_agent", "create_ingest_key", "first_event", "view_queue")


async def signal_step(redis, tenant_id: UUID, step_id: str) -> None:
    """Best-effort signal; never fails the calling request."""
    if step_id not in STEP_IDS:
        raise ValueError(f"unknown onboarding step {step_id!r}")
    try:
        await redis.hset(f"onboarding:{tenant_id}", step_id, "1")
    except Exception:
        logger.debug("onboarding signal %s dropped (redis unavailable)", step_id)


async def read_signals(redis, tenant_id: UUID) -> set[str]:
    try:
        raw = await redis.hgetall(f"onboarding:{tenant_id}")
    except Exception:
        return set()
    decoded = {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in raw.items()
    }
    return {step for step, flag in decoded.items() if flag == "1" and step in STEP_IDS}


async def clear_signals(redis, tenant_id: UUID) -> None:
    try:
        await redis.delete(f"onboarding:{tenant_id}")
    except Exception:
        pass
