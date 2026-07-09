"""Runtime dependency construction (real asyncpg/Redis/httpx clients).

Kept out of the app factories so unit tests can inject fakes without ever
importing driver internals. The asyncpg pool and redis client satisfy the
same duck types the fakes implement (acquire()/fetchrow/... and the redis
command subset).
"""

from __future__ import annotations

import httpx

from controlplane.abuse import build_challenge_verifier
from controlplane.config import Settings
from controlplane.mailer import build_mailer
from controlplane.security.passwords import FileBreachedPasswordChecker
from controlplane.services import AppServices, build_services


async def build_runtime_services(settings: Settings) -> AppServices:
    import asyncpg
    from redis.asyncio import Redis

    pool = await asyncpg.create_pool(settings.database_url, min_size=2, max_size=10)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    dataplane_client = httpx.AsyncClient(
        base_url=settings.dataplane_internal_url, timeout=10.0
    )
    return build_services(
        settings=settings,
        db=pool,
        redis=redis,
        mailer=build_mailer(settings),
        breached_checker=FileBreachedPasswordChecker(),
        challenge_verifier=build_challenge_verifier(settings),
        dataplane_client=dataplane_client,
    )


async def shutdown_runtime_services(services: AppServices) -> None:
    for task in list(services.background_tasks):
        task.cancel()
    await services.dataplane_client.aclose()
    await services.redis.aclose()
    await services.db.close()
