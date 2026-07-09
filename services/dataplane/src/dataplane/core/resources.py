"""Process-wide resource assembly for the dataplane apps.

`AppResources` is the single injection seam: production builds it from
Settings (real asyncpg/redis/ES/entitlements); tests construct it directly
with fakes (fakeredis, fake pool, mock ES) — no live services in unit tests.

Workers/jobs (sibling agent) may import `AppResources`, `build_resources`,
and `dataplane.core.db` / `dataplane.core.settings` — that is the binding
core surface for them; nothing under `dataplane.api` is importable by
workers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import redis.asyncio as redis_asyncio
from elasticsearch import AsyncElasticsearch

from dataplane.core.ca import CertificateAuthority
from dataplane.core.db import Database, create_database
from dataplane.core.quotas import QuotaService
from dataplane.core.sessions import SessionStore
from dataplane.core.settings import Settings
from dataplane.core.status_stores import StatusStores
from soc_entitlements import EntitlementsClient
from soc_pipeline import StreamProducer
from soc_telemetry import PipelineMetrics


class EntitlementsLike(Protocol):
    """Subset of soc_entitlements.EntitlementsClient the API uses."""

    async def get(self, tenant_id: UUID | str) -> Any: ...


@dataclass(slots=True)
class AppResources:
    settings: Settings
    db: Database
    redis: Any
    es: Any
    producer: StreamProducer
    entitlements: EntitlementsLike
    status_stores: StatusStores
    quotas: QuotaService
    sessions: SessionStore
    ca: CertificateAuthority
    metrics: PipelineMetrics

    async def aclose(self) -> None:
        close = getattr(self.entitlements, "aclose", None)
        if close is not None:
            await close()
        await self.db.close()
        await self.redis.aclose()
        es_close = getattr(self.es, "close", None)
        if es_close is not None:
            await es_close()


async def build_resources(settings: Settings) -> AppResources:
    """Production wiring (compose/K8s). Tests build AppResources directly."""
    db = await create_database(settings.database_url)
    redis_client = redis_asyncio.from_url(settings.redis_url, decode_responses=True)
    es = AsyncElasticsearch(settings.es_url)
    entitlements = EntitlementsClient(
        base_url=settings.entitlements_base_url,
        service_name=settings.service_name,
        signing_key=settings.entitlements_signing_key,
    )
    return AppResources(
        settings=settings,
        db=db,
        redis=redis_client,
        es=es,
        producer=StreamProducer(redis_client),
        entitlements=entitlements,
        status_stores=StatusStores(
            redis_client, db, cache_ttl_seconds=settings.status_cache_ttl_seconds
        ),
        quotas=QuotaService(redis_client),
        sessions=SessionStore(redis_client),
        ca=CertificateAuthority.from_files(
            settings.ca_cert_path,
            settings.ca_key_path,
            lifetime_days=settings.cert_lifetime_days,
        ),
        metrics=PipelineMetrics(),
    )
