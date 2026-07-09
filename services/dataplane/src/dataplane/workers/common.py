"""Self-contained runtime helpers for data-plane workers and jobs.

Deliberately does NOT import ``dataplane.api``/``dataplane.core`` (owned by the
API agent, built concurrently): workers and jobs must start and run with only
this module + the shared ``packages/*`` libraries. Anything here may be
superseded later by a coordinated refactor through the Architect.

Contents:
- ``Settings``           — env-driven configuration (no secrets in code, SEC-49)
- ULID + prefixed id generators (``al_``/``cg_`` per db/migrations 0005)
- client factories (asyncpg pool, redis, elasticsearch)
- ``tenant_transaction`` — RLS-pinned transaction scope (SEC-23)
- dead-letter insert (AC-32/AC-91, 64KB cap per SEC-21)
- ``load_platform_config`` — control.platform_config reads with fail-safe defaults
- graceful-shutdown signal wiring (SIGTERM -> stop event)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import signal
import socket
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import asyncpg
from elasticsearch import AsyncElasticsearch
from redis.asyncio import Redis

from soc_pipeline import DeadLetteredMessage
from soc_tenancy import set_local_tenant

logger = logging.getLogger(__name__)

DLQ_MAX_PAYLOAD_BYTES = 65_536
"""dead_letter_events.raw_payload hard cap (SEC-21, event-schema §6)."""

PLATFORM_TENANT_ID = UUID("00000000-0000-0000-0000-000000000000")
"""Reserved platform-scope tenant id (db/README.md) — used when a poisoned
pipeline entry carries no usable tenant id (the row must still land in the
DLQ, never be dropped silently — AC-91)."""


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _env(*names: str, default: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


@dataclass(frozen=True, slots=True)
class Settings:
    """Worker/jobs runtime settings from the environment (12-factor, SEC-49)."""

    database_url: str
    redis_url: str
    elasticsearch_url: str
    consumer_name: str
    # Fallback defaults for control.platform_config keys — used only when the
    # runtime role cannot read control.platform_config (see obstacles report);
    # values mirror db/migrations/0009_seed_plans.sql.
    alert_dedup_window_minutes: int = 60
    correlation_window_minutes: int = 30
    billable_window_days: int = 30
    dlq_retention_days: int = 7
    trial_purge_after_days: int = 30
    heartbeat_interval_seconds: int = 60
    agent_offline_after_missed_heartbeats: int = 3
    default_retention_days: int = 14

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_url=_env(
                "SOC_DATABASE_URL",
                "DATABASE_URL",
                default="postgresql://localhost:5432/soc",
            ),
            redis_url=_env("SOC_REDIS_URL", "REDIS_URL", default="redis://localhost:6379/0"),
            elasticsearch_url=_env(
                "SOC_ELASTICSEARCH_URL", "ELASTICSEARCH_URL", default="http://localhost:9200"
            ),
            consumer_name=_env(
                "SOC_CONSUMER_NAME",
                default=f"{socket.gethostname()}-{os.getpid()}",
            ),
        )


# ---------------------------------------------------------------------------
# ULID (no external dependency — 48-bit ms timestamp + 80-bit randomness,
# Crockford base32, 26 chars, lexicographically sortable)
# ---------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid(timestamp_ms: int | None = None) -> str:
    """Generate a ULID string (spec: https://github.com/ulid/spec)."""
    ts = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if not 0 <= ts < (1 << 48):
        raise ValueError("timestamp out of ULID range")
    value = (ts << 80) | secrets.randbits(80)
    chars = []
    for shift in range(125, -5, -5):
        chars.append(_CROCKFORD[(value >> shift) & 0x1F])
    return "".join(chars)


def new_alert_id() -> str:
    """Alert id: 'al_' + ULID (db/migrations/0005 — sortable cursor tie-break)."""
    return f"al_{new_ulid()}"


def new_correlation_group_id() -> str:
    """Correlation group id: 'cg_' + ULID (db/migrations/0005)."""
    return f"cg_{new_ulid()}"


# ---------------------------------------------------------------------------
# Client factories
# ---------------------------------------------------------------------------


def create_redis(settings: Settings) -> Redis:
    return Redis.from_url(settings.redis_url)


def create_es(settings: Settings) -> AsyncElasticsearch:
    return AsyncElasticsearch(settings.elasticsearch_url)


async def create_pg_pool(settings: Settings, *, min_size: int = 1, max_size: int = 8) -> asyncpg.Pool:
    return await asyncpg.create_pool(
        dsn=settings.database_url, min_size=min_size, max_size=max_size
    )


# ---------------------------------------------------------------------------
# Tenant-scoped transaction (SEC-23): every data access path is RLS-pinned;
# tenant_id comes from the authenticated stream envelope or the control-plane
# tenant list — never from event payload content (SEC-20).
# ---------------------------------------------------------------------------


@asynccontextmanager
async def tenant_transaction(pool: Any, tenant_id: UUID | str) -> AsyncIterator[Any]:
    """Acquire a connection, open a transaction, SET LOCAL app.tenant_id."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            await set_local_tenant(conn, tenant_id)
            yield conn


# ---------------------------------------------------------------------------
# Dead-letter queue (AC-32 / AC-91 / SEC-21)
# ---------------------------------------------------------------------------

DLQ_INSERT_SQL = """\
INSERT INTO tenantdata.dead_letter_events
    (tenant_id, batch_id, source_type, raw_payload, error_code, error_detail)
VALUES ($1, $2, $3, $4, $5, $6)\
"""


def clamp_payload_bytes(payload: Any, *, cap: int = DLQ_MAX_PAYLOAD_BYTES) -> bytes:
    """Serialize an arbitrary payload to JSON bytes, truncated at the 64KB cap."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8", errors="replace")
    else:
        raw = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    return raw[:cap]


async def insert_dead_letter(
    conn: Any,
    *,
    tenant_id: UUID | str,
    batch_id: UUID | str | None,
    source_type: str,
    payload: Any,
    error_code: str,
    error_detail: str | None,
) -> None:
    """Insert one dead_letter_events row on an RLS-pinned connection."""
    batch: UUID | None
    try:
        batch = UUID(str(batch_id)) if batch_id else None
    except ValueError:
        batch = None
    await conn.execute(
        DLQ_INSERT_SQL,
        UUID(str(tenant_id)),
        batch,
        source_type if source_type in ("agent", "generic") else "generic",
        clamp_payload_bytes(payload),
        error_code,
        (error_detail or "")[:2000] or None,
    )


def make_pipeline_dead_letter_handler(pool: Any, *, metrics: Any, stage: str):
    """Dead-letter callback for soc_pipeline.StreamConsumer (AC-91).

    Poisoned stream entries (malformed envelope, handler failed after max
    delivery attempts) land in tenantdata.dead_letter_events. Entries without
    a valid tenant id are stored under the reserved platform tenant so the
    loss is still visible and auditable.
    """

    async def _dead_letter(message: DeadLetteredMessage) -> None:
        tenant: UUID
        try:
            tenant = UUID(str(message.tenant_id))
        except (ValueError, TypeError):
            tenant = PLATFORM_TENANT_ID
        source_type = "generic"
        batch_id: str | None = None
        payload_raw = message.raw_fields.get("payload")
        if payload_raw:
            try:
                payload = json.loads(payload_raw)
                if isinstance(payload, dict):
                    if payload.get("source_type") in ("agent", "generic"):
                        source_type = payload["source_type"]
                    batch_id = payload.get("batch_id")
            except (ValueError, TypeError):
                pass
        async with tenant_transaction(pool, tenant) as conn:
            await insert_dead_letter(
                conn,
                tenant_id=tenant,
                batch_id=batch_id,
                source_type=source_type,
                payload=message.raw_fields,
                error_code=message.error_code,
                error_detail=f"stream={message.stream} id={message.message_id}: "
                f"{message.error_detail}",
            )
        metrics.record(tenant_id=tenant, stage=stage, outcome="dead_lettered")
        logger.error(
            "pipeline message dead-lettered",
            extra={
                "stream": message.stream,
                "message_id": message.message_id,
                "error_code": message.error_code,
            },
        )

    return _dead_letter


# ---------------------------------------------------------------------------
# Platform config (control.platform_config) with fail-safe defaults
# ---------------------------------------------------------------------------

PLATFORM_CONFIG_SQL = "SELECT key, value FROM control.platform_config WHERE key = ANY($1::text[])"


async def load_platform_config(
    pool: Any, keys_with_defaults: Mapping[str, Any]
) -> dict[str, Any]:
    """Read platform knobs; fall back to seeded defaults if the role lacks
    the control-schema grant (reported as an obstacle — never crash a worker
    over a config read)."""
    result = dict(keys_with_defaults)
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(PLATFORM_CONFIG_SQL, list(keys_with_defaults))
    except asyncpg.PostgresError as exc:
        logger.warning("platform_config unavailable, using defaults: %s", exc)
        return result
    for row in rows:
        value = row["value"]
        result[row["key"]] = json.loads(value) if isinstance(value, str) else value
    return result


# ---------------------------------------------------------------------------
# Graceful shutdown (SIGTERM -> stop event; workers finish in-flight, ack)
# ---------------------------------------------------------------------------


def install_stop_signal_handlers(stop: asyncio.Event) -> None:
    """Set `stop` on SIGTERM/SIGINT. Falls back to signal.signal on platforms
    without loop.add_signal_handler (Windows dev boxes)."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover - platform dependent
            signal.signal(sig, lambda _s, _f: stop.set())


@dataclass(slots=True)
class WorkerRuntime:
    """Bundle of live clients shared by a worker process."""

    settings: Settings
    pool: Any
    redis: Redis
    es: AsyncElasticsearch | None = None
    _closed: bool = field(default=False, init=False)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.pool.close()
        await self.redis.aclose()
        if self.es is not None:
            await self.es.close()


async def build_runtime(*, with_es: bool = False) -> WorkerRuntime:
    settings = Settings.from_env()
    pool = await create_pg_pool(settings)
    redis = create_redis(settings)
    es = create_es(settings) if with_es else None
    return WorkerRuntime(settings=settings, pool=pool, redis=redis, es=es)
