"""worker-normalizer — pipe:raw -> validate/normalize -> ES + pipe:normalized.

Run: ``python -m dataplane.workers.normalizer``

Responsibilities (design §2/§4, AC-31..34, AC-91):
- consume ``pipe:raw`` batch messages (consumer group ``normalizers``);
- per event: strip client-assigned fields (SEC-18, event-schema §5), assemble
  the server-authoritative envelope, validate via ``soc_schemas.parse_event``;
- malformed events -> per-tenant ``dead_letter_events`` row (error code +
  detail, 64KB cap) + ``events_rejected`` counter; the rest of the batch
  proceeds — malformed input NEVER stalls the pipeline (AC-32);
- valid events -> ES bulk ``op_type=create`` with the idempotent ``_id``
  (design §3); duplicates counted and dropped (AC-34); index
  ``events-v1-{tenant}-{yyyy.MM}`` derived from event_time (AC-33);
- ONLY after the ES write succeeds: XADD ``pipe:normalized`` (envelope+class)
  and ``pipe:asset.observations`` (identity observation, AC-20/22);
- first stored event for a tenant flips the ``first_event`` onboarding step
  (Redis signal + tenantdata.onboarding_steps, AC-70);
- per-stage metrics {tenant_id, stage=normalize, outcome} on every event (AC-91).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError

from dataplane.workers.common import (
    Settings,
    build_runtime,
    insert_dead_letter,
    install_stop_signal_handlers,
    make_pipeline_dead_letter_handler,
    tenant_transaction,
)
from soc_pipeline import (
    STREAM_ASSET_OBSERVATIONS,
    STREAM_NORMALIZED,
    STREAM_RAW,
    ReceivedMessage,
    StreamConsumer,
    StreamProducer,
)
from soc_schemas import (
    SCHEMA_VERSION,
    Event,
    EventClass,
    Host,
    MalformedEventError,
    SourceType,
    derive_es_document_id,
    move_unknown_to_unmapped,
    parse_event,
    strip_client_assigned_fields,
    truncate_generic_raw,
)
from soc_schemas.events import MAX_MESSAGE_CHARS, MAX_SOURCE_EVENT_ID_CHARS
from soc_telemetry import PipelineMetrics, PipelineOutcome, PipelineStage
from soc_tenancy import events_index, tenant_context

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "normalizers"
STAGE = PipelineStage.normalize

# Keys the ingest API is allowed to put in the batch source context; anything
# else is dropped before it can reach the stored envelope (SEC-18/20).
_SOURCE_KEYS = ("device_id", "agent_version", "ingest_key_id", "vendor", "product")

ONBOARDING_FIRST_EVENT_SQL = """\
INSERT INTO tenantdata.onboarding_steps (tenant_id, step_id, state, completed_at)
VALUES ($1, 'first_event', 'done', now())
ON CONFLICT (tenant_id, step_id) DO UPDATE
SET state = 'done',
    completed_at = COALESCE(onboarding_steps.completed_at, now())\
"""


class RawBatch(BaseModel):
    """``pipe:raw`` message payload (producer: ingest API after auth/quota).

    ``source`` carries the AUTHENTICATED source context (device identity or
    ingest key id) — set by the ingest API, never from client payloads.
    """

    model_config = ConfigDict(extra="ignore")

    batch_id: UUID
    source_type: SourceType
    ingest_time: AwareDatetime
    source: dict[str, Any]
    events: list[Any]


class NormalizedEvent(BaseModel):
    """Internal carrier for one successfully normalized event."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    doc: dict[str, Any]
    es_index: str
    doc_id: str
    host: dict[str, Any] | None
    event_time: str


def _parse_event_time(value: Any) -> datetime | None:
    """RFC3339 -> aware datetime; None when missing/unparseable (contract §2)."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else None
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _best_effort_generic(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Map arbitrary generic-ingest JSON to the `generic` class (contract §5)."""
    message = None
    for key in ("message", "msg", "log"):
        candidate = raw_event.get(key)
        if isinstance(candidate, str) and candidate:
            message = candidate
            break
    if message is None:
        message = json.dumps(raw_event, default=str, separators=(",", ":"))
    raw, truncated = truncate_generic_raw(raw_event)
    normalized: dict[str, Any] = {
        "event_class": "generic",
        "activity": "log",
        "message": message[:MAX_MESSAGE_CHARS],
        "raw": raw,
    }
    if truncated:
        normalized["raw_truncated"] = True
    category = raw_event.get("category")
    if isinstance(category, str) and category:
        normalized["category"] = category
    fields = raw_event.get("fields")
    if isinstance(fields, dict) and all(
        isinstance(v, (str, int, float, bool)) for v in fields.values()
    ):
        try:
            if len(json.dumps(fields, separators=(",", ":")).encode()) <= 16 * 1024:
                normalized["fields"] = fields
        except (TypeError, ValueError):
            pass
    host = raw_event.get("host")
    if isinstance(host, dict):
        try:
            normalized["host"] = Host.model_validate(host).model_dump(exclude_none=True)
        except ValidationError:
            pass  # best-effort: bad host shape stays in raw only
    event_time = raw_event.get("event_time")
    if isinstance(event_time, str):
        normalized["event_time"] = event_time
    source_event_id = raw_event.get("source_event_id")
    if isinstance(source_event_id, str) and 0 < len(source_event_id) <= MAX_SOURCE_EVENT_ID_CHARS:
        normalized["source_event_id"] = source_event_id
    return normalized


class Normalizer:
    def __init__(
        self,
        *,
        pool: Any,
        redis: Any,
        es: Any,
        producer: StreamProducer,
        metrics: PipelineMetrics,
        settings: Settings,
    ) -> None:
        self._pool = pool
        self._redis = redis
        self._es = es
        self._producer = producer
        self._metrics = metrics
        self._settings = settings

    # -- normalization -----------------------------------------------------

    def _normalize_one(
        self, tenant_id: UUID, batch: RawBatch, raw_event: dict[str, Any]
    ) -> NormalizedEvent:
        """One raw client event -> validated normalized doc + ES identity.

        Raises MalformedEventError for anything that must dead-letter (AC-32).
        """
        stripped = strip_client_assigned_fields(raw_event)
        event_class = stripped.get("event_class")

        if batch.source_type == SourceType.generic and event_class not in EventClass.__members__:
            normalized = _best_effort_generic(raw_event)
        else:
            # Pre-classified (agent always; generic optionally). Unknown
            # event_class on an agent event => malformed => DLQ.
            normalized = move_unknown_to_unmapped(stripped)

        # Server-authoritative envelope (contract §5, SEC-18/20): identity
        # comes from the authenticated batch context, never the client payload.
        normalized["event_id"] = str(uuid4())
        normalized["tenant_id"] = str(tenant_id)
        normalized["schema_version"] = SCHEMA_VERSION
        normalized["ingest_time"] = batch.ingest_time.isoformat()
        normalized["batch_id"] = str(batch.batch_id)
        normalized["source_type"] = batch.source_type.value
        normalized["source"] = {
            k: batch.source[k] for k in _SOURCE_KEYS if batch.source.get(k) is not None
        }

        event_time = _parse_event_time(normalized.get("event_time"))
        if event_time is None:
            normalized["event_time"] = batch.ingest_time.isoformat()
            normalized["time_inferred"] = True

        if batch.source_type == SourceType.generic and not normalized.get("source_event_id"):
            # Contract §2: generic without source_event_id gets a server UUID
            # (no dedup across retries).
            normalized["source_event_id"] = str(uuid4())

        model: Event = parse_event(normalized)  # raises MalformedEventError
        doc = model.model_dump(mode="json", exclude_none=True)
        source_scope = model.source.device_id or model.source.ingest_key_id or ""
        return NormalizedEvent(
            doc=doc,
            es_index=events_index(tenant_id, model.event_time),
            doc_id=derive_es_document_id(tenant_id, source_scope, model.source_event_id or ""),
            host=doc.get("host"),
            event_time=doc["event_time"],
        )

    # -- side-effect helpers -------------------------------------------------

    async def _dead_letter_events(
        self,
        tenant_id: UUID,
        batch: RawBatch | None,
        dead: list[tuple[Any, str, str]],
        *,
        source_type: str,
    ) -> None:
        if not dead:
            return
        async with tenant_transaction(self._pool, tenant_id) as conn:
            for payload, code, detail in dead:
                await insert_dead_letter(
                    conn,
                    tenant_id=tenant_id,
                    batch_id=batch.batch_id if batch else None,
                    source_type=source_type,
                    payload=payload,
                    error_code=code,
                    error_detail=detail,
                )
        for _ in dead:
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.dead_lettered
            )
        await self._bump_usage(tenant_id, "rejected_events", len(dead))

    async def _bump_usage(self, tenant_id: UUID, metric: str, count: int) -> None:
        """Daily usage counter (AC-88; redis-conventions usage:ingest:*)."""
        if count <= 0:
            return
        day = datetime.now(UTC).strftime("%Y%m%d")
        key = f"usage:ingest:{tenant_id}:{day}:{metric}"
        await self._redis.incrby(key, count)
        await self._redis.expire(key, 48 * 3600)

    async def _mark_first_event(self, tenant_id: UUID) -> None:
        """AC-70: first stored event completes the onboarding step."""
        newly_set = await self._redis.hsetnx(f"onboarding:{tenant_id}", "first_event", "1")
        if newly_set:
            async with tenant_transaction(self._pool, tenant_id) as conn:
                await conn.execute(ONBOARDING_FIRST_EVENT_SQL, tenant_id)

    def _asset_observation(
        self, batch: RawBatch, normalized: NormalizedEvent
    ) -> dict[str, Any] | None:
        host = normalized.host
        if not host or not host.get("hostname"):
            return None
        source = "agent" if batch.source_type == SourceType.agent else "log_ingest"
        obs: dict[str, Any] = {
            "observed_at": normalized.event_time,
            "source": source,
            "hostname": host.get("hostname"),
            "os_family": host.get("os_family"),
            "os_name": host.get("os_name"),
            "os_version": host.get("os_version"),
            "ip": host.get("ip"),
            "mac": host.get("mac"),
        }
        device_id = normalized.doc.get("source", {}).get("device_id")
        if device_id:
            obs["device_id"] = device_id
            obs["agent_version"] = normalized.doc.get("source", {}).get("agent_version")
        return {k: v for k, v in obs.items() if v is not None}

    # -- handler ---------------------------------------------------------------

    async def handle(self, message: ReceivedMessage) -> None:
        tenant_id = message.tenant_id
        try:
            batch = RawBatch.model_validate(message.payload)
        except ValidationError as exc:
            # Structurally unusable batch: DLQ the whole payload, ack. AC-32:
            # malformed input never stalls the pipeline.
            detail = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]
            )
            source_type = message.payload.get("source_type")
            await self._dead_letter_events(
                tenant_id,
                None,
                [(message.payload, "RAW_BATCH_MALFORMED", detail)],
                source_type=source_type if source_type in ("agent", "generic") else "generic",
            )
            return

        normalized: list[NormalizedEvent] = []
        dead: list[tuple[Any, str, str]] = []
        for raw_event in batch.events:
            if not isinstance(raw_event, dict):
                dead.append((raw_event, "EVENT_NOT_AN_OBJECT", "event must be a JSON object"))
                continue
            try:
                normalized.append(self._normalize_one(tenant_id, batch, raw_event))
            except MalformedEventError as exc:
                dead.append((raw_event, exc.error_code, exc.error_detail))

        await self._dead_letter_events(
            tenant_id, batch, dead, source_type=batch.source_type.value
        )

        if not normalized:
            return

        # ES bulk with op_type=create + deterministic _id (AC-33/34).
        operations: list[dict[str, Any]] = []
        for item in normalized:
            operations.append({"create": {"_index": item.es_index, "_id": item.doc_id}})
            operations.append(item.doc)
        response = await self._es.bulk(operations=operations)

        stored: list[NormalizedEvent] = []
        duplicates = 0
        failures: list[str] = []
        for item, result in zip(normalized, response["items"], strict=True):
            outcome = result.get("create", {})
            status = outcome.get("status")
            if status in (200, 201):
                stored.append(item)
            elif status == 409:
                duplicates += 1  # AC-34: duplicate delivery — counted, dropped
                self._metrics.record(
                    tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.duplicate
                )
            else:
                failures.append(f"{item.doc_id}: status={status}")
                self._metrics.record(
                    tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.error
                )

        # Downstream fan-out ONLY for events that are durably in ES (design §4).
        for item in stored:
            await self._producer.publish(
                STREAM_NORMALIZED,
                tenant_id=tenant_id,
                trace_id=message.trace_id,
                payload=item.doc,
            )
            observation = self._asset_observation(batch, item)
            if observation is not None:
                await self._producer.publish(
                    STREAM_ASSET_OBSERVATIONS,
                    tenant_id=tenant_id,
                    trace_id=message.trace_id,
                    payload=observation,
                )
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.stored
            )

        await self._bump_usage(tenant_id, "events_accepted", len(stored))
        await self._bump_usage(tenant_id, "duplicates_dropped", duplicates)
        if stored:
            await self._mark_first_event(tenant_id)

        if failures:
            # Retryable store failure: leave the message pending (at-least-once);
            # already-stored events dedup as 409 on redelivery (AC-34).
            raise RuntimeError(f"ES bulk store failed for {len(failures)} event(s): {failures[:5]}")


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    runtime = await build_runtime(with_es=True)
    stop = asyncio.Event()
    install_stop_signal_handlers(stop)
    metrics = PipelineMetrics()
    normalizer = Normalizer(
        pool=runtime.pool,
        redis=runtime.redis,
        es=runtime.es,
        producer=StreamProducer(runtime.redis),
        metrics=metrics,
        settings=runtime.settings,
    )
    consumer = StreamConsumer(
        runtime.redis,
        stream=STREAM_RAW,
        group=CONSUMER_GROUP,
        consumer_name=runtime.settings.consumer_name,
        handler=normalizer.handle,
        tenant_context=lambda msg: tenant_context(msg.tenant_id),
        dead_letter=make_pipeline_dead_letter_handler(
            runtime.pool, metrics=metrics, stage=STAGE
        ),
    )
    logger.info("worker-normalizer starting (group=%s)", CONSUMER_GROUP)
    try:
        # Graceful shutdown: SIGTERM sets `stop`; run() finishes the in-flight
        # batch (handler + ack) before returning.
        await consumer.run(stop=stop)
    finally:
        await runtime.close()
        logger.info("worker-normalizer stopped")


if __name__ == "__main__":
    asyncio.run(main())
