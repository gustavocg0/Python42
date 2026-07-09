"""worker-detector — Sigma-style rule evaluation over pipe:normalized
(AC-35..40, SEC-27/28/29, design §5 rule row).

Run: ``python -m dataplane.workers.detector``

- consumes ``pipe:normalized`` in consumer group ``detectors``
  (db/redis-conventions.md) via soc_pipeline.StreamConsumer — tenant context
  is established from the stream envelope per message (SEC-20);
- evaluates the ACTIVE published rule pack (compiled in memory, AC-37 p95),
  hot-reloading on the 30s pack-version poll (AC-39, no restart);
- effective enablement = pack default minus rule_runtime_disables minus per-tenant
  rule_toggles overlay, cached <= 30s (AC-38);
- per-event per-rule exceptions are isolated (SEC-28(b)): rule_eval_errors
  metric++, event skipped for that rule, rule STAYS enabled;
- sustained multi-tenant failure ⇒ rule_runtime_disables row + ops alert
  (SEC-28(c));
- one XADD to ``pipe:detections`` per hit; payload per rules/FORMAT.md §5.5;
- pipeline metrics {tenant_id, stage=detect, outcome} (AC-91) + a
  ``rule_eval_errors`` counter {rule_id, tenant_id};
- graceful shutdown on SIGTERM/SIGINT (finish in-flight, then stop).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

from opentelemetry import metrics as otel_metrics
from redis.asyncio import Redis

from dataplane.workers.common import (
    Settings,
    build_runtime,
    install_stop_signal_handlers,
    load_platform_config,
    make_pipeline_dead_letter_handler,
)
from dataplane.workers.detector_engine import (
    DEFAULT_DISABLE_FRACTION,
    DEFAULT_MIN_SAMPLES,
    DEFAULT_MIN_TENANTS,
    DEFAULT_WINDOW_SECONDS,
    DetectionHit,
    DetectorEngine,
    DisableDecision,
    FailureTracker,
)
from dataplane.workers.detector_pack import (
    EnablementCache,
    PackManager,
    PostgresRuleStore,
    RuleStore,
)
from soc_pipeline import (
    STREAM_DETECTIONS,
    STREAM_NORMALIZED,
    ReceivedMessage,
    StreamConsumer,
    StreamProducer,
)
from soc_telemetry import PipelineMetrics, PipelineOutcome, PipelineStage, configure_json_logging
from soc_tenancy import events_index, tenant_context

logger = logging.getLogger(__name__)

STAGE = PipelineStage.detect
DETECTORS_GROUP = "detectors"
"""Consumer group on pipe:normalized (db/redis-conventions.md streams table)."""

RULE_EVAL_ERRORS_COUNTER = "rule_eval_errors"

# platform_config keys (db/migrations/0009 seeds) with env overrides for
# deployments where the dataplane role lacks the control-schema read grant.
CONFIG_DISABLE_FRACTION = "rule_error_disable_fraction"
CONFIG_MIN_TENANTS = "rule_error_min_tenants"
ENV_DISABLE_FRACTION = "DETECTOR_RULE_ERROR_DISABLE_FRACTION"
ENV_MIN_TENANTS = "DETECTOR_RULE_ERROR_MIN_TENANTS"
ENV_MIN_SAMPLES = "DETECTOR_RULE_ERROR_MIN_SAMPLES"
ENV_WINDOW_SECONDS = "DETECTOR_RULE_ERROR_WINDOW_SECONDS"


def _event_time_utc(event: dict[str, Any]) -> datetime:
    """Event time for the deterministic monthly ES index name; the normalizer
    used `events_index(tenant_id, event_time)` when it wrote the document, so
    the same derivation reproduces the same index."""
    for key in ("event_time", "ingest_time"):
        raw = event.get(key)
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed
    return datetime.now(UTC)


def detection_payload(
    hit: DetectionHit, *, event_id: Any, event_time: str, es_index: str
) -> dict[str, Any]:
    """pipe:detections payload — EXACTLY rules/FORMAT.md §5.5 (canonical FLAT
    shape per the Architect integration ruling, 2026-07-08; the alerter needs
    event_time/entity_hostname for its window math and correlation).

    tenant_id/trace_id travel ONLY in the soc_pipeline envelope — the
    envelope tenant is authoritative (SEC-20). entity_hostname/entity_user
    are included only when present."""
    payload: dict[str, Any] = {
        "rule_id": hit.rule_id,
        "rule_version": hit.rule_version,
        "title": hit.title,
        "severity": hit.severity,
        "mitre_technique_ids": list(hit.mitre_technique_ids),
        "entity_key": hit.entity_key,
        "event_id": event_id,
        "event_time": event_time,
        "es_index": es_index,
        "pack_version": hit.pack_version,
    }
    if hit.entity_hostname is not None:
        payload["entity_hostname"] = hit.entity_hostname
    if hit.entity_user is not None:
        payload["entity_user"] = hit.entity_user
    return payload


class DetectorWorker:
    """Wires consumer, pack manager, engine, producer, and metrics together."""

    def __init__(
        self,
        *,
        redis: Redis,
        store: RuleStore,
        consumer_name: str,
        metrics: PipelineMetrics | None = None,
        tracker: FailureTracker | None = None,
        dead_letter: Any = None,
        pack_poll_seconds: float | None = None,
        overlay_ttl_seconds: float | None = None,
    ) -> None:
        self._store = store
        self._metrics = metrics or PipelineMetrics()
        meter = otel_metrics.get_meter("soc.detector")
        self._rule_eval_errors = meter.create_counter(
            RULE_EVAL_ERRORS_COUNTER,
            unit="1",
            description="Per-event rule evaluation exceptions (SEC-28b; rule stays enabled)",
        )
        self.eval_error_counts: dict[str, int] = {}
        pack_kwargs = {} if pack_poll_seconds is None else {
            "poll_interval_seconds": pack_poll_seconds
        }
        self.pack_manager = PackManager(store, **pack_kwargs)
        overlay_kwargs = {} if overlay_ttl_seconds is None else {
            "ttl_seconds": overlay_ttl_seconds
        }
        self.enablement = EnablementCache(store, **overlay_kwargs)
        self.tracker = tracker or FailureTracker()
        self.engine = DetectorEngine(
            enablement=self.enablement,
            tracker=self.tracker,
            on_eval_error=self._count_eval_error,
        )
        self._producer = StreamProducer(redis)
        self.stop = asyncio.Event()

        async def _log_dead_letter(message: Any) -> None:
            # Fallback when no PG-backed handler is injected: never silent (AC-91).
            logger.error(
                "ops_alert: detector dead-lettered a pipeline message",
                extra={
                    "ops_alert": "detector_dead_letter",
                    "stream": message.stream,
                    "message_id": message.message_id,
                    "error_code": message.error_code,
                },
            )
            self._metrics.record(
                tenant_id=str(message.tenant_id or "00000000-0000-0000-0000-000000000000"),
                stage=STAGE,
                outcome=PipelineOutcome.dead_lettered,
            )

        self.consumer = StreamConsumer(
            redis,
            stream=STREAM_NORMALIZED,
            group=DETECTORS_GROUP,
            consumer_name=consumer_name,
            handler=self.handle,
            tenant_context=lambda msg: tenant_context(msg.tenant_id),
            dead_letter=dead_letter or _log_dead_letter,
        )

    # -- SEC-28(b) accounting -------------------------------------------------

    def _count_eval_error(self, rule_id: str, tenant_id: str, error: str) -> None:
        self.eval_error_counts[rule_id] = self.eval_error_counts.get(rule_id, 0) + 1
        self._rule_eval_errors.add(1, {"rule_id": rule_id, "tenant_id": tenant_id})
        logger.warning(
            "rule evaluation error; event skipped for this rule only (SEC-28b)",
            extra={"rule_id": rule_id, "tenant_id": tenant_id, "error": error},
        )

    # -- SEC-28(c) ------------------------------------------------------------

    async def _apply_runtime_disable(self, decision: DisableDecision) -> None:
        reason = (
            f"sustained eval failure: {decision.error_fraction:.4f} of "
            f"{decision.samples} evaluations across {decision.tenants_affected} tenants "
            f"within {decision.window_seconds:.0f}s (SEC-28c)"
        )
        newly = await self._store.insert_runtime_disable(
            rule_id=decision.rule_id,
            reason=reason,
            error_fraction=decision.error_fraction,
            tenants_affected=decision.tenants_affected,
        )
        self.enablement.note_runtime_disable(decision.rule_id)
        logger.error(
            "ops_alert: rule auto-disabled on sustained multi-tenant failure — "
            "ops review required (SEC-28c)",
            extra={
                "ops_alert": "rule_runtime_disable",
                "rule_id": decision.rule_id,
                "error_fraction": decision.error_fraction,
                "tenants_affected": decision.tenants_affected,
                "newly_inserted": newly,
            },
        )

    # -- message handler --------------------------------------------------------

    async def handle(self, message: ReceivedMessage) -> None:
        started = time.perf_counter()
        tenant_id = str(message.tenant_id)
        pack = await self.pack_manager.ensure_loaded()
        if pack is None:
            # No published pack yet: detection is content-driven; nothing to
            # evaluate. ACK (skip) rather than poison-loop the stream.
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.skipped
            )
            return

        payload = message.payload
        if isinstance(payload.get("event"), dict):
            event: dict[str, Any] = payload["event"]
            es_index = payload.get("es_index")
        else:
            event = payload
            es_index = None
        if not isinstance(es_index, str) or not es_index:
            es_index = events_index(message.tenant_id, _event_time_utc(event))
        # event_time is REQUIRED in the detection payload (alerter window
        # math). The schema requires it on every normalized event; if it is
        # ever missing/unparseable, re-derive the RFC3339 form defensively.
        event_time = event.get("event_time")
        if not isinstance(event_time, str) or not event_time:
            event_time = _event_time_utc(event).strftime("%Y-%m-%dT%H:%M:%SZ")

        result = await self.engine.evaluate_event(pack=pack, event=event, tenant_id=tenant_id)

        for hit in result.hits:
            await self._producer.publish(
                STREAM_DETECTIONS,
                tenant_id=message.tenant_id,
                trace_id=message.trace_id,
                payload=detection_payload(
                    hit,
                    event_id=event.get("event_id"),
                    event_time=event_time,
                    es_index=es_index,
                ),
            )
        for decision in result.disable_decisions:
            await self._apply_runtime_disable(decision)

        self._metrics.record(
            tenant_id=tenant_id,
            stage=STAGE,
            outcome=PipelineOutcome.ok,
            duration_seconds=time.perf_counter() - started,
        )

    # -- lifecycle ---------------------------------------------------------------

    async def run(self) -> None:
        """Consume until `stop` is set; the pack-version poll runs alongside."""
        await self.pack_manager.ensure_loaded()
        poll_task = asyncio.create_task(self.pack_manager.poll_forever(self.stop))
        try:
            await self.consumer.run(stop=self.stop)
        finally:
            self.stop.set()
            poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await poll_task


def _tracker_from_config(config: dict[str, Any]) -> FailureTracker:
    """SEC-28(c) thresholds: platform_config values, then env overrides,
    then the 0009 seed defaults."""

    def _num(env_name: str, config_key: str | None, default: float) -> float:
        raw = os.environ.get(env_name)
        if raw:
            return float(raw)
        if config_key is not None and config_key in config:
            return float(config[config_key])
        return default

    return FailureTracker(
        disable_fraction=_num(
            ENV_DISABLE_FRACTION, CONFIG_DISABLE_FRACTION, DEFAULT_DISABLE_FRACTION
        ),
        min_tenants=int(_num(ENV_MIN_TENANTS, CONFIG_MIN_TENANTS, DEFAULT_MIN_TENANTS)),
        min_samples=int(_num(ENV_MIN_SAMPLES, None, DEFAULT_MIN_SAMPLES)),
        window_seconds=_num(ENV_WINDOW_SECONDS, None, DEFAULT_WINDOW_SECONDS),
    )


async def amain() -> None:
    configure_json_logging()
    runtime = await build_runtime(with_es=False)
    settings: Settings = runtime.settings
    metrics = PipelineMetrics()
    try:
        config = await load_platform_config(
            runtime.pool,
            {
                CONFIG_DISABLE_FRACTION: DEFAULT_DISABLE_FRACTION,
                CONFIG_MIN_TENANTS: DEFAULT_MIN_TENANTS,
            },
        )
        worker = DetectorWorker(
            redis=runtime.redis,
            store=PostgresRuleStore(runtime.pool),
            consumer_name=settings.consumer_name,
            metrics=metrics,
            tracker=_tracker_from_config(config),
            dead_letter=make_pipeline_dead_letter_handler(
                runtime.pool, metrics=metrics, stage=STAGE
            ),
        )
        install_stop_signal_handlers(worker.stop)
        logger.info(
            "worker-detector starting",
            extra={"stream": STREAM_NORMALIZED, "group": DETECTORS_GROUP},
        )
        await worker.run()
    finally:
        await runtime.close()


if __name__ == "__main__":
    asyncio.run(amain())
