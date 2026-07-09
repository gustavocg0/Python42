"""worker-triager — pipe:alerts.triage -> AI triage fields on the alert (E7).

Run: ``python -m dataplane.workers.triager``

Message contract (producer: worker-alerter, new alerts only): the envelope
carries ``tenant_id``/``trace_id`` (SEC-20) and the payload carries at least
``{"alert_id": "al_..."}``. Extra payload fields (rule_*, entity_*,
event_refs, ...) are deliberately IGNORED: the triager re-reads the alert and
its event links through tenant-scoped fetchers so redeliveries see fresh
state and prompt content never bypasses the SEC-36 assembly path.

Modes:
- ANTHROPIC_API_KEY set  -> real model calls (fast model, TRIAGE_MODEL_ID);
- TRIAGE_FAKE=1          -> deterministic fake LLM (valid summaries, zero cost)
                            for compose demos / e2e;
- neither                -> dev mode: worker runs, every alert is marked
                            triage_status=unavailable (AC-50 fallback), loudly
                            logged. No code path performs a network LLM call
                            without an API key.

Failure semantics: triage failures NEVER block alert delivery (the alert is
already queued; we only UPDATE). Handler exceptions (DB down etc.) leave the
message pending for redelivery; after max attempts it dead-letters (AC-91).
Metrics: pipeline_events_total{tenant_id, stage=triage, outcome} + duration.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from dataplane.triage.budget import TriageBudget
from dataplane.triage.config import TriageSettings
from dataplane.triage.context import ESEventFetcher, EventRef, PGAlertFetcher
from dataplane.triage.graph import TriageRunner
from dataplane.triage.llm import (
    AnthropicTriageClient,
    FakeTriageClient,
    TriageLLMClient,
)
from dataplane.triage.metering import LLMMeter
from dataplane.triage.persist import TriagePersister
from dataplane.workers.common import (
    Settings,
    WorkerRuntime,
    build_runtime,
    install_stop_signal_handlers,
    load_platform_config,
    make_pipeline_dead_letter_handler,
)
from soc_pipeline import STREAM_ALERTS_TRIAGE, ReceivedMessage, StreamConsumer
from soc_telemetry import (
    PipelineMetrics,
    PipelineOutcome,
    PipelineStage,
    configure_json_logging,
    init_telemetry,
)
from soc_tenancy import tenant_context

logger = logging.getLogger(__name__)

SERVICE_NAME = "worker-triager"
CONSUMER_GROUP = "triagers"  # db/redis-conventions.md
STAGE = PipelineStage.triage

PLATFORM_CONFIG_BUDGET_KEY = "triage_daily_token_budget"

_OUTCOME_MAP = {
    "completed": PipelineOutcome.ok,
    "skipped": PipelineOutcome.skipped,
    "unavailable": PipelineOutcome.error,
}


class SafeEventFetcher:
    """ES event enrichment is best-effort: if ES is down the prompt is built
    from the alert row alone rather than blocking triage (AC-50 spirit)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def fetch_events(self, tenant_id: Any, refs: list[EventRef]) -> list[dict[str, Any]]:
        try:
            return await self._inner.fetch_events(tenant_id, refs)
        except Exception as exc:
            logger.warning(
                "event fetch failed; continuing with alert-only context",
                extra={"tenant_id": str(tenant_id), "error": f"{type(exc).__name__}: {exc}"},
            )
            return []


def select_client(settings: TriageSettings) -> TriageLLMClient | None:
    """Model-call mode selection. Never constructs a network client without a key."""
    if settings.fake_mode:
        logger.warning(
            "TRIAGE_FAKE=1 — deterministic fake LLM in use (no API calls, no cost)"
        )
        return FakeTriageClient()
    if settings.api_key:
        return AnthropicTriageClient(settings.api_key)
    logger.warning(
        "ANTHROPIC_API_KEY is not set — dev mode: every alert will be marked "
        "triage_status=unavailable (AC-50 fallback). Set the key or TRIAGE_FAKE=1."
    )
    return None


def build_handler(runner: TriageRunner, metrics: PipelineMetrics):
    async def handle(message: ReceivedMessage) -> None:
        alert_id = message.payload.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            # Permanently malformed: raise -> pending -> DLQ after max attempts (AC-91).
            raise ValueError("triage message payload has no alert_id")
        started = time.perf_counter()
        try:
            outcome = await runner.run(
                tenant_id=message.tenant_id,
                trace_id=message.trace_id,
                alert_id=alert_id,
            )
        except Exception:
            metrics.record(
                tenant_id=message.tenant_id,
                stage=STAGE,
                outcome=PipelineOutcome.error,
                duration_seconds=time.perf_counter() - started,
            )
            raise  # left pending for redelivery; DLQ after max attempts
        metrics.record(
            tenant_id=message.tenant_id,
            stage=STAGE,
            outcome=_OUTCOME_MAP[outcome.outcome],
            duration_seconds=time.perf_counter() - started,
        )

    return handle


async def build_consumer(
    runtime: WorkerRuntime, *, triage_settings: TriageSettings | None = None
) -> StreamConsumer:
    settings = triage_settings or TriageSettings.from_env()
    config = await load_platform_config(
        runtime.pool, {PLATFORM_CONFIG_BUDGET_KEY: settings.daily_token_budget}
    )
    metrics = PipelineMetrics()
    runner = TriageRunner(
        settings=settings,
        alerts=PGAlertFetcher(runtime.pool),
        events=SafeEventFetcher(ESEventFetcher(runtime.es)),
        client=select_client(settings),
        budget=TriageBudget(
            runtime.redis, daily_token_cap=int(config[PLATFORM_CONFIG_BUDGET_KEY])
        ),
        meter=LLMMeter(runtime.pool),
        persister=TriagePersister(runtime.pool),
    )
    return StreamConsumer(
        runtime.redis,
        stream=STREAM_ALERTS_TRIAGE,
        group=CONSUMER_GROUP,
        consumer_name=runtime.settings.consumer_name,
        handler=build_handler(runner, metrics),
        tenant_context=lambda msg: tenant_context(msg.tenant_id),
        dead_letter=make_pipeline_dead_letter_handler(
            runtime.pool, metrics=metrics, stage=str(STAGE)
        ),
    )


async def main() -> None:
    configure_json_logging(SERVICE_NAME)
    init_telemetry(SERVICE_NAME)
    _ = Settings.from_env()  # fail fast on obviously broken env
    runtime = await build_runtime(with_es=True)
    stop = asyncio.Event()
    install_stop_signal_handlers(stop)
    consumer = await build_consumer(runtime)
    logger.info(
        "worker-triager started",
        extra={"stream": STREAM_ALERTS_TRIAGE, "group": CONSUMER_GROUP},
    )
    try:
        await consumer.run(stop=stop)
    finally:
        await runtime.close()
        logger.info("worker-triager stopped")


if __name__ == "__main__":
    asyncio.run(main())
