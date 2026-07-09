"""Per-stage pipeline metrics labeled {tenant_id, stage, outcome} (AC-91).

Failure semantics: every event ends stored (ES), dead-lettered (PG), or
rejected with an error code at the API; each stage emits these metrics so
observability can prove it (design §4, SEC-22 alerting builds on them).
"""

from __future__ import annotations

import enum
import time
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from opentelemetry import metrics as otel_metrics
from opentelemetry.metrics import Meter

EVENTS_COUNTER_NAME = "pipeline_events_total"
STAGE_DURATION_HISTOGRAM_NAME = "pipeline_stage_duration_seconds"


class PipelineStage(enum.StrEnum):
    ingest = "ingest"
    normalize = "normalize"
    detect = "detect"
    alert = "alert"
    triage = "triage"
    asset_dedup = "asset_dedup"


class PipelineOutcome(enum.StrEnum):
    ok = "ok"
    stored = "stored"
    dead_lettered = "dead_lettered"
    rejected = "rejected"
    duplicate = "duplicate"
    retried = "retried"
    error = "error"
    skipped = "skipped"


class PipelineMetrics:
    """Counter + duration histogram for pipeline stages.

    Attributes on every point: tenant_id, stage, outcome (AC-91).
    """

    def __init__(self, meter: Meter | None = None) -> None:
        meter = meter or otel_metrics.get_meter("soc.pipeline")
        self._events = meter.create_counter(
            EVENTS_COUNTER_NAME,
            unit="1",
            description="Events handled per pipeline stage by outcome",
        )
        self._duration = meter.create_histogram(
            STAGE_DURATION_HISTOGRAM_NAME,
            unit="s",
            description="Per-stage processing duration",
        )

    @staticmethod
    def _attributes(
        tenant_id: UUID | str, stage: PipelineStage | str, outcome: PipelineOutcome | str
    ) -> dict[str, str]:
        return {
            "tenant_id": str(tenant_id),
            "stage": str(PipelineStage(stage)),
            "outcome": str(PipelineOutcome(outcome)),
        }

    def record(
        self,
        *,
        tenant_id: UUID | str,
        stage: PipelineStage | str,
        outcome: PipelineOutcome | str,
        count: int = 1,
        duration_seconds: float | None = None,
    ) -> None:
        attributes = self._attributes(tenant_id, stage, outcome)
        self._events.add(count, attributes)
        if duration_seconds is not None:
            self._duration.record(duration_seconds, attributes)

    @contextmanager
    def time_stage(
        self,
        *,
        tenant_id: UUID | str,
        stage: PipelineStage | str,
        outcome_on_success: PipelineOutcome | str = PipelineOutcome.ok,
    ) -> Iterator[None]:
        """Time a stage; records outcome=error and re-raises on exception."""
        start = time.perf_counter()
        try:
            yield
        except Exception:
            self.record(
                tenant_id=tenant_id,
                stage=stage,
                outcome=PipelineOutcome.error,
                duration_seconds=time.perf_counter() - start,
            )
            raise
        self.record(
            tenant_id=tenant_id,
            stage=stage,
            outcome=outcome_on_success,
            duration_seconds=time.perf_counter() - start,
        )
