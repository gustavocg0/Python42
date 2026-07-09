import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from soc_telemetry import PipelineMetrics, PipelineOutcome, PipelineStage
from soc_telemetry.metrics import EVENTS_COUNTER_NAME, STAGE_DURATION_HISTOGRAM_NAME

TENANT = "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f"


@pytest.fixture
def meter_setup():
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    metrics = PipelineMetrics(provider.get_meter("test"))
    return reader, metrics


def collect_points(reader, name):
    data = reader.get_metrics_data()
    points = []
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    points.extend(metric.data.data_points)
    return points


def test_counter_has_required_labels(meter_setup):
    reader, metrics = meter_setup
    metrics.record(
        tenant_id=TENANT,
        stage=PipelineStage.normalize,
        outcome=PipelineOutcome.stored,
        count=3,
    )
    points = collect_points(reader, EVENTS_COUNTER_NAME)
    assert len(points) == 1
    point = points[0]
    assert point.value == 3
    # AC-91: labels are exactly {tenant_id, stage, outcome}
    assert dict(point.attributes) == {
        "tenant_id": TENANT,
        "stage": "normalize",
        "outcome": "stored",
    }


def test_duration_histogram_recorded(meter_setup):
    reader, metrics = meter_setup
    metrics.record(
        tenant_id=TENANT,
        stage="detect",
        outcome="ok",
        duration_seconds=0.05,
    )
    points = collect_points(reader, STAGE_DURATION_HISTOGRAM_NAME)
    assert len(points) == 1
    assert points[0].sum == pytest.approx(0.05)


def test_time_stage_success(meter_setup):
    reader, metrics = meter_setup
    with metrics.time_stage(tenant_id=TENANT, stage=PipelineStage.alert):
        pass
    points = collect_points(reader, EVENTS_COUNTER_NAME)
    assert points[0].attributes["outcome"] == "ok"


def test_time_stage_error_outcome(meter_setup):
    reader, metrics = meter_setup
    with pytest.raises(RuntimeError):
        with metrics.time_stage(tenant_id=TENANT, stage=PipelineStage.triage):
            raise RuntimeError("llm timeout")
    points = collect_points(reader, EVENTS_COUNTER_NAME)
    assert points[0].attributes["outcome"] == "error"
    assert points[0].attributes["stage"] == "triage"


def test_unknown_stage_rejected(meter_setup):
    _, metrics = meter_setup
    with pytest.raises(ValueError):
        metrics.record(tenant_id=TENANT, stage="teleport", outcome="ok")
