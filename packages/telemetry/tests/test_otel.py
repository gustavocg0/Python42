"""init_telemetry must work with no collector running (dependency-light)."""

import pytest

from soc_telemetry import init_telemetry


def test_init_none_exporter_offline():
    handles = init_telemetry("dataplane-api", exporter="none", set_global=False)
    tracer = handles.tracer_provider.get_tracer("test")
    with tracer.start_as_current_span("span") as span:
        assert span.get_span_context().is_valid
    handles.shutdown()


def test_resource_carries_service_name():
    handles = init_telemetry(
        "controlplane-api",
        exporter="none",
        resource_attributes={"deployment.environment": "test"},
        set_global=False,
    )
    attrs = handles.tracer_provider.resource.attributes
    assert attrs["service.name"] == "controlplane-api"
    assert attrs["deployment.environment"] == "test"
    handles.shutdown()


def test_env_var_selection(monkeypatch):
    monkeypatch.setenv("SOC_OTEL_EXPORTER", "none")
    handles = init_telemetry("worker-normalizer", set_global=False)
    handles.shutdown()


def test_invalid_exporter_rejected():
    with pytest.raises(ValueError):
        init_telemetry("x", exporter="jaeger", set_global=False)
