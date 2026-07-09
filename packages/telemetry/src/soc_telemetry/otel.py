"""OpenTelemetry initialization for services and workers.

Exporter switch (env var SOC_OTEL_EXPORTER or explicit argument):
- "none" (default): providers configured with the service resource but no
  exporters — zero network dependencies, safe with no collector running;
- "console": span/metric export to stdout (local dev);
- "otlp": OTLP over HTTP (lazily imported; install `soc-telemetry[otlp]`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from opentelemetry import metrics as otel_metrics
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricReader,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

ENV_EXPORTER = "SOC_OTEL_EXPORTER"
ENV_OTLP_ENDPOINT = "OTEL_EXPORTER_OTLP_ENDPOINT"
_VALID_EXPORTERS = ("none", "console", "otlp")


@dataclass(frozen=True, slots=True)
class TelemetryHandles:
    tracer_provider: TracerProvider
    meter_provider: MeterProvider

    def shutdown(self) -> None:
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()


def init_telemetry(
    service_name: str,
    *,
    exporter: str | None = None,
    resource_attributes: dict[str, str] | None = None,
    set_global: bool = True,
) -> TelemetryHandles:
    """Configure tracer + meter providers for a service/worker process.

    Call once at process startup, e.g. init_telemetry("dataplane-api").
    Returns handles for shutdown; with set_global=True (default) they are
    also installed as the process-global providers.
    """
    exporter_name = (exporter or os.environ.get(ENV_EXPORTER, "none")).lower()
    if exporter_name not in _VALID_EXPORTERS:
        raise ValueError(f"{ENV_EXPORTER} must be one of {_VALID_EXPORTERS}")

    attributes: dict[str, str] = {"service.name": service_name}
    if resource_attributes:
        attributes.update(resource_attributes)
    resource = Resource.create(attributes)

    tracer_provider = TracerProvider(resource=resource)
    metric_readers: list[MetricReader] = []

    if exporter_name == "console":
        tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        metric_readers.append(PeriodicExportingMetricReader(ConsoleMetricExporter()))
    elif exporter_name == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise RuntimeError(
                "SOC_OTEL_EXPORTER=otlp requires the 'soc-telemetry[otlp]' extra"
            ) from exc
        endpoint = os.environ.get(ENV_OTLP_ENDPOINT)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint) if endpoint else OTLPSpanExporter())
        )
        metric_readers.append(
            PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=endpoint) if endpoint else OTLPMetricExporter()
            )
        )

    meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)

    if set_global:
        otel_trace.set_tracer_provider(tracer_provider)
        otel_metrics.set_meter_provider(meter_provider)

    return TelemetryHandles(tracer_provider=tracer_provider, meter_provider=meter_provider)
