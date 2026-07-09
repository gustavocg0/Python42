"""soc_telemetry — OTel init, structured JSON logging, pipeline metrics (AC-91).

Dependency-light by design: imports and runs fine with no collector.
Exporter selection via env var SOC_OTEL_EXPORTER: none (default) | console | otlp
(otlp requires the `soc-telemetry[otlp]` extra).
"""

from soc_telemetry.logging_json import JsonLogFormatter, configure_json_logging
from soc_telemetry.metrics import PipelineMetrics, PipelineOutcome, PipelineStage
from soc_telemetry.otel import ENV_EXPORTER, TelemetryHandles, init_telemetry

__all__ = [
    "ENV_EXPORTER",
    "JsonLogFormatter",
    "PipelineMetrics",
    "PipelineOutcome",
    "PipelineStage",
    "TelemetryHandles",
    "configure_json_logging",
    "init_telemetry",
]
