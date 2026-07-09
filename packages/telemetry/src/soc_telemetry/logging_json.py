"""Structured JSON logging with trace correlation and secret redaction (SEC-49)."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from opentelemetry import trace as otel_trace

_STANDARD_RECORD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}

_SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|credential|private_key|api_key"
    r"|(^|[_\-.])key(s)?([_\-.]|$))"
)
_REDACTED = "[REDACTED]"


def _redact(key: str, value: Any) -> Any:
    return _REDACTED if _SECRET_KEY_RE.search(key) else value


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, message, service,
    trace/span ids when a span is active, plus record extras (secret-named
    extras redacted per SEC-49)."""

    def __init__(self, service_name: str) -> None:
        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self._service_name,
        }

        span = otel_trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            entry["trace_id"] = otel_trace.format_trace_id(ctx.trace_id)
            entry["span_id"] = otel_trace.format_span_id(ctx.span_id)

        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_"):
                entry[key] = _redact(key, value)

        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str, separators=(",", ":"))


def configure_json_logging(
    service_name: str,
    *,
    level: int | str = logging.INFO,
    stream: TextIO | None = None,
) -> logging.Handler:
    """Install a JSON handler on the root logger (idempotent per stream)."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonLogFormatter(service_name))
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [
        h for h in root.handlers if not isinstance(h.formatter, JsonLogFormatter)
    ]
    root.addHandler(handler)
    return handler
