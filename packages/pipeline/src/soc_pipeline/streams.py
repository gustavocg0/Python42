"""Stream names and operating constants (design doc §4, ADR-0004)."""

STREAM_RAW = "pipe:raw"
STREAM_NORMALIZED = "pipe:normalized"
STREAM_DETECTIONS = "pipe:detections"
STREAM_ALERTS_TRIAGE = "pipe:alerts.triage"
STREAM_ASSET_OBSERVATIONS = "pipe:asset.observations"

ALL_STREAMS: tuple[str, ...] = (
    STREAM_RAW,
    STREAM_NORMALIZED,
    STREAM_DETECTIONS,
    STREAM_ALERTS_TRIAGE,
    STREAM_ASSET_OBSERVATIONS,
)

DEFAULT_MAXLEN = 1_000_000
"""MAXLEN ~ 1,000,000 (approximate trim) per ADR-0004."""

DEFAULT_MAX_DELIVERY_ATTEMPTS = 5
"""After 5 delivery attempts a message goes to the DLQ — never dropped (ADR-0004/AC-91)."""

DEFAULT_MIN_IDLE_MS = 60_000
"""XAUTOCLAIM min-idle for stuck-message reclaim (ADR-0004)."""
