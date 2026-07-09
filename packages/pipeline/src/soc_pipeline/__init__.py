"""soc_pipeline — Redis Streams transport abstraction (ADR-0004).

Binding rules implemented here:
- Every message carries `tenant_id` + `trace_id`, set only by the
  authenticated producer (SEC-20) — enforced at the publish API.
- Consumers cannot process a message without establishing tenant context:
  StreamConsumer requires a tenant-context factory and enters it around the
  handler (SEC-20).
- At-least-once delivery; ACK only after side effects complete; stuck
  messages reclaimed via XAUTOCLAIM (min idle 60s); after 5 delivery
  attempts a message is handed to the dead-letter callback — never dropped
  (AC-91).
- Streams capped with MAXLEN ~ 1,000,000 (approximate).

No module may call redis stream APIs directly (ADR-0004).
"""

from soc_pipeline.consumer import DeadLetteredMessage, StreamConsumer
from soc_pipeline.messages import (
    MalformedPipelineMessage,
    PipelineMessage,
    ReceivedMessage,
)
from soc_pipeline.producer import StreamProducer
from soc_pipeline.streams import (
    ALL_STREAMS,
    DEFAULT_MAXLEN,
    STREAM_ALERTS_TRIAGE,
    STREAM_ASSET_OBSERVATIONS,
    STREAM_DETECTIONS,
    STREAM_NORMALIZED,
    STREAM_RAW,
)

__all__ = [
    "ALL_STREAMS",
    "DEFAULT_MAXLEN",
    "STREAM_ALERTS_TRIAGE",
    "STREAM_ASSET_OBSERVATIONS",
    "STREAM_DETECTIONS",
    "STREAM_NORMALIZED",
    "STREAM_RAW",
    "DeadLetteredMessage",
    "MalformedPipelineMessage",
    "PipelineMessage",
    "ReceivedMessage",
    "StreamConsumer",
    "StreamProducer",
]
