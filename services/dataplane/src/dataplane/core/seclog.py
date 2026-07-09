"""Security-event structured logging (AC-58/AC-81 server-side logs).

These are operational security logs (JSON via soc_telemetry logging), NOT the
tenant-facing audit trail (soc_audit). Cross-tenant probes surface here.
"""

from __future__ import annotations

import logging
from typing import Any

_security_logger = logging.getLogger("dataplane.security")


def log_security_event(event: str, **fields: Any) -> None:
    """One structured security log line; never raises."""
    try:
        _security_logger.warning(event, extra={"security_event": event, **fields})
    except Exception:  # pragma: no cover - logging must never break a request
        logging.getLogger(__name__).exception("security log emit failed")
