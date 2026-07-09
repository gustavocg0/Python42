"""Secret redaction + size caps for audit before/after values (SEC-44)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

MAX_AUDIT_VALUE_BYTES = 16 * 1024
"""Hard cap for a serialized before/after value — makes raw-payload dumping
impossible by design (SEC-44)."""

_MAX_DEPTH = 20

_SECRET_KEY_RE = re.compile(
    r"(?i)("
    r"token|secret|password|passwd|credential|cert_key|private_key|api_key"
    r"|(^|[_\-.])key(s)?([_\-.]|$)"
    r")"
)


class AuditValueTooLarge(ValueError):
    """A before/after value exceeded the audit size cap — record IDs/fingerprints instead."""


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


def redact_secrets(value: Any, _depth: int = 0) -> Any:
    """Recursively replace values of secret-named keys with REDACTED."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if _is_secret_key(str(k)) else redact_secrets(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item, _depth + 1) for item in value]
    return value


def serialize_audit_value(value: Mapping[str, Any] | None) -> str | None:
    """Redact and serialize a before/after dict for storage.

    Raises AuditValueTooLarge over MAX_AUDIT_VALUE_BYTES (SEC-44: no raw
    payloads; secrets recorded as IDs/fingerprint-prefixes only).
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError("audit before/after values must be mappings (structured, not raw blobs)")
    serialized = json.dumps(redact_secrets(value), default=str, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_AUDIT_VALUE_BYTES:
        raise AuditValueTooLarge(
            f"audit value exceeds {MAX_AUDIT_VALUE_BYTES} bytes — "
            "record identifiers/fingerprints, never payloads (SEC-44)"
        )
    return serialized
