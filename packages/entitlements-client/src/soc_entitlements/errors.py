"""Entitlements client errors (ADR-0005)."""

from __future__ import annotations


class EntitlementsError(Exception):
    """Base class."""


class EntitlementsUnavailable(EntitlementsError):
    """Cold cache (or LKG past the 30-min hard ceiling) + service unreachable.

    Maps to HTTP 503 ENTITLEMENTS_UNAVAILABLE with Retry-After on
    ingest paths; capability-granting checks deny (ADR-0005 §3).
    """

    def __init__(self, message: str, *, retry_after_seconds: int = 30) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class NeverGracedFieldStale(EntitlementsError):
    """A never-graced field was read from a stale snapshot (SEC-39).

    abuse_frozen / device status / key status must be enforced from their own
    authoritative stores — never from a graced entitlements copy.
    """
