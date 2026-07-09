"""Tenant-scoped Elasticsearch naming (SEC-24, threat model §4.2, AC-80).

Index names are built EXCLUSIVELY from validated server-side tenant UUIDs —
no interpolation of client-derived strings, hence no index-pattern injection.
Raises InvalidTenantError before any network call when tenant_id is
missing/invalid (fail closed). No query may target `events-v1-*` unscoped.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from soc_tenancy.errors import InvalidTenantError

EVENTS_ALIAS_PREFIX = "events-"
EVENTS_INDEX_PREFIX = "events-v1-"


def validate_tenant_uuid(tenant_id: UUID | str | None) -> UUID:
    """Canonical tenant UUID or InvalidTenantError — the SEC-24 gate."""
    if tenant_id is None:
        raise InvalidTenantError("tenant_id is required and was not provided")
    if isinstance(tenant_id, UUID):
        return tenant_id
    try:
        return UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidTenantError(f"tenant_id is not a valid UUID: {tenant_id!r}") from exc


def events_alias(tenant_id: UUID | str) -> str:
    """Per-tenant read alias: `events-{tenant_id}` (design §3)."""
    return f"{EVENTS_ALIAS_PREFIX}{validate_tenant_uuid(tenant_id)}"


def events_index(tenant_id: UUID | str, when: datetime) -> str:
    """Per-tenant monthly write index: `events-v1-{tenant_id}-{yyyy.MM}` (design §3).

    `when` must be timezone-aware; it is normalized to UTC before formatting
    so month boundaries are consistent platform-wide.
    """
    tenant = validate_tenant_uuid(tenant_id)
    if when.tzinfo is None:
        raise InvalidTenantError("events_index requires a timezone-aware datetime")
    when_utc = when.astimezone(UTC)
    return f"{EVENTS_INDEX_PREFIX}{tenant}-{when_utc:%Y.%m}"
