"""Prefixed opaque public IDs (contract §1: clients treat all IDs as opaque).

DB primary keys are UUIDs; the wire form is `<prefix>_<uuid>`:
accounts `acc_...`, tenants `tn_...`, users `usr_...`.
"""

from __future__ import annotations

from uuid import UUID

from soc_schemas.errors import ApiError, ErrorCode

ACCOUNT_PREFIX = "acc"
TENANT_PREFIX = "tn"
USER_PREFIX = "usr"


def public_id(prefix: str, value: UUID | str) -> str:
    return f"{prefix}_{UUID(str(value))}"


def parse_public_id(prefix: str, value: str, *, code: ErrorCode = ErrorCode.NOT_FOUND) -> UUID:
    """Decode a prefixed public id; unknown shape => 404 by default.

    Foreign/unknown resources must be indistinguishable from malformed ids
    (AC-81), hence NOT_FOUND rather than a validation error for path ids.
    """
    marker = f"{prefix}_"
    if not value.startswith(marker):
        raise ApiError(code, "Resource not found.")
    try:
        return UUID(value[len(marker) :])
    except ValueError:
        raise ApiError(code, "Resource not found.") from None


def rfc3339(dt) -> str:
    """RFC3339 UTC with trailing Z (contract §1 timestamp convention)."""
    return dt.isoformat().replace("+00:00", "Z")
