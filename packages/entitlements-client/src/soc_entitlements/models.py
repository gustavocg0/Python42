"""Entitlements payload models (api-contracts.md §5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EntitlementValues(BaseModel):
    """Quantitative plan values — the ONLY part eligible for LKG grace (ADR-0005 §4).

    extra='allow': plan config is changeable without code deploy (AC-12);
    additive values must not break the client.
    """

    model_config = ConfigDict(extra="allow")

    endpoint_cap: int
    retention_days: int
    deep_investigation_daily_quota: int  # -1 means unlimited
    response_mode: str
    ingest_events_per_min: int


class TenantEntitlements(BaseModel):
    """GET /internal/v1/tenants/{id}/entitlements response shape."""

    model_config = ConfigDict(extra="allow")

    plan: str
    tenant_status: str
    abuse_frozen: bool
    trial_expires_at: datetime | None = None
    entitlements: EntitlementValues
    as_of: datetime
