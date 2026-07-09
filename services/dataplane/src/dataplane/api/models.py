"""Request models (pydantic) for dataplane-api endpoints (contract §6-§13).

Response shapes are built as dicts in the routers (they mirror the contract
examples verbatim); requests are strictly validated here — unknown fields are
rejected (extra='forbid') so contract drift surfaces as 400s, not silence.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from soc_schemas import Host


class IngestKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)


class EnrollmentTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    expires_in_hours: int | None = Field(default=None, ge=1, le=24 * 30)


class ProviderStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["etw", "simulated"]
    status: Literal["ok", "degraded", "failed"]


class DroppedEvents(BaseModel):
    model_config = ConfigDict(extra="forbid")

    network_activity: int = Field(ge=0, default=0)
    process_activity: int = Field(ge=0, default=0)
    authentication: int = Field(ge=0, default=0)


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=1, max_length=512)
    csr_pem: str = Field(min_length=1, max_length=16384)
    host: Host
    agent_version: str = Field(min_length=1, max_length=64)


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=128)
    providers: list[ProviderStatus] = Field(max_length=16)
    buffer_utilization_pct: float = Field(ge=0, le=100)
    cpu_pct: float = Field(ge=0)
    rss_mb: float = Field(ge=0)
    dropped_events_since_last: DroppedEvents


class RenewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csr_pem: str = Field(min_length=1, max_length=16384)


class AssetMergeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_ids: list[str] = Field(min_length=2, max_length=50)
    reason: str = Field(min_length=1, max_length=1000)


class AssetSplitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_ids: list[str] = Field(min_length=1, max_length=50)
    reason: str = Field(min_length=1, max_length=1000)


CloseReason = Literal["resolved", "false_positive", "expected_behavior", "duplicate"]


class AlertCloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: CloseReason
    comment: str | None = Field(default=None, max_length=4000)


class AlertBulkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["acknowledge", "close"]
    reason: CloseReason | None = None
    alert_ids: list[str] = Field(min_length=1, max_length=50)


class RuleToggleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
