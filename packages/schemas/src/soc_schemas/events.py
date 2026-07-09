"""Event envelope and class models — transcribed from docs/contracts/event-schema.md v1.0.0.

Versioning (contract §1): additive optional fields => minor bump; renamed/removed/
retyped fields => major bump (new ES index template + dual-read window).
"""

from __future__ import annotations

import enum
import json
import re
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    UUID4,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "1.0.0"
"""Current internal event schema version (contract §1, semver)."""

# Size caps from the contract (bytes of JSON-serialized value / chars for strings).
MAX_CMD_LINE_CHARS = 32 * 1024
MAX_MESSAGE_CHARS = 32 * 1024
MAX_UNMAPPED_BYTES = 16 * 1024
MAX_FIELDS_BYTES = 16 * 1024
MAX_RAW_BYTES = 32 * 1024
MAX_SOURCE_EVENT_ID_CHARS = 128
MAX_HOSTNAME_CHARS = 253

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _json_size(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"))


class EventClass(enum.StrEnum):
    process_activity = "process_activity"
    network_activity = "network_activity"
    authentication = "authentication"
    generic = "generic"


class SourceType(enum.StrEnum):
    agent = "agent"
    generic = "generic"


class OsFamily(enum.StrEnum):
    windows = "windows"
    linux = "linux"
    macos = "macos"
    other = "other"


class SeverityHint(enum.StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ProcessActivity(enum.StrEnum):
    process_launched = "process_launched"
    process_terminated = "process_terminated"


class NetworkActivity(enum.StrEnum):
    connection_opened = "connection_opened"
    connection_closed = "connection_closed"


class Direction(enum.StrEnum):
    inbound = "inbound"
    outbound = "outbound"
    unknown = "unknown"


class Protocol(enum.StrEnum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"
    other = "other"


class AuthActivity(enum.StrEnum):
    logon = "logon"
    logoff = "logoff"
    logon_failed = "logon_failed"


class AuthStatus(enum.StrEnum):
    success = "success"
    failure = "failure"


class LogonType(enum.StrEnum):
    interactive = "interactive"
    network = "network"
    remote_interactive = "remote_interactive"
    service = "service"
    batch = "batch"
    unlock = "unlock"
    other = "other"


class FailureReason(enum.StrEnum):
    bad_password = "bad_password"  # noqa: S105 - enum label, not a credential
    unknown_user = "unknown_user"
    account_locked = "account_locked"
    account_disabled = "account_disabled"
    expired = "expired"
    other = "other"


class User(BaseModel):
    """Contract §2.2: `uid` = Windows SID / POSIX uid."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    domain: str | None = None
    uid: str | None = None


class Host(BaseModel):
    """Contract §2.1 — drives asset dedup (AC-20/22)."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=MAX_HOSTNAME_CHARS)
    os_family: OsFamily
    os_name: str
    os_version: str
    ip: str | None = None
    mac: str | None = None

    @field_validator("hostname")
    @classmethod
    def _lowercase_hostname(cls, v: str) -> str:
        return v.lower()

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.lower()
        if not _MAC_RE.match(v):
            raise ValueError("mac must match aa:bb:cc:dd:ee:ff (lowercased)")
        return v


class SourceInfo(BaseModel):
    """Contract §2 `source` object — device_id XOR ingest_key_id present."""

    model_config = ConfigDict(extra="forbid")

    device_id: str | None = None
    agent_version: str | None = None
    ingest_key_id: str | None = None
    vendor: str | None = None
    product: str | None = None

    @model_validator(mode="after")
    def _device_xor_ingest_key(self) -> SourceInfo:
        if (self.device_id is None) == (self.ingest_key_id is None):
            raise ValueError("exactly one of source.device_id / source.ingest_key_id is required")
        return self


class EventEnvelope(BaseModel):
    """Contract §2 — envelope fields common to all event classes.

    `tenant_id`, `event_id`, `ingest_time`, `batch_id`, `source.*` are
    server-authoritative (contract §5, SEC-18): they are set only by the
    ingest/normalizer path from the authenticated context, never trusted
    from the client payload.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: UUID4  # contract §2: UUIDv4, platform-assigned
    tenant_id: UUID  # contract §2: UUID string (any version), from ingest auth
    schema_version: str = SCHEMA_VERSION
    event_class: EventClass
    activity: str
    event_time: AwareDatetime
    time_inferred: bool = False
    ingest_time: AwareDatetime
    source_type: SourceType
    source_event_id: str | None = Field(default=None, max_length=MAX_SOURCE_EVENT_ID_CHARS)
    batch_id: UUID  # contract §2: UUID string
    source: SourceInfo
    host: Host | None = None
    severity_hint: SeverityHint | None = None
    unmapped: dict[str, Any] | None = None

    @field_validator("schema_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError("schema_version must be semver, e.g. '1.0.0'")
        return v

    @field_validator("unmapped")
    @classmethod
    def _cap_unmapped(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and _json_size(v) > MAX_UNMAPPED_BYTES:
            raise ValueError(f"unmapped exceeds {MAX_UNMAPPED_BYTES} bytes")
        return v

    @model_validator(mode="after")
    def _agent_requirements(self) -> EventEnvelope:
        if self.source_type == SourceType.agent:
            if self.source_event_id is None:
                raise ValueError("source_event_id is required for agent events")
            if self.host is None:
                raise ValueError("host is required for agent events")
            if self.source.device_id is None:
                raise ValueError("source.device_id is required for agent events")
        elif self.source.ingest_key_id is None:
            raise ValueError("source.ingest_key_id is required for generic events")
        return self


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int
    name: str = Field(min_length=1)
    exe_path: str = Field(min_length=1)
    cmd_line: str | None = Field(default=None, max_length=MAX_CMD_LINE_CHARS)
    sha256: str | None = None
    created_time: AwareDatetime | None = None

    @field_validator("sha256")
    @classmethod
    def _hex(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.lower()
        if not _SHA256_RE.match(v):
            raise ValueError("sha256 must be a 64-char hex string")
        return v


class ParentProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int | None = None
    name: str | None = None
    exe_path: str | None = None


class ProcessActivityEvent(EventEnvelope):
    """Contract §3.1."""

    event_class: Literal[EventClass.process_activity] = EventClass.process_activity
    activity: ProcessActivity
    process: ProcessInfo
    parent: ParentProcessInfo | None = None
    user: User
    exit_code: int | None = None

    @model_validator(mode="after")
    def _class_rules(self) -> ProcessActivityEvent:
        if self.activity == ProcessActivity.process_launched:
            if self.process.cmd_line is None:
                raise ValueError("process.cmd_line is required for process_launched")
            if self.parent is None or self.parent.pid is None or self.parent.name is None:
                raise ValueError("parent.pid and parent.name are required for process_launched")
        if self.activity != ProcessActivity.process_terminated and self.exit_code is not None:
            raise ValueError("exit_code is only valid for process_terminated")
        return self


class NetworkEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=0, le=65535)


class NetworkDestination(NetworkEndpoint):
    hostname: str | None = None


class NetworkProcessRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int | None = None
    name: str | None = None
    exe_path: str | None = None


class NetworkActivityEvent(EventEnvelope):
    """Contract §3.2."""

    event_class: Literal[EventClass.network_activity] = EventClass.network_activity
    activity: NetworkActivity
    direction: Direction
    protocol: Protocol
    src: NetworkEndpoint
    dst: NetworkDestination
    process: NetworkProcessRef | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    user: User | None = None

    @model_validator(mode="after")
    def _class_rules(self) -> NetworkActivityEvent:
        if self.protocol in (Protocol.tcp, Protocol.udp):
            if self.src.port is None or self.dst.port is None:
                raise ValueError("src.port and dst.port are required for tcp/udp")
        if self.activity != NetworkActivity.connection_closed and (
            self.bytes_sent is not None or self.bytes_received is not None
        ):
            raise ValueError("bytes_sent/bytes_received are only valid for connection_closed")
        return self


class AuthenticationEvent(EventEnvelope):
    """Contract §3.3."""

    event_class: Literal[EventClass.authentication] = EventClass.authentication
    activity: AuthActivity
    status: AuthStatus
    logon_type: LogonType
    user: User
    src_ip: str | None = None
    session_id: str | None = None
    failure_reason: FailureReason | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_status(cls, data: Any) -> Any:
        # Contract §3.3: status derived — logon_failed => failure.
        if isinstance(data, dict) and data.get("activity") == "logon_failed":
            data.setdefault("status", "failure")
        return data

    @model_validator(mode="after")
    def _class_rules(self) -> AuthenticationEvent:
        if self.activity == AuthActivity.logon_failed:
            if self.status != AuthStatus.failure:
                raise ValueError("logon_failed implies status=failure")
            if self.failure_reason is None:
                raise ValueError("failure_reason is required for logon_failed")
        return self


class GenericEvent(EventEnvelope):
    """Contract §3.4 — fallback for generic-ingest events."""

    event_class: Literal[EventClass.generic] = EventClass.generic
    activity: Literal["log"] = "log"
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)
    category: str | None = None
    fields: dict[str, str | int | float | bool] | None = None
    raw: dict[str, Any]
    raw_truncated: bool = False

    @field_validator("fields")
    @classmethod
    def _cap_fields(
        cls, v: dict[str, str | int | float | bool] | None
    ) -> dict[str, str | int | float | bool] | None:
        if v is not None and _json_size(v) > MAX_FIELDS_BYTES:
            raise ValueError(f"fields exceeds {MAX_FIELDS_BYTES} bytes")
        return v

    @field_validator("raw")
    @classmethod
    def _cap_raw(cls, v: dict[str, Any]) -> dict[str, Any]:
        if _json_size(v) > MAX_RAW_BYTES:
            raise ValueError(
                f"raw exceeds {MAX_RAW_BYTES} bytes; truncate first "
                "(soc_schemas.truncate_generic_raw) and set raw_truncated=true"
            )
        return v


Event = Annotated[
    ProcessActivityEvent | NetworkActivityEvent | AuthenticationEvent | GenericEvent,
    Field(discriminator="event_class"),
]
"""Discriminated union over `event_class` — use soc_schemas.parse_event()."""
