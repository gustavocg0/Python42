"""Environment-driven settings for the dataplane API processes.

Defaults mirror the plan/platform-config seeds in db/migrations/0009 — the
DB values remain the tunable source of truth for job-side behavior; the API
reads the hot-path limits from here (contract-fixed values per AC-30).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_5MB = 5 * 1024 * 1024


class SettingsError(RuntimeError):
    """Missing/invalid required environment configuration."""


def _require(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise SettingsError(f"required environment variable {key} is not set")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """All knobs for dataplane-api (public + internal listeners)."""

    database_url: str
    redis_url: str
    es_url: str
    gateway_auth_secret: str
    ca_cert_path: str
    ca_key_path: str
    entitlements_base_url: str
    entitlements_signing_key: str
    internal_service_keys: dict[str, str] = field(default_factory=dict)
    console_origin: str = "http://localhost:3000"
    public_ingest_base_url: str = "https://ingest.localhost"
    service_name: str = "dataplane"
    # Contract-fixed ingest limits (AC-30):
    ingest_max_events: int = 1000
    ingest_max_bytes: int = _5MB
    # Plan-config defaults (0009 seeds; jobs read the DB, API uses these):
    heartbeat_interval_seconds: int = 60
    billable_window_days: int = 30
    cert_lifetime_days: int = 90
    renewal_overlap_hours: int = 24
    enrollment_token_default_expiry_hours: int = 72
    enroll_rate_limit_per_token_per_min: int = 30
    enroll_rate_limit_per_ip_per_min: int = 10
    # Allowlist cache TTL (SEC-10/17 — 60s worst-case propagation):
    status_cache_ttl_seconds: int = 60
    retry_after_unavailable_seconds: int = 30

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ) if env is None else env
        keys_raw = env.get("DP_INTERNAL_SERVICE_KEYS", "{}")
        try:
            internal_keys = json.loads(keys_raw)
        except json.JSONDecodeError as exc:
            raise SettingsError("DP_INTERNAL_SERVICE_KEYS must be a JSON object") from exc
        if not isinstance(internal_keys, dict):
            raise SettingsError("DP_INTERNAL_SERVICE_KEYS must be a JSON object")
        return cls(
            database_url=_require(env, "DP_DATABASE_URL"),
            redis_url=_require(env, "DP_REDIS_URL"),
            es_url=_require(env, "DP_ES_URL"),
            gateway_auth_secret=_require(env, "DP_GATEWAY_AUTH_SECRET"),
            ca_cert_path=_require(env, "DP_CA_CERT"),
            ca_key_path=_require(env, "DP_CA_KEY"),
            entitlements_base_url=_require(env, "DP_ENTITLEMENTS_BASE_URL"),
            entitlements_signing_key=_require(env, "DP_ENTITLEMENTS_SIGNING_KEY"),
            internal_service_keys={str(k): str(v) for k, v in internal_keys.items()},
            console_origin=env.get("DP_CONSOLE_ORIGIN", "http://localhost:3000"),
            public_ingest_base_url=env.get("DP_PUBLIC_INGEST_BASE_URL", "https://ingest.localhost"),
        )
