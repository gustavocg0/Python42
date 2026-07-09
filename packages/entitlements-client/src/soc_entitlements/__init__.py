"""soc_entitlements — ADR-0005 client + design §5.1 HMAC service tokens.

Fail-closed rules (binding):
- cold cache + service unreachable => EntitlementsUnavailable (maps to 503
  ENTITLEMENTS_UNAVAILABLE); never fail-open, no permissive defaults;
- last-known-good grace applies ONLY to quantitative plan values, up to 30
  minutes past TTL (hard ceiling), with a staleness metric/log;
- NEVER graced (checked against their own authoritative stores, never this
  client): device status (SEC-10), ingest-key status (SEC-17), tenant
  abuse_frozen flag (SEC-39), session/role validity (SEC-3).
"""

from soc_entitlements.client import (
    NEVER_GRACED,
    EntitlementsClient,
    EntitlementsSnapshot,
)
from soc_entitlements.errors import (
    EntitlementsError,
    EntitlementsUnavailable,
    NeverGracedFieldStale,
)
from soc_entitlements.models import EntitlementValues, TenantEntitlements
from soc_entitlements.tokens import (
    CLOCK_SKEW_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
    ExpiredServiceToken,
    InvalidServiceToken,
    ServiceTokenError,
    generate_service_token,
    verify_service_token,
)

__all__ = [
    "CLOCK_SKEW_SECONDS",
    "MAX_TOKEN_LIFETIME_SECONDS",
    "NEVER_GRACED",
    "EntitlementValues",
    "EntitlementsClient",
    "EntitlementsError",
    "EntitlementsSnapshot",
    "EntitlementsUnavailable",
    "ExpiredServiceToken",
    "InvalidServiceToken",
    "NeverGracedFieldStale",
    "ServiceTokenError",
    "TenantEntitlements",
    "generate_service_token",
    "verify_service_token",
]
