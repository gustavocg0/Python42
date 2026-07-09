"""Cached, fail-closed entitlements client (ADR-0005, SEC-39, AC-12/13/15).

Cache layers per ADR-0005: the shared Redis cache is written ONLY by the
controlplane entitlements service (SEC-41); this client implements the
in-process layer — fresh TTL <= 5 min, last-known-good (LKG) retained up to
30 minutes past TTL for outage bridging, then hard fail-closed.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from uuid import UUID

import httpx

from soc_entitlements.errors import EntitlementsUnavailable, NeverGracedFieldStale
from soc_entitlements.models import EntitlementValues, TenantEntitlements
from soc_entitlements.tokens import generate_service_token

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_SECONDS = 300  # AC-13: TTL <= 5 min
MAX_CACHE_TTL_SECONDS = 300
DEFAULT_LKG_GRACE_SECONDS = 1800  # ADR-0005: 30 min HARD ceiling past TTL
MAX_LKG_GRACE_SECONDS = 1800

NEVER_GRACED: frozenset[str] = frozenset(
    {
        "abuse_frozen",  # SEC-39 — tenant-status store, cut-off <= 60s
        "device_status",  # SEC-10 — device allowlist store
        "ingest_key_status",  # SEC-17 — key allowlist store
        "session_role_validity",  # SEC-3 — session store
    }
)
"""ADR-0005 §4 binding exclusion list. These are NEVER enforced from this
client — each has its own authoritative store. Enumerated here so enforcement
code can assert against it."""


class EntitlementsSnapshot:
    """A point-in-time entitlements read, fresh or LKG-stale.

    Quantitative values (`entitlements`, `plan`, `tenant_status`,
    `trial_expires_at`) are readable even when stale (bounded by the grace
    ceiling). `abuse_frozen` is informational when fresh and RAISES when
    stale (SEC-39): enforcement must use the tenant-status store either way.
    """

    __slots__ = ("_data", "_stale", "_staleness_seconds")

    def __init__(self, data: TenantEntitlements, *, stale: bool, staleness_seconds: float) -> None:
        self._data = data
        self._stale = stale
        self._staleness_seconds = staleness_seconds

    @property
    def stale(self) -> bool:
        return self._stale

    @property
    def staleness_seconds(self) -> float:
        """Seconds past the fresh-TTL boundary (0.0 when fresh)."""
        return self._staleness_seconds

    @property
    def plan(self) -> str:
        return self._data.plan

    @property
    def tenant_status(self) -> str:
        return self._data.tenant_status

    @property
    def trial_expires_at(self):
        return self._data.trial_expires_at

    @property
    def entitlements(self) -> EntitlementValues:
        return self._data.entitlements

    @property
    def as_of(self):
        return self._data.as_of

    @property
    def abuse_frozen(self) -> bool:
        """Informational only (SEC-39) — never the enforcement source.

        Raises NeverGracedFieldStale when this snapshot is a graced LKG copy.
        """
        if self._stale:
            raise NeverGracedFieldStale(
                "abuse_frozen is never graced (SEC-39): stale snapshot — "
                "check the tenant-status store instead"
            )
        return self._data.abuse_frozen


class _CacheEntry:
    __slots__ = ("data", "fetched_at")

    def __init__(self, data: TenantEntitlements, fetched_at: float) -> None:
        self.data = data
        self.fetched_at = fetched_at


class EntitlementsClient:
    """Client for GET /internal/v1/tenants/{id}/entitlements (ADR-0005).

    Fail-closed: cold cache + unreachable service raises
    EntitlementsUnavailable (503 ENTITLEMENTS_UNAVAILABLE + Retry-After).
    """

    def __init__(
        self,
        *,
        base_url: str,
        service_name: str,
        signing_key: str | bytes,
        http_client: httpx.AsyncClient | None = None,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        lkg_grace_seconds: int = DEFAULT_LKG_GRACE_SECONDS,
        request_timeout_seconds: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        on_stale_served: Callable[[UUID, float], None] | None = None,
    ) -> None:
        if cache_ttl_seconds > MAX_CACHE_TTL_SECONDS:
            raise ValueError(f"cache TTL must be <= {MAX_CACHE_TTL_SECONDS}s (AC-13)")
        if lkg_grace_seconds > MAX_LKG_GRACE_SECONDS:
            raise ValueError(f"LKG grace must be <= {MAX_LKG_GRACE_SECONDS}s (ADR-0005 ceiling)")
        self._base_url = base_url.rstrip("/")
        self._service_name = service_name
        self._signing_key = signing_key
        self._http = http_client or httpx.AsyncClient(timeout=request_timeout_seconds)
        self._owns_http = http_client is None
        self._ttl = cache_ttl_seconds
        self._grace = lkg_grace_seconds
        self._clock = clock
        self._on_stale_served = on_stale_served
        self._cache: dict[UUID, _CacheEntry] = {}

    async def get(self, tenant_id: UUID | str) -> EntitlementsSnapshot:
        """Entitlements for a tenant: fresh cache -> refetch -> LKG -> deny."""
        tenant = UUID(str(tenant_id))
        now = self._clock()
        entry = self._cache.get(tenant)

        if entry is not None and now - entry.fetched_at <= self._ttl:
            return EntitlementsSnapshot(entry.data, stale=False, staleness_seconds=0.0)

        try:
            data = await self._fetch(tenant)
        except (httpx.HTTPError, _UpstreamServerError):
            if entry is not None:
                staleness = (now - entry.fetched_at) - self._ttl
                if staleness <= self._grace:
                    logger.warning(
                        "serving last-known-good entitlements",
                        extra={
                            "tenant_id": str(tenant),
                            "staleness_seconds": round(staleness, 3),
                        },
                    )
                    if self._on_stale_served is not None:
                        self._on_stale_served(tenant, staleness)
                    return EntitlementsSnapshot(
                        entry.data, stale=True, staleness_seconds=staleness
                    )
            raise EntitlementsUnavailable(
                "entitlements service unreachable and no last-known-good value "
                "within the grace ceiling — denying (ADR-0005 fail-closed)"
            ) from None

        self._cache[tenant] = _CacheEntry(data, self._clock())
        return EntitlementsSnapshot(data, stale=False, staleness_seconds=0.0)

    def invalidate(self, tenant_id: UUID | str) -> None:
        self._cache.pop(UUID(str(tenant_id)), None)

    def clear(self) -> None:
        self._cache.clear()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _fetch(self, tenant: UUID) -> TenantEntitlements:
        token = generate_service_token(
            service_name=self._service_name, key=self._signing_key
        )
        response = await self._http.get(
            f"{self._base_url}/internal/v1/tenants/{tenant}/entitlements",
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code >= 500:
            # Outage-shaped: eligible for the LKG path in get().
            raise _UpstreamServerError(response.status_code)
        if response.status_code != 200:
            # Config/auth/unknown-tenant problems are NOT graced: deny now.
            raise EntitlementsUnavailable(
                f"entitlements service returned {response.status_code} "
                f"for tenant {tenant} — denying (fail-closed)"
            )
        return TenantEntitlements.model_validate(response.json())


class _UpstreamServerError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"upstream 5xx: {status_code}")
        self.status_code = status_code
