"""Allowlist status stores (B-1/SEC-10/17, G-1/SEC-39) — FAIL CLOSED.

Pattern (db/redis-conventions.md, BINDING):
- PG is the source of truth; Redis `device:{t}:{id}` / `ingestkey:{t}:{id}` /
  `tenantstatus:{t}` are 60s-TTL caches, deleted on any status change.
- Cache MISS => read PG + backfill. Absent in PG => DENY (401/403).
- BOTH stores unreachable => 503 SERVICE_UNAVAILABLE (+Retry-After) — the
  request is never accepted on store failure.
- These stores — never the entitlements cache — enforce abuse_frozen,
  device status, and ingest-key status (ADR-0005 exclusion list).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from dataplane.core.db import Database
from dataplane.core.seclog import log_security_event
from dataplane.core.tokens import MalformedCredential, parse_credential, secret_matches
from soc_schemas import ApiError, ErrorCode

logger = logging.getLogger(__name__)

_DEVICE_SQL = (
    "SELECT status, cert_serial, prev_cert_serial, prev_cert_rotated_at, asset_id "
    "FROM tenantdata.devices WHERE id = $1"
)
_INGEST_KEY_SQL = "SELECT key_hash, revoked_at FROM tenantdata.ingest_keys WHERE id = $1"
_TOUCH_KEY_SQL = "UPDATE tenantdata.ingest_keys SET last_used_at = now() WHERE id = $1"
_TENANT_SQL = "SELECT status::text AS status, abuse_frozen FROM control.tenants WHERE id = $1"


@dataclass(frozen=True, slots=True)
class DeviceStatus:
    status: str
    cert_serial: str
    prev_cert_serial: str | None
    prev_valid_until: datetime | None


@dataclass(frozen=True, slots=True)
class VerifiedIngestKey:
    tenant_id: UUID
    key_id: str


@dataclass(frozen=True, slots=True)
class TenantStatus:
    status: str
    abuse_frozen: bool


def _unavailable() -> ApiError:
    return ApiError(
        ErrorCode.SERVICE_UNAVAILABLE,
        "Status stores are unavailable; retry with backoff.",
        retry_after_seconds=30,
    )


class StatusStores:
    def __init__(self, redis, db: Database, *, cache_ttl_seconds: int = 60) -> None:
        self._redis = redis
        self._db = db
        self._ttl = cache_ttl_seconds

    # ------------------------------------------------------------ devices
    async def verify_device(
        self, tenant_id: UUID, device_id: str, presented_serial: str | None
    ) -> None:
        """SEC-10 allowlist check; raises on any non-active outcome."""
        record = await self._device_record(tenant_id, device_id)
        if record is None:
            log_security_event(
                "device_identity_invalid", tenant_id=str(tenant_id), device_id=device_id
            )
            raise ApiError(
                ErrorCode.DEVICE_IDENTITY_INVALID, "Device identity could not be established."
            )
        if record.status != "active":
            raise ApiError(ErrorCode.DEVICE_REVOKED, "This device credential has been revoked.")
        if not presented_serial or not self._serial_ok(record, presented_serial.lower()):
            log_security_event(
                "device_serial_mismatch", tenant_id=str(tenant_id), device_id=device_id
            )
            raise ApiError(
                ErrorCode.DEVICE_IDENTITY_INVALID, "Device identity could not be established."
            )

    @staticmethod
    def _serial_ok(record: DeviceStatus, presented: str) -> bool:
        if presented == record.cert_serial:
            return True
        if (
            record.prev_cert_serial
            and record.prev_valid_until is not None
            and presented == record.prev_cert_serial
            and datetime.now(UTC) <= record.prev_valid_until
        ):
            return True  # SEC-11 <=24h renewal overlap
        return False

    async def _device_record(self, tenant_id: UUID, device_id: str) -> DeviceStatus | None:
        key = f"device:{tenant_id}:{device_id}"
        cached, redis_up = await self._cache_get(key)
        if cached:
            prev_until = cached.get("prev_valid_until") or None
            return DeviceStatus(
                status=cached.get("status", ""),
                cert_serial=cached.get("cert_serial", ""),
                prev_cert_serial=cached.get("prev_cert_serial") or None,
                prev_valid_until=datetime.fromisoformat(prev_until) if prev_until else None,
            )
        row = await self._pg_fetchrow_tenant(tenant_id, _DEVICE_SQL, device_id, redis_up=redis_up)
        if row is None:
            return None
        prev_until: datetime | None = None
        if row["prev_cert_serial"] and row["prev_cert_rotated_at"] is not None:
            prev_until = row["prev_cert_rotated_at"] + timedelta(hours=24)
        record = DeviceStatus(
            status=row["status"],
            cert_serial=row["cert_serial"],
            prev_cert_serial=row["prev_cert_serial"],
            prev_valid_until=prev_until,
        )
        await self._cache_set(
            key,
            {
                "status": record.status,
                "cert_serial": record.cert_serial,
                "prev_cert_serial": record.prev_cert_serial or "",
                "prev_valid_until": prev_until.isoformat() if prev_until else "",
            },
        )
        return record

    async def invalidate_device(self, tenant_id: UUID, device_id: str) -> None:
        """Delete-on-change (SEC-10: TTL is worst case, not the mechanism)."""
        try:
            await self._redis.delete(f"device:{tenant_id}:{device_id}")
        except Exception:
            logger.exception("device cache delete failed (TTL bounds staleness at 60s)")

    # --------------------------------------------------------- ingest keys
    async def verify_ingest_key(self, presented: str) -> VerifiedIngestKey:
        """SEC-16/17: constant-time hash compare against the allowlist cache.

        Unknown, foreign-tenant, and malformed keys are indistinguishable
        (INGEST_KEY_INVALID); only a hash-matching revoked key returns
        INGEST_KEY_REVOKED.
        """
        try:
            parsed = parse_credential(presented, expected_prefix="ik_")
        except MalformedCredential:
            raise ApiError(ErrorCode.INGEST_KEY_INVALID, "Ingest key invalid.") from None
        cache_key = f"ingestkey:{parsed.tenant_id}:{parsed.credential_id}"
        cached, redis_up = await self._cache_get(cache_key)
        status: str | None = None
        key_hash: str | None = None
        if cached:
            status = cached.get("status")
            key_hash = cached.get("key_hash")
        else:
            row = await self._pg_fetchrow_tenant(
                parsed.tenant_id,
                _INGEST_KEY_SQL,
                parsed.credential_id,
                redis_up=redis_up,
                touch_sql=_TOUCH_KEY_SQL,
            )
            if row is not None:
                status = "revoked" if row["revoked_at"] is not None else "active"
                key_hash = row["key_hash"]
                await self._cache_set(cache_key, {"status": status, "key_hash": key_hash})
        if key_hash is None or not secret_matches(parsed.secret, key_hash):
            log_security_event("ingest_key_invalid", key_id=parsed.credential_id)
            raise ApiError(ErrorCode.INGEST_KEY_INVALID, "Ingest key invalid.")
        if status != "active":
            raise ApiError(ErrorCode.INGEST_KEY_REVOKED, "Ingest key revoked.")
        return VerifiedIngestKey(tenant_id=parsed.tenant_id, key_id=parsed.credential_id)

    async def invalidate_ingest_key(self, tenant_id: UUID, key_id: str) -> None:
        try:
            await self._redis.delete(f"ingestkey:{tenant_id}:{key_id}")
        except Exception:
            logger.exception("ingest-key cache delete failed (TTL bounds staleness at 60s)")

    # -------------------------------------------------------- tenant status
    async def tenant_status(self, tenant_id: UUID) -> TenantStatus:
        key = f"tenantstatus:{tenant_id}"
        cached, redis_up = await self._cache_get(key)
        if cached:
            return TenantStatus(
                status=cached.get("status", ""),
                abuse_frozen=cached.get("abuse_frozen") == "1",
            )
        row = await self._pg_fetchrow_system(_TENANT_SQL, tenant_id, redis_up=redis_up)
        if row is None:
            # Authenticated credential for a tenant with no row: deny.
            log_security_event("tenant_status_missing", tenant_id=str(tenant_id))
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")
        status = TenantStatus(status=row["status"], abuse_frozen=bool(row["abuse_frozen"]))
        await self._cache_set(
            key,
            {"status": status.status, "abuse_frozen": "1" if status.abuse_frozen else "0"},
        )
        return status

    async def require_ingest_allowed(self, tenant_id: UUID) -> None:
        """Contract §1: abuse => 403 TENANT_FROZEN(cause=abuse); frozen/purged
        trial => 402 TRIAL_EXPIRED; not-yet-provisioned => 503 (retryable)."""
        status = await self.tenant_status(tenant_id)
        if status.abuse_frozen:
            raise ApiError(
                ErrorCode.TENANT_FROZEN, "Tenant is frozen.", details={"cause": "abuse"}
            )
        if status.status in ("frozen", "purged"):
            raise ApiError(ErrorCode.TRIAL_EXPIRED, "Trial expired; ingestion is disabled.")
        if status.status != "active":
            raise _unavailable()

    async def require_writes_allowed(self, tenant_id: UUID) -> None:
        """Console mutating endpoints: 403 TENANT_FROZEN for trial-frozen or
        abuse-frozen tenants (reads stay available)."""
        status = await self.tenant_status(tenant_id)
        if status.abuse_frozen:
            raise ApiError(
                ErrorCode.TENANT_FROZEN, "Tenant is frozen.", details={"cause": "abuse"}
            )
        if status.status == "frozen":
            raise ApiError(
                ErrorCode.TENANT_FROZEN,
                "Trial expired; the console is read-only.",
                details={"cause": "trial"},
            )

    # ------------------------------------------------------------ plumbing
    async def _cache_get(self, key: str) -> tuple[dict[str, str] | None, bool]:
        try:
            value = await self._redis.hgetall(key)
        except Exception:
            logger.warning("redis unavailable for %s; falling back to PG", key)
            return None, False
        if not value:
            return None, True
        return {self._s(k): self._s(v) for k, v in value.items()}, True

    async def _cache_set(self, key: str, mapping: dict[str, str]) -> None:
        try:
            await self._redis.hset(key, mapping=mapping)
            await self._redis.expire(key, self._ttl)
        except Exception:
            logger.warning("redis backfill failed for %s (non-fatal)", key)

    async def _pg_fetchrow_tenant(
        self,
        tenant_id: UUID,
        sql: str,
        *args,
        redis_up: bool,
        touch_sql: str | None = None,
    ):
        try:
            async with self._db.tenant_transaction(tenant_id) as conn:
                row = await conn.fetchrow(sql, *args)
                if row is not None and touch_sql is not None:
                    await conn.execute(touch_sql, *args)
                return row
        except ApiError:
            raise
        except Exception:
            logger.exception("PG allowlist read failed (redis_up=%s)", redis_up)
            raise _unavailable() from None

    async def _pg_fetchrow_system(self, sql: str, *args, redis_up: bool):
        try:
            async with self._db.system_transaction() as conn:
                return await conn.fetchrow(sql, *args)
        except Exception:
            logger.exception("PG tenant-status read failed (redis_up=%s)", redis_up)
            raise _unavailable() from None

    @staticmethod
    def _s(value: bytes | str) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else value
