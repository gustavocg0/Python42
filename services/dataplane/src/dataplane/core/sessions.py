"""Console session validation (dataplane side — READ ONLY).

Controlplane identityadmin OWNS session issuance/rotation/invalidation and
the Redis `sess:{sid}` hash (db/redis-conventions.md): fields
`{user_id, tenant_id, role, csrf_token, created_at, absolute_expires_at}`.
This module only validates: presence, absolute expiry (7d hard cap, SEC-3),
role, and the CSRF double-submit header on mutating requests (contract §14.1).

Fail-closed: session store unreachable => 503 SERVICE_UNAVAILABLE.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from soc_schemas import ApiError, ErrorCode

CSRF_HEADER = "X-CSRF-Token"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    user_id: UUID
    tenant_id: UUID
    role: str  # 'admin' | 'analyst'
    session_id: str
    csrf_token: str


def _parse_expiry(raw: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC)
    except (TypeError, ValueError):
        pass
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class SessionStore:
    def __init__(self, redis) -> None:
        self._redis = redis

    async def validate(self, session_id: str) -> SessionPrincipal:
        try:
            raw = await self._redis.hgetall(f"sess:{session_id}")
        except Exception:
            raise ApiError(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Session store unavailable; retry.",
                retry_after_seconds=15,
            ) from None
        if not raw:
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.")
        data = {self._s(k): self._s(v) for k, v in raw.items()}
        expires_raw = data.get("absolute_expires_at", "")
        expires_at = _parse_expiry(expires_raw) if expires_raw else None
        if expires_at is None or datetime.now(UTC) >= expires_at:
            raise ApiError(ErrorCode.SESSION_EXPIRED, "Session expired; sign in again.")
        try:
            return SessionPrincipal(
                user_id=UUID(data["user_id"]),
                tenant_id=UUID(data["tenant_id"]),
                role=data["role"],
                session_id=session_id,
                csrf_token=data.get("csrf_token", ""),
            )
        except (KeyError, ValueError):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Authentication required.") from None

    @staticmethod
    def check_csrf(principal: SessionPrincipal, presented: str | None) -> None:
        """Double-submit check (contract §14.1) for cookie-authed writes."""
        if (
            not presented
            or not principal.csrf_token
            or not hmac.compare_digest(presented, principal.csrf_token)
        ):
            raise ApiError(
                ErrorCode.AUTH_REQUIRED,
                "CSRF token missing or invalid.",
                details={"csrf": "send the csrf_token cookie value in X-CSRF-Token"},
            )

    @staticmethod
    def _s(value: bytes | str) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else value
