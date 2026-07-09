"""Server-side sessions (SEC-3): Redis `sess:{sid}` live store + PG metadata.

- New CSPRNG session id at every login (no fixation); per-session CSRF token
  (double-submit cookie `csrf_token` / header `X-CSRF-Token`, contract §14).
- 24h idle timeout = Redis key TTL, refreshed on read; 7d absolute lifetime
  stored in the hash and checked on every read.
- PG `control.sessions` holds hashed-id metadata for invalidation sweeps and
  audit; the plaintext session id exists only in the cookie and the Redis key.
- `sess:user:{uid}` set powers invalidate-all on password/role change/delete.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from controlplane import redis_keys
from controlplane.config import Settings
from controlplane.queries import (
    INSERT_SESSION,
    REVOKE_SESSION,
    REVOKE_USER_SESSIONS,
    REVOKE_USER_SESSIONS_EXCEPT,
)

SESSION_COOKIE_NAME = "sid"
CSRF_COOKIE_NAME = "csrf_token"


class SessionExpiredError(Exception):
    """Absolute lifetime exceeded — maps to 401 SESSION_EXPIRED."""


@dataclass(frozen=True, slots=True)
class SessionData:
    session_id: str
    user_id: UUID
    tenant_id: UUID
    role: str
    csrf_token: str
    created_at: datetime
    absolute_expires_at: datetime


def _hash_sid(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


class SessionStore:
    def __init__(self, *, db: Any, redis: Any, clock, settings: Settings) -> None:
        self._db = db
        self._redis = redis
        self._clock = clock
        self._settings = settings

    async def create(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID,
        role: str,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionData:
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = self._clock()
        absolute = now + self._settings_absolute()
        key = redis_keys.sess(session_id)
        await self._redis.hset(
            key,
            mapping={
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
                "role": role,
                "csrf_token": csrf_token,
                "created_at": now.isoformat(),
                "absolute_expires_at": absolute.isoformat(),
            },
        )
        await self._redis.expire(key, self._settings.session_idle_seconds)
        user_set = redis_keys.sess_user(user_id)
        await self._redis.sadd(user_set, session_id)
        await self._redis.expire(user_set, self._settings.session_absolute_seconds)

        async with self._db.acquire() as conn:
            await conn.execute(
                INSERT_SESSION,
                _hash_sid(session_id),
                user_id,
                tenant_id,
                absolute,
                ip,
                (user_agent or "")[:512] or None,
                now,
            )
        return SessionData(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            csrf_token=csrf_token,
            created_at=now,
            absolute_expires_at=absolute,
        )

    async def get(self, session_id: str) -> SessionData | None:
        """Fetch + idle-refresh. None => unknown/idle-expired; raises on absolute expiry."""
        key = redis_keys.sess(session_id)
        data = await self._redis.hgetall(key)
        if not data:
            return None
        absolute = datetime.fromisoformat(data["absolute_expires_at"])
        if self._clock() >= absolute:
            await self.revoke(session_id, reason="expired")
            raise SessionExpiredError
        await self._redis.expire(key, self._settings.session_idle_seconds)
        return SessionData(
            session_id=session_id,
            user_id=UUID(data["user_id"]),
            tenant_id=UUID(data["tenant_id"]),
            role=data["role"],
            csrf_token=data["csrf_token"],
            created_at=datetime.fromisoformat(data["created_at"]),
            absolute_expires_at=absolute,
        )

    async def revoke(self, session_id: str, *, reason: str) -> None:
        key = redis_keys.sess(session_id)
        data = await self._redis.hgetall(key)
        await self._redis.delete(key)
        if data.get("user_id"):
            await self._redis.srem(redis_keys.sess_user(UUID(data["user_id"])), session_id)
        async with self._db.acquire() as conn:
            await conn.execute(REVOKE_SESSION, _hash_sid(session_id), self._clock(), reason)

    async def revoke_all_for_user(
        self, user_id: UUID, *, reason: str, except_session_id: str | None = None
    ) -> int:
        """Invalidate every session of a user (SEC-3), optionally keeping one."""
        user_set = redis_keys.sess_user(user_id)
        session_ids = await self._redis.smembers(user_set)
        revoked = 0
        for sid in session_ids:
            if except_session_id is not None and sid == except_session_id:
                continue
            await self._redis.delete(redis_keys.sess(sid))
            await self._redis.srem(user_set, sid)
            revoked += 1
        now = self._clock()
        async with self._db.acquire() as conn:
            if except_session_id is None:
                await conn.execute(REVOKE_USER_SESSIONS, user_id, now, reason)
            else:
                await conn.execute(
                    REVOKE_USER_SESSIONS_EXCEPT,
                    user_id,
                    now,
                    reason,
                    _hash_sid(except_session_id),
                )
        return revoked

    def _settings_absolute(self):
        from datetime import timedelta

        return timedelta(seconds=self._settings.session_absolute_seconds)
