"""Password policy, argon2id hashing, breached-password check (SEC-1).

- argon2id, m=64 MiB, t=3, p=4 (threat-model minimums); hashing/verification
  run in a worker thread — never on the event loop (async-by-default rule).
- Policy: min 12 chars, max 512 (SEC-1: no max below 128), no composition
  rules.
- Breached check is a pluggable interface. MVP ships an offline checker over
  a small vendored list of top breached passwords (the plaintext never leaves
  the service). PRODUCTION FOLLOW-UP: HIBP k-anonymity range API
  implementation behind the same interface (SEC-1) — tracked for the
  Architect backlog.
"""

from __future__ import annotations

import asyncio
from importlib.resources import files
from typing import Protocol

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 512

# SEC-1 minimum parameters (argon2-cffi units: memory_cost is KiB).
ARGON2_MEMORY_COST_KIB = 64 * 1024
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4

_DUMMY_PASSWORD = "dummy-timing-equalizer-password"  # noqa: S105 - not a credential


class PasswordPolicyViolation(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def validate_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyViolation(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyViolation(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters long."
        )


class BreachedPasswordChecker(Protocol):
    """Pluggable breached-password check; the plaintext never leaves the service."""

    async def is_breached(self, password: str) -> bool: ...


class FileBreachedPasswordChecker:
    """Offline checker over the bundled top-breached-passwords list."""

    def __init__(self, entries: frozenset[str] | None = None) -> None:
        self._entries = entries if entries is not None else _load_bundled_breached_list()

    async def is_breached(self, password: str) -> bool:
        return password.lower() in self._entries


def _load_bundled_breached_list() -> frozenset[str]:
    raw = files("controlplane").joinpath("data/breached_passwords.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("#")
    )


class PasswordService:
    """argon2id hash/verify off the event loop, with a timing-equalizing dummy."""

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        self._hasher = hasher or PasswordHasher(
            memory_cost=ARGON2_MEMORY_COST_KIB,
            time_cost=ARGON2_TIME_COST,
            parallelism=ARGON2_PARALLELISM,
        )
        self._dummy_hash = self._hasher.hash(_DUMMY_PASSWORD)

    async def hash(self, password: str) -> str:
        return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, password_hash: str, password: str) -> bool:
        def _verify() -> bool:
            try:
                self._hasher.verify(password_hash, password)
                return True
            except (VerifyMismatchError, VerificationError):
                return False

        return await asyncio.to_thread(_verify)

    async def dummy_verify(self) -> None:
        """Burn the same work as a real verification (SEC-4 uniform timing)."""
        await self.verify(self._dummy_hash, "not-the-dummy-password")
