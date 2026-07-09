"""Signup abuse controls (AC-8, SEC-5, OQ-5).

- Per-IP signup counter `abuse:signup:ip:{ip}` (1h TTL per the Redis key
  registry); threshold from `control.platform_config
  signup_per_ip_hourly_threshold` (seeded 5).
- Disposable-domain blocklist: vendored copy of a maintained OSS list
  (refresh >= monthly per SEC-5 — devsecops owns the refresh automation).
- Challenge verifier is a pluggable interface (config-swappable per OQ-5/G-6;
  production recommendation: Cloudflare Turnstile). MVP ships a stub that
  accepts only the deployment-configured token, and a reject-all default
  (fail closed when unconfigured).
"""

from __future__ import annotations

import hmac
from importlib.resources import files
from typing import Protocol

from controlplane.config import Settings


class ChallengeVerifier(Protocol):
    async def verify(self, *, response: str, ip: str | None) -> bool: ...


class RejectAllChallengeVerifier:
    """Fail-closed default when no challenge provider is configured."""

    async def verify(self, *, response: str, ip: str | None) -> bool:
        return False


class StaticTokenChallengeVerifier:
    """Dev/CI stub (OQ-5): accepts exactly the configured token."""

    def __init__(self, expected: str) -> None:
        self._expected = expected

    async def verify(self, *, response: str, ip: str | None) -> bool:
        return bool(self._expected) and hmac.compare_digest(response, self._expected)


def build_challenge_verifier(settings: Settings) -> ChallengeVerifier:
    if settings.challenge_stub_token:
        return StaticTokenChallengeVerifier(settings.challenge_stub_token)
    return RejectAllChallengeVerifier()


def load_disposable_domains() -> frozenset[str]:
    raw = files("controlplane").joinpath("data/disposable_domains.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("#")
    )
