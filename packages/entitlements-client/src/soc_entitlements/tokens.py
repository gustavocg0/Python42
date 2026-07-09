"""HMAC-signed short-lived service tokens (design §5.1 item 2, SEC-40).

Format: `v1.<service_name>.<expires_unix>.<hmac_sha256_hex>`
- HMAC over `v1.<service_name>.<expires_unix>` with the per-service-pair key;
- lifetime <= 300s, +/-30s clock skew tolerated;
- verification uses constant-time compare.
"""

from __future__ import annotations

import hmac
import re
import time
from collections.abc import Callable, Mapping
from hashlib import sha256

TOKEN_VERSION = "v1"  # noqa: S105 - format version tag, not a credential
MAX_TOKEN_LIFETIME_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
_MIN_KEY_BYTES = 32
_SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ServiceTokenError(Exception):
    """Base class for service-token failures."""


class InvalidServiceToken(ServiceTokenError):
    """Malformed, unknown-service, bad-signature, or over-lifetime token."""


class ExpiredServiceToken(ServiceTokenError):
    """Token past expiry (beyond clock skew)."""


def _coerce_key(key: str | bytes) -> bytes:
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if len(key_bytes) < _MIN_KEY_BYTES:
        raise ValueError(f"service-token key must be at least {_MIN_KEY_BYTES} bytes")
    return key_bytes


def _sign(signing_input: str, key: bytes) -> str:
    return hmac.new(key, signing_input.encode("utf-8"), sha256).hexdigest()


def generate_service_token(
    *,
    service_name: str,
    key: str | bytes,
    ttl_seconds: int = MAX_TOKEN_LIFETIME_SECONDS,
    now: int | None = None,
) -> str:
    """Mint a token for `service_name` valid for ttl_seconds (<=300)."""
    if not _SERVICE_NAME_RE.match(service_name):
        raise ValueError(f"invalid service_name: {service_name!r}")
    if not 0 < ttl_seconds <= MAX_TOKEN_LIFETIME_SECONDS:
        raise ValueError(f"ttl_seconds must be in (0, {MAX_TOKEN_LIFETIME_SECONDS}]")
    key_bytes = _coerce_key(key)
    issued_at = int(time.time()) if now is None else int(now)
    expires = issued_at + ttl_seconds
    signing_input = f"{TOKEN_VERSION}.{service_name}.{expires}"
    return f"{signing_input}.{_sign(signing_input, key_bytes)}"


def verify_service_token(
    token: str,
    *,
    keys: Mapping[str, str | bytes] | Callable[[str], str | bytes | None],
    now: int | None = None,
) -> str:
    """Verify a token; returns the authenticated service_name.

    `keys` maps service_name -> shared key (per service pair, from the secrets
    store), or is a lookup callable returning None for unknown services.

    Raises InvalidServiceToken / ExpiredServiceToken — callers deny on any
    ServiceTokenError (fail closed).
    """
    current = int(time.time()) if now is None else int(now)
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != TOKEN_VERSION:
        raise InvalidServiceToken("malformed service token")
    _version, service_name, expires_raw, presented_sig = parts
    if not _SERVICE_NAME_RE.match(service_name):
        raise InvalidServiceToken("malformed service name")
    try:
        expires = int(expires_raw)
    except ValueError as exc:
        raise InvalidServiceToken("malformed expiry") from exc

    key_raw = keys(service_name) if callable(keys) else keys.get(service_name)
    if key_raw is None:
        raise InvalidServiceToken(f"unknown service: {service_name}")
    key_bytes = _coerce_key(key_raw)

    expected_sig = _sign(f"{TOKEN_VERSION}.{service_name}.{expires}", key_bytes)
    if not hmac.compare_digest(presented_sig.encode(), expected_sig.encode()):
        raise InvalidServiceToken("signature mismatch")

    if current > expires + CLOCK_SKEW_SECONDS:
        raise ExpiredServiceToken("service token expired")
    if expires > current + MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS:
        raise InvalidServiceToken("token lifetime exceeds the 300s maximum")
    return service_name
