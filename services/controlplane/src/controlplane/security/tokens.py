"""Email verification / invite tokens (SEC-2).

>=128-bit CSPRNG tokens, stored as SHA-256 hex, single use enforced by a CAS
UPDATE (queries.CONSUME_VERIFICATION), 24h expiry. Comparison happens via the
hash-indexed lookup, so no timing side channel on the token value itself.
"""

from __future__ import annotations

import hashlib
import secrets


def new_url_token() -> str:
    """256-bit URL-safe token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
