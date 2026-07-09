"""Prefixed, lexicographically sortable public IDs (ULID-based).

Alert ids are 'al_' + ULID per db/migrations/0005 (stable cursor tie-break);
the same generator serves every prefixed id ('dev_', 'et_', 'ik_', 'inv_',
'b_', 'as_' is a uuid in PG — asset ids are server uuids, not ULIDs).
"""

from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    """26-char Crockford-base32 ULID (48-bit ms timestamp + 80-bit randomness)."""
    ts = int(time.time() * 1000) if now_ms is None else int(now_ms)
    rand = int.from_bytes(os.urandom(10))
    value = (ts << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    """Prefixed opaque id, e.g. new_id('al') -> 'al_01J9ZM2W...'."""
    return f"{prefix}_{ulid()}"
