"""Wire format for enrollment tokens and ingest keys (SEC-7/SEC-16).

Wire shape: `<id>.<secret>` where `<id>` is the prefixed lookup segment
('et_...' / 'ik_...') and `<secret>` is base64url(tenant_uuid_bytes[16] +
32 random bytes), unpadded. Only sha256(<secret>) is stored (BINDING per
db/migrations/0004 comments).

Embedding the tenant UUID in the opaque secret is what lets the server set
the RLS GUC BEFORE looking the credential row up (FORCE RLS means no
cross-tenant scan is possible): a foreign/unknown credential simply resolves
to zero visible rows or a hash mismatch — indistinguishable by construction
(contract §2 / §10). The tenant id is not secret material; entropy lives in
the 32 random bytes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from uuid import UUID

_SECRET_RANDOM_BYTES = 32


class MalformedCredential(ValueError):
    """Presented credential does not parse — treat as invalid (never 500)."""


@dataclass(frozen=True, slots=True)
class MintedSecret:
    wire_token: str  # "<id>.<secret>" — shown once, never stored
    secret_hash: str  # sha256 hex of the secret segment — stored at rest


@dataclass(frozen=True, slots=True)
class ParsedCredential:
    credential_id: str  # 'et_...' / 'ik_...'
    tenant_id: UUID
    secret: str  # the raw secret segment (hash before compare)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def mint_secret(credential_id: str, tenant_id: UUID) -> MintedSecret:
    raw = tenant_id.bytes + os.urandom(_SECRET_RANDOM_BYTES)
    secret = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return MintedSecret(
        wire_token=f"{credential_id}.{secret}",
        secret_hash=_hash_secret(secret),
    )


def parse_credential(presented: str, *, expected_prefix: str) -> ParsedCredential:
    """Split + decode a presented credential; raises MalformedCredential."""
    if not presented or len(presented) > 512:
        raise MalformedCredential("credential empty or oversized")
    credential_id, sep, secret = presented.partition(".")
    if not sep or not secret or not credential_id.startswith(expected_prefix):
        raise MalformedCredential("credential format invalid")
    padded = secret + "=" * (-len(secret) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise MalformedCredential("credential secret not base64url") from exc
    if len(raw) != 16 + _SECRET_RANDOM_BYTES:
        raise MalformedCredential("credential secret wrong length")
    return ParsedCredential(
        credential_id=credential_id,
        tenant_id=UUID(bytes=raw[:16]),
        secret=secret,
    )


def secret_matches(secret: str, stored_hash: str) -> bool:
    """Constant-time compare of sha256(secret) against the stored hash."""
    return hmac.compare_digest(_hash_secret(secret), stored_hash)


def hash_secret(secret: str) -> str:
    return _hash_secret(secret)
