"""Redis key builders — exact prefixes per db/redis-conventions.md (BINDING).

Keys are built ONLY from server-side values (rule 1): tenant/user UUIDs come
from our own rows, session ids from our CSPRNG, IPs from the transport layer.
"""

from __future__ import annotations

from uuid import UUID


def sess(session_id: str) -> str:
    return f"sess:{session_id}"


def sess_user(user_id: UUID) -> str:
    return f"sess:user:{user_id}"


def throttle_login_acct(user_id: UUID) -> str:
    return f"throttle:login:acct:{user_id}"


def throttle_login_ip(ip: str) -> str:
    return f"throttle:login:ip:{ip}"


def abuse_signup_ip(ip: str) -> str:
    return f"abuse:signup:ip:{ip}"


def tenantstatus(tenant_id: UUID) -> str:
    return f"tenantstatus:{tenant_id}"


def ent(tenant_id: UUID) -> str:
    return f"ent:{tenant_id}"
