"""soc_audit — the ONLY way runtime code writes audit records (SEC-42..45).

Binding rules implemented here:
- SEC-43: the INSERT runs on the CALLER's connection, inside the caller's
  transaction — if the audit write fails, the action fails. Never
  fire-and-forget.
- SEC-44: records never contain secret material or raw event payloads —
  the API takes structured before/after dicts only, redacts secret-named
  keys, and hard-caps serialized size.
- SEC-45: timestamps come from the DB clock (now() in SQL), never from the
  application; actor taxonomy is fixed: user | system | device.

DB-side append-only enforcement (INSERT-only role, guard trigger, RLS) is
the database-architect's migration deliverable (SEC-42).
"""

from soc_audit.redact import (
    REDACTED,
    AuditValueTooLarge,
    redact_secrets,
    serialize_audit_value,
)
from soc_audit.writer import AUDIT_INSERT_SQL, Actor, Target, write_audit

__all__ = [
    "AUDIT_INSERT_SQL",
    "REDACTED",
    "Actor",
    "AuditValueTooLarge",
    "Target",
    "redact_secrets",
    "serialize_audit_value",
    "write_audit",
]
