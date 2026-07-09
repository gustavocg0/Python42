"""Idempotent-ingest document identity (design doc §3, AC-34).

ES document `_id` = sha256(tenant_id + ":" + source_scope + ":" + source_event_id)
where `source_scope` = `device_id` (agent) or `ingest_key_id` (generic).
Writes use op_type=create; duplicates are counted and dropped.
"""

from __future__ import annotations

import hashlib
from uuid import UUID


def derive_es_document_id(
    tenant_id: UUID | str, source_scope: str, source_event_id: str
) -> str:
    """Deterministic ES `_id` for idempotent event writes (AC-34).

    Args:
        tenant_id: server-authoritative tenant UUID (validated, canonicalized).
        source_scope: `device_id` for agent events, `ingest_key_id` for generic.
        source_event_id: source-assigned dedup key (server UUID if absent upstream).
    """
    canonical_tenant = str(UUID(str(tenant_id)))
    if not source_scope:
        raise ValueError("source_scope must be non-empty (device_id or ingest_key_id)")
    if not source_event_id:
        raise ValueError("source_event_id must be non-empty")
    material = f"{canonical_tenant}:{source_scope}:{source_event_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
