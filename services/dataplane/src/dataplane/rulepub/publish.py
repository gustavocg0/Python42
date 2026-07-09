"""Rule-pack publish operation (SEC-27, design §5 rule row, AC-39).

Authenticated, audited content publish — no code deploy:
- the WHOLE pack is validated + compiled first (one invalid rule rejects the
  entire pack version, atomically);
- rule_packs + rules rows are written in ONE transaction; the previously
  active pack is marked 'superseded' in the same transaction (the detector's
  30s version poll picks the new version up without a restart);
- manifest_hash = sha256 of the canonical manifest (packio.manifest_hash),
  recorded per SEC-27;
- an audit_log entry is written in the SAME transaction (soc_audit, SEC-43)
  under the reserved platform tenant id (db/migrations/0007 header).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from dataplane.rulepub.packio import PackValidation, manifest_hash
from soc_audit import Actor, Target, write_audit
from soc_tenancy import set_local_tenant

PLATFORM_TENANT_ID = UUID("00000000-0000-0000-0000-000000000000")
"""Reserved platform-scope tenant id for global content audit entries
(db/migrations/0007_audit_log.sql header)."""

AUDIT_ACTION_PUBLISH = "rule_pack.publish"

SQL_PACK_EXISTS = "SELECT 1 FROM tenantdata.rule_packs WHERE version = $1"
SQL_SUPERSEDE_ACTIVE = (
    "UPDATE tenantdata.rule_packs SET status = 'superseded' "
    "WHERE status = 'active' AND version <> $1"
)
SQL_INSERT_PACK = (
    "INSERT INTO tenantdata.rule_packs "
    "(version, manifest_hash, status, rule_count, published_by) "
    "VALUES ($1, $2, 'active', $3, $4)"
)
SQL_INSERT_RULE = (
    "INSERT INTO tenantdata.rules "
    "(pack_version, rule_id, rule_version, title, severity, mitre_technique_ids, "
    "event_classes, description, min_schema_version, definition, enabled_default, "
    "compile_error) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, NULL)"
)


class PackPublishError(RuntimeError):
    """Publish rejected (validation failure, duplicate version, ...)."""


class _TransactionCM(Protocol):
    async def __aenter__(self) -> Any: ...

    async def __aexit__(self, *exc_info: Any) -> Any: ...


class PublishConnection(Protocol):
    """Duck type for asyncpg Connection (or a test fake)."""

    def transaction(self) -> _TransactionCM: ...

    async def execute(self, query: str, *args: Any) -> Any: ...

    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass(frozen=True)
class PublishResult:
    pack_version: str
    manifest_hash: str
    rule_count: int
    generated_at: str
    published_by: str


def _rfc3339_utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def publish_pack(
    conn: PublishConnection,
    validation: PackValidation,
    *,
    published_by: str,
    generated_at: str | None = None,
) -> PublishResult:
    """Publish a fully validated pack in one transaction (SEC-27 atomic)."""
    if not validation.ok or validation.manifest is None:
        raise PackPublishError(
            "pack failed validation; publish rejected atomically (SEC-27):\n"
            + "\n".join(validation.errors)
        )
    if not published_by or not published_by.strip():
        raise PackPublishError("--published-by must name the operator/CI identity (SEC-27)")

    manifest = validation.manifest
    stamped_at = generated_at or _rfc3339_utc_now()
    digest = manifest_hash(manifest, stamped_at)
    version = manifest.pack_version

    async with conn.transaction():
        exists = await conn.fetchval(SQL_PACK_EXISTS, version)
        if exists:
            raise PackPublishError(
                f"pack version {version!r} is already published; bump pack_version"
            )
        await conn.execute(SQL_SUPERSEDE_ACTIVE, version)
        await conn.execute(SQL_INSERT_PACK, version, digest, len(validation.rules), published_by)
        for pack_rule in validation.rules:
            compiled = pack_rule.compiled
            await conn.execute(
                SQL_INSERT_RULE,
                version,
                compiled.rule_id,
                compiled.version,
                compiled.title,
                compiled.severity,
                list(compiled.mitre_technique_ids),
                [compiled.event_class],
                compiled.description,
                compiled.min_schema_version,
                json.dumps(compiled.definition, separators=(",", ":")),
                pack_rule.entry.enabled,
            )
        # Audit in the SAME transaction (SEC-43); platform tenant scope, so
        # the RLS GUC is pinned to the reserved id before the insert.
        await set_local_tenant(conn, PLATFORM_TENANT_ID)
        await write_audit(
            conn,
            tenant_id=PLATFORM_TENANT_ID,
            actor=Actor(type="user", id=published_by),
            action_type=AUDIT_ACTION_PUBLISH,
            target=Target(type="rule_pack", id=version),
            after={
                "pack_version": version,
                "manifest_hash": digest,
                "rule_count": len(validation.rules),
                "generated_at": stamped_at,
            },
        )

    return PublishResult(
        pack_version=version,
        manifest_hash=digest,
        rule_count=len(validation.rules),
        generated_at=stamped_at,
        published_by=published_by,
    )
