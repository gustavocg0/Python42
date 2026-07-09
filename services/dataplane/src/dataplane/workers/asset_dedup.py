"""worker-asset-dedup — pipe:asset.observations -> deduplicated asset inventory.

Run: ``python -m dataplane.workers.asset_dedup``

Responsibilities (design §5 "Asset dedup", AC-19..27):
- consume ``pipe:asset.observations`` (consumer group ``asset-dedup``);
  producers: worker-normalizer (per stored event with a host) and the
  enrollment API;
- deterministic match order (AC-22): (1) agent ``device_id``,
  (2) ``lower(hostname) + os_family``, (3) MAC address;
- ``asset_identity_pins`` are consulted BEFORE automatic rules for every
  identifier — manual merge/split corrections always win and are never
  re-merged automatically (AC-25);
- agent identity always wins over hostname matching (AC-23): an observation
  carrying a device_id never merges into an asset whose device_id identity
  differs — re-imaged machines sharing a hostname stay separate assets;
- create/update ``assets`` + ``asset_identities`` (sources union, first/last
  seen, applied ``dedup_rule``) and write ``asset_merge_audit`` rows when a
  new identifier merges onto an existing asset (AC-24);
- billable recompute is read-time (API-side, AC-26); this worker keeps
  ``last_seen``/identities correct and re-marks a seen asset billable unless
  its agent is revoked. The scheduled job clears stale billable flags.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError

from dataplane.workers.common import (
    build_runtime,
    insert_dead_letter,
    install_stop_signal_handlers,
    make_pipeline_dead_letter_handler,
    tenant_transaction,
)
from soc_pipeline import STREAM_ASSET_OBSERVATIONS, ReceivedMessage, StreamConsumer
from soc_telemetry import PipelineMetrics, PipelineOutcome, PipelineStage
from soc_tenancy import tenant_context

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "asset-dedup"
STAGE = PipelineStage.asset_dedup
ACTOR_ID = "worker-asset-dedup"

RULE_BY_IDENTIFIER_TYPE = {
    "device_id": "device_id_match",
    "hostname_os": "hostname_os_match",
    "mac": "mac_match",
}

# --- SQL ----------------------------------------------------------------------

PIN_LOOKUP_SQL = """\
SELECT pinned_asset_id
FROM tenantdata.asset_identity_pins
WHERE tenant_id = $1 AND identifier_type = $2 AND value = $3\
"""

IDENTITY_LOOKUP_SQL = """\
SELECT asset_id
FROM tenantdata.asset_identities
WHERE tenant_id = $1 AND identifier_type = $2 AND value = $3\
"""

ASSET_DEVICE_IDENTITY_SQL = """\
SELECT value
FROM tenantdata.asset_identities
WHERE tenant_id = $1 AND asset_id = $2 AND identifier_type = 'device_id'
LIMIT 1\
"""

UPDATE_ASSET_SQL = """\
UPDATE tenantdata.assets
SET hostname   = COALESCE($3, hostname),
    os_family  = COALESCE($4, os_family),
    os_name    = COALESCE($5, os_name),
    os_version = COALESCE($6, os_version),
    ip         = COALESCE($7, ip),
    mac        = COALESCE($8, mac),
    sources    = CASE WHEN $9 = ANY(sources) THEN sources ELSE array_append(sources, $9) END,
    last_seen  = GREATEST(last_seen, $10),
    billable   = CASE WHEN agent_status = 'revoked' THEN billable ELSE true END,
    billable_computed_at = now(),
    dedup_rule = COALESCE($11, dedup_rule),
    updated_at = now()
WHERE tenant_id = $1 AND id = $2\
"""

INSERT_ASSET_SQL = """\
INSERT INTO tenantdata.assets
    (id, tenant_id, hostname, os_family, os_name, os_version, ip, mac, sources,
     agent_status, billable, billable_computed_at, created_via, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, now(), $11, $12, $12)\
"""

UPSERT_IDENTITY_SQL = """\
INSERT INTO tenantdata.asset_identities
    (tenant_id, asset_id, source, identifier_type, value, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $6)
ON CONFLICT (tenant_id, identifier_type, value) DO UPDATE
SET last_seen = GREATEST(asset_identities.last_seen, EXCLUDED.last_seen)
WHERE asset_identities.asset_id = EXCLUDED.asset_id
RETURNING (xmax = 0) AS inserted\
"""

INSERT_MERGE_AUDIT_SQL = """\
INSERT INTO tenantdata.asset_merge_audit (tenant_id, asset_id, rule, actor_type, actor_id, details)
VALUES ($1, $2, $3, 'system', $4, $5::jsonb)\
"""


class AssetObservation(BaseModel):
    """``pipe:asset.observations`` payload (produced by normalizer/enrollment)."""

    model_config = ConfigDict(extra="ignore")

    observed_at: AwareDatetime
    source: Literal["agent", "log_ingest"]
    hostname: str | None = None
    os_family: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    ip: str | None = None
    mac: str | None = None
    device_id: str | None = None
    agent_version: str | None = None

    def identifiers(self) -> list[tuple[str, str]]:
        """Deterministic dedup identifiers, strongest first (AC-22)."""
        idents: list[tuple[str, str]] = []
        if self.device_id:
            idents.append(("device_id", self.device_id))
        if self.hostname and self.os_family:
            idents.append(("hostname_os", f"{self.hostname.lower()}|{self.os_family}"))
        if self.mac:
            idents.append(("mac", self.mac.lower()))
        return idents


class AssetDeduper:
    def __init__(self, *, pool: Any, metrics: PipelineMetrics) -> None:
        self._pool = pool
        self._metrics = metrics

    async def handle(self, message: ReceivedMessage) -> None:
        tenant_id = message.tenant_id
        try:
            obs = AssetObservation.model_validate(message.payload)
            identifiers = obs.identifiers()
            if not identifiers:
                raise ValueError(
                    "observation carries no dedup identifier "
                    "(device_id, hostname+os_family, or mac required)"
                )
        except (ValidationError, ValueError) as exc:
            async with tenant_transaction(self._pool, tenant_id) as conn:
                await insert_dead_letter(
                    conn,
                    tenant_id=tenant_id,
                    batch_id=None,
                    source_type="agent" if message.payload.get("source") == "agent" else "generic",
                    payload=message.payload,
                    error_code="ASSET_OBSERVATION_MALFORMED",
                    error_detail=str(exc)[:500],
                )
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.dead_lettered
            )
            return

        async with tenant_transaction(self._pool, tenant_id) as conn:
            asset_id, matched_rule = await self._resolve(conn, tenant_id, obs, identifiers)
            created = asset_id is None
            if created:
                asset_id = await self._create_asset(conn, tenant_id, obs)
            else:
                await conn.execute(
                    UPDATE_ASSET_SQL,
                    tenant_id,
                    asset_id,
                    obs.hostname.lower() if obs.hostname else None,
                    obs.os_family,
                    obs.os_name,
                    obs.os_version,
                    obs.ip,
                    obs.mac.lower() if obs.mac else None,
                    obs.source,
                    obs.observed_at,
                    matched_rule,
                )
            await self._bind_identities(
                conn,
                tenant_id,
                asset_id,
                obs,
                identifiers,
                audit_merges=not created,
                matched_rule=matched_rule,
            )
        self._metrics.record(tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.ok)

    # -- matching --------------------------------------------------------------

    async def _resolve(
        self,
        conn: Any,
        tenant_id: UUID,
        obs: AssetObservation,
        identifiers: list[tuple[str, str]],
    ) -> tuple[UUID | None, str | None]:
        """Deterministic matcher: per identifier (strongest first), pins are
        consulted BEFORE automatic identity bindings (AC-25). Candidates that
        would violate AC-23 (observation has a device_id, candidate asset is
        bound to a DIFFERENT device_id) are skipped — agent identity wins."""
        for identifier_type, value in identifiers:
            candidate: UUID | None = None
            rule: str | None = None
            pin = await conn.fetchrow(PIN_LOOKUP_SQL, tenant_id, identifier_type, value)
            if pin is not None:
                candidate = pin["pinned_asset_id"]
                rule = None  # manual pin: keep the asset's manual_* dedup_rule
            else:
                identity = await conn.fetchrow(
                    IDENTITY_LOOKUP_SQL, tenant_id, identifier_type, value
                )
                if identity is not None:
                    candidate = identity["asset_id"]
                    rule = RULE_BY_IDENTIFIER_TYPE[identifier_type]
            if candidate is None:
                continue
            if identifier_type != "device_id" and obs.device_id:
                bound_device = await conn.fetchval(
                    ASSET_DEVICE_IDENTITY_SQL, tenant_id, candidate
                )
                if bound_device and bound_device != obs.device_id:
                    continue  # AC-23: differing device_ids stay separate assets
            return candidate, rule
        return None, None

    async def _create_asset(self, conn: Any, tenant_id: UUID, obs: AssetObservation) -> UUID:
        asset_id = uuid4()
        await conn.execute(
            INSERT_ASSET_SQL,
            asset_id,
            tenant_id,
            obs.hostname.lower() if obs.hostname else None,
            obs.os_family,
            obs.os_name,
            obs.os_version,
            obs.ip,
            obs.mac.lower() if obs.mac else None,
            [obs.source],
            "enrolled" if obs.source == "agent" else "none",
            "agent_enrollment" if obs.source == "agent" else "log_ingest",
            obs.observed_at,
        )
        return asset_id

    async def _bind_identities(
        self,
        conn: Any,
        tenant_id: UUID,
        asset_id: UUID,
        obs: AssetObservation,
        identifiers: list[tuple[str, str]],
        *,
        audit_merges: bool,
        matched_rule: str | None,
    ) -> None:
        for identifier_type, value in identifiers:
            # A pin binding this identifier to a DIFFERENT asset blocks the
            # automatic (re)binding entirely (AC-25: no automatic re-merge).
            pin = await conn.fetchrow(PIN_LOOKUP_SQL, tenant_id, identifier_type, value)
            if pin is not None and pin["pinned_asset_id"] != asset_id:
                continue
            row = await conn.fetchrow(
                UPSERT_IDENTITY_SQL,
                tenant_id,
                asset_id,
                obs.source,
                identifier_type,
                value,
                obs.observed_at,
            )
            # row is None when the identifier is already bound to ANOTHER
            # asset (e.g. shared hostname held by the first device, AC-23):
            # the existing binding is left untouched.
            inserted = bool(row and row["inserted"])
            if inserted and audit_merges:
                await conn.execute(
                    INSERT_MERGE_AUDIT_SQL,
                    tenant_id,
                    asset_id,
                    matched_rule or RULE_BY_IDENTIFIER_TYPE[identifier_type],
                    ACTOR_ID,
                    json.dumps(
                        {
                            "identifier_type": identifier_type,
                            "value": value,
                            "source": obs.source,
                        }
                    ),
                )


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    runtime = await build_runtime()
    stop = asyncio.Event()
    install_stop_signal_handlers(stop)
    metrics = PipelineMetrics()
    deduper = AssetDeduper(pool=runtime.pool, metrics=metrics)
    consumer = StreamConsumer(
        runtime.redis,
        stream=STREAM_ASSET_OBSERVATIONS,
        group=CONSUMER_GROUP,
        consumer_name=runtime.settings.consumer_name,
        handler=deduper.handle,
        tenant_context=lambda msg: tenant_context(msg.tenant_id),
        dead_letter=make_pipeline_dead_letter_handler(
            runtime.pool, metrics=metrics, stage=STAGE
        ),
    )
    logger.info("worker-asset-dedup starting (group=%s)", CONSUMER_GROUP)
    try:
        await consumer.run(stop=stop)
    finally:
        await runtime.close()
        logger.info("worker-asset-dedup stopped")


if __name__ == "__main__":
    asyncio.run(main())
