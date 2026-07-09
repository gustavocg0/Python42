"""worker-alerter — pipe:detections -> alert create/dedup/correlate -> pipe:alerts.triage.

Run: ``python -m dataplane.workers.alerter``

Responsibilities (design §2/§5, AC-41..43, priority-score contract):
- consume ``pipe:detections`` (consumer group ``alerters``); payload per
  rules/FORMAT.md §5.5 plus ``event_time`` (see DetectionHit);
- dedup upsert against the UNIQUE partial index ``alerts_open_dedup_uq``
  (tenant_id, rule_id, entity_key) WHERE state IN ('new','acknowledged') —
  the index IS the concurrency-safe dedup mechanism (db/migrations/0005);
- window semantics (AC-41/42): hit inside the 60-min window of an open alert
  => occurrence_count++/last_seen/link event; open alert OUTSIDE the window
  => close it (system actor) and create a NEW alert;
- correlation (AC-43): on alert create, open alerts of the same tenant+host
  with last_seen within 30 min and a different rule join/create a
  correlation_group;
- priority score via ``dataplane.scoring`` (triage pending => rule-severity-
  only path, AC-50); recompute on occurrence-tier crossings (2/5/20);
- NEW alerts only: XADD ``pipe:alerts.triage``;
- alert_history rows for every transition (created/occurrence_added/
  correlated/closed).

Concurrency-safe upsert approach (documented per task brief):
1. INSERT ... ON CONFLICT (dedup index) DO UPDATE ... WHERE the existing open
   alert's last_seen is still inside the dedup window, RETURNING the row.
   - insert happened  -> new alert path;
   - update happened  -> dedup-hit path (occurrence++);
   - NO row returned  -> an open alert exists but its window expired.
2. On the expired case: UPDATE that open alert to closed (guarded by the same
   window predicate so a concurrent occurrence-update makes it a no-op), then
   retry step 1. Two concurrent hits on an empty key: one row inserted, the
   other conflicts into the DO UPDATE branch => one alert, count=2. The loop
   is bounded (3 attempts) and the message is retried via the stream's
   at-least-once semantics if contention persists.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Literal
from uuid import UUID

from pydantic import AliasChoices, AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from dataplane.scoring import PriorityScore, compute_priority
from dataplane.workers.common import (
    Settings,
    build_runtime,
    insert_dead_letter,
    install_stop_signal_handlers,
    load_platform_config,
    make_pipeline_dead_letter_handler,
    new_alert_id,
    new_correlation_group_id,
    tenant_transaction,
)
from soc_pipeline import (
    STREAM_ALERTS_TRIAGE,
    STREAM_DETECTIONS,
    ReceivedMessage,
    StreamConsumer,
    StreamProducer,
)
from soc_telemetry import PipelineMetrics, PipelineOutcome, PipelineStage
from soc_tenancy import events_index, tenant_context

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "alerters"
STAGE = PipelineStage.alert
ACTOR_ID = "worker-alerter"

# --- SQL (binding shapes from db/migrations 0005; asyncpg placeholders) -------

ALERT_EVENT_LINKED_SQL = """\
SELECT 1
FROM tenantdata.alert_events ae
JOIN tenantdata.alerts a ON a.tenant_id = ae.tenant_id AND a.id = ae.alert_id
WHERE ae.tenant_id = $1 AND ae.event_id = $2 AND a.rule_id = $3
LIMIT 1\
"""

RESOLVE_ASSET_SQL = """\
SELECT id, agent_status
FROM tenantdata.assets
WHERE tenant_id = $1 AND hostname = $2 AND state = 'active'
ORDER BY last_seen DESC
LIMIT 1\
"""

ALERT_UPSERT_SQL = """\
INSERT INTO tenantdata.alerts
    (id, tenant_id, state, rule_id, rule_version, rule_title, rule_severity,
     mitre_technique_ids, entity_key, entity_hostname, entity_user, asset_id,
     occurrence_count, first_seen, last_seen, priority_score, priority_inputs)
VALUES ($1, $2, 'new', $3, $4, $5, $6, $7, $8, $9, $10, $11, 1, $12, $12, $13, $14::jsonb)
ON CONFLICT (tenant_id, rule_id, entity_key) WHERE state IN ('new','acknowledged')
DO UPDATE SET
    occurrence_count = alerts.occurrence_count + 1,
    last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen),
    updated_at = now()
WHERE alerts.last_seen >= EXCLUDED.last_seen - make_interval(mins => $15)
RETURNING id, occurrence_count, (xmax = 0) AS inserted, rule_severity,
          triage_status, ai_severity, correlation_group_id\
"""

CLOSE_EXPIRED_OPEN_ALERT_SQL = """\
UPDATE tenantdata.alerts
SET state = 'closed',
    close_reason = 'resolved',
    close_comment = 'auto-closed: dedup window expired; superseded by a new alert',
    closed_at = now(),
    updated_at = now()
WHERE tenant_id = $1 AND rule_id = $2 AND entity_key = $3
  AND state IN ('new','acknowledged')
  AND last_seen < $4::timestamptz - make_interval(mins => $5)
RETURNING id\
"""

LINK_EVENT_SQL = """\
INSERT INTO tenantdata.alert_events (tenant_id, alert_id, event_id, es_index)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, alert_id, event_id) DO NOTHING\
"""

INSERT_HISTORY_SQL = """\
INSERT INTO tenantdata.alert_history
    (tenant_id, alert_id, actor_type, actor_id, action, from_state, to_state, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)\
"""

CORRELATION_CANDIDATES_SQL = """\
SELECT id, correlation_group_id
FROM tenantdata.alerts
WHERE tenant_id = $1 AND entity_hostname = $2
  AND state IN ('new','acknowledged')
  AND rule_id <> $3 AND id <> $4
  AND last_seen >= $5::timestamptz - make_interval(mins => $6)
ORDER BY last_seen DESC\
"""

CREATE_CORRELATION_GROUP_SQL = """\
INSERT INTO tenantdata.correlation_groups (id, tenant_id, entity_hostname, alert_count, last_alert_at)
VALUES ($1, $2, $3, 0, $4)\
"""

ASSIGN_CORRELATION_GROUP_SQL = """\
UPDATE tenantdata.alerts
SET correlation_group_id = $3, updated_at = now()
WHERE tenant_id = $1 AND id = ANY($2::text[]) AND correlation_group_id IS NULL
RETURNING id\
"""

UPDATE_CORRELATION_GROUP_STATS_SQL = """\
UPDATE tenantdata.correlation_groups g
SET alert_count = (SELECT count(*) FROM tenantdata.alerts a
                   WHERE a.tenant_id = g.tenant_id AND a.correlation_group_id = g.id),
    last_alert_at = GREATEST(g.last_alert_at, $3::timestamptz)
WHERE g.tenant_id = $1 AND g.id = $2\
"""

UPDATE_PRIORITY_SQL = """\
UPDATE tenantdata.alerts
SET priority_score = $3, priority_inputs = $4::jsonb, updated_at = now()
WHERE tenant_id = $1 AND id = $2\
"""


class DetectionHit(BaseModel):
    """``pipe:detections`` payload — rules/FORMAT.md §5.5 + ``event_time``.

    ``tenant_id`` inside the payload is IGNORED: tenant context comes from the
    authenticated stream envelope only (SEC-20). ``es_index`` is optional; when
    absent it is derived from ``event_time`` (events-v1-{tenant}-{yyyy.MM}).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    rule_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    title: str = Field(min_length=1, validation_alias=AliasChoices("title", "rule_title"))
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique_ids: list[str] = Field(default_factory=list)
    entity_key: str
    event_id: UUID
    pack_version: str | None = None
    event_time: AwareDatetime
    entity_hostname: str | None = None
    entity_user: str | None = None
    es_index: str | None = None


class Alerter:
    def __init__(
        self,
        *,
        pool: Any,
        producer: StreamProducer,
        metrics: PipelineMetrics,
        settings: Settings,
        dedup_window_minutes: int | None = None,
        correlation_window_minutes: int | None = None,
    ) -> None:
        self._pool = pool
        self._producer = producer
        self._metrics = metrics
        self._settings = settings
        self._dedup_window = dedup_window_minutes or settings.alert_dedup_window_minutes
        self._correlation_window = (
            correlation_window_minutes or settings.correlation_window_minutes
        )

    async def handle(self, message: ReceivedMessage) -> None:
        tenant_id = message.tenant_id
        try:
            hit = DetectionHit.model_validate(message.payload)
        except ValidationError as exc:
            detail = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]
            )
            async with tenant_transaction(self._pool, tenant_id) as conn:
                await insert_dead_letter(
                    conn,
                    tenant_id=tenant_id,
                    batch_id=None,
                    source_type="generic",
                    payload=message.payload,
                    error_code="DETECTION_HIT_MALFORMED",
                    error_detail=detail,
                )
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.dead_lettered
            )
            return

        es_index = hit.es_index or events_index(tenant_id, hit.event_time)
        triage_payload: dict[str, Any] | None = None

        async with tenant_transaction(self._pool, tenant_id) as conn:
            # Redelivery guard (at-least-once): the same event already linked
            # to an alert of this rule means this hit was fully processed.
            already = await conn.fetchrow(
                ALERT_EVENT_LINKED_SQL, tenant_id, hit.event_id, hit.rule_id
            )
            if already:
                self._metrics.record(
                    tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.duplicate
                )
                return

            asset_id, agent_status = await self._resolve_asset(conn, tenant_id, hit)
            score = compute_priority(
                rule_severity=hit.severity,
                ai_severity=None,  # triage pending at creation (AC-50 path)
                occurrence_count=1,
                agent_status=agent_status,
            )

            row = await self._upsert_with_window(conn, tenant_id, hit, asset_id, score)
            if row is None:
                raise RuntimeError(
                    "alert upsert contention persisted; leaving message for retry"
                )

            alert_id: str = row["id"]
            await conn.execute(LINK_EVENT_SQL, tenant_id, alert_id, hit.event_id, es_index)

            if row["inserted"]:
                await self._history(
                    conn,
                    tenant_id,
                    alert_id,
                    action="created",
                    to_state="new",
                    details={
                        "rule_id": hit.rule_id,
                        "rule_version": hit.rule_version,
                        "priority_score": score.score,
                        "event_id": str(hit.event_id),
                    },
                )
                group_id = await self._correlate(conn, tenant_id, hit, alert_id)
                triage_payload = {
                    "alert_id": alert_id,
                    "rule_id": hit.rule_id,
                    "rule_version": hit.rule_version,
                    "rule_title": hit.title,
                    "rule_severity": hit.severity,
                    "entity_key": hit.entity_key,
                    "entity_hostname": hit.entity_hostname,
                    "entity_user": hit.entity_user,
                    "correlation_group_id": group_id,
                    "occurrence_count": 1,
                    "event_refs": [{"event_id": str(hit.event_id), "es_index": es_index}],
                }
            else:
                count = row["occurrence_count"]
                await self._history(
                    conn,
                    tenant_id,
                    alert_id,
                    action="occurrence_added",
                    details={"occurrence_count": count, "event_id": str(hit.event_id)},
                )
                if count in (2, 5, 20):  # tier boundary => recompute (contract §3)
                    await self._recompute_priority(conn, tenant_id, hit, row)

        # Publish AFTER commit so the triager never sees an uncommitted alert.
        # (Crash between commit and XADD => redelivery hits the guard above and
        # the alert stays triage_status=pending — surfaced by triage-latency
        # metrics rather than lost silently.)
        if triage_payload is not None:
            await self._producer.publish(
                STREAM_ALERTS_TRIAGE,
                tenant_id=tenant_id,
                trace_id=message.trace_id,
                payload=triage_payload,
            )
            self._metrics.record(
                tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.stored
            )
        else:
            self._metrics.record(tenant_id=tenant_id, stage=STAGE, outcome=PipelineOutcome.ok)

    # -- steps ---------------------------------------------------------------

    async def _resolve_asset(
        self, conn: Any, tenant_id: UUID, hit: DetectionHit
    ) -> tuple[UUID | None, str]:
        """agent_status is read fresh at each (re)computation (contract §3)."""
        if not hit.entity_hostname:
            return None, "none"
        row = await conn.fetchrow(RESOLVE_ASSET_SQL, tenant_id, hit.entity_hostname.lower())
        if row is None:
            return None, "none"
        return row["id"], row["agent_status"]

    async def _upsert_with_window(
        self,
        conn: Any,
        tenant_id: UUID,
        hit: DetectionHit,
        asset_id: UUID | None,
        score: PriorityScore,
    ) -> Any:
        for _attempt in range(3):
            row = await conn.fetchrow(
                ALERT_UPSERT_SQL,
                new_alert_id(),
                tenant_id,
                hit.rule_id,
                hit.rule_version,
                hit.title,
                hit.severity,
                hit.mitre_technique_ids,
                hit.entity_key,
                hit.entity_hostname,
                hit.entity_user,
                asset_id,
                hit.event_time,
                score.score,
                json.dumps(score.inputs),
                self._dedup_window,
            )
            if row is not None:
                return row
            # Open alert exists but its dedup window expired: close-out
            # semantics = new alert (design §5). The window predicate makes
            # this a no-op if a concurrent worker already touched it.
            closed = await conn.fetch(
                CLOSE_EXPIRED_OPEN_ALERT_SQL,
                tenant_id,
                hit.rule_id,
                hit.entity_key,
                hit.event_time,
                self._dedup_window,
            )
            for closed_row in closed:
                await self._history(
                    conn,
                    tenant_id,
                    closed_row["id"],
                    action="closed",
                    to_state="closed",
                    details={"reason": "dedup_window_expired"},
                )
        return None

    async def _correlate(
        self, conn: Any, tenant_id: UUID, hit: DetectionHit, alert_id: str
    ) -> str | None:
        """AC-43: same tenant+host, last_seen within window, different rule."""
        if not hit.entity_hostname:
            return None
        candidates = await conn.fetch(
            CORRELATION_CANDIDATES_SQL,
            tenant_id,
            hit.entity_hostname,
            hit.rule_id,
            alert_id,
            hit.event_time,
            self._correlation_window,
        )
        if not candidates:
            return None
        group_id = next(
            (c["correlation_group_id"] for c in candidates if c["correlation_group_id"]),
            None,
        )
        if group_id is None:
            group_id = new_correlation_group_id()
            await conn.execute(
                CREATE_CORRELATION_GROUP_SQL,
                group_id,
                tenant_id,
                hit.entity_hostname,
                hit.event_time,
            )
        to_assign = [alert_id] + [
            c["id"] for c in candidates if c["correlation_group_id"] is None
        ]
        assigned = await conn.fetch(
            ASSIGN_CORRELATION_GROUP_SQL, tenant_id, to_assign, group_id
        )
        await conn.execute(
            UPDATE_CORRELATION_GROUP_STATS_SQL, tenant_id, group_id, hit.event_time
        )
        for assigned_row in assigned:
            await self._history(
                conn,
                tenant_id,
                assigned_row["id"],
                action="correlated",
                details={"correlation_group_id": group_id},
            )
        return group_id

    async def _recompute_priority(
        self, conn: Any, tenant_id: UUID, hit: DetectionHit, row: Any
    ) -> None:
        _asset_id, agent_status = await self._resolve_asset(conn, tenant_id, hit)
        ai_severity = row["ai_severity"] if row["triage_status"] == "completed" else None
        score = compute_priority(
            rule_severity=row["rule_severity"],  # the ALERT's severity, not the hit's
            ai_severity=ai_severity,
            occurrence_count=row["occurrence_count"],
            agent_status=agent_status,
        )
        await conn.execute(
            UPDATE_PRIORITY_SQL, tenant_id, row["id"], score.score, json.dumps(score.inputs)
        )

    async def _history(
        self,
        conn: Any,
        tenant_id: UUID,
        alert_id: str,
        *,
        action: str,
        from_state: str | None = None,
        to_state: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        await conn.execute(
            INSERT_HISTORY_SQL,
            tenant_id,
            alert_id,
            "system",
            ACTOR_ID,
            action,
            from_state,
            to_state,
            json.dumps(details or {}),
        )


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    runtime = await build_runtime()
    stop = asyncio.Event()
    install_stop_signal_handlers(stop)
    metrics = PipelineMetrics()
    config = await load_platform_config(
        runtime.pool,
        {
            "alert_dedup_window_minutes": runtime.settings.alert_dedup_window_minutes,
            "correlation_window_minutes": runtime.settings.correlation_window_minutes,
        },
    )
    alerter = Alerter(
        pool=runtime.pool,
        producer=StreamProducer(runtime.redis),
        metrics=metrics,
        settings=runtime.settings,
        dedup_window_minutes=int(config["alert_dedup_window_minutes"]),
        correlation_window_minutes=int(config["correlation_window_minutes"]),
    )
    consumer = StreamConsumer(
        runtime.redis,
        stream=STREAM_DETECTIONS,
        group=CONSUMER_GROUP,
        consumer_name=runtime.settings.consumer_name,
        handler=alerter.handle,
        tenant_context=lambda msg: tenant_context(msg.tenant_id),
        dead_letter=make_pipeline_dead_letter_handler(
            runtime.pool, metrics=metrics, stage=STAGE
        ),
    )
    logger.info("worker-alerter starting (group=%s)", CONSUMER_GROUP)
    try:
        await consumer.run(stop=stop)
    finally:
        await runtime.close()
        logger.info("worker-alerter stopped")


if __name__ == "__main__":
    asyncio.run(main())
