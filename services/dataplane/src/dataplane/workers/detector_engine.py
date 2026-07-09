"""Detection evaluation engine + SEC-28 runtime failure taxonomy (B-2).

Error taxonomy implemented here (design §5 rule row, BINDING):

(b) A runtime per-event evaluation exception is caught per (rule, event):
    the ``rule_eval_errors`` metric is incremented, the event is skipped for
    that rule ONLY, and the rule STAYS enabled — attacker-crafted events must
    never disable detection (threat model §2.5). All other rules continue.

(c) Auto-disable happens ONLY on a sustained failure fraction across
    MULTIPLE tenants (FailureTracker below), plus an ops review alert; the
    decision is persisted to tenantdata.rule_runtime_disables by the worker.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from dataplane.rulepub.compiler import schema_version_applies
from dataplane.workers.detector_pack import EnablementCache, LoadedPack

# SEC-28(c) defaults. fraction/min_tenants mirror control.platform_config
# seeds `rule_error_disable_fraction` = 0.05 and `rule_error_min_tenants` = 3
# (db/migrations/0009); they are plan-config knobs, overridable via env by
# the deployment (see detector.py).
DEFAULT_DISABLE_FRACTION = 0.05
DEFAULT_MIN_TENANTS = 3
DEFAULT_MIN_SAMPLES = 200
DEFAULT_WINDOW_SECONDS = 300.0
DEFAULT_BUCKET_COUNT = 10


@dataclass(frozen=True)
class DetectionHit:
    """One (rule, event) match — becomes a pipe:detections payload.

    entity_hostname/entity_user feed the alerter's dedup + correlation math
    (Architect integration ruling, 2026-07-08): hostname from the matched
    event's host.hostname when present; user from the event's user.name when
    the rule declares user.name in its entity list. Either may be None."""

    rule_id: str
    rule_version: str
    title: str
    severity: str
    mitre_technique_ids: tuple[str, ...]
    entity_key: str
    pack_version: str
    entity_hostname: str | None = None
    entity_user: str | None = None


@dataclass(frozen=True)
class EvalErrorRecord:
    rule_id: str
    error: str


@dataclass(frozen=True)
class DisableDecision:
    """A SEC-28(c) sustained-multi-tenant-failure assessment that crossed the
    threshold. Persisting it (rule_runtime_disables) is the worker's job."""

    rule_id: str
    error_fraction: float
    tenants_affected: int
    samples: int
    window_seconds: float


@dataclass
class EngineResult:
    hits: list[DetectionHit] = field(default_factory=list)
    eval_errors: list[EvalErrorRecord] = field(default_factory=list)
    disable_decisions: list[DisableDecision] = field(default_factory=list)
    rules_evaluated: int = 0


def _event_hostname(event: dict[str, Any]) -> str | None:
    """host.hostname from the matched event, when present (alerter contract)."""
    host = event.get("host")
    if isinstance(host, dict):
        hostname = host.get("hostname")
        if isinstance(hostname, str) and hostname:
            return hostname
    return None


def _entity_user(compiled: Any, event: dict[str, Any]) -> str | None:
    """user.name from the event, when the rule declares user.name in its
    entity list (alerter contract)."""
    if "user.name" not in getattr(compiled, "entity", ()):
        return None
    user = event.get("user")
    if isinstance(user, dict):
        name = user.get("name")
        if isinstance(name, str) and name:
            return name
    return None


class _Bucket:
    __slots__ = ("error_tenants", "errors", "evals", "start")

    def __init__(self, start: float) -> None:
        self.start = start
        self.evals = 0
        self.errors = 0
        self.error_tenants: set[str] = set()


class FailureTracker:
    """Sliding-window per-rule failure accounting for SEC-28(c).

    Threshold rationale (documented per detection-engineering rules):

    - ``disable_fraction`` (default 0.05) and ``min_tenants`` (default 3)
      mirror the platform_config seeds. Requiring MULTIPLE tenants means a
      single tenant — or a single attacker feeding one tenant crafted
      events — can NEVER disable a rule (SEC-28(b) protection); a genuine
      content defect in a published rule shows up across unrelated tenants
      almost immediately at any real event volume.
    - ``min_samples`` (default 200 evaluations inside the window) prevents
      auto-disable decisions on tiny volumes where a short burst of
      malformed events would dominate the fraction: with the 5% fraction,
      at least 10 independent errors across >= 3 tenants are needed before
      a disable can fire.
    - ``window_seconds`` (default 300, in 10 buckets of 30s) matches
      "sustained": errors must keep occurring across a 5-minute span, not
      one instant.

    A rule is flagged at most once per tracker lifetime (the PG row is the
    durable record; ON CONFLICT DO NOTHING makes duplicates harmless).
    """

    def __init__(
        self,
        *,
        disable_fraction: float = DEFAULT_DISABLE_FRACTION,
        min_tenants: int = DEFAULT_MIN_TENANTS,
        min_samples: int = DEFAULT_MIN_SAMPLES,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        bucket_count: int = DEFAULT_BUCKET_COUNT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if disable_fraction <= 0 or min_tenants < 2:
            raise ValueError(
                "SEC-28(c) requires a positive fraction and min_tenants >= 2 "
                "(multi-tenant by definition)"
            )
        self._fraction = disable_fraction
        self._min_tenants = min_tenants
        self._min_samples = min_samples
        self._window = window_seconds
        self._bucket_width = window_seconds / bucket_count
        self._clock = clock
        self._buckets: dict[str, deque[_Bucket]] = {}
        self._flagged: set[str] = set()

    def record(
        self, rule_id: str, tenant_id: str, *, error: bool
    ) -> DisableDecision | None:
        """Record one evaluation outcome; returns a decision when a rule
        first crosses the sustained multi-tenant threshold."""
        now = self._clock()
        buckets = self._buckets.setdefault(rule_id, deque())
        cutoff = now - self._window
        while buckets and buckets[0].start < cutoff:
            buckets.popleft()
        bucket_start = now - (now % self._bucket_width)
        if not buckets or buckets[-1].start != bucket_start:
            buckets.append(_Bucket(bucket_start))
        bucket = buckets[-1]
        bucket.evals += 1
        if not error:
            return None
        bucket.errors += 1
        bucket.error_tenants.add(tenant_id)

        if rule_id in self._flagged:
            return None
        samples = sum(b.evals for b in buckets)
        errors = sum(b.errors for b in buckets)
        tenants: set[str] = set()
        for b in buckets:
            tenants |= b.error_tenants
        if samples < self._min_samples:
            return None
        fraction = errors / samples
        if fraction < self._fraction or len(tenants) < self._min_tenants:
            return None
        self._flagged.add(rule_id)
        return DisableDecision(
            rule_id=rule_id,
            error_fraction=round(fraction, 6),
            tenants_affected=len(tenants),
            samples=samples,
            window_seconds=self._window,
        )


class DetectorEngine:
    """Evaluates the loaded pack against one normalized event at a time.

    Stateless per event (§5.1): no rule sees prior events, wall-clock time,
    counters, or other tenants; ``tenant_id`` only scopes the enablement
    overlay and travels with the hit.
    """

    def __init__(
        self,
        *,
        enablement: EnablementCache,
        tracker: FailureTracker | None = None,
        on_eval_error: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._enablement = enablement
        self._tracker = tracker
        self._on_eval_error = on_eval_error

    async def evaluate_event(
        self, *, pack: LoadedPack, event: Any, tenant_id: str
    ) -> EngineResult:
        result = EngineResult()
        if not isinstance(event, dict):
            return result
        for rule in pack.candidates(event.get("event_class")):
            compiled = rule.compiled
            # §5.1 gate 2: same MAJOR, event schema_version >= rule minimum.
            if not schema_version_applies(compiled.min_schema, event.get("schema_version")):
                continue
            # §5.1 gate 3 (AC-38): pack default minus runtime disables minus toggles.
            if not await self._enablement.is_enabled(rule, tenant_id):
                continue
            result.rules_evaluated += 1
            error = False
            try:
                if compiled.matches_condition(event):
                    result.hits.append(
                        DetectionHit(
                            rule_id=compiled.rule_id,
                            rule_version=compiled.version,
                            title=compiled.title,
                            severity=compiled.severity,
                            mitre_technique_ids=compiled.mitre_technique_ids,
                            entity_key=compiled.entity_key(event),
                            pack_version=pack.pack_version,
                            entity_hostname=_event_hostname(event),
                            entity_user=_entity_user(compiled, event),
                        )
                    )
            except Exception as exc:  # SEC-28(b): per-(rule,event) isolation
                error = True
                detail = f"{type(exc).__name__}: {exc}"
                result.eval_errors.append(EvalErrorRecord(rule_id=compiled.rule_id, error=detail))
                if self._on_eval_error is not None:
                    self._on_eval_error(compiled.rule_id, tenant_id, detail)
            if self._tracker is not None:
                decision = self._tracker.record(compiled.rule_id, tenant_id, error=error)
                if decision is not None:
                    result.disable_decisions.append(decision)
        return result


__all__ = [
    "DEFAULT_DISABLE_FRACTION",
    "DEFAULT_MIN_SAMPLES",
    "DEFAULT_MIN_TENANTS",
    "DEFAULT_WINDOW_SECONDS",
    "DetectionHit",
    "DetectorEngine",
    "DisableDecision",
    "EngineResult",
    "EvalErrorRecord",
    "FailureTracker",
]
