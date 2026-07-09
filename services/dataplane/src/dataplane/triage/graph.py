"""The triage LangGraph: assemble -> generate -> validate -> persist.

Properties (binding):
- ZERO tools anywhere in the graph — prompt-in/JSON-out only (SEC-35);
- one alert, one tenant per invocation; context comes only from
  tenant-scoped fetchers (SEC-36); no checkpointer, no cross-run state;
- AC-50 resilience: 30s per model call (inside the client), at most
  `max_attempts` (3) API calls with backoff; a validation-failure
  regeneration happens at most ONCE and consumes an attempt; any terminal
  failure => triage_status=unavailable, priority stays rule-derived, alert
  delivery is never blocked (the alert is already in the queue — we UPDATE);
- SEC-37 budget backstop checked before any model call;
- every call attempt is metered, including failures (AC-51);
- every decision is traceable: structured logs carry tenant_id, trace_id,
  alert_id, attempt, outcome, reason — never prompt/completion text (SEC-38).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph

from dataplane.triage.budget import TriageBudget
from dataplane.triage.config import TriageSettings
from dataplane.triage.context import (
    AlertContext,
    AlertFetcher,
    EventFetcher,
    assemble_context,
    build_prompt,
)
from dataplane.triage.llm import (
    Grounding,
    TriageLLMClient,
    TriageLLMError,
    TriageLLMTimeout,
)
from dataplane.triage.metering import LLMMeter, MeterRecord
from dataplane.triage.persist import TriagePersister
from dataplane.triage.pricing import cost_usd
from dataplane.triage.validator import (
    OutputParseError,
    parse_model_output,
    validate_summary,
)

logger = logging.getLogger(__name__)

OutcomeKind = Literal["completed", "unavailable", "skipped"]


@dataclass(frozen=True, slots=True)
class TriageOutcome:
    outcome: OutcomeKind
    reason: str | None
    attempts: int


class TriageState(TypedDict, total=False):
    tenant_id: UUID
    trace_id: str
    alert_id: str
    ctx: AlertContext | None
    attempts: int
    regenerations: int
    correction: str | None
    llm_ok: bool
    llm_failure: str | None  # 'timeout' | 'error'
    raw_text: str | None
    result_model_id: str | None
    summary: str | None
    ai_severity: str | None
    outcome: OutcomeKind
    reason: str | None


class TriageRunner:
    """Owns the compiled graph plus injected, mockable dependencies."""

    def __init__(
        self,
        *,
        settings: TriageSettings,
        alerts: AlertFetcher,
        events: EventFetcher,
        client: TriageLLMClient | None,
        budget: TriageBudget,
        meter: LLMMeter,
        persister: TriagePersister,
        sleep: Any = asyncio.sleep,
    ) -> None:
        self._settings = settings
        self._alerts = alerts
        self._events = events
        self._client = client  # None => dev mode without API key (AC-50 fallback)
        self._budget = budget
        self._meter = meter
        self._persister = persister
        self._sleep = sleep
        self._graph = self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> Any:
        g: StateGraph = StateGraph(TriageState)
        g.add_node("assemble", self._node_assemble)
        g.add_node("generate", self._node_generate)
        g.add_node("validate", self._node_validate)
        g.add_node("persist", self._node_persist)
        g.add_edge(START, "assemble")
        g.add_conditional_edges(
            "assemble",
            lambda s: "persist" if s.get("outcome") else "generate",
            {"persist": "persist", "generate": "generate"},
        )
        g.add_conditional_edges(
            "generate",
            self._route_after_generate,
            {"validate": "validate", "generate": "generate", "persist": "persist"},
        )
        g.add_conditional_edges(
            "validate",
            lambda s: "persist" if s.get("outcome") else "generate",
            {"persist": "persist", "generate": "generate"},
        )
        g.add_edge("persist", END)
        return g.compile()  # SEC-35: no tools bound anywhere in this graph

    # ------------------------------------------------------------------ nodes

    async def _node_assemble(self, state: TriageState) -> TriageState:
        tenant_id, alert_id = state["tenant_id"], state["alert_id"]
        ctx = await assemble_context(
            tenant_id=tenant_id,
            alert_id=alert_id,
            alerts=self._alerts,
            events=self._events,
            max_events=self._settings.max_events,
            max_field_chars=self._settings.max_field_chars,
        )
        if ctx is None:
            return {"ctx": None, "outcome": "skipped", "reason": "alert_not_found"}
        if ctx.alert.triage_status != "pending":
            # At-least-once redelivery of an already-terminal alert: idempotent skip.
            return {"ctx": ctx, "outcome": "skipped", "reason": "already_terminal"}
        if self._client is None:
            return {"ctx": ctx, "outcome": "unavailable", "reason": "no_api_key"}

        budget = await self._budget.state(tenant_id)
        if budget.exceeded:
            # SEC-37 backstop: no model call; metered as over_budget; ops alert.
            await self._meter.record(
                MeterRecord(
                    tenant_id=tenant_id,
                    alert_id=alert_id,
                    model_id=self._settings.model_id,
                    tokens_in=0,
                    tokens_out=0,
                    cost_usd=Decimal("0"),
                    latency_ms=None,
                    outcome="over_budget",
                    endpoint_region=self._settings.endpoint_region,
                )
            )
            logger.warning(
                "triage budget exceeded — skipping LLM call",
                extra={
                    "event": "triage_budget_exceeded",
                    "tenant_id": str(tenant_id),
                    "alert_id": alert_id,
                    "trace_id": state.get("trace_id"),
                    "spent_tokens": budget.spent_tokens,
                    "cap_tokens": budget.cap_tokens,
                },
            )
            return {"ctx": ctx, "outcome": "unavailable", "reason": "budget"}
        return {"ctx": ctx}

    async def _node_generate(self, state: TriageState) -> TriageState:
        ctx = state["ctx"]
        assert ctx is not None and self._client is not None
        attempt = state.get("attempts", 0) + 1
        if attempt > 1:
            await self._sleep(self._settings.backoff_base_s * (attempt - 1))

        prompt = build_prompt(ctx, correction=state.get("correction"))
        grounding = Grounding(
            hostname=ctx.alert.entity_hostname,
            user=ctx.alert.entity_user,
            rule_severity=ctx.alert.rule_severity,
            occurrence_count=ctx.alert.occurrence_count,
            last_seen=ctx.alert.last_seen,
        )
        update: TriageState = {"attempts": attempt, "raw_text": None, "llm_ok": False}
        try:
            result = await self._client.complete(
                system=prompt.system,
                user=prompt.user,
                model_id=self._settings.model_id,
                max_tokens=self._settings.max_tokens,
                temperature=self._settings.temperature,
                timeout_s=self._settings.timeout_s,
                grounding=grounding,
            )
        except TriageLLMTimeout as exc:
            await self._record_failed_call(state, outcome="timeout")
            self._log_attempt(state, attempt, "timeout", detail=str(exc))
            return self._after_failed_call(update, attempt, "timeout")
        except TriageLLMError as exc:
            await self._record_failed_call(state, outcome="error")
            self._log_attempt(state, attempt, "error", detail=str(exc))
            return self._after_failed_call(update, attempt, "error")

        tokens = result.tokens_in + result.tokens_out
        await self._meter.record(
            MeterRecord(
                tenant_id=state["tenant_id"],
                alert_id=state["alert_id"],
                model_id=result.model_id,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                cost_usd=cost_usd(result.model_id, result.tokens_in, result.tokens_out),
                latency_ms=result.latency_ms,
                outcome="ok",
                endpoint_region=self._settings.endpoint_region,
            )
        )
        await self._budget.add(state["tenant_id"], tokens)
        self._log_attempt(state, attempt, "ok", detail=None)
        update.update(
            {"llm_ok": True, "llm_failure": None, "raw_text": result.text,
             "result_model_id": result.model_id}
        )
        return update

    async def _node_validate(self, state: TriageState) -> TriageState:
        ctx = state["ctx"]
        assert ctx is not None
        raw = state.get("raw_text") or ""
        errors: tuple[str, ...]
        try:
            parsed = parse_model_output(raw)
        except OutputParseError as exc:
            errors = (f"parse: {exc}",)
        else:
            result = validate_summary(
                parsed.summary,
                entity_hostname=ctx.alert.entity_hostname,
                entity_user=ctx.alert.entity_user,
            )
            if result.ok:
                return {
                    "summary": parsed.summary,
                    "ai_severity": parsed.ai_severity,
                    "outcome": "completed",
                    "reason": None,
                }
            errors = result.errors

        logger.info(
            "triage output failed validation",
            extra={
                "event": "triage_validation_failed",
                "tenant_id": str(state["tenant_id"]),
                "alert_id": state["alert_id"],
                "trace_id": state.get("trace_id"),
                "attempt": state.get("attempts", 0),
                "errors": list(errors),  # our labels only, no model text (SEC-38)
            },
        )
        regenerations = state.get("regenerations", 0)
        if regenerations < 1 and state.get("attempts", 0) < self._settings.max_attempts:
            # ux-alert-style §1.8: regenerate ONCE with our error labels.
            return {"regenerations": regenerations + 1, "correction": "; ".join(errors)}
        return {"outcome": "unavailable", "reason": "validation_failed"}

    async def _node_persist(self, state: TriageState) -> TriageState:
        outcome = state["outcome"]
        if outcome == "completed":
            ctx = state["ctx"]
            assert ctx is not None
            await self._persister.persist_completed(
                tenant_id=state["tenant_id"],
                alert=ctx.alert,
                summary=state["summary"] or "",
                ai_severity=state["ai_severity"] or "",  # RAW (clamp inside scoring)
                model_id=state.get("result_model_id") or self._settings.model_id,
                attempts=state.get("attempts", 0),
            )
        elif outcome == "unavailable":
            await self._persister.persist_unavailable(
                tenant_id=state["tenant_id"],
                alert_id=state["alert_id"],
                attempts=state.get("attempts", 0),
                reason=state.get("reason") or "unknown",
            )
        # 'skipped': nothing to write (idempotent redelivery / stale message).
        return {}

    # ------------------------------------------------------------------ routing

    @staticmethod
    def _route_after_generate(state: TriageState) -> str:
        if state.get("llm_ok"):
            return "validate"
        if state.get("outcome"):  # attempts exhausted (set in the generate node)
            return "persist"
        return "generate"

    # ------------------------------------------------------------------ helpers

    def _after_failed_call(
        self, update: TriageState, attempt: int, kind: Literal["error", "timeout"]
    ) -> TriageState:
        update["llm_failure"] = kind
        if attempt >= self._settings.max_attempts:
            update["outcome"] = "unavailable"  # AC-50: terminal after 3 attempts
            update["reason"] = f"llm_{kind}"
        return update

    async def _record_failed_call(
        self, state: TriageState, *, outcome: Literal["error", "timeout"]
    ) -> None:
        await self._meter.record(
            MeterRecord(
                tenant_id=state["tenant_id"],
                alert_id=state["alert_id"],
                model_id=self._settings.model_id,
                tokens_in=0,
                tokens_out=0,
                cost_usd=Decimal("0"),
                latency_ms=int(self._settings.timeout_s * 1000) if outcome == "timeout" else None,
                outcome=outcome,
                endpoint_region=self._settings.endpoint_region,
            )
        )

    def _log_attempt(
        self, state: TriageState, attempt: int, call_outcome: str, *, detail: str | None
    ) -> None:
        logger.info(
            "triage model call",
            extra={
                "event": "triage_model_call",
                "tenant_id": str(state["tenant_id"]),
                "alert_id": state["alert_id"],
                "trace_id": state.get("trace_id"),
                "attempt": attempt,
                "call_outcome": call_outcome,
                "model_id": self._settings.model_id,
                "detail": detail,
            },
        )

    # ------------------------------------------------------------------ api

    async def run(self, *, tenant_id: UUID, trace_id: str, alert_id: str) -> TriageOutcome:
        """Triage one alert for one tenant. Raises only on persistence errors
        (so the stream consumer retries/DLQs the message, AC-91)."""
        initial: TriageState = {
            "tenant_id": tenant_id,
            "trace_id": trace_id,
            "alert_id": alert_id,
            "attempts": 0,
            "regenerations": 0,
        }
        final = await self._graph.ainvoke(initial)
        outcome = TriageOutcome(
            outcome=final.get("outcome", "unavailable"),
            reason=final.get("reason"),
            attempts=final.get("attempts", 0),
        )
        logger.info(
            "triage finished",
            extra={
                "event": "triage_finished",
                "tenant_id": str(tenant_id),
                "alert_id": alert_id,
                "trace_id": trace_id,
                "outcome": outcome.outcome,
                "reason": outcome.reason,
                "attempts": outcome.attempts,
            },
        )
        return outcome
