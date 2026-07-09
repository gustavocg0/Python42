"""LLM clients for triage: real Anthropic client + deterministic fake.

- ZERO tools are ever passed to the model (SEC-35) — prompt-in/JSON-out only.
- The real client is used only when ANTHROPIC_API_KEY is present; tests and
  TRIAGE_FAKE=1 runs never touch the network.
- Prompts/completions are never logged here (SEC-38); callers log metadata only.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Protocol


class TriageLLMError(RuntimeError):
    """Model call failed (API/transport error). Retryable up to AC-50 limits."""


class TriageLLMTimeout(TriageLLMError):
    """Model call exceeded the per-call timeout (AC-50: 30s)."""


@dataclass(frozen=True, slots=True)
class Grounding:
    """Non-secret hints for the FAKE client only (ignored by the real one)."""

    hostname: str | None
    user: str | None
    rule_severity: str
    occurrence_count: int
    last_seen: str


@dataclass(frozen=True, slots=True)
class LLMResult:
    text: str
    model_id: str
    tokens_in: int
    tokens_out: int
    latency_ms: int


class TriageLLMClient(Protocol):
    async def complete(
        self,
        *,
        system: str,
        user: str,
        model_id: str,
        max_tokens: int,
        temperature: float,
        timeout_s: float,
        grounding: Grounding | None = None,
    ) -> LLMResult: ...


class AnthropicTriageClient:
    """Thin wrapper over the Anthropic SDK. No tools, no streaming, no state."""

    def __init__(self, api_key: str) -> None:
        import anthropic  # deferred: never imported in fake/test paths

        self._client = anthropic.AsyncAnthropic(api_key=api_key, max_retries=0)

    async def complete(
        self,
        *,
        system: str,
        user: str,
        model_id: str,
        max_tokens: int,
        temperature: float,
        timeout_s: float,
        grounding: Grounding | None = None,
    ) -> LLMResult:
        del grounding  # real client uses only the assembled prompt
        started = time.perf_counter()
        try:
            response = await asyncio.wait_for(
                self._client.messages.create(
                    model=model_id,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    # SEC-35: no `tools` argument, ever.
                ),
                timeout=timeout_s,
            )
        except TimeoutError as exc:
            raise TriageLLMTimeout(f"model call exceeded {timeout_s}s") from exc
        except Exception as exc:  # SDK errors: APIError, connection, etc.
            raise TriageLLMError(f"{type(exc).__name__}: {exc}") from exc
        latency_ms = int((time.perf_counter() - started) * 1000)
        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        return LLMResult(
            text=text,
            model_id=response.model,
            tokens_in=response.usage.input_tokens,
            tokens_out=response.usage.output_tokens,
            latency_ms=latency_ms,
        )


_TIME_RE = re.compile(r"[T ](\d{2}):(\d{2})")

FAKE_MODEL_ID = "fake-triage-v1"


def _fake_summary(g: Grounding) -> str:
    """Deterministic, validator-passing three-line summary (TRIAGE_FAKE=1)."""
    m = _TIME_RE.search(g.last_seen)
    when = f"{m.group(1)}:{m.group(2)}" if m else "00:00"
    device = f"the computer {g.hostname}" if g.hostname else "one of your devices"
    device_ref = g.hostname if g.hostname else "the device"

    happened = (
        f"What happened: We flagged activity on {device} at {when} UTC that matched"
        " one of our detection rules."
    )
    if g.user:
        happened += f" The activity ran under the account {g.user}."
    if g.occurrence_count > 1:
        happened += f" This happened {g.occurrence_count} times."

    matters = (
        "Why it matters: This kind of activity can be a sign of an attacker at work,"
        " but everyday software and IT tools can also cause it."
    )

    if g.user:
        action = (
            f"Do this next: Ask {g.user} whether they recognize this activity around"
            f" {when} UTC. If not, disconnect {device_ref} from the network and call"
            " your IT provider."
        )
    else:
        action = (
            "Do this next: Check whether your IT tools explain this activity around"
            f" {when} UTC. If not, disconnect {device_ref} from the network and call"
            " your IT provider."
        )
    return "\n".join((happened, matters, action))


class FakeTriageClient:
    """Deterministic fake LLM for compose demos / e2e without keys or cost.

    Produces a valid summary grounded in the alert entity and echoes the rule
    severity as ai_severity (deterministic, sensible for demos).
    """

    async def complete(
        self,
        *,
        system: str,
        user: str,
        model_id: str,
        max_tokens: int,
        temperature: float,
        timeout_s: float,
        grounding: Grounding | None = None,
    ) -> LLMResult:
        if grounding is None:
            raise TriageLLMError("FakeTriageClient requires grounding")
        import json

        text = json.dumps(
            {"summary": _fake_summary(grounding), "ai_severity": grounding.rule_severity}
        )
        return LLMResult(
            text=text,
            model_id=FAKE_MODEL_ID,
            tokens_in=max(1, len(user) // 4),
            tokens_out=max(1, len(text) // 4),
            latency_ms=1,
        )
