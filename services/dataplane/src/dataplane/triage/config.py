"""Triage worker configuration — every knob env-overridable, safe defaults.

SEC-37: the daily budget backstop is a per-tenant TOKEN budget (matching the
binding `budget:triage:{t}:{yyyymmdd}` counter in db/redis-conventions.md);
the platform_config key `triage_daily_token_budget` is expected to feed
TRIAGE_DAILY_TOKEN_BUDGET at deploy time (generous default here).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL_ID = "claude-haiku-4-5-20251001"

ENV_MODEL_ID = "TRIAGE_MODEL_ID"
ENV_MAX_TOKENS = "TRIAGE_MAX_TOKENS"
ENV_TEMPERATURE = "TRIAGE_TEMPERATURE"
ENV_TIMEOUT_S = "TRIAGE_TIMEOUT_S"
ENV_MAX_ATTEMPTS = "TRIAGE_MAX_ATTEMPTS"
ENV_MAX_EVENTS = "TRIAGE_MAX_EVENTS"
ENV_MAX_FIELD_CHARS = "TRIAGE_MAX_FIELD_CHARS"
ENV_DAILY_TOKEN_BUDGET = "TRIAGE_DAILY_TOKEN_BUDGET"  # noqa: S105 - env var name, not a secret
ENV_BACKOFF_BASE_S = "TRIAGE_BACKOFF_BASE_S"
ENV_FAKE = "TRIAGE_FAKE"
ENV_ENDPOINT_REGION = "TRIAGE_ENDPOINT_REGION"
ENV_ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"


@dataclass(frozen=True, slots=True)
class TriageSettings:
    """All runtime knobs for the triage graph (model routing is config, not code)."""

    model_id: str = DEFAULT_MODEL_ID
    max_tokens: int = 1024  # bounded output (SEC-33); summary is ~120 words
    temperature: float = 0.2  # low: deterministic-ish, structured output
    timeout_s: float = 30.0  # AC-50: 30s per model call
    max_attempts: int = 3  # AC-50: <=3 API calls total (incl. regeneration)
    max_events: int = 5  # SEC-33: bounded context
    max_field_chars: int = 256  # SEC-33: per-field cap in the untrusted block
    daily_token_budget: int = 2_000_000  # SEC-37 backstop (tokens in+out/tenant/day)
    backoff_base_s: float = 2.0  # attempt N waits base * N seconds
    fake_mode: bool = False  # TRIAGE_FAKE=1 -> deterministic fake LLM
    endpoint_region: str | None = None  # llm_metering.endpoint_region (CR-2)
    api_key: str | None = field(default=None, repr=False)  # never logged

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> TriageSettings:
        e = os.environ if env is None else env
        return cls(
            model_id=e.get(ENV_MODEL_ID, DEFAULT_MODEL_ID),
            max_tokens=int(e.get(ENV_MAX_TOKENS, "1024")),
            temperature=float(e.get(ENV_TEMPERATURE, "0.2")),
            timeout_s=float(e.get(ENV_TIMEOUT_S, "30")),
            max_attempts=int(e.get(ENV_MAX_ATTEMPTS, "3")),
            max_events=int(e.get(ENV_MAX_EVENTS, "5")),
            max_field_chars=int(e.get(ENV_MAX_FIELD_CHARS, "256")),
            daily_token_budget=int(e.get(ENV_DAILY_TOKEN_BUDGET, "2000000")),
            backoff_base_s=float(e.get(ENV_BACKOFF_BASE_S, "2.0")),
            fake_mode=e.get(ENV_FAKE, "") in ("1", "true", "yes"),
            endpoint_region=e.get(ENV_ENDPOINT_REGION) or None,
            api_key=e.get(ENV_ANTHROPIC_API_KEY) or None,
        )
