"""Model pricing table for metering cost computation (AC-51).

USD per million tokens, keyed by model id (prefix match so dated snapshots
resolve). Overridable without a deploy via TRIAGE_PRICING_JSON, e.g.:

    TRIAGE_PRICING_JSON='{"claude-haiku-4-5": {"in": 1.0, "out": 5.0}}'

Unknown models fall back to the default rates (never 0 — spend must always
be visible in metering, SEC-37/AC-51).
"""

from __future__ import annotations

import json
import os
from decimal import Decimal

ENV_PRICING_JSON = "TRIAGE_PRICING_JSON"

# USD per 1M tokens: (input, output).
_DEFAULT_PRICES: dict[str, tuple[Decimal, Decimal]] = {
    "claude-haiku-4-5": (Decimal("1.00"), Decimal("5.00")),
    "claude-sonnet-4-5": (Decimal("3.00"), Decimal("15.00")),
    "fake-triage": (Decimal("0"), Decimal("0")),
}

_FALLBACK = (Decimal("3.00"), Decimal("15.00"))

_MTOK = Decimal(1_000_000)


def _table(env: dict[str, str] | None = None) -> dict[str, tuple[Decimal, Decimal]]:
    e = os.environ if env is None else env
    table = dict(_DEFAULT_PRICES)
    raw = e.get(ENV_PRICING_JSON)
    if raw:
        for model, rates in json.loads(raw).items():
            table[model] = (Decimal(str(rates["in"])), Decimal(str(rates["out"])))
    return table


def cost_usd(
    model_id: str,
    tokens_in: int,
    tokens_out: int,
    *,
    env: dict[str, str] | None = None,
) -> Decimal:
    """Cost of one call in USD (Decimal, 6 dp — matches llm_metering numeric)."""
    table = _table(env)
    rates = _FALLBACK
    for prefix in sorted(table, key=len, reverse=True):
        if model_id.startswith(prefix):
            rates = table[prefix]
            break
    raw = (Decimal(tokens_in) * rates[0] + Decimal(tokens_out) * rates[1]) / _MTOK
    return raw.quantize(Decimal("0.000001"))
