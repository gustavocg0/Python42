"""Worker entrypoint units: mode selection (no network without a key),
payload handling, metrics outcomes, and the SafeEventFetcher degradation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from triage_fixtures import TENANT_A, new_trace

from dataplane.triage.config import TriageSettings
from dataplane.triage.context import EventRef
from dataplane.triage.llm import FakeTriageClient
from dataplane.workers.triager import SafeEventFetcher, build_handler, select_client
from soc_pipeline import ReceivedMessage

# ---------------------------------------------------------------------------
# select_client: never a network client without a key; fake mode wins
# ---------------------------------------------------------------------------


def test_no_key_no_fake_returns_none():
    settings = TriageSettings(api_key=None, fake_mode=False)
    assert select_client(settings) is None


def test_fake_mode_returns_fake_client_even_with_key():
    settings = TriageSettings(api_key="sk-test-not-real", fake_mode=True)
    assert isinstance(select_client(settings), FakeTriageClient)


def test_settings_from_env_reads_model_and_fake():
    settings = TriageSettings.from_env(
        {"TRIAGE_MODEL_ID": "claude-haiku-9", "TRIAGE_FAKE": "1", "TRIAGE_TIMEOUT_S": "12"}
    )
    assert settings.model_id == "claude-haiku-9"
    assert settings.fake_mode is True
    assert settings.timeout_s == 12.0
    assert settings.api_key is None


def test_default_model_is_env_overridable_haiku():
    assert TriageSettings.from_env({}).model_id == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# handler: payload contract + metrics
# ---------------------------------------------------------------------------


@dataclass
class FakeRunner:
    outcome_kind: str = "completed"
    calls: list[dict[str, Any]] | None = None

    async def run(self, **kwargs: Any):
        from dataplane.triage.graph import TriageOutcome

        if self.calls is None:
            self.calls = []
        self.calls.append(kwargs)
        return TriageOutcome(outcome=self.outcome_kind, reason=None, attempts=1)


class FakeMetrics:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


def make_message(payload: dict[str, Any]) -> ReceivedMessage:
    return ReceivedMessage(
        stream="pipe:alerts.triage",
        message_id="1-1",
        tenant_id=TENANT_A,
        trace_id=new_trace(),
        payload=payload,
        delivery_count=1,
    )


async def test_handler_extracts_alert_id_and_records_ok():
    runner, metrics = FakeRunner(), FakeMetrics()
    handle = build_handler(runner, metrics)
    await handle(make_message({"alert_id": "al_X", "rule_id": "ignored-extra"}))
    assert runner.calls[0]["alert_id"] == "al_X"
    assert runner.calls[0]["tenant_id"] == TENANT_A
    assert metrics.records[0]["outcome"] == "ok"
    assert str(metrics.records[0]["stage"]) == "triage"


async def test_handler_maps_unavailable_to_error_metric():
    runner, metrics = FakeRunner(outcome_kind="unavailable"), FakeMetrics()
    await build_handler(runner, metrics)(make_message({"alert_id": "al_X"}))
    assert metrics.records[0]["outcome"] == "error"


async def test_handler_rejects_payload_without_alert_id():
    runner, metrics = FakeRunner(), FakeMetrics()
    with pytest.raises(ValueError, match="alert_id"):
        await build_handler(runner, metrics)(make_message({"nope": 1}))
    assert not runner.calls  # never ran triage


# ---------------------------------------------------------------------------
# SafeEventFetcher: ES failure degrades to alert-only context
# ---------------------------------------------------------------------------


class ExplodingFetcher:
    async def fetch_events(self, tenant_id, refs):
        raise ConnectionError("es down")


async def test_event_fetch_failure_returns_empty_not_raise():
    safe = SafeEventFetcher(ExplodingFetcher())
    result = await safe.fetch_events(TENANT_A, [EventRef("e1", "idx")])
    assert result == []
