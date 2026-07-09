"""Context assembly + prompt structure tests (SEC-32/33/36, AC-52)."""

from __future__ import annotations

import re

import pytest
from triage_fixtures import (
    TENANT_A,
    TENANT_B,
    DictAlertFetcher,
    DictEventFetcher,
    make_alert,
)

from dataplane.triage.context import (
    AlertContext,
    assemble_context,
    build_prompt,
    trim_event,
)


async def _assemble(fetcher, events, tenant, alert_id):
    return await assemble_context(
        tenant_id=tenant,
        alert_id=alert_id,
        alerts=fetcher,
        events=events,
        max_events=5,
        max_field_chars=256,
    )


# ---------------------------------------------------------------------------
# AC-52 — cross-tenant isolation, proven with marker strings
# ---------------------------------------------------------------------------


async def test_tenant_a_context_never_reaches_tenant_b_prompt():
    marker_a = "MARKER-TENANT-A-cafe0001-SECRET-CMDLINE"
    marker_b = "MARKER-TENANT-B-beef0002-SECRET-CMDLINE"

    fetcher = DictAlertFetcher()
    fetcher.add(make_alert(tenant_id=TENANT_A, alert_id="al_A", hostname=f"host-a-{1}"))
    fetcher.add(make_alert(tenant_id=TENANT_B, alert_id="al_B", hostname=f"host-b-{2}"))
    events = DictEventFetcher()
    events.bodies[TENANT_A] = [{"process": {"cmd_line": marker_a}}]
    events.bodies[TENANT_B] = [{"process": {"cmd_line": marker_b}}]
    # refs must exist for bodies to be fetched
    from dataplane.triage.context import EventRef

    fetcher.refs[(TENANT_A, "al_A")] = [EventRef("e1", "events-v1-a-2026.07")]
    fetcher.refs[(TENANT_B, "al_B")] = [EventRef("e2", "events-v1-b-2026.07")]

    ctx_a = await _assemble(fetcher, events, TENANT_A, "al_A")
    ctx_b = await _assemble(fetcher, events, TENANT_B, "al_B")
    prompt_a = build_prompt(ctx_a)
    prompt_b = build_prompt(ctx_b)

    assert marker_a in prompt_a.user
    assert marker_b in prompt_b.user
    # release gate (SEC-36): tenant A data never in tenant B's prompt, and vice versa
    assert marker_a not in prompt_b.user
    assert marker_b not in prompt_a.user
    assert marker_a not in prompt_b.system and marker_b not in prompt_a.system


async def test_alert_ids_do_not_leak_across_tenants():
    fetcher = DictAlertFetcher()
    fetcher.add(make_alert(tenant_id=TENANT_A, alert_id="al_ONLY_A"))
    events = DictEventFetcher()
    # tenant B asks for tenant A's alert id -> nothing (tenant-scoped fetcher)
    assert await _assemble(fetcher, events, TENANT_B, "al_ONLY_A") is None


# ---------------------------------------------------------------------------
# SEC-32 — fenced untrusted block, static system prompt
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx() -> AlertContext:
    return AlertContext(
        tenant_id=TENANT_A,
        alert=make_alert(),
        events=({"process": {"cmd_line": "powershell -nop"}},),
    )


def test_prompt_fences_untrusted_data(ctx):
    prompt = build_prompt(ctx)
    begin = f"<<<BEGIN-UNTRUSTED-TELEMETRY-{prompt.boundary}>>>"
    end = f"<<<END-UNTRUSTED-TELEMETRY-{prompt.boundary}>>>"
    assert begin in prompt.user and end in prompt.user
    # all alert/event-derived content sits INSIDE the fence
    inside = prompt.user.split(begin)[1].split(end)[0]
    assert "fin-laptop-07" in inside
    assert "powershell -nop" in inside
    before = prompt.user.split(begin)[0]
    after = prompt.user.split(end)[1]
    assert "fin-laptop-07" not in before + after
    # explicit data-not-instructions framing
    assert "not instructions" in prompt.user


def test_boundary_is_random_per_call(ctx):
    assert build_prompt(ctx).boundary != build_prompt(ctx).boundary


def test_system_prompt_is_static_and_tenant_free(ctx):
    prompt = build_prompt(ctx)
    # the system prompt is EXACTLY the versioned repo file — no runtime data
    # is ever concatenated into it (SEC-32). (§1.9 few-shot names like
    # fin-laptop-07 appear in it as static fixtures, which is fine.)
    from dataplane.triage.prompts import load_system_prompt

    assert prompt.system == load_system_prompt()
    assert str(TENANT_A) not in prompt.system
    assert ctx.alert.id not in prompt.system


def test_prompt_grounds_rule_and_entity(ctx):
    prompt = build_prompt(ctx)
    assert "Suspicious encoded PowerShell" in prompt.user  # rule title
    assert '"rule_severity":"high"' in prompt.user
    assert "T1059.001" in prompt.user
    assert "sam.jones" in prompt.user


def test_correction_is_appended_only_on_regeneration(ctx):
    plain = build_prompt(ctx)
    corrected = build_prompt(ctx, correction="jargon: banned term (C2)")
    assert "rejected by the format validator" not in plain.user
    assert "jargon: banned term (C2)" in corrected.user


# ---------------------------------------------------------------------------
# SEC-33 — event trimming caps
# ---------------------------------------------------------------------------


def test_trim_caps_long_fields():
    event = {"process": {"cmd_line": "x" * 5000}}
    trimmed = trim_event(event, max_chars=256)
    assert len(trimmed["process"]["cmd_line"]) <= 256 + len("…[truncated]")


def test_trim_drops_raw_and_unmapped():
    event = {"message": "hello", "raw": {"blob": "x"}, "unmapped": {"y": 1}}
    trimmed = trim_event(event, max_chars=256)
    assert "raw" not in trimmed and "unmapped" not in trimmed
    assert trimmed["message"] == "hello"


def test_trim_scrubs_base64_blobs():
    blob = "QQ" * 64  # 128 chars of base64-ish content
    trimmed = trim_event({"process": {"cmd_line": f"powershell -enc {blob}"}}, max_chars=256)
    assert blob not in trimmed["process"]["cmd_line"]
    assert "[blob-removed]" in trimmed["process"]["cmd_line"]


async def test_event_count_is_capped():
    fetcher = DictAlertFetcher()
    alert = make_alert()
    from dataplane.triage.context import EventRef

    fetcher.add(alert, [EventRef(f"e{i}", "idx") for i in range(20)])
    events = DictEventFetcher()
    events.bodies[TENANT_A] = [{"n": i} for i in range(20)]
    ctx = await _assemble(fetcher, events, TENANT_A, alert.id)
    assert len(ctx.events) <= 5


def test_boundary_marker_format(ctx):
    assert re.fullmatch(r"[0-9a-f]{16}", build_prompt(ctx).boundary)
