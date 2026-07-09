"""Validator tests: every ux-alert-style §1.8 rule + the §1.9 canonical fixtures."""

from __future__ import annotations

import json

import pytest

from dataplane.triage.validator import (
    OutputParseError,
    parse_model_output,
    validate_summary,
)

# ---------------------------------------------------------------------------
# §1.9 canonical examples MUST pass (they are the QA pattern targets)
# ---------------------------------------------------------------------------

EXAMPLE_A = (
    "What happened: The computer fin-laptop-07 ran a PowerShell command at 09:42 UTC "
    "under the account sam.jones. The command was disguised so its contents could not "
    "be read directly, which is a common way to hide malicious activity.\n"
    "Why it matters: Normal software rarely hides its commands this way. If an attacker "
    "ran this, they may already have remote control of this computer.\n"
    "Do this next: Ask sam.jones whether they or your IT tools ran a script around "
    "09:42 UTC. If not, disconnect fin-laptop-07 from the network now and change "
    "sam.jones's password."
)

EXAMPLE_B = (
    "What happened: The account m.rivera on the computer hr-desktop-02 had 24 failed "
    "sign-in attempts between 14:05 and 14:15 UTC. No sign-in succeeded during or after "
    "the attempts.\n"
    "Why it matters: Many failures in a short burst usually means a person or automated "
    "tool is guessing the password. Since none succeeded, there is no sign of a break-in "
    "yet.\n"
    "Do this next: Ask m.rivera whether they had password trouble around 14:05 UTC. If "
    "they did not, change their password and watch this account for new alerts over the "
    "next few days."
)

EXAMPLE_C = (
    "What happened: The computer ops-server-01 ran 'whoami' at 03:12 UTC under the "
    "account svc-backup, which looks like an automated service account. This built-in "
    "Windows command shows which account is signed in and what it can access.\n"
    "Why it matters: Admins and scheduled jobs use this command every day, but attackers "
    "also run it early on to learn what access they have. On its own, this is low risk.\n"
    "Do this next: Check whether a backup job or scheduled task runs on ops-server-01 "
    "around 03:12 UTC. If nothing explains it, watch this computer for further alerts."
)


@pytest.mark.parametrize(
    ("summary", "hostname", "user"),
    [
        (EXAMPLE_A, "fin-laptop-07", "sam.jones"),
        (EXAMPLE_B, "hr-desktop-02", "m.rivera"),
        (EXAMPLE_C, "ops-server-01", "svc-backup"),
    ],
)
def test_canonical_examples_pass(summary, hostname, user):
    result = validate_summary(summary, entity_hostname=hostname, entity_user=user)
    assert result.ok, result.errors


def _valid(**overrides):
    return validate_summary(
        overrides.pop("summary", EXAMPLE_A),
        entity_hostname=overrides.pop("hostname", "fin-laptop-07"),
        entity_user=overrides.pop("user", "sam.jones"),
    )


# ---------------------------------------------------------------------------
# §1.8 check 1 — structure
# ---------------------------------------------------------------------------


def test_rejects_two_lines():
    two = "What happened: a thing.\nWhy it matters: badness."
    assert not _valid(summary=two).ok


def test_rejects_four_lines():
    four = EXAMPLE_A + "\nAnd also: extra."
    assert not _valid(summary=four).ok


def test_rejects_wrong_label():
    bad = EXAMPLE_A.replace("Why it matters:", "Why it Matters:")
    result = _valid(summary=bad)
    assert not result.ok
    assert any("structure" in e for e in result.errors)


def test_rejects_reordered_labels():
    lines = EXAMPLE_A.split("\n")
    reordered = "\n".join([lines[1], lines[0], lines[2]])
    assert not _valid(summary=reordered).ok


def test_rejects_empty_line_content():
    bad = "What happened: \nWhy it matters: x.\nDo this next: y."
    assert not _valid(summary=bad).ok


# ---------------------------------------------------------------------------
# §1.8 check 2 — word budget
# ---------------------------------------------------------------------------


def test_rejects_over_120_words():
    padding = " very" * 120
    bad = (
        f"What happened: something{padding} happened.\n"
        "Why it matters: it matters.\nDo this next: check it."
    )
    result = _valid(summary=bad)
    assert not result.ok
    assert any("length" in e for e in result.errors)


# ---------------------------------------------------------------------------
# §1.8 check 3 — markdown/format denylist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "needle",
    ["`code`", "**bold**", "# heading", "[link](x)", "http://evil.example", "https://x.example", "now!"],
)
def test_rejects_format_denylist(needle):
    bad = (
        f"What happened: the computer fin-laptop-07 did {needle} today.\n"
        "Why it matters: it may be bad.\nDo this next: check the device."
    )
    result = _valid(summary=bad)
    assert not result.ok
    assert any("format" in e for e in result.errors)


def test_rejects_emoji():
    bad = (
        "What happened: the computer fin-laptop-07 did a thing \U0001f6a8 today.\n"
        "Why it matters: it may be bad.\nDo this next: check the device."
    )
    assert not _valid(summary=bad).ok


# ---------------------------------------------------------------------------
# §1.8 check 4 — banned jargon (§1.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "lateral movement",
        "command and control",
        "C2",
        "beaconing",
        "exfiltration",
        "persistence",
        "privilege escalation",
        "credential dumping",
        "brute force",
        "a malicious payload",
        "reverse shell",
        "an obfuscated script",
        "an encoded command",
        "process injection",
        "living off the land",
        "LOLBin",
        "enumeration",
        "account discovery",
        "an IOC",
        "an indicator",
        "the threat actor",
        "the adversary",
        "the endpoint",
        "the host",
        "a compromised machine",
        "mitigate the issue",
        "remediate the issue",
        "exploit the flaw",
        "a zero-day",
        "CVE-2026-1234",
    ],
)
def test_rejects_banned_jargon(phrase):
    bad = (
        f"What happened: the computer fin-laptop-07 showed {phrase} at 09:00 UTC.\n"
        "Why it matters: it may be bad.\nDo this next: check the device."
    )
    result = _valid(summary=bad)
    assert not result.ok, phrase
    assert any("jargon" in e for e in result.errors)


def test_phishing_banned_without_gloss():
    bad = (
        "What happened: the account sam.jones received a phishing email at 09:00 UTC.\n"
        "Why it matters: it may be bad.\nDo this next: check with sam.jones."
    )
    assert not _valid(summary=bad).ok


def test_phishing_allowed_with_trick_gloss():
    ok = (
        "What happened: the account sam.jones received a phishing email, a fake message "
        "designed to trick someone, at 09:00 UTC.\n"
        "Why it matters: it may be bad.\nDo this next: check with sam.jones."
    )
    assert _valid(summary=ok).ok


def test_hostname_word_not_flagged_inside_longer_words():
    ok = (
        "What happened: the computer fin-laptop-07 was renamed at 09:00 UTC.\n"
        "Why it matters: renaming can hide a device from your records.\n"
        "Do this next: check whether your IT provider renamed fin-laptop-07."
    )
    assert _valid(summary=ok).ok


# ---------------------------------------------------------------------------
# §1.8 check 5 — entity grounding (no invented hostnames/accounts)
# ---------------------------------------------------------------------------


def test_rejects_invented_hostname():
    bad = EXAMPLE_A.replace("fin-laptop-07", "evil-invented-99", 1)
    result = _valid(summary=bad)
    assert not result.ok
    assert any("entity" in e for e in result.errors)


def test_rejects_invented_account():
    bad = EXAMPLE_A.replace("sam.jones", "eve.mallory")
    result = _valid(summary=bad)
    assert not result.ok
    assert any("entity" in e for e in result.errors)


def test_entity_tokens_matching_alert_are_allowed():
    assert _valid().ok


# ---------------------------------------------------------------------------
# blob/hash reproduction (§1.2 / SEC-33)
# ---------------------------------------------------------------------------


def test_rejects_base64_blob():
    blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBibG9i" * 2
    bad = (
        f"What happened: the computer fin-laptop-07 ran {blob} at 09:00 UTC.\n"
        "Why it matters: it may be bad.\nDo this next: check the device."
    )
    result = _valid(summary=bad)
    assert not result.ok
    assert any("content" in e for e in result.errors)


def test_rejects_sha256_hash():
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    bad = (
        f"What happened: the computer fin-laptop-07 ran a file with hash {digest}.\n"
        "Why it matters: it may be bad.\nDo this next: check the device."
    )
    assert not _valid(summary=bad).ok


# ---------------------------------------------------------------------------
# parse_model_output (SEC-33 strict JSON)
# ---------------------------------------------------------------------------


def test_parse_plain_json():
    out = parse_model_output(json.dumps({"summary": EXAMPLE_A, "ai_severity": "High"}))
    assert out.ai_severity == "high"
    assert out.summary == EXAMPLE_A


def test_parse_tolerates_code_fence_wrapper():
    wrapped = "```json\n" + json.dumps({"summary": "x", "ai_severity": "low"}) + "\n```"
    assert parse_model_output(wrapped).ai_severity == "low"


@pytest.mark.parametrize(
    "bad",
    [
        "not json at all",
        json.dumps({"summary": "x"}),
        json.dumps({"ai_severity": "low"}),
        json.dumps({"summary": "", "ai_severity": "low"}),
        json.dumps({"summary": "x", "ai_severity": "urgent"}),
        json.dumps(["x"]),
    ],
)
def test_parse_rejects_bad_shapes(bad):
    with pytest.raises(OutputParseError):
        parse_model_output(bad)
