"""Output validation: ux-alert-style §1.8 as code + strict JSON parsing (SEC-33).

Model output is untrusted. It is accepted only if it parses as the strict
JSON shape {"summary": str, "ai_severity": enum} AND the summary passes every
deterministic check below. On failure the graph regenerates ONCE, then marks
triage unavailable (AC-50) — malformed text never ships.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

MAX_TOTAL_WORDS = 120

_LINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^What happened: \S"),
    re.compile(r"^Why it matters: \S"),
    re.compile(r"^Do this next: \S"),
)

# §1.8 check 3 — markdown/format denylist (substring match) + '!' ban.
_FORMAT_DENYLIST: tuple[str, ...] = ("`", "**", "# ", "](", "http://", "https://", "!")

# §1.4 banned-jargon table -> case-insensitive word-boundary patterns.
# "phishing" is handled separately (exempt when glossed with "trick").
_BANNED_TERMS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in (
        ("lateral movement", r"\blateral movement\b"),
        ("C2 / command and control", r"\bc2\b|\bcommand[ -]and[ -]control\b"),
        ("beaconing / callback", r"\bbeacon(ing|s)?\b|\bcallback(s)?\b"),
        ("exfiltration", r"\bexfiltrat\w*\b"),
        ("persistence", r"\bpersistence\b"),
        ("privilege escalation", r"\bprivilege escalation\b"),
        ("credential dumping/access", r"\bcredential (dump\w*|access)\b"),
        ("brute force", r"\bbrute[ -]force\w*\b"),
        ("payload/dropper/implant/RAT", r"\bpayload(s)?\b|\bdropper(s)?\b|\bimplant(s)?\b|\brats?\b"),
        ("reverse shell / shell access", r"\breverse shell\b|\bshell access\b"),
        ("obfuscated/encoded", r"\bobfuscat\w*\b|\bencoded\b"),
        ("process injection", r"\bprocess injection\b"),
        ("living off the land / LOLBin", r"\bliving off the land\b|\blolbins?\b"),
        ("enumeration/recon/discovery", r"\benumerat\w*\b|\brecon\b|\bdiscovery\b"),
        ("IOC / indicator", r"\biocs?\b|\bindicator(s)?\b"),
        ("threat actor/adversary/TTP", r"\bthreat actor(s)?\b|\badversar(y|ies)\b|\bttps?\b"),
        ("endpoint/host as nouns", r"\bendpoint(s)?\b|\bhost(s)?\b"),
        ("compromised", r"\bcompromised\b"),
        ("mitigate/remediate", r"\bmitigat\w*\b|\bremediat\w*\b"),
        ("exploit (verb)", r"\bexploit\w*\b"),
        ("zero-day / CVE", r"\bzero[ -]day(s)?\b|\bcve-\d+"),
    )
)

_PHISHING = re.compile(r"\bphishing\b", re.IGNORECASE)
_TRICK = re.compile(r"\btrick", re.IGNORECASE)
_SENTENCE_SPLIT = re.compile(r"[.?]")

# Entity grounding (§1.8 check 5): tokens that LOOK like hostnames/accounts
# must exactly equal alert.entity values — guards model-invented entities.
# Hostname-like: lowercase, hyphenated, contains a digit ("fin-laptop-07").
_HOSTLIKE = re.compile(r"\b(?=[a-z0-9-]*\d)[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b")
# Account-like: dotted lowercase names ("sam.jones", "m.rivera").
_USERLIKE = re.compile(r"\b[a-z][a-z0-9_-]*\.[a-z][a-z0-9._-]*[a-z0-9]\b")

# Never reproduce encoded blobs / hashes (§1.2 / SEC-33).
_BLOBLIKE = re.compile(r"[A-Za-z0-9+/=]{40,}|\b[0-9a-fA-F]{32,}\b")

# Emoji / symbol codepoints (§1.8 check 3).
_EMOJI_RANGES: tuple[tuple[int, int], ...] = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE00, 0xFE0F),
)


class OutputParseError(ValueError):
    """Model output was not the strict JSON shape (SEC-33)."""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...] = field(default=())


@dataclass(frozen=True, slots=True)
class TriageOutput:
    summary: str
    ai_severity: str  # RAW model output; the B-4 clamp happens in scoring


def parse_model_output(text: str) -> TriageOutput:
    """Strict parse of the model reply into {summary, ai_severity} (SEC-33).

    Tolerates surrounding whitespace/code fences around the JSON object but
    nothing else; any other free text is a parse failure, never partially used.
    """
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", candidate).strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise OutputParseError("no JSON object in model output")
    try:
        obj = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError as exc:
        raise OutputParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise OutputParseError("model output is not a JSON object")
    summary = obj.get("summary")
    ai_severity = obj.get("ai_severity")
    if not isinstance(summary, str) or not summary.strip():
        raise OutputParseError("missing/empty 'summary'")
    if not isinstance(ai_severity, str) or ai_severity.lower() not in SEVERITIES:
        raise OutputParseError(f"'ai_severity' not in {SEVERITIES}")
    return TriageOutput(summary=summary, ai_severity=ai_severity.lower())


def validate_summary(
    summary: str,
    *,
    entity_hostname: str | None,
    entity_user: str | None,
) -> ValidationResult:
    """Every deterministic check from ux-alert-style §1.8 (checks 1-5)."""
    errors: list[str] = []

    lines = summary.split("\n")
    if len(lines) != 3:
        errors.append(f"structure: expected exactly 3 lines, got {len(lines)}")
    else:
        for pattern, line in zip(_LINE_PATTERNS, lines, strict=True):
            if not pattern.match(line):
                errors.append(f"structure: line does not match '{pattern.pattern}'")

    if len(summary.split()) > MAX_TOTAL_WORDS:
        errors.append(f"length: over {MAX_TOTAL_WORDS} words")

    for token in _FORMAT_DENYLIST:
        if token in summary:
            errors.append(f"format: banned sequence {token!r}")
    if any(a <= ord(ch) <= b for ch in summary for a, b in _EMOJI_RANGES):
        errors.append("format: emoji codepoint")

    for label, pattern in _BANNED_TERMS:
        if pattern.search(summary):
            errors.append(f"jargon: banned term ({label})")
    for sentence in _SENTENCE_SPLIT.split(summary):
        if _PHISHING.search(sentence) and not _TRICK.search(sentence):
            errors.append("jargon: 'phishing' without the required gloss")

    allowed = {v for v in (entity_hostname, entity_user) if v}
    for match in _HOSTLIKE.findall(summary):
        if match not in allowed:
            errors.append(f"entity: hostname-like token {match!r} not in alert.entity")
    for match in _USERLIKE.findall(summary):
        if match not in allowed:
            errors.append(f"entity: account-like token {match!r} not in alert.entity")

    if _BLOBLIKE.search(summary):
        errors.append("content: encoded blob or hash reproduced")

    return ValidationResult(ok=not errors, errors=tuple(errors))
