"""rules/mitre-descriptions.yaml — managed plain-language technique strings
(ux-alert-style.md §3): full pack coverage, §3.3 canonical strings verbatim,
§3.2 formula constraints."""

from __future__ import annotations

import re

import yaml
from conftest import MITRE_DESCRIPTIONS, pack_validation  # noqa: F401 (fixture)

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# ux-alert-style.md §3.3 — canonical strings, MUST be copied verbatim.
CANONICAL = {
    "T1059.001": (
        "Attackers run commands through PowerShell — a tool built into every Windows "
        "machine — so they can act without installing anything that antivirus might catch."
    ),
    "T1110": (
        "Attackers guess passwords over and over, usually with automated tools, so they "
        "can break into an account without needing to steal the password first."
    ),
    "T1021.001": (
        "Attackers sign in over Remote Desktop — the same tool IT uses for remote "
        "support — so they can move from one computer to another inside your network."
    ),
    "T1547.001": (
        "Attackers add their program to the list of things Windows starts automatically, "
        "so their access survives every restart."
    ),
    "T1071.001": (
        "Attackers make an infected computer quietly report back to a server they "
        "control, disguising that traffic as ordinary web browsing so it isn't noticed."
    ),
}

# §1.4 jargon denylist spot-check (exact phrases; lowercase comparison).
BANNED_PHRASES = (
    "lateral movement",
    "command and control",
    "beaconing",
    "exfiltration",
    "privilege escalation",
    "credential dumping",
    "brute force",
    "payload",
    "dropper",
    "implant",
    "reverse shell",
    "process injection",
    "living off the land",
    "lolbin",
    "threat actor",
    "adversary",
    "zero-day",
)


def _load() -> dict:
    with MITRE_DESCRIPTIONS.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_every_pack_technique_has_a_description(pack_validation) -> None:  # noqa: F811
    doc = _load()
    described = set(doc["techniques"])
    referenced: set[str] = set()
    for pack_rule in pack_validation.rules:
        referenced |= set(pack_rule.compiled.mitre_technique_ids)
    missing = referenced - described
    assert not missing, f"pack technique(s) without plain-language string: {sorted(missing)}"


def test_fallback_string_present() -> None:
    doc = _load()
    assert doc["fallback"] == "A known attack technique. Learn more on MITRE ATT&CK."


def test_canonical_strings_verbatim() -> None:
    doc = _load()
    for technique_id, sentence in CANONICAL.items():
        assert doc["techniques"][technique_id]["sentence"] == sentence, technique_id


def test_formula_constraints() -> None:
    """§3.2: one sentence, <= 30 words, subject 'Attackers', jargon-free."""
    doc = _load()
    for technique_id, entry in doc["techniques"].items():
        assert TECHNIQUE_ID_RE.match(technique_id), technique_id
        assert entry["name"].strip(), technique_id
        sentence = entry["sentence"]
        assert sentence.startswith("Attackers "), technique_id
        assert sentence.endswith("."), technique_id
        assert ". " not in sentence, f"{technique_id}: must be a single sentence"
        words = [w for w in sentence.split() if any(c.isalnum() for c in w)]
        assert len(words) <= 30, f"{technique_id}: {len(words)} words"
        lowered = sentence.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, f"{technique_id}: banned term {phrase!r}"
