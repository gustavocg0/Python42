"""Versioned prompt files (SEC-32: prompts live in the repo, reviewable as diffs).

The system prompt contains NO tenant data, ever. All alert/event-derived
content goes only into the fenced untrusted block of the user template,
with a random-per-call boundary marker.
"""

from __future__ import annotations

from importlib import resources
from string import Template

PROMPT_VERSION = "v1"

_SYSTEM_FILE = f"system_{PROMPT_VERSION}.txt"
_USER_FILE = f"user_{PROMPT_VERSION}.txt"


def _read(name: str) -> str:
    return (resources.files(__package__) / name).read_text(encoding="utf-8")


def load_system_prompt() -> str:
    """The fixed, versioned system prompt (static — no substitutions)."""
    return _read(_SYSTEM_FILE)


def load_user_template() -> Template:
    """User-message template with $boundary / $data / $correction slots."""
    return Template(_read(_USER_FILE))
