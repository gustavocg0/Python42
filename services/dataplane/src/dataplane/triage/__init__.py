"""AI triage for alerts (PRD E7, AC-48..52).

Zero-tool LangGraph pipeline: assemble tenant-scoped context -> generate
(fast model) -> validate (ux-alert-style §1.8) -> regenerate once ->
persist (triage fields + priority recompute via dataplane.scoring).

Binding references:
- docs/design/ux-alert-style.md §1 (output format, validator, few-shots)
- docs/security/threat-model-platform-foundation-mvp.md SEC-32..38
- docs/contracts/priority-score.md (RAW ai_severity in, clamp inside scoring)
- docs/contracts/api-contracts.md §8 (triage fields) + §13 (metering)
"""

from dataplane.triage.config import TriageSettings
from dataplane.triage.graph import TriageOutcome, TriageRunner
from dataplane.triage.validator import parse_model_output, validate_summary

__all__ = [
    "TriageOutcome",
    "TriageRunner",
    "TriageSettings",
    "parse_model_output",
    "validate_summary",
]
