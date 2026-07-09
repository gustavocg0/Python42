"""Rule compiler + evaluation semantics for `rule-pack/v1` (rules/FORMAT.md).

FORMAT.md is the single source of truth; this module implements it EXACTLY:

- §5.2/§5.3: an unresolved path makes the leaf evaluate **False for every
  operator, including `exists`**; `not` inverts that (so `not` over a missing
  field is True — authors guard with `exists`).
- §3.1: zero type coercion. `bool` is never a number; numbers never match
  strings; int/float are interchangeable for numeric equality/comparison.
- §3.2: case-insensitive operators apply Python `str.casefold()` to BOTH
  sides (Unicode full case folding, never locale-dependent).
- §3.1: string operators accept a scalar or a list of strings; a list means
  "any of" (logical OR over the list).
- §3 bounds (SEC-29, compile-enforced): tree depth ≤ 8, leaves ≤ 64,
  string values ≤ 1024 chars, lists ≤ 64 entries, 1..32 children per
  `all`/`any`.
- §3.3: regex restricted to the RE2 subset (no backreferences, lookaround,
  atomic/conditional groups, recursion), pattern ≤ 512 chars, evaluated
  under a hard 10 ms wall-clock guard. A timeout is a *runtime* eval error
  (SEC-28(b)): the event is skipped for that rule and the rule stays enabled.
- §4: per-class field-path allowlist derived from
  docs/contracts/event-schema.md; `tenant_id`/`event_id`/`batch_id`/
  `ingest_time`, `raw.*`, `unmapped.*` and identity fields are never
  matchable (compile error).
- §5.4: entity_key = declared paths, resolved, folded (casefold strings,
  decimal numbers, "true"/"false" bools, "" for unresolved), joined "|",
  in declared order.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FuturesTimeoutError
from dataclasses import dataclass, field
from typing import Any

# --- Compile-time bounds (FORMAT.md §3, SEC-29) ----------------------------

MAX_TREE_DEPTH = 8
MAX_LEAVES = 64
MAX_STRING_CHARS = 1024
MAX_LIST_ENTRIES = 64
MAX_CHILDREN = 32
MAX_REGEX_CHARS = 512
REGEX_TIMEOUT_SECONDS = 0.010  # 10 ms hard wall-clock guard (§3.3)

SEVERITIES = ("low", "medium", "high", "critical")
EVENT_CLASSES = ("process_activity", "network_activity", "authentication", "generic")

RULE_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

_TOP_LEVEL_ORDER = (
    "id",
    "version",
    "title",
    "description",
    "severity",
    "event_class",
    "min_schema_version",
    "mitre_technique_ids",
    "entity",
    "detection",
    "false_positives",
    "references",
)
_REQUIRED_TOP_LEVEL = frozenset(_TOP_LEVEL_ORDER)

_STRING_OPS = frozenset(
    {"contains", "icontains", "startswith", "istartswith", "endswith", "iendswith"}
)
_NUMERIC_OPS: Mapping[str, Callable[[Any, Any], bool]] = {
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
}

# --- Field-path allowlist (FORMAT.md §4 / event-schema.md) ------------------

_ENVELOPE_MATCHABLE = frozenset(
    {
        "activity",
        "event_time",
        "time_inferred",
        "source_type",
        "source_event_id",
        "severity_hint",
        "host.hostname",
        "host.os_family",
        "host.os_name",
        "host.os_version",
        "host.ip",
        "host.mac",
        "source.vendor",
        "source.product",
        "source.agent_version",
    }
)

_CLASS_MATCHABLE: Mapping[str, frozenset[str]] = {
    "process_activity": frozenset(
        {
            "process.pid",
            "process.name",
            "process.exe_path",
            "process.cmd_line",
            "process.sha256",
            "process.created_time",
            "parent.pid",
            "parent.name",
            "parent.exe_path",
            "user.name",
            "user.domain",
            "user.uid",
            "exit_code",
        }
    ),
    "network_activity": frozenset(
        {
            "direction",
            "protocol",
            "src.ip",
            "src.port",
            "dst.ip",
            "dst.port",
            "dst.hostname",
            "process.pid",
            "process.name",
            "process.exe_path",
            "bytes_sent",
            "bytes_received",
            "user.name",
            "user.domain",
            "user.uid",
        }
    ),
    "authentication": frozenset(
        {
            "status",
            "logon_type",
            "user.name",
            "user.domain",
            "user.uid",
            "src_ip",
            "session_id",
            "failure_reason",
        }
    ),
    "generic": frozenset({"message", "category", "raw_truncated"}),
}

_NEVER_MATCHABLE = frozenset(
    {
        "tenant_id",
        "event_id",
        "batch_id",
        "ingest_time",
        "schema_version",  # gated via min_schema_version, not matchable
        "event_class",  # gated via the class gate, not matchable
        "source.device_id",  # tenant-coupled identity — rules are tenant-agnostic
        "source.ingest_key_id",
    }
)
_FORBIDDEN_ROOTS = ("raw", "unmapped")  # not contract-stable (FORMAT.md §4)

# RE2 subset enforcement (§3.3): constructs Python `re` supports but RE2 does
# not (or that break the linear-time guarantee) are compile errors.
_RE2_FORBIDDEN: tuple[tuple[str, str], ...] = (
    ("(?=", "lookahead"),
    ("(?!", "negative lookahead"),
    ("(?<=", "lookbehind"),
    ("(?<!", "negative lookbehind"),
    ("(?>", "atomic group"),
    ("(?(", "conditional group"),
    ("(?P=", "named backreference"),
    ("(?P>", "subpattern recursion"),
    ("(?R", "recursion"),
    ("\\g", "backreference"),
    ("\\k", "named backreference"),
)
_BACKREF_RE = re.compile(r"\\[1-9]")


class RuleCompileError(ValueError):
    """Compile-time rule error (FORMAT.md §5.6): rejects the whole pack at
    publish (SEC-27); at detector load time it disables that one rule and
    fires an ops alert (SEC-28(a))."""

    def __init__(self, message: str, *, rule_id: str | None = None) -> None:
        self.rule_id = rule_id
        prefix = f"rule {rule_id!r}: " if rule_id else ""
        super().__init__(f"{prefix}{message}")


class RuleEvalError(RuntimeError):
    """Runtime per-event evaluation error (SEC-28(b)): caught per (rule,
    event); the event is skipped for that rule only; the rule STAYS enabled."""


class RegexTimeoutError(RuleEvalError):
    """Regex evaluation exceeded the 10 ms wall-clock guard (§3.3)."""


_UNRESOLVED = object()
"""Sentinel: path did not resolve to a non-null scalar (§5.2)."""

Predicate = Callable[[Mapping[str, Any]], bool]


# --- Semver -----------------------------------------------------------------


def parse_semver(value: Any) -> tuple[int, int, int]:
    """Strict MAJOR.MINOR.PATCH; raises ValueError otherwise."""
    if not isinstance(value, str):
        raise ValueError(f"semver must be a string, got {type(value).__name__}")
    match = _SEMVER_RE.match(value)
    if match is None:
        raise ValueError(f"not a MAJOR.MINOR.PATCH semver: {value!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def schema_version_applies(min_schema: tuple[int, int, int], event_schema_version: Any) -> bool:
    """§5.1 gate 2: same MAJOR and event version >= rule min (semver order).

    An unparseable/missing event schema_version means the rule does not
    apply (fail closed, no exception)."""
    if not isinstance(event_schema_version, str):
        return False
    match = _SEMVER_RE.match(event_schema_version)
    if match is None:
        return False
    ev = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return ev[0] == min_schema[0] and ev >= min_schema


# --- Field paths ------------------------------------------------------------


def validate_field_path(path: Any, event_class: str, *, rule_id: str | None = None) -> None:
    """Compile-time allowlist check (FORMAT.md §4)."""
    if not isinstance(path, str) or not path:
        raise RuleCompileError(f"field path must be a non-empty string, got {path!r}",
                               rule_id=rule_id)
    segments = path.split(".")
    if any(not seg for seg in segments):
        raise RuleCompileError(f"malformed field path {path!r}", rule_id=rule_id)
    if path in _NEVER_MATCHABLE or segments[0] in _NEVER_MATCHABLE:
        raise RuleCompileError(
            f"field {path!r} is not matchable (rules are global, tenant-agnostic content)",
            rule_id=rule_id,
        )
    if segments[0] in _FORBIDDEN_ROOTS:
        raise RuleCompileError(
            f"field {path!r} traverses into {segments[0]!r}, which is not contract-stable",
            rule_id=rule_id,
        )
    if path in _ENVELOPE_MATCHABLE or path in _CLASS_MATCHABLE[event_class]:
        return
    if (
        event_class == "generic"
        and len(segments) == 2
        and segments[0] == "fields"
        and segments[1]
    ):
        return  # generic `fields.<key>` — flat object of scalars
    raise RuleCompileError(
        f"field {path!r} is not a matchable field for event_class {event_class!r}",
        rule_id=rule_id,
    )


def resolve_path(event: Mapping[str, Any], segments: tuple[str, ...]) -> Any:
    """§5.2 path resolution. Returns the scalar or the _UNRESOLVED sentinel.

    Absent segment, non-object intermediate, or final null/object/array
    ⇒ unresolved."""
    current: Any = event
    for segment in segments:
        if not isinstance(current, Mapping) or segment not in current:
            return _UNRESOLVED
        current = current[segment]
    if current is None or isinstance(current, (Mapping, list, tuple)):
        return _UNRESOLVED
    return current


def is_unresolved(value: Any) -> bool:
    return value is _UNRESOLVED


# --- Entity key (§5.4) -------------------------------------------------------


def fold_entity_value(value: Any) -> str:
    """fold(v): casefold strings, decimal render numbers, true/false bools,
    empty string for unresolved (§5.4)."""
    if value is _UNRESOLVED:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    return ""


# --- Value validation helpers -----------------------------------------------


def _check_string_value(value: Any, *, rule_id: str | None) -> str:
    if not isinstance(value, str):
        raise RuleCompileError(f"expected a string value, got {type(value).__name__}",
                               rule_id=rule_id)
    if len(value) > MAX_STRING_CHARS:
        raise RuleCompileError(
            f"string value exceeds {MAX_STRING_CHARS} chars ({len(value)})", rule_id=rule_id
        )
    return value


def _string_or_list(value: Any, *, rule_id: str | None) -> tuple[str, ...]:
    """String operators accept a scalar or a list[str] meaning any-of (§3.1)."""
    if isinstance(value, str):
        return (_check_string_value(value, rule_id=rule_id),)
    if isinstance(value, list):
        if not value:
            raise RuleCompileError("value list must not be empty", rule_id=rule_id)
        if len(value) > MAX_LIST_ENTRIES:
            raise RuleCompileError(
                f"value list exceeds {MAX_LIST_ENTRIES} entries ({len(value)})", rule_id=rule_id
            )
        return tuple(_check_string_value(v, rule_id=rule_id) for v in value)
    raise RuleCompileError(
        f"expected a string or list of strings, got {type(value).__name__}", rule_id=rule_id
    )


def _check_scalar_value(value: Any, *, rule_id: str | None) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return _check_string_value(value, rule_id=rule_id)
    raise RuleCompileError(
        f"expected a scalar (string/number/bool), got {type(value).__name__}", rule_id=rule_id
    )


def _scalar_equals(field_value: Any, rule_value: Any) -> bool:
    """`equals` semantics (§3.1): exact, zero cross-type coercion.

    bool is NOT a number; int/float are numerically interchangeable."""
    if isinstance(rule_value, bool):
        return isinstance(field_value, bool) and field_value is rule_value
    if isinstance(rule_value, (int, float)):
        return (
            isinstance(field_value, (int, float))
            and not isinstance(field_value, bool)
            and field_value == rule_value
        )
    if isinstance(rule_value, str):
        return isinstance(field_value, str) and field_value == rule_value
    return False


# --- Regex guard (§3.3, SEC-29) ----------------------------------------------

_regex_pool: ThreadPoolExecutor | None = None


def _get_regex_pool() -> ThreadPoolExecutor:
    global _regex_pool
    if _regex_pool is None:
        _regex_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rule-regex")
    return _regex_pool


def _validate_re2_subset(pattern: str, *, rule_id: str | None) -> re.Pattern[str]:
    if len(pattern) > MAX_REGEX_CHARS:
        raise RuleCompileError(
            f"regex pattern exceeds {MAX_REGEX_CHARS} chars ({len(pattern)})", rule_id=rule_id
        )
    for needle, label in _RE2_FORBIDDEN:
        if needle in pattern:
            raise RuleCompileError(
                f"regex uses {label} ({needle!r}), outside the RE2 subset (SEC-29)",
                rule_id=rule_id,
            )
    if _BACKREF_RE.search(pattern):
        raise RuleCompileError(
            "regex uses a numeric backreference, outside the RE2 subset (SEC-29)",
            rule_id=rule_id,
        )
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RuleCompileError(f"invalid regex pattern: {exc}", rule_id=rule_id) from exc


def _regex_search_guarded(compiled: re.Pattern[str], value: str) -> bool:
    """Unanchored search under the 10 ms wall-clock guard.

    Python `re` is not linear-time, so the guard runs the match on a worker
    thread and abandons it on timeout (the RE2-subset validation makes the
    pathological case unlikely; the guard is the SEC-29 backstop). Timeout
    ⇒ RegexTimeoutError, handled per SEC-28(b)."""
    future = _get_regex_pool().submit(compiled.search, value)
    try:
        return future.result(timeout=REGEX_TIMEOUT_SECONDS) is not None
    except _FuturesTimeoutError:
        future.cancel()
        raise RegexTimeoutError(
            f"regex evaluation exceeded {REGEX_TIMEOUT_SECONDS * 1000:.0f}ms"
        ) from None


# --- Condition-tree compilation ----------------------------------------------


@dataclass
class _CompileState:
    rule_id: str | None
    event_class: str
    leaves: int = 0


def _compile_leaf(node: Mapping[str, Any], state: _CompileState) -> Predicate:
    rule_id = state.rule_id
    extra = set(node) - {"field", "op", "value"}
    if extra:
        raise RuleCompileError(f"unknown leaf key(s) {sorted(extra)}", rule_id=rule_id)
    path = node.get("field")
    op = node.get("op")
    if not isinstance(op, str):
        raise RuleCompileError("leaf requires a string 'op'", rule_id=rule_id)
    validate_field_path(path, state.event_class, rule_id=rule_id)
    segments = tuple(str(path).split("."))

    state.leaves += 1
    if state.leaves > MAX_LEAVES:
        raise RuleCompileError(f"rule exceeds {MAX_LEAVES} leaves", rule_id=rule_id)

    if op == "exists":
        if "value" in node:
            raise RuleCompileError("'exists' takes no value", rule_id=rule_id)

        def _exists(event: Mapping[str, Any], _segs=segments) -> bool:
            return resolve_path(event, _segs) is not _UNRESOLVED

        return _exists

    if "value" not in node:
        raise RuleCompileError(f"op {op!r} requires a value", rule_id=rule_id)
    value = node["value"]

    if op == "equals":
        rule_value = _check_scalar_value(value, rule_id=rule_id)

        def _equals(event: Mapping[str, Any], _segs=segments, _rv=rule_value) -> bool:
            return _scalar_equals(resolve_path(event, _segs), _rv)

        return _equals

    if op == "iequals":
        folded = _check_string_value(value, rule_id=rule_id).casefold()

        def _iequals(event: Mapping[str, Any], _segs=segments, _rv=folded) -> bool:
            resolved = resolve_path(event, _segs)
            return isinstance(resolved, str) and resolved.casefold() == _rv

        return _iequals

    if op in _STRING_OPS:
        case_insensitive = op.startswith("i")
        values = _string_or_list(value, rule_id=rule_id)
        if case_insensitive:
            values = tuple(v.casefold() for v in values)
        base = op[1:] if case_insensitive else op
        tester: Callable[[str, str], bool]
        if base == "contains":
            tester = str.__contains__
        elif base == "startswith":
            tester = str.startswith
        else:  # endswith
            tester = str.endswith

        def _string_op(
            event: Mapping[str, Any],
            _segs=segments,
            _vals=values,
            _fold=case_insensitive,
            _test=tester,
        ) -> bool:
            resolved = resolve_path(event, _segs)
            if not isinstance(resolved, str):
                return False
            haystack = resolved.casefold() if _fold else resolved
            return any(_test(haystack, needle) for needle in _vals)

        return _string_op

    if op == "in":
        if not isinstance(value, list) or not value:
            raise RuleCompileError("'in' requires a non-empty list of scalars", rule_id=rule_id)
        if len(value) > MAX_LIST_ENTRIES:
            raise RuleCompileError(
                f"value list exceeds {MAX_LIST_ENTRIES} entries ({len(value)})", rule_id=rule_id
            )
        scalars = tuple(_check_scalar_value(v, rule_id=rule_id) for v in value)

        def _in(event: Mapping[str, Any], _segs=segments, _vals=scalars) -> bool:
            resolved = resolve_path(event, _segs)
            return any(_scalar_equals(resolved, rv) for rv in _vals)

        return _in

    if op == "iin":
        if not isinstance(value, list) or not value:
            raise RuleCompileError("'iin' requires a non-empty list of strings", rule_id=rule_id)
        folded_set = frozenset(v.casefold() for v in _string_or_list(value, rule_id=rule_id))

        def _iin(event: Mapping[str, Any], _segs=segments, _vals=folded_set) -> bool:
            resolved = resolve_path(event, _segs)
            return isinstance(resolved, str) and resolved.casefold() in _vals

        return _iin

    if op in _NUMERIC_OPS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuleCompileError(f"op {op!r} requires a number value", rule_id=rule_id)
        compare = _NUMERIC_OPS[op]

        def _numeric(
            event: Mapping[str, Any], _segs=segments, _rv=value, _cmp=compare
        ) -> bool:
            resolved = resolve_path(event, _segs)
            if isinstance(resolved, bool) or not isinstance(resolved, (int, float)):
                return False  # bool is NOT a number (§3.1)
            return _cmp(resolved, _rv)

        return _numeric

    if op == "regex":
        pattern = _check_string_value(value, rule_id=rule_id)
        compiled = _validate_re2_subset(pattern, rule_id=rule_id)

        def _regex(event: Mapping[str, Any], _segs=segments, _re=compiled) -> bool:
            resolved = resolve_path(event, _segs)
            if not isinstance(resolved, str):
                return False
            return _regex_search_guarded(_re, resolved)

        return _regex

    raise RuleCompileError(f"unknown operator {op!r}", rule_id=rule_id)


def _compile_node(node: Any, state: _CompileState, depth: int) -> Predicate:
    rule_id = state.rule_id
    if depth > MAX_TREE_DEPTH:
        raise RuleCompileError(f"condition tree exceeds depth {MAX_TREE_DEPTH}", rule_id=rule_id)
    if not isinstance(node, Mapping):
        raise RuleCompileError(f"condition node must be a mapping, got {type(node).__name__}",
                               rule_id=rule_id)
    structural = {key for key in ("field", "all", "any", "not") if key in node}
    if len(structural) != 1:
        raise RuleCompileError(
            "node must contain exactly one of 'field'/'all'/'any'/'not' "
            f"(found {sorted(structural) or 'none'})",
            rule_id=rule_id,
        )

    if "field" in node:
        return _compile_leaf(node, state)

    if "not" in node:
        if set(node) != {"not"}:
            raise RuleCompileError("'not' node must have no sibling keys", rule_id=rule_id)
        child = _compile_node(node["not"], state, depth + 1)

        def _not(event: Mapping[str, Any], _child=child) -> bool:
            return not _child(event)

        return _not

    key = "all" if "all" in node else "any"
    if set(node) != {key}:
        raise RuleCompileError(f"'{key}' node must have no sibling keys", rule_id=rule_id)
    children = node[key]
    if not isinstance(children, list) or not children:
        raise RuleCompileError(f"'{key}' requires a non-empty list of child nodes",
                               rule_id=rule_id)
    if len(children) > MAX_CHILDREN:
        raise RuleCompileError(
            f"'{key}' exceeds {MAX_CHILDREN} children ({len(children)})", rule_id=rule_id
        )
    predicates = tuple(_compile_node(child, state, depth + 1) for child in children)
    if key == "all":

        def _all(event: Mapping[str, Any], _preds=predicates) -> bool:
            return all(pred(event) for pred in _preds)

        return _all

    def _any(event: Mapping[str, Any], _preds=predicates) -> bool:
        return any(pred(event) for pred in _preds)

    return _any


# --- Rule document -----------------------------------------------------------


@dataclass(frozen=True)
class CompiledRule:
    """A validated rule with an executable predicate (deterministic, §5.7)."""

    rule_id: str
    version: str
    title: str
    description: str
    severity: str
    event_class: str
    min_schema_version: str
    min_schema: tuple[int, int, int]
    mitre_technique_ids: tuple[str, ...]
    entity: tuple[str, ...]
    false_positives: tuple[str, ...]
    references: tuple[str, ...]
    definition: dict[str, Any] = field(repr=False)
    predicate: Predicate = field(repr=False)
    entity_segments: tuple[tuple[str, ...], ...] = field(repr=False)

    def applies_to(self, event: Mapping[str, Any]) -> bool:
        """§5.1 gates 1+2: exact class equality + schema-version gate."""
        return event.get("event_class") == self.event_class and schema_version_applies(
            self.min_schema, event.get("schema_version")
        )

    def matches_condition(self, event: Mapping[str, Any]) -> bool:
        """Condition tree only (gates not applied). May raise RuleEvalError."""
        return self.predicate(event)

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        """Full evaluation: gates + condition (the QA fixture contract, §7)."""
        return self.applies_to(event) and self.matches_condition(event)

    def entity_key(self, event: Mapping[str, Any]) -> str:
        """§5.4: fold each declared path (missing ⇒ ''), join '|', declared order."""
        return "|".join(
            fold_entity_value(resolve_path(event, segments))
            for segments in self.entity_segments
        )


def _require_str(doc: Mapping[str, Any], key: str, rule_id: str | None) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleCompileError(f"'{key}' must be a non-empty string", rule_id=rule_id)
    return value


def _require_str_list(doc: Mapping[str, Any], key: str, rule_id: str | None) -> tuple[str, ...]:
    value = doc.get(key)
    if not isinstance(value, list) or not value:
        raise RuleCompileError(f"'{key}' must be a non-empty list", rule_id=rule_id)
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RuleCompileError(f"'{key}' entries must be non-empty strings", rule_id=rule_id)
        out.append(item)
    return tuple(out)


def compile_rule(doc: Any) -> CompiledRule:
    """Validate + compile one rule document (FORMAT.md §2-§4).

    Raises RuleCompileError on ANY violation — at publish this rejects the
    whole pack atomically (SEC-27)."""
    if not isinstance(doc, Mapping):
        raise RuleCompileError(f"rule document must be a mapping, got {type(doc).__name__}")
    raw_id = doc.get("id")
    rule_id = raw_id if isinstance(raw_id, str) else None

    unknown = set(doc) - _REQUIRED_TOP_LEVEL
    if unknown:
        raise RuleCompileError(f"unknown top-level key(s) {sorted(unknown)}", rule_id=rule_id)
    missing = _REQUIRED_TOP_LEVEL - set(doc)
    if missing:
        raise RuleCompileError(f"missing required key(s) {sorted(missing)}", rule_id=rule_id)

    rule_id = _require_str(doc, "id", rule_id)
    if len(rule_id) > 64 or not RULE_ID_RE.match(rule_id):
        raise RuleCompileError(
            "id must match ^[a-z0-9]+(-[a-z0-9]+)*$ and be <= 64 chars", rule_id=rule_id
        )

    version = _require_str(doc, "version", rule_id)
    try:
        parse_semver(version)
    except ValueError as exc:
        raise RuleCompileError(f"version: {exc}", rule_id=rule_id) from exc

    title = _require_str(doc, "title", rule_id)
    if len(title) > 120:
        raise RuleCompileError("title exceeds 120 chars", rule_id=rule_id)
    description = _require_str(doc, "description", rule_id)

    severity = _require_str(doc, "severity", rule_id)
    if severity not in SEVERITIES:
        raise RuleCompileError(f"severity must be one of {SEVERITIES}", rule_id=rule_id)

    event_class = _require_str(doc, "event_class", rule_id)
    if event_class not in EVENT_CLASSES:
        raise RuleCompileError(f"event_class must be one of {EVENT_CLASSES}", rule_id=rule_id)

    min_schema_version = _require_str(doc, "min_schema_version", rule_id)
    try:
        min_schema = parse_semver(min_schema_version)
    except ValueError as exc:
        raise RuleCompileError(f"min_schema_version: {exc}", rule_id=rule_id) from exc

    techniques = _require_str_list(doc, "mitre_technique_ids", rule_id)
    for tid in techniques:
        if not TECHNIQUE_ID_RE.match(tid):
            raise RuleCompileError(
                f"mitre_technique_ids entry {tid!r} must match ^T\\d{{4}}(\\.\\d{{3}})?$ (AC-36)",
                rule_id=rule_id,
            )

    entity_paths = _require_str_list(doc, "entity", rule_id)
    if not 1 <= len(entity_paths) <= 4:
        raise RuleCompileError("entity must declare 1-4 field paths", rule_id=rule_id)
    for path in entity_paths:
        validate_field_path(path, event_class, rule_id=rule_id)
    entity_segments = tuple(tuple(path.split(".")) for path in entity_paths)

    false_positives = _require_str_list(doc, "false_positives", rule_id)
    references = _require_str_list(doc, "references", rule_id)

    detection = doc.get("detection")
    if not isinstance(detection, Mapping) or set(detection) != {"condition"}:
        raise RuleCompileError(
            "detection must be a mapping with exactly one key: 'condition'", rule_id=rule_id
        )
    state = _CompileState(rule_id=rule_id, event_class=event_class)
    predicate = _compile_node(detection["condition"], state, depth=1)

    return CompiledRule(
        rule_id=rule_id,
        version=version,
        title=title,
        description=description,
        severity=severity,
        event_class=event_class,
        min_schema_version=min_schema_version,
        min_schema=min_schema,
        mitre_technique_ids=techniques,
        entity=entity_paths,
        false_positives=false_positives,
        references=references,
        definition={key: doc[key] for key in _TOP_LEVEL_ORDER},
        predicate=predicate,
        entity_segments=entity_segments,
    )
