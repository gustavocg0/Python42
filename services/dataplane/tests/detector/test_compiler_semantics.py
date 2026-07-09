"""Normative-semantics unit tests for the rule compiler (rules/FORMAT.md).

Every behavior asserted here cites the FORMAT.md section it implements.
"""

from __future__ import annotations

import pytest

from dataplane.rulepub.compiler import (
    MAX_LIST_ENTRIES,
    MAX_STRING_CHARS,
    RegexTimeoutError,
    RuleCompileError,
    compile_rule,
    fold_entity_value,
    parse_semver,
    schema_version_applies,
)


def rule_doc(condition, *, event_class="process_activity", entity=None, **overrides):
    doc = {
        "id": "test-rule",
        "version": "1.0.0",
        "title": "Test rule",
        "description": "test",
        "severity": "low",
        "event_class": event_class,
        "min_schema_version": "1.0.0",
        "mitre_technique_ids": ["T1059"],
        "entity": entity or ["host.hostname"],
        "detection": {"condition": condition},
        "false_positives": ["none"],
        "references": ["https://attack.mitre.org/techniques/T1059/"],
    }
    doc.update(overrides)
    return doc


def event(**fields):
    base = {
        "event_class": "process_activity",
        "schema_version": "1.0.0",
        "host": {"hostname": "ws-01"},
        "user": {"name": "sam"},
        "process": {"name": "powershell.exe", "cmd_line": "powershell -enc AAA", "pid": 42},
    }
    base.update(fields)
    return base


# --- §5.2/§5.3 missing fields -------------------------------------------------


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "process.sha256", "op": "equals", "value": "aa"},
        {"field": "process.sha256", "op": "icontains", "value": "aa"},
        {"field": "process.pid", "op": "gt", "value": 0},
        {"field": "process.sha256", "op": "exists"},
    ],
    ids=["equals", "icontains", "gt", "exists"],
)
def test_unresolved_path_is_false_for_every_op(condition) -> None:
    """§5.3: unresolved path ⇒ leaf False for EVERY op, including exists."""
    compiled = compile_rule(rule_doc(condition))
    ev = event()
    del ev["process"]  # path unresolved
    if condition["field"] == "process.pid":
        assert compiled.matches_condition(ev) is False
    assert compiled.matches_condition(ev) is False


def test_null_object_array_are_unresolved() -> None:
    """§5.2: final null/object/array ⇒ unresolved ⇒ exists is False."""
    compiled = compile_rule(rule_doc({"field": "process.sha256", "op": "exists"}))
    assert compiled.matches_condition(event(process={"sha256": None})) is False
    assert compiled.matches_condition(event(process={"sha256": {"a": 1}})) is False
    assert compiled.matches_condition(event(process={"sha256": ["aa"]})) is False
    assert compiled.matches_condition(event(process={"sha256": "aa"})) is True


def test_not_over_missing_field_is_true() -> None:
    """§5.3: `not` inverts the leaf, so absence makes `not` True."""
    compiled = compile_rule(
        rule_doc({"not": {"field": "process.sha256", "op": "equals", "value": "aa"}})
    )
    assert compiled.matches_condition(event()) is True  # sha256 absent


def test_exists_guard_pattern() -> None:
    """§5.3 worked example: exists guard stops absence from matching."""
    compiled = compile_rule(
        rule_doc(
            {
                "all": [
                    {"field": "src_ip", "op": "exists"},
                    {"not": {"field": "src_ip", "op": "istartswith", "value": ["10."]}},
                ]
            },
            event_class="authentication",
        )
    )
    auth = {"event_class": "authentication", "schema_version": "1.0.0"}
    assert compiled.matches_condition({**auth, "src_ip": "203.0.113.9"}) is True
    assert compiled.matches_condition({**auth, "src_ip": "10.1.2.3"}) is False
    assert compiled.matches_condition(auth) is False  # missing: guarded


# --- §3.1 zero type coercion ---------------------------------------------------


def test_equals_no_cross_type_coercion() -> None:
    number = compile_rule(rule_doc({"field": "process.pid", "op": "equals", "value": 1}))
    assert number.matches_condition(event(process={"pid": 1})) is True
    assert number.matches_condition(event(process={"pid": "1"})) is False
    assert number.matches_condition(event(process={"pid": True})) is False  # bool != number
    assert number.matches_condition(event(process={"pid": 1.0})) is True  # int/float interchange

    string = compile_rule(rule_doc({"field": "process.name", "op": "equals", "value": "1"}))
    assert string.matches_condition(event(process={"name": 1})) is False

    boolean = compile_rule(
        rule_doc({"field": "time_inferred", "op": "equals", "value": True})
    )
    assert boolean.matches_condition(event(time_inferred=True)) is True
    assert boolean.matches_condition(event(time_inferred=1)) is False  # 1 is not True here


def test_numeric_ops_reject_bool_and_strings() -> None:
    compiled = compile_rule(rule_doc({"field": "process.pid", "op": "gte", "value": 1}))
    assert compiled.matches_condition(event(process={"pid": True})) is False
    assert compiled.matches_condition(event(process={"pid": "5"})) is False
    assert compiled.matches_condition(event(process={"pid": 5})) is True


def test_string_ops_require_string_field() -> None:
    compiled = compile_rule(rule_doc({"field": "process.pid", "op": "contains", "value": "4"}))
    assert compiled.matches_condition(event(process={"pid": 42})) is False


# --- §3.2 case folding ----------------------------------------------------------


def test_casefold_both_sides_unicode_full() -> None:
    """§3.2: str.casefold(), not lower() — 'ß' folds to 'ss'."""
    compiled = compile_rule(
        rule_doc({"field": "process.name", "op": "iequals", "value": "STRASSE"})
    )
    assert compiled.matches_condition(event(process={"name": "straße"})) is True

    iin = compile_rule(
        rule_doc({"field": "process.name", "op": "iin", "value": ["POWERSHELL.EXE"]})
    )
    assert iin.matches_condition(event(process={"name": "PowerShell.exe"})) is True


def test_case_sensitive_ops_stay_sensitive() -> None:
    compiled = compile_rule(
        rule_doc({"field": "process.name", "op": "contains", "value": "PowerShell"})
    )
    assert compiled.matches_condition(event(process={"name": "powershell.exe"})) is False


# --- §3.1 scalar-or-list any-of ---------------------------------------------------


def test_string_op_list_is_any_of() -> None:
    compiled = compile_rule(
        rule_doc({"field": "process.cmd_line", "op": "icontains", "value": [" -e ", " -enc"]})
    )
    assert compiled.matches_condition(event(process={"cmd_line": "x -ENC y"})) is True
    assert compiled.matches_condition(event(process={"cmd_line": "x -e y"})) is True
    assert compiled.matches_condition(event(process={"cmd_line": "clean"})) is False


def test_in_op_equals_semantics_per_element() -> None:
    compiled = compile_rule(
        rule_doc({"field": "dst.port", "op": "in", "value": [4444, 8443]},
                 event_class="network_activity", entity=["host.hostname", "dst.ip"])
    )
    net = {"event_class": "network_activity", "schema_version": "1.0.0"}
    assert compiled.matches_condition({**net, "dst": {"port": 4444}}) is True
    assert compiled.matches_condition({**net, "dst": {"port": "4444"}}) is False
    assert compiled.matches_condition({**net, "dst": {"port": 443}}) is False


# --- §5.4 entity key ---------------------------------------------------------------


def test_entity_key_order_folding_and_missing() -> None:
    compiled = compile_rule(
        rule_doc(
            {"field": "process.name", "op": "exists"},
            entity=["host.hostname", "user.name", "process.pid"],
        )
    )
    ev = event(host={"hostname": "WS-01"}, user={"name": "Sam.Jones"}, process={"pid": 42})
    assert compiled.entity_key(ev) == "ws-01|sam.jones|42"
    del ev["user"]
    assert compiled.entity_key(ev) == "ws-01||42"  # missing ⇒ '' (§5.4)


def test_fold_entity_value_rendering() -> None:
    assert fold_entity_value(True) == "true"
    assert fold_entity_value(False) == "false"
    assert fold_entity_value(42) == "42"
    assert fold_entity_value(42.0) == "42"
    assert fold_entity_value("ABC") == "abc"


# --- §3 bounds (compile-enforced) -----------------------------------------------------


def test_depth_bound() -> None:
    condition = {"field": "process.name", "op": "exists"}
    for _ in range(7):
        condition = {"not": condition}
    compile_rule(rule_doc(condition))  # depth 8: ok
    with pytest.raises(RuleCompileError, match="depth"):
        compile_rule(rule_doc({"not": condition}))  # depth 9


def test_leaf_count_bound() -> None:
    leaf = {"field": "process.name", "op": "exists"}
    ok = {"all": [{"any": [dict(leaf)] * 32}, {"any": [dict(leaf)] * 32}]}
    compile_rule(rule_doc(ok))  # exactly 64 leaves
    over = {"all": [{"any": [dict(leaf)] * 32}, {"any": [dict(leaf)] * 32}, dict(leaf)]}
    with pytest.raises(RuleCompileError, match="leaves"):
        compile_rule(rule_doc(over))


def test_string_length_bound() -> None:
    with pytest.raises(RuleCompileError, match="1024"):
        compile_rule(
            rule_doc(
                {"field": "process.cmd_line", "op": "contains",
                 "value": "a" * (MAX_STRING_CHARS + 1)}
            )
        )


def test_list_length_bound() -> None:
    with pytest.raises(RuleCompileError, match="64"):
        compile_rule(
            rule_doc(
                {"field": "process.name", "op": "iin",
                 "value": [f"x{i}" for i in range(MAX_LIST_ENTRIES + 1)]}
            )
        )


def test_children_bound() -> None:
    leaf = {"field": "process.name", "op": "exists"}
    with pytest.raises(RuleCompileError, match="children"):
        compile_rule(rule_doc({"any": [dict(leaf)] * 33}))


# --- §4 field-path allowlist ------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "event_class"),
    [
        ("dst.port", "process_activity"),  # other class's field
        ("tenant_id", "process_activity"),  # never matchable
        ("event_id", "generic"),
        ("ingest_time", "authentication"),
        ("schema_version", "process_activity"),  # gate, not matchable
        ("event_class", "process_activity"),
        ("source.device_id", "process_activity"),  # tenant-coupled identity
        ("raw.msg", "generic"),  # not contract-stable
        ("unmapped.x", "process_activity"),
        ("fields", "generic"),  # object itself
        ("fields.a.b", "generic"),  # too deep — fields is flat
        ("fields.action", "process_activity"),  # generic-only
    ],
)
def test_forbidden_field_paths(path, event_class) -> None:
    with pytest.raises(RuleCompileError):
        compile_rule(
            rule_doc({"field": path, "op": "exists"}, event_class=event_class)
        )


def test_generic_fields_subkey_allowed() -> None:
    compiled = compile_rule(
        rule_doc(
            {"field": "fields.action", "op": "iequals", "value": "block"},
            event_class="generic",
        )
    )
    ev = {"event_class": "generic", "schema_version": "1.0.0", "fields": {"action": "BLOCK"}}
    assert compiled.matches_condition(ev) is True


# --- §2/§3 structural compile errors ---------------------------------------------------


def test_unknown_top_level_key_is_compile_error() -> None:
    with pytest.raises(RuleCompileError, match="unknown top-level"):
        compile_rule(rule_doc({"field": "process.name", "op": "exists"}, extra_key=1))


def test_node_must_have_exactly_one_structural_key() -> None:
    with pytest.raises(RuleCompileError, match="exactly one"):
        compile_rule(
            rule_doc({"field": "process.name", "op": "exists",
                      "all": [{"field": "process.pid", "op": "exists"}]})
        )
    with pytest.raises(RuleCompileError, match="exactly one"):
        compile_rule(rule_doc({}))


def test_exists_with_value_is_compile_error() -> None:
    with pytest.raises(RuleCompileError, match="no value"):
        compile_rule(rule_doc({"field": "process.name", "op": "exists", "value": "x"}))


def test_unknown_operator_is_compile_error() -> None:
    with pytest.raises(RuleCompileError, match="unknown operator"):
        compile_rule(rule_doc({"field": "process.name", "op": "matches", "value": "x"}))


def test_entity_bounds() -> None:
    with pytest.raises(RuleCompileError):
        compile_rule(
            rule_doc(
                {"field": "process.name", "op": "exists"},
                entity=["host.hostname", "user.name", "process.pid", "process.name",
                        "parent.name"],
            )
        )


def test_bad_technique_id_is_compile_error() -> None:
    with pytest.raises(RuleCompileError, match="AC-36"):
        compile_rule(
            rule_doc({"field": "process.name", "op": "exists"},
                     mitre_technique_ids=["1059"])
        )


# --- §3.3 regex (RE2 subset + 10ms guard) -------------------------------------------------


def test_regex_basic_search_unanchored() -> None:
    compiled = compile_rule(
        rule_doc({"field": "process.cmd_line", "op": "regex", "value": r"-enc\s+[A-Za-z0-9+/=]+"})
    )
    assert compiled.matches_condition(event(process={"cmd_line": "ps -enc QUJD end"})) is True
    assert compiled.matches_condition(event(process={"cmd_line": "clean"})) is False
    assert compiled.matches_condition(event(process={"cmd_line": 42})) is False


@pytest.mark.parametrize(
    "pattern",
    [r"(?=x)y", r"(?!x)y", r"(?<=x)y", r"(?<!x)y", r"(x)\1", r"(?P<a>x)(?P=a)", r"(?(1)x|y)"],
    ids=["lookahead", "neg-lookahead", "lookbehind", "neg-lookbehind",
         "backref", "named-backref", "conditional"],
)
def test_regex_outside_re2_subset_is_compile_error(pattern) -> None:
    with pytest.raises(RuleCompileError, match=r"SEC-29|invalid regex"):
        compile_rule(rule_doc({"field": "process.cmd_line", "op": "regex", "value": pattern}))


def test_regex_length_bound() -> None:
    with pytest.raises(RuleCompileError, match="512"):
        compile_rule(
            rule_doc({"field": "process.cmd_line", "op": "regex", "value": "a" * 513})
        )


def test_regex_timeout_is_runtime_eval_error() -> None:
    """§3.3: a pathological (but RE2-subset-passing) pattern hits the 10ms
    wall-clock guard ⇒ RuleEvalError (SEC-28(b): event skipped, rule stays
    enabled — asserted at the engine layer)."""
    compiled = compile_rule(
        rule_doc({"field": "process.cmd_line", "op": "regex", "value": r"(a+)+b$"})
    )
    hostile = "a" * 26 + "!"  # catastrophic backtracking in Python re
    with pytest.raises(RegexTimeoutError):
        compiled.matches_condition(event(process={"cmd_line": hostile}))


# --- §5.1 gates ----------------------------------------------------------------------------


def test_class_gate_exact_equality() -> None:
    compiled = compile_rule(rule_doc({"field": "process.name", "op": "exists"}))
    assert compiled.evaluate(event()) is True
    assert compiled.evaluate(event(event_class="network_activity")) is False
    assert compiled.evaluate(event(event_class=None)) is False


def test_schema_version_gate() -> None:
    min_schema = parse_semver("1.2.0")
    assert schema_version_applies(min_schema, "1.2.0") is True
    assert schema_version_applies(min_schema, "1.10.3") is True  # semver, not lexical
    assert schema_version_applies(min_schema, "1.1.9") is False  # below minimum
    assert schema_version_applies(min_schema, "2.0.0") is False  # MAJOR mismatch
    assert schema_version_applies(min_schema, "garbage") is False
    assert schema_version_applies(min_schema, None) is False
