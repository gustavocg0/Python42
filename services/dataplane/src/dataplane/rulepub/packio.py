"""Pack manifest loading + whole-pack validation (rules/FORMAT.md §6-§7, SEC-27).

Publish validation is atomic: ONE invalid rule (or fixture failure) rejects
the entire pack version. The fixture harness here is also the QA automation
contract (§7): load pack → evaluate each named rule against each case event
→ assert match/no-match.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dataplane.rulepub.compiler import (
    CompiledRule,
    RuleCompileError,
    compile_rule,
    parse_semver,
)

PACK_SCHEMA = "rule-pack/v1"
_MANIFEST_ENTRY_KEYS = frozenset({"id", "version", "path", "enabled"})
_MANIFEST_KEYS = frozenset(
    {"schema", "pack_version", "generated_at", "min_schema_version", "rules"}
)


class _StrictYamlLoader(yaml.SafeLoader):
    """YAML 1.1 safe loader with anchors/aliases/merge keys rejected (§1)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not allowed (FORMAT.md §1)")
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML anchors are not allowed (FORMAT.md §1)")
        return super().compose_node(parent, index)

    def flatten_mapping(self, node: Any) -> None:
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.YAMLError("YAML merge keys are not allowed (FORMAT.md §1)")
        super().flatten_mapping(node)


def load_yaml_document(path: Path) -> Any:
    """Load exactly one YAML document with the strict safe loader."""
    with path.open("r", encoding="utf-8") as handle:
        documents = list(yaml.load_all(handle, Loader=_StrictYamlLoader))
    if len(documents) != 1:
        raise yaml.YAMLError(
            f"{path.name}: expected exactly one YAML document, got {len(documents)}"
        )
    return documents[0]


@dataclass(frozen=True)
class ManifestEntry:
    rule_id: str
    version: str
    path: str
    enabled: bool


@dataclass(frozen=True)
class PackManifest:
    schema: str
    pack_version: str
    generated_at: str
    min_schema_version: str
    entries: tuple[ManifestEntry, ...]


@dataclass(frozen=True)
class PackRule:
    entry: ManifestEntry
    compiled: CompiledRule


@dataclass
class PackValidation:
    """Result of validating a pack directory. `ok` gates publish (SEC-27)."""

    pack_dir: Path
    manifest: PackManifest | None = None
    rules: list[PackRule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    fixture_case_count: int = 0

    @property
    def ok(self) -> bool:
        return self.manifest is not None and not self.errors


def canonical_manifest_bytes(manifest: PackManifest, generated_at: str) -> bytes:
    """Canonical JSON form of the manifest with the publish-stamped timestamp.

    manifest_hash (SEC-27/AC-39) = sha256 over these bytes; recorded in
    tenantdata.rule_packs and stamped onto every alert with rule id/version/
    pack_version."""
    payload = {
        "schema": manifest.schema,
        "pack_version": manifest.pack_version,
        "generated_at": generated_at,
        "min_schema_version": manifest.min_schema_version,
        "rules": [
            {
                "id": entry.rule_id,
                "version": entry.version,
                "path": entry.path,
                "enabled": entry.enabled,
            }
            for entry in manifest.entries
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_hash(manifest: PackManifest, generated_at: str) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest, generated_at)).hexdigest()


def _parse_manifest(doc: Any, errors: list[str]) -> PackManifest | None:
    if not isinstance(doc, Mapping):
        errors.append("pack.yaml: manifest must be a mapping")
        return None
    unknown = set(doc) - _MANIFEST_KEYS
    if unknown:
        errors.append(f"pack.yaml: unknown key(s) {sorted(unknown)}")
    missing = _MANIFEST_KEYS - set(doc)
    if missing:
        errors.append(f"pack.yaml: missing key(s) {sorted(missing)}")
        return None
    if doc["schema"] != PACK_SCHEMA:
        errors.append(f"pack.yaml: schema must be {PACK_SCHEMA!r}, got {doc['schema']!r}")
        return None
    for key in ("pack_version", "min_schema_version"):
        try:
            parse_semver(doc[key])
        except ValueError as exc:
            errors.append(f"pack.yaml: {key}: {exc}")
            return None
    if not isinstance(doc.get("generated_at"), str):
        errors.append("pack.yaml: generated_at must be a string")
        return None
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        errors.append("pack.yaml: rules must be a non-empty list")
        return None

    entries: list[ManifestEntry] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, Mapping) or set(raw) != _MANIFEST_ENTRY_KEYS:
            errors.append(
                f"pack.yaml: rules[{index}] must have exactly keys "
                f"{sorted(_MANIFEST_ENTRY_KEYS)}"
            )
            continue
        rule_id, version, path, enabled = raw["id"], raw["version"], raw["path"], raw["enabled"]
        if not all(isinstance(v, str) and v for v in (rule_id, version, path)):
            errors.append(f"pack.yaml: rules[{index}] id/version/path must be strings")
            continue
        if not isinstance(enabled, bool):
            errors.append(f"pack.yaml: rules[{index}] enabled must be a bool")
            continue
        if rule_id in seen_ids:
            errors.append(f"pack.yaml: rule id {rule_id!r} listed more than once")
            continue
        if path in seen_paths:
            errors.append(f"pack.yaml: rule path {path!r} listed more than once")
            continue
        seen_ids.add(rule_id)
        seen_paths.add(path)
        entries.append(ManifestEntry(rule_id=rule_id, version=version, path=path, enabled=enabled))
    if errors:
        return None
    return PackManifest(
        schema=doc["schema"],
        pack_version=doc["pack_version"],
        generated_at=doc["generated_at"],
        min_schema_version=doc["min_schema_version"],
        entries=tuple(entries),
    )


def load_fixture(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_fixture(
    compiled: CompiledRule, fixture: Mapping[str, Any], errors: list[str]
) -> int:
    """Structural fixture checks (§7). Returns the number of cases found."""
    rid = compiled.rule_id
    if fixture.get("rule_id") != rid:
        errors.append(f"{rid}: fixture rule_id {fixture.get('rule_id')!r} != rule id")
    if fixture.get("rule_version") != compiled.version:
        errors.append(
            f"{rid}: fixture rule_version {fixture.get('rule_version')!r} "
            f"!= rule version {compiled.version!r}"
        )
    count = 0
    for section in ("must_match", "must_not_match"):
        cases = fixture.get(section)
        if not isinstance(cases, list) or not cases:
            errors.append(f"{rid}: fixture needs >= 1 {section} case (§7)")
            continue
        for case in cases:
            if not isinstance(case, Mapping) or "name" not in case or "event" not in case:
                errors.append(f"{rid}: every {section} case needs 'name' and 'event'")
                continue
            count += 1
            if (
                section == "must_not_match"
                and case["event"].get("event_class") != compiled.event_class
            ):
                errors.append(
                    f"{rid}: must_not_match case {case['name']!r} must be the same "
                    f"event_class as the rule (§7 — exercise the condition, not the gate)"
                )
    return count


def run_rule_fixture(compiled: CompiledRule, fixture: Mapping[str, Any]) -> list[str]:
    """Evaluate all fixture cases against the real engine; return failures."""
    failures: list[str] = []
    for case in fixture.get("must_match", []):
        if not compiled.evaluate(case["event"]):
            failures.append(
                f"{compiled.rule_id}: must_match case {case['name']!r} did NOT match"
            )
    for case in fixture.get("must_not_match", []):
        if compiled.evaluate(case["event"]):
            failures.append(
                f"{compiled.rule_id}: must_not_match case {case['name']!r} MATCHED"
            )
    return failures


def load_pack(pack_yaml: Path, *, run_fixtures: bool = True) -> PackValidation:
    """Load + validate a whole pack directory (FORMAT.md §6 publish validation).

    Checks: manifest shape, every listed file exists/parses/compiles, id and
    version match between manifest and rule file, filename equals rule id,
    no unlisted rule files, per-rule fixtures exist and (optionally) pass."""
    pack_yaml = Path(pack_yaml)
    pack_dir = pack_yaml.parent
    result = PackValidation(pack_dir=pack_dir)

    try:
        doc = load_yaml_document(pack_yaml)
    except (OSError, yaml.YAMLError) as exc:
        result.errors.append(f"pack.yaml: {exc}")
        return result

    manifest = _parse_manifest(doc, result.errors)
    if manifest is None:
        return result
    result.manifest = manifest

    listed_files: set[Path] = set()
    for entry in manifest.entries:
        rule_path = pack_dir / entry.path
        listed_files.add(rule_path.resolve())
        if not rule_path.is_file():
            result.errors.append(f"{entry.rule_id}: rule file {entry.path!r} does not exist")
            continue
        if rule_path.stem != entry.rule_id:
            result.errors.append(
                f"{entry.rule_id}: filename {rule_path.name!r} must equal the rule id (§1)"
            )
        try:
            rule_doc = load_yaml_document(rule_path)
        except (OSError, yaml.YAMLError) as exc:
            result.errors.append(f"{entry.rule_id}: cannot parse rule file: {exc}")
            continue
        try:
            compiled = compile_rule(rule_doc)
        except RuleCompileError as exc:
            result.errors.append(str(exc))
            continue
        if compiled.rule_id != entry.rule_id:
            result.errors.append(
                f"{entry.rule_id}: manifest id != rule file id {compiled.rule_id!r}"
            )
            continue
        if compiled.version != entry.version:
            result.errors.append(
                f"{entry.rule_id}: manifest version {entry.version!r} "
                f"!= rule file version {compiled.version!r}"
            )
            continue

        fixture_path = pack_dir / "tests" / "cases" / f"{entry.rule_id}.json"
        if not fixture_path.is_file():
            result.errors.append(
                f"{entry.rule_id}: missing fixture tests/cases/{entry.rule_id}.json "
                "(required for publish, §7)"
            )
            continue
        try:
            fixture = load_fixture(fixture_path)
        except (OSError, json.JSONDecodeError) as exc:
            result.errors.append(f"{entry.rule_id}: cannot parse fixture: {exc}")
            continue
        result.fixture_case_count += _validate_fixture(compiled, fixture, result.errors)
        if run_fixtures:
            result.errors.extend(run_rule_fixture(compiled, fixture))

        result.rules.append(PackRule(entry=entry, compiled=compiled))

    rules_dir = pack_dir / "rules"
    if rules_dir.is_dir():
        for rule_file in sorted(rules_dir.glob("*.yml")):
            if rule_file.resolve() not in listed_files:
                result.errors.append(
                    f"pack.yaml: rule file rules/{rule_file.name} exists but is not listed "
                    "(every rule file must be listed exactly once, §6)"
                )

    return result
