"""Publish tooling tests: validate subcommand (CI gate) + atomic publish
(SEC-27) against a fake connection — no live Postgres."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import PACK_YAML, RULES_DIR

from dataplane.rulepub.__main__ import main
from dataplane.rulepub.packio import load_pack, manifest_hash
from dataplane.rulepub.publish import (
    SQL_INSERT_PACK,
    SQL_INSERT_RULE,
    SQL_SUPERSEDE_ACTIVE,
    PackPublishError,
    publish_pack,
)


class _FakeTransaction:
    def __init__(self, conn: FakeConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> FakeConn:
        self._conn.tx_depth += 1
        return self._conn

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        self._conn.tx_depth -= 1
        if exc_type is not None:
            self._conn.rolled_back = True
        return False


class FakeConn:
    """asyncpg-Connection-shaped recorder."""

    def __init__(self, *, pack_exists: Any = None) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.tx_depth = 0
        self.rolled_back = False
        self._pack_exists = pack_exists

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    async def execute(self, sql: str, *args: Any) -> str:
        assert self.tx_depth > 0, "publish writes must happen inside the transaction"
        self.calls.append((sql, args))
        return "INSERT 0 1"

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.calls.append((sql, args))
        return self._pack_exists


# --- validate ---------------------------------------------------------------------


def test_validate_real_pack_passes(capsys) -> None:
    assert main(["validate", str(PACK_YAML)]) == 0
    out = capsys.readouterr().out
    assert "25 rules compiled" in out
    assert "81 fixture cases passed" in out


def _copy_pack_subset(tmp_path: Path, rule_ids: list[str]) -> Path:
    """Materialize a small pack directory reusing real rule files."""
    (tmp_path / "rules").mkdir()
    (tmp_path / "tests" / "cases").mkdir(parents=True)
    lines = [
        "schema: rule-pack/v1",
        'pack_version: "0.0.1"',
        'generated_at: "1970-01-01T00:00:00Z"',
        'min_schema_version: "1.0.0"',
        "rules:",
    ]
    for rule_id in rule_ids:
        shutil.copy(RULES_DIR / "rules" / f"{rule_id}.yml", tmp_path / "rules")
        shutil.copy(RULES_DIR / "tests" / "cases" / f"{rule_id}.json",
                    tmp_path / "tests" / "cases")
        lines += [
            f"  - id: {rule_id}",
            '    version: "1.0.0"',
            f"    path: rules/{rule_id}.yml",
            "    enabled: true",
        ]
    pack_yaml = tmp_path / "pack.yaml"
    pack_yaml.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pack_yaml


def test_one_invalid_rule_rejects_whole_pack(tmp_path, capsys) -> None:
    """SEC-27: a single bad rule fails validation for the entire pack."""
    pack_yaml = _copy_pack_subset(
        tmp_path, ["proc-powershell-encoded-command", "gen-ssh-auth-failure"]
    )
    bad = tmp_path / "rules" / "gen-ssh-auth-failure.yml"
    bad.write_text(
        bad.read_text(encoding="utf-8").replace("op: icontains", "op: bogus-op"),
        encoding="utf-8",
    )
    validation = load_pack(pack_yaml)
    assert not validation.ok
    assert any("gen-ssh-auth-failure" in e and "bogus-op" in e for e in validation.errors)
    assert main(["validate", str(pack_yaml)]) == 1
    assert "REJECTED" in capsys.readouterr().err


def test_fixture_failure_blocks_publish(tmp_path) -> None:
    """§7: a fixture regression is a validation error (blocks publish)."""
    pack_yaml = _copy_pack_subset(tmp_path, ["proc-powershell-encoded-command"])
    rule_file = tmp_path / "rules" / "proc-powershell-encoded-command.yml"
    # Break the rule so its must_match cases stop matching.
    rule_file.write_text(
        rule_file.read_text(encoding="utf-8").replace(
            '["powershell.exe", "pwsh.exe"]', '["nonexistent.exe"]'
        ),
        encoding="utf-8",
    )
    validation = load_pack(pack_yaml)
    assert not validation.ok
    assert any("must_match" in e and "did NOT match" in e for e in validation.errors)


def test_unlisted_rule_file_is_error(tmp_path) -> None:
    pack_yaml = _copy_pack_subset(tmp_path, ["proc-powershell-encoded-command"])
    shutil.copy(RULES_DIR / "rules" / "gen-ssh-auth-failure.yml", tmp_path / "rules")
    validation = load_pack(pack_yaml)
    assert not validation.ok
    assert any("not listed" in e for e in validation.errors)


# --- publish ----------------------------------------------------------------------


async def test_publish_writes_pack_rules_and_audit_atomically() -> None:
    validation = load_pack(PACK_YAML)
    assert validation.ok
    conn = FakeConn()
    result = await publish_pack(conn, validation, published_by="ops@example.com")

    assert result.pack_version == "1.0.0"
    assert result.rule_count == 25
    assert len(result.manifest_hash) == 64
    assert result.manifest_hash == manifest_hash(validation.manifest, result.generated_at)

    executed = [sql for sql, _ in conn.calls]
    assert SQL_SUPERSEDE_ACTIVE in executed  # previous active pack superseded
    assert SQL_INSERT_PACK in executed
    assert executed.index(SQL_SUPERSEDE_ACTIVE) < executed.index(SQL_INSERT_PACK)
    rule_inserts = [args for sql, args in conn.calls if sql == SQL_INSERT_RULE]
    assert len(rule_inserts) == 25
    assert all(args[0] == "1.0.0" for args in rule_inserts)  # pack_version
    pack_args = next(args for sql, args in conn.calls if sql == SQL_INSERT_PACK)
    assert pack_args == ("1.0.0", result.manifest_hash, 25, "ops@example.com")
    # audit written in the SAME transaction, platform tenant scope (SEC-43)
    audit_calls = [sql for sql, _ in conn.calls if "INSERT INTO audit_log" in sql]
    assert len(audit_calls) == 1
    guc_calls = [args for sql, args in conn.calls if "app.tenant_id" in sql]
    assert guc_calls == [("00000000-0000-0000-0000-000000000000",)]
    assert conn.rolled_back is False


async def test_publish_rejects_duplicate_version() -> None:
    validation = load_pack(PACK_YAML)
    conn = FakeConn(pack_exists=1)
    with pytest.raises(PackPublishError, match="already published"):
        await publish_pack(conn, validation, published_by="ops@example.com")
    assert conn.rolled_back is True  # transaction unwound: nothing persists
    assert not any(sql == SQL_INSERT_PACK for sql, _ in conn.calls)


async def test_publish_refuses_invalid_validation(tmp_path) -> None:
    pack_yaml = _copy_pack_subset(tmp_path, ["proc-powershell-encoded-command"])
    (tmp_path / "rules" / "proc-powershell-encoded-command.yml").write_text(
        "id: broken\n", encoding="utf-8"
    )
    validation = load_pack(pack_yaml)
    assert not validation.ok
    conn = FakeConn()
    with pytest.raises(PackPublishError, match="SEC-27"):
        await publish_pack(conn, validation, published_by="ops@example.com")
    assert conn.calls == []  # zero DB writes on a rejected pack


def test_publish_cli_rejects_before_touching_db(tmp_path, capsys) -> None:
    pack_yaml = _copy_pack_subset(tmp_path, ["proc-powershell-encoded-command"])
    (tmp_path / "rules" / "proc-powershell-encoded-command.yml").write_text(
        "not: [valid\n", encoding="utf-8"
    )
    rc = main(
        ["publish", str(pack_yaml), "--published-by", "ci", "--dsn", "postgres://unused"]
    )
    assert rc == 1
    assert "REJECTED" in capsys.readouterr().err
