"""Rule-pack CLI (SEC-27).

    python -m dataplane.rulepub validate [rules/pack.yaml]
        Validate + compile the whole pack and run every fixture case.
        No database access — safe for CI. Exit 0 = pack publishable.

    python -m dataplane.rulepub publish rules/pack.yaml --published-by <op>
        Validate (as above), then write rule_packs + rules + audit_log in one
        transaction; previous active pack is marked superseded. DSN from
        --dsn or $DATAPLANE_DATABASE_URL.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from dataplane.rulepub.packio import PackValidation, load_pack
from dataplane.rulepub.publish import PackPublishError, publish_pack

DEFAULT_PACK_PATH = "rules/pack.yaml"
ENV_DATABASE_URL = "DATAPLANE_DATABASE_URL"


def _validate(pack_path: Path) -> PackValidation:
    validation = load_pack(pack_path, run_fixtures=True)
    if validation.ok:
        print(
            f"OK: pack {validation.manifest.pack_version} — "
            f"{len(validation.rules)} rules compiled, "
            f"{validation.fixture_case_count} fixture cases passed"
        )
    else:
        print(
            f"REJECTED: pack failed validation with {len(validation.errors)} error(s) "
            "(whole pack rejected atomically, SEC-27):",
            file=sys.stderr,
        )
        for error in validation.errors:
            print(f"  - {error}", file=sys.stderr)
    return validation


async def _publish(dsn: str, validation: PackValidation, published_by: str) -> int:
    import asyncpg  # imported lazily: `validate` must work without a DB driver

    conn = await asyncpg.connect(dsn)
    try:
        result = await publish_pack(conn, validation, published_by=published_by)
    finally:
        await conn.close()
    print(
        f"PUBLISHED: pack {result.pack_version} "
        f"({result.rule_count} rules, manifest_hash {result.manifest_hash}, "
        f"published_by {result.published_by})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dataplane.rulepub")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate a pack (no DB; CI gate)")
    validate_parser.add_argument("pack", nargs="?", default=DEFAULT_PACK_PATH)

    publish_parser = subparsers.add_parser("publish", help="validate and publish a pack")
    publish_parser.add_argument("pack")
    publish_parser.add_argument(
        "--published-by",
        required=True,
        help="named operator or CI identity recorded in rule_packs + audit_log (SEC-27)",
    )
    publish_parser.add_argument(
        "--dsn",
        default=None,
        help=f"Postgres DSN (default: ${ENV_DATABASE_URL})",
    )

    args = parser.parse_args(argv)
    pack_path = Path(args.pack)

    validation = _validate(pack_path)
    if not validation.ok:
        return 1
    if args.command == "validate":
        return 0

    dsn = args.dsn or os.environ.get(ENV_DATABASE_URL)
    if not dsn:
        print(f"error: no DSN — pass --dsn or set ${ENV_DATABASE_URL}", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_publish(dsn, validation, args.published_by))
    except PackPublishError as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
