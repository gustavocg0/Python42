#!/usr/bin/env python3
"""Plain-SQL migration runner for the SOC platform PostgreSQL database.

Migrations live in db/migrations/NNNN_description.sql and are applied in
filename order. Each file MUST contain two sections:

    -- migrate:up
    <forward DDL/DML>
    -- migrate:down
    <reverse DDL/DML>

Each migration (up or down) runs in a single transaction. Applied files are
tracked in public.schema_migrations (filename, sha256 checksum, applied_at).
Re-running `up` is a no-op for already-applied files (idempotent). Checksum
drift on an already-applied file prints a warning (never silently re-applies).

Usage:
    python db/migrate.py --dsn postgresql://user:pass@host:5432/db up
    python db/migrate.py up                 # uses $DATABASE_URL
    python db/migrate.py down --steps 1     # revert last migration
    python db/migrate.py status

The connecting user becomes the OWNER of all created objects. Run migrations
as a dedicated owner/migration user (e.g. `soc_owner`), NEVER as the runtime
application users: runtime roles must not own tables (AC-79/SEC-23).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
UP_MARK = "-- migrate:up"
DOWN_MARK = "-- migrate:down"


@dataclass(frozen=True)
class Migration:
    name: str
    up_sql: str
    down_sql: str
    checksum: str


def load_migrations(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    migrations: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        if UP_MARK not in text or DOWN_MARK not in text:
            raise SystemExit(
                f"{path.name}: every migration must contain both "
                f"'{UP_MARK}' and '{DOWN_MARK}' sections (reversibility rule)"
            )
        up_part, down_part = text.split(DOWN_MARK, 1)
        up_sql = up_part.split(UP_MARK, 1)[1].strip()
        down_sql = down_part.strip()
        if not up_sql or not down_sql:
            raise SystemExit(f"{path.name}: empty up or down section")
        checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()
        migrations.append(Migration(path.name, up_sql, down_sql, checksum))
    if not migrations:
        raise SystemExit(f"no .sql migrations found in {directory}")
    return migrations


def ensure_tracking_table(conn: psycopg.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS public.schema_migrations (
            filename   text        PRIMARY KEY,
            checksum   text        NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def applied_map(conn: psycopg.Connection) -> dict[str, str]:
    rows = conn.execute(
        "SELECT filename, checksum FROM public.schema_migrations"
    ).fetchall()
    return {name: checksum for name, checksum in rows}


def cmd_up(conn: psycopg.Connection, migrations: list[Migration]) -> int:
    applied = applied_map(conn)
    newly_applied = 0
    for mig in migrations:
        if mig.name in applied:
            if applied[mig.name] != mig.checksum:
                print(
                    f"WARNING: {mig.name} was modified after being applied "
                    f"(checksum drift) -- write a new migration instead",
                    file=sys.stderr,
                )
            continue
        with conn.transaction():
            conn.execute(mig.up_sql)
            conn.execute(
                "INSERT INTO public.schema_migrations (filename, checksum) "
                "VALUES (%s, %s)",
                (mig.name, mig.checksum),
            )
        print(f"applied  {mig.name}")
        newly_applied += 1
    print(f"up to date: {len(applied) + newly_applied} applied "
          f"({newly_applied} new)")
    return 0


def cmd_down(conn: psycopg.Connection, migrations: list[Migration],
             steps: int) -> int:
    applied = applied_map(conn)
    by_name = {m.name: m for m in migrations}
    to_revert = sorted(applied, reverse=True)[:steps]
    if not to_revert:
        print("nothing to revert")
        return 0
    for name in to_revert:
        mig = by_name.get(name)
        if mig is None:
            raise SystemExit(
                f"cannot revert {name}: migration file missing from "
                f"{MIGRATIONS_DIR}"
            )
        with conn.transaction():
            conn.execute(mig.down_sql)
            conn.execute(
                "DELETE FROM public.schema_migrations WHERE filename = %s",
                (name,),
            )
        print(f"reverted {name}")
    return 0


def cmd_status(conn: psycopg.Connection, migrations: list[Migration]) -> int:
    applied = applied_map(conn)
    for mig in migrations:
        if mig.name not in applied:
            state = "pending"
        elif applied[mig.name] != mig.checksum:
            state = "APPLIED (checksum drift!)"
        else:
            state = "applied"
        print(f"{state:<24} {mig.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dsn",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL DSN (default: $DATABASE_URL)",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("up", help="apply all pending migrations (default)")
    down = sub.add_parser("down", help="revert the most recent migration(s)")
    down.add_argument("--steps", type=int, default=1,
                      help="number of migrations to revert (default 1)")
    sub.add_parser("status", help="list migration state")
    args = parser.parse_args(argv)

    if not args.dsn:
        parser.error("no DSN: pass --dsn or set DATABASE_URL")

    command = args.command or "up"
    migrations = load_migrations()

    with psycopg.connect(args.dsn, autocommit=True) as conn:
        ensure_tracking_table(conn)
        if command == "up":
            return cmd_up(conn, migrations)
        if command == "down":
            return cmd_down(conn, migrations, args.steps)
        return cmd_status(conn, migrations)


if __name__ == "__main__":
    raise SystemExit(main())
