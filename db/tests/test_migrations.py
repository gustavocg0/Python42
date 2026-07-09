"""Tests for the SOC platform data layer (db/).

Two layers:

1. Static tests -- always run; no database needed. Validate migration file
   hygiene (up/down sections, ordering) and that every tenant-scoped
   tenantdata table ships with FORCE RLS + the tenant_isolation policy in
   the same migration (SEC-23).

2. Live-PG tests -- run ONLY when SOC_DB_TEST_DSN (or DATABASE_URL) points
   at a reachable PostgreSQL >= 13 with a superuser (dev/CI) account, and
   SOC_DB_SKIP_PG != 1. They are DESTRUCTIVE (drop/recreate the schemas and
   runtime roles) -- point them at a disposable database only. CI runs them
   against a postgres:16 service container.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")

DB_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DB_DIR))
import migrate  # noqa: E402

MIGRATION_FILES = sorted((DB_DIR / "migrations").glob("*.sql"))

# Global platform content tables: deliberately NOT tenant-scoped, no RLS
# (documented in 0006_rules_dlq_metering.sql).
GLOBAL_TABLES = {
    "tenantdata.rule_packs",
    "tenantdata.rules",
    "tenantdata.rule_runtime_disables",
}

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
RUNTIME_ROLES = ("app_control", "app_dataplane", "audit_writer", "system_jobs")


# ---------------------------------------------------------------- static

def test_migration_filenames_numbered_and_unique():
    assert MIGRATION_FILES, "no migrations found"
    prefixes = [p.name.split("_", 1)[0] for p in MIGRATION_FILES]
    assert all(re.fullmatch(r"\d{4}", x) for x in prefixes), prefixes
    assert prefixes == sorted(prefixes)
    assert len(set(prefixes)) == len(prefixes), "duplicate migration numbers"


def test_every_migration_has_up_and_down_sections():
    migrations = migrate.load_migrations()  # SystemExit on violation
    assert len(migrations) == len(MIGRATION_FILES)
    for mig in migrations:
        assert mig.up_sql and mig.down_sql


def test_every_tenant_scoped_table_has_force_rls_and_policy():
    for path in MIGRATION_FILES:
        sql = path.read_text(encoding="utf-8")
        for m in re.finditer(r"CREATE TABLE (tenantdata\.\w+)", sql):
            table = m.group(1)
            if table in GLOBAL_TABLES:
                continue
            for stmt in (
                f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
                f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
                f"CREATE POLICY tenant_isolation ON {table}",
            ):
                assert stmt in sql, f"{path.name}: missing '{stmt}' (SEC-23)"


def test_audit_migration_ships_immutability_guards():
    sql = (DB_DIR / "migrations" / "0007_audit_log.sql").read_text("utf-8")
    assert "BEFORE UPDATE OR DELETE ON tenantdata.audit_log" in sql
    assert "BEFORE TRUNCATE ON tenantdata.audit_log" in sql
    assert "audit_purge_expired" in sql
    assert "retention_days < 365" in sql  # SEC-44 floor


def test_audit_log_columns_match_soc_audit_writer_contract():
    """The binding column contract is AUDIT_INSERT_SQL in packages/audit
    (soc_audit.writer). Every column it inserts must exist in the 0007
    CREATE TABLE (Architect integration ruling: writer contract wins)."""
    writer_py = (DB_DIR.parent / "packages" / "audit" / "src" / "soc_audit"
                 / "writer.py")
    if not writer_py.exists():
        pytest.skip("packages/audit not present in this checkout")
    src = writer_py.read_text(encoding="utf-8")
    m = re.search(r"INSERT INTO audit_log\s*\(([^)]*)\)", src)
    assert m, "AUDIT_INSERT_SQL not found in soc_audit.writer"
    contract_cols = [c.strip() for c in m.group(1).replace("\n", " ").split(",")]

    sql = (DB_DIR / "migrations" / "0007_audit_log.sql").read_text("utf-8")
    t = re.search(r"CREATE TABLE tenantdata\.audit_log \((.*?)\n\);", sql,
                  re.DOTALL)
    assert t, "CREATE TABLE tenantdata.audit_log not found"
    table_cols = {
        line.strip().split()[0]
        for line in t.group(1).splitlines()
        if line.strip() and not line.strip().startswith("--")
    }
    missing = [c for c in contract_cols if c not in table_cols]
    assert not missing, f"audit_log missing writer-contract columns: {missing}"
    assert "created_at" in contract_cols  # DB-clock timestamp (SEC-45)


# ---------------------------------------------------------------- live PG

DSN = os.environ.get("SOC_DB_TEST_DSN") or os.environ.get("DATABASE_URL")

requires_pg = pytest.mark.skipif(
    not DSN or os.environ.get("SOC_DB_SKIP_PG") == "1",
    reason="live-PG tests need SOC_DB_TEST_DSN/DATABASE_URL "
           "(and SOC_DB_SKIP_PG unset)",
)


@pytest.fixture(scope="session")
def conn():
    try:
        c = psycopg.connect(DSN, autocommit=True, connect_timeout=5)
    except Exception as exc:  # unreachable PG -> auto-skip
        pytest.skip(f"PostgreSQL unreachable: {exc}")
    yield c
    c.close()


@pytest.fixture(scope="session")
def migrated(conn):
    """Clean slate, then all migrations up. DESTRUCTIVE."""
    conn.execute("DROP SCHEMA IF EXISTS tenantdata CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS control CASCADE")
    conn.execute("DROP TABLE IF EXISTS public.schema_migrations")
    for role in RUNTIME_ROLES:
        conn.execute(
            f"""DO $$ BEGIN
                  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                    EXECUTE 'DROP OWNED BY {role}';
                    EXECUTE 'DROP ROLE {role}';
                  END IF;
                END $$"""
        )
    migrate.ensure_tracking_table(conn)
    migrate.cmd_up(conn, migrate.load_migrations())
    return conn


@requires_pg
def test_up_is_idempotent(migrated):
    migrate.cmd_up(migrated, migrate.load_migrations())  # second run: no-op
    n = migrated.execute(
        "SELECT count(*) FROM public.schema_migrations").fetchone()[0]
    assert n == len(MIGRATION_FILES)


@requires_pg
def test_expected_tables_exist(migrated):
    rows = migrated.execute(
        """SELECT table_schema || '.' || table_name
           FROM information_schema.tables
           WHERE table_schema IN ('control','tenantdata')"""
    ).fetchall()
    tables = {r[0] for r in rows}
    expected = {
        "control.accounts", "control.tenants", "control.plans",
        "control.plan_config", "control.platform_config",
        "control.entitlement_overrides", "control.users",
        "control.email_verifications", "control.sessions",
        "control.provisioning_sagas", "control.provisioning_saga_steps",
        "control.signup_abuse_log", "control.purge_registry",
        "tenantdata.assets", "tenantdata.asset_identities",
        "tenantdata.asset_identity_pins", "tenantdata.asset_merge_audit",
        "tenantdata.devices", "tenantdata.enrollment_tokens",
        "tenantdata.ingest_keys", "tenantdata.correlation_groups",
        "tenantdata.alerts", "tenantdata.alert_events",
        "tenantdata.alert_history", "tenantdata.rule_packs",
        "tenantdata.rules", "tenantdata.rule_runtime_disables",
        "tenantdata.rule_toggles", "tenantdata.dead_letter_events",
        "tenantdata.llm_metering", "tenantdata.deep_investigation_runs",
        "tenantdata.onboarding_steps", "tenantdata.usage_counters",
        "tenantdata.audit_log",
    }
    assert expected <= tables, expected - tables


@requires_pg
def test_rls_enabled_and_forced_on_all_tenant_tables(migrated):
    rows = migrated.execute(
        """SELECT n.nspname || '.' || c.relname,
                  c.relrowsecurity, c.relforcerowsecurity
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'tenantdata' AND c.relkind = 'r'"""
    ).fetchall()
    for table, enabled, forced in rows:
        if table in GLOBAL_TABLES:
            continue
        assert enabled and forced, f"{table}: RLS not ENABLE+FORCE (SEC-23)"


@requires_pg
def test_runtime_roles_have_no_dangerous_attributes(migrated):
    rows = migrated.execute(
        """SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
           FROM pg_roles WHERE rolname = ANY(%s)""", (list(RUNTIME_ROLES),)
    ).fetchall()
    assert len(rows) == len(RUNTIME_ROLES)
    for name, superuser, bypassrls, canlogin in rows:
        assert not superuser and not bypassrls and not canlogin, name


@requires_pg
def test_runtime_roles_own_no_tables(migrated):
    rows = migrated.execute(
        """SELECT schemaname, tablename, tableowner FROM pg_tables
           WHERE schemaname IN ('control','tenantdata')
             AND tableowner = ANY(%s)""", (list(RUNTIME_ROLES),)
    ).fetchall()
    assert rows == [], f"runtime roles own tables (AC-79): {rows}"


@requires_pg
def test_rls_deny_by_default_and_tenant_isolation(migrated):
    c = migrated
    # Seed one asset per tenant as app_dataplane with pinned GUC.
    for tenant, host in ((TENANT_A, "host-a"), (TENANT_B, "host-b")):
        with c.transaction():
            c.execute("SET LOCAL ROLE app_dataplane")
            c.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
            c.execute(
                "INSERT INTO tenantdata.assets (tenant_id, hostname, os_family)"
                " VALUES (%s, %s, 'windows')", (tenant, host))
    # Unset GUC => zero rows (deny-by-default), not an error.
    with c.transaction():
        c.execute("SET LOCAL ROLE app_dataplane")
        n = c.execute("SELECT count(*) FROM tenantdata.assets").fetchone()[0]
        assert n == 0
    # Pinned to A => only A's rows.
    with c.transaction():
        c.execute("SET LOCAL ROLE app_dataplane")
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT_A,))
        rows = c.execute("SELECT hostname FROM tenantdata.assets").fetchall()
        assert rows == [("host-a",)]
    # WITH CHECK: pinned to A, inserting a B row must fail.
    with pytest.raises(psycopg.Error, match="row-level security"):
        with c.transaction():
            c.execute("SET LOCAL ROLE app_dataplane")
            c.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT_A,))
            c.execute(
                "INSERT INTO tenantdata.assets (tenant_id, hostname, os_family)"
                " VALUES (%s, 'evil', 'windows')", (TENANT_B,))


@requires_pg
def test_audit_log_is_append_only(migrated):
    c = migrated
    with c.transaction():
        c.execute("SET LOCAL ROLE audit_writer")
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT_A,))
        c.execute(
            "INSERT INTO tenantdata.audit_log"
            " (tenant_id, actor_type, actor_id, action_type)"
            " VALUES (%s, 'user', 'usr_test', 'test.event')", (TENANT_A,))
    # Guard trigger fires even for the superuser/owner.
    with pytest.raises(psycopg.Error, match="append-only"):
        with c.transaction():
            c.execute("UPDATE tenantdata.audit_log SET action_type = 'x'")
    with pytest.raises(psycopg.Error, match="append-only"):
        with c.transaction():
            c.execute("DELETE FROM tenantdata.audit_log")
    with pytest.raises(psycopg.Error, match="append-only"):
        with c.transaction():
            c.execute("TRUNCATE tenantdata.audit_log")
    # No runtime role holds UPDATE/DELETE (SEC-42).
    for role in RUNTIME_ROLES:
        for priv in ("UPDATE", "DELETE"):
            ok = c.execute(
                "SELECT has_table_privilege(%s, 'tenantdata.audit_log', %s)",
                (role, priv)).fetchone()[0]
            assert not ok, f"{role} must not have {priv} on audit_log"
    # audit_writer can INSERT; app_dataplane cannot.
    assert c.execute(
        "SELECT has_table_privilege('audit_writer', 'tenantdata.audit_log',"
        " 'INSERT')").fetchone()[0]
    assert not c.execute(
        "SELECT has_table_privilege('app_dataplane', 'tenantdata.audit_log',"
        " 'INSERT')").fetchone()[0]


@requires_pg
def test_audit_purge_enforces_365_day_floor(migrated):
    with pytest.raises(psycopg.Error, match="floor is 365"):
        with migrated.transaction():
            migrated.execute("SELECT tenantdata.audit_purge_expired(30)")
    # At the floor it runs (nothing old enough to delete).
    deleted = migrated.execute(
        "SELECT tenantdata.audit_purge_expired(365)").fetchone()[0]
    assert deleted == 0


@requires_pg
def test_open_alert_dedup_is_unique(migrated):
    c = migrated

    def insert(alert_id):
        c.execute(
            """INSERT INTO tenantdata.alerts
               (id, tenant_id, state, rule_id, rule_version, rule_title,
                rule_severity, entity_key, first_seen, last_seen,
                priority_score)
               VALUES (%s, %s, 'new', 'r1', '1.0.0', 'T', 'high',
                       'h|u', now(), now(), 50)""", (alert_id, TENANT_A))

    with c.transaction():
        insert("al_dedup_1")
    with pytest.raises(psycopg.errors.UniqueViolation):
        with c.transaction():
            insert("al_dedup_2")  # same (tenant, rule, entity), still open


@requires_pg
def test_dlq_payload_cap_64kb(migrated):
    with pytest.raises(psycopg.errors.CheckViolation):
        with migrated.transaction():
            migrated.execute(
                """INSERT INTO tenantdata.dead_letter_events
                   (tenant_id, source_type, raw_payload, error_code)
                   VALUES (%s, 'generic', %s, 'SCHEMA_INVALID')""",
                (TENANT_A, b"x" * 65537))


@requires_pg
def test_plan_config_seed_matches_prd(migrated):
    rows = migrated.execute(
        "SELECT plan_id, key, value FROM control.plan_config").fetchall()
    cfg = {(p, k): v for p, k, v in rows}
    assert cfg[("trial", "trial_duration_days")] == 14
    assert cfg[("trial", "endpoint_cap")] == 100
    assert cfg[("core", "endpoint_cap")] == 250
    assert cfg[("pro", "endpoint_cap")] == 1000
    assert cfg[("trial", "retention_days")] == 14
    assert cfg[("core", "retention_days")] == 30
    assert cfg[("pro", "retention_days")] == 90
    assert cfg[("trial", "deep_investigation_daily_quota")] == 5
    assert cfg[("pro", "deep_investigation_daily_quota")] == -1
    assert cfg[("trial", "response_mode")] == "recommend_only"
    assert cfg[("pro", "response_mode")] == "playbooks_with_approval"
    assert cfg[("trial", "ingest_events_per_min")] == 5000
    assert cfg[("core", "ingest_events_per_min")] == 10000
    assert cfg[("pro", "ingest_events_per_min")] == 40000


@requires_pg
def test_purge_registry_has_no_gaps(migrated):
    gaps = migrated.execute(
        "SELECT * FROM control.purge_registry_gaps").fetchall()
    assert gaps == [], f"tenant-scoped tables missing from purge registry: {gaps}"


@requires_pg
def test_seed_dev_applies(migrated):
    sql = (DB_DIR / "seed_dev.sql").read_text(encoding="utf-8")
    migrated.execute(sql)
    n = migrated.execute(
        "SELECT count(*) FROM control.tenants WHERE id IN (%s, %s)",
        (TENANT_A, TENANT_B)).fetchone()[0]
    assert n == 2


@requires_pg
def test_down_to_zero_then_up_again(migrated):
    """Reversibility: every migration's down section works, in order.
    Runs LAST (file order) -- it drops and recreates everything."""
    migrations = migrate.load_migrations()
    migrate.cmd_down(migrated, migrations, steps=len(migrations))
    schemas = migrated.execute(
        """SELECT nspname FROM pg_namespace
           WHERE nspname IN ('control','tenantdata')""").fetchall()
    assert schemas == []
    roles = migrated.execute(
        "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)",
        (list(RUNTIME_ROLES),)).fetchall()
    assert roles == []
    migrate.cmd_up(migrated, migrations)
    n = migrated.execute(
        "SELECT count(*) FROM public.schema_migrations").fetchone()[0]
    assert n == len(migrations)
