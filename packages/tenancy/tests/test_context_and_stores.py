import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest

from soc_tenancy import (
    SET_TENANT_GUC_SQL,
    InvalidTenantError,
    TenantContextError,
    events_alias,
    events_index,
    get_current_tenant,
    require_current_tenant,
    set_local_tenant,
    set_local_tenant_sql,
    tenant_context,
)

TENANT = uuid.UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")


async def test_tenant_context_sets_and_resets():
    assert get_current_tenant() is None
    async with tenant_context(TENANT) as tid:
        assert tid == TENANT
        assert require_current_tenant() == TENANT
    assert get_current_tenant() is None
    with pytest.raises(TenantContextError):
        require_current_tenant()


async def test_tenant_context_rejects_garbage():
    with pytest.raises(InvalidTenantError):
        async with tenant_context("nope"):
            pass


def test_events_alias_and_index():
    assert events_alias(TENANT) == f"events-{TENANT}"
    when = datetime(2026, 7, 8, 9, 14, tzinfo=UTC)
    assert events_index(TENANT, when) == f"events-v1-{TENANT}-2026.07"


def test_events_index_normalizes_to_utc():
    # 2026-08-01T01:00+03:00 is 2026-07-31T22:00 UTC -> July index
    when = datetime(2026, 8, 1, 1, 0, tzinfo=timezone(timedelta(hours=3)))
    assert events_index(TENANT, when).endswith("2026.07")


def test_events_index_rejects_naive_datetime():
    with pytest.raises(InvalidTenantError):
        events_index(TENANT, datetime(2026, 7, 8))  # naive on purpose


@pytest.mark.parametrize("bad", [None, "", "not-a-uuid", "events-v1-*", "*", "a;DROP"])
def test_es_helpers_fail_closed(bad):
    with pytest.raises(InvalidTenantError):
        events_alias(bad)
    with pytest.raises(InvalidTenantError):
        events_index(bad, datetime.now(UTC))


class FakeConn:
    def __init__(self):
        self.calls = []

    async def execute(self, query, *args):
        self.calls.append((query, args))


async def test_set_local_tenant_uses_transaction_scoped_guc():
    conn = FakeConn()
    await set_local_tenant(conn, str(TENANT))
    assert conn.calls == [(SET_TENANT_GUC_SQL, (str(TENANT),))]
    assert "set_config('app.tenant_id', $1, true)" in SET_TENANT_GUC_SQL


async def test_set_local_tenant_rejects_bad_uuid_before_io():
    conn = FakeConn()
    with pytest.raises(InvalidTenantError):
        await set_local_tenant(conn, "1 OR 1=1")
    assert conn.calls == []


def test_set_local_tenant_sql_literal_is_canonical_uuid():
    sql = set_local_tenant_sql(str(TENANT).upper())
    assert sql == f"SET LOCAL app.tenant_id = '{TENANT}'"
    with pytest.raises(InvalidTenantError):
        set_local_tenant_sql("'; DROP TABLE alerts; --")
