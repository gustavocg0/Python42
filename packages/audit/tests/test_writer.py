import json
import uuid

import pytest
from pydantic import ValidationError

from soc_audit import AUDIT_INSERT_SQL, Actor, AuditValueTooLarge, Target, write_audit

TENANT = uuid.UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")
ACTOR = Actor(type="user", id="u_01J9ZX")
TARGET = Target(type="device", id="dev_01J9ZK3T")


class FakeConn:
    def __init__(self):
        self.calls = []

    async def execute(self, query, *args):
        self.calls.append((query, args))


async def test_insert_within_callers_connection_db_clock():
    conn = FakeConn()
    await write_audit(
        conn,
        tenant_id=TENANT,
        actor=ACTOR,
        action_type="device.revoke",
        target=TARGET,
        before={"status": "active"},
        after={"status": "revoked"},
        reason_code="admin_request",
    )
    assert len(conn.calls) == 1
    query, args = conn.calls[0]
    assert query == AUDIT_INSERT_SQL
    assert "now()" in query  # SEC-45: DB clock, not client
    assert args[0] == str(TENANT)
    assert args[1:6] == ("user", "u_01J9ZX", "device.revoke", "device", "dev_01J9ZK3T")
    assert json.loads(args[6]) == {"status": "active"}
    assert json.loads(args[7]) == {"status": "revoked"}
    assert args[8] == "admin_request"


async def test_secret_values_redacted_in_before_after():
    conn = FakeConn()
    await write_audit(
        conn,
        tenant_id=TENANT,
        actor=Actor(type="system", id="jobs-scheduler"),
        action_type="ingest_key.rotate",
        target=Target(type="ingest_key", id="ik_01"),
        after={"name": "fw", "key": "ik_01.supersecret"},
    )
    _, args = conn.calls[0]
    stored = json.loads(args[7])
    assert stored == {"name": "fw", "key": "[REDACTED]"}


async def test_oversized_value_fails_before_io():
    conn = FakeConn()
    with pytest.raises(AuditValueTooLarge):
        await write_audit(
            conn,
            tenant_id=TENANT,
            actor=ACTOR,
            action_type="x",
            target=TARGET,
            before={"raw_event_payload": "x" * (20 * 1024)},
        )
    assert conn.calls == []  # nothing written


async def test_invalid_tenant_fails_before_io():
    conn = FakeConn()
    with pytest.raises(ValueError):
        await write_audit(
            conn, tenant_id="nope", actor=ACTOR, action_type="x", target=TARGET
        )
    assert conn.calls == []


async def test_empty_action_type_rejected():
    conn = FakeConn()
    with pytest.raises(ValueError):
        await write_audit(
            conn, tenant_id=TENANT, actor=ACTOR, action_type="  ", target=TARGET
        )


def test_actor_taxonomy_fixed():
    with pytest.raises(ValidationError):
        Actor(type="robot", id="r2")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Actor(type="user", id="")
