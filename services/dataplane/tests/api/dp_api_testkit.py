"""Shared fakes/helpers for dataplane API tests (uniquely named module —
`conftest` cannot be imported by name once multiple test roots are collected
in one pytest run).

- PostgreSQL: SqlRouter + FakeConn/FakePool (behind the real Database wrapper)
- Elasticsearch: FakeES
- Entitlements: StubEntitlements
- CSR/session/allowlist seeding helpers
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dataplane.core.settings import Settings
from dataplane.core.tokens import mint_secret

TENANT_ID = UUID("11111111-2222-3333-4444-555555555555")
OTHER_TENANT_ID = UUID("99999999-8888-7777-6666-555555555555")
USER_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
GATEWAY_SECRET = "gw-secret-" + "x" * 54
INTERNAL_KEY = "internal-key-" + "k" * 32


# --------------------------------------------------------------- fake PG
class _FakeTx:
    async def start(self) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


class SqlRouter:
    """Rule-based fake SQL dispatcher. First matching rule wins; unmatched
    statements return empty results (fetch []/fetchrow None/fetchval None)."""

    def __init__(self) -> None:
        self._rules: list[tuple[re.Pattern[str], Any]] = []
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def on(
        self,
        pattern: str,
        *,
        rows: Any = None,
        value: Any = None,
        raises: Exception | None = None,
    ) -> None:
        if raises is not None:
            responder: Any = ("raises", raises)
        elif value is not None or rows is None:
            responder = ("value", value)
        else:
            responder = ("rows", rows)
        self._rules.append((re.compile(pattern, re.IGNORECASE | re.DOTALL), responder))

    def dispatch(self, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        self.calls.append((sql, args))
        flat = " ".join(sql.split())
        for pattern, (kind, payload) in self._rules:
            if pattern.search(flat):
                if kind == "raises":
                    raise payload
                if kind == "value":
                    resolved = payload(args) if callable(payload) else payload
                    return [] if resolved is None else [{"v": resolved}]
                resolved = payload(args) if callable(payload) else payload
                return list(resolved or [])
        return []

    def executed(self, pattern: str) -> list[tuple[str, tuple[Any, ...]]]:
        rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        return [(s, a) for s, a in self.calls if rx.search(" ".join(s.split()))]


class FakeConn:
    def __init__(self, router: SqlRouter) -> None:
        self._router = router
        self.tenant: str | None = None

    def transaction(self) -> _FakeTx:
        return _FakeTx()

    async def execute(self, sql: str, *args: Any) -> Any:
        if "set_config('app.tenant_id'" in sql:
            self.tenant = args[0]
            return None
        self._router.dispatch(sql, args)
        return "OK"

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return self._router.dispatch(sql, args)

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        rows = self._router.dispatch(sql, args)
        return rows[0] if rows else None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        rows = self._router.dispatch(sql, args)
        if not rows:
            return None
        return next(iter(rows[0].values()))


class _AcquireCM:
    def __init__(self, conn: FakeConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> FakeConn:
        return self._conn

    async def __aexit__(self, *exc: Any) -> None: ...


class FakePool:
    def __init__(self, conn: FakeConn) -> None:
        self._conn = conn

    def acquire(self) -> _AcquireCM:
        return _AcquireCM(self._conn)

    async def close(self) -> None: ...


# --------------------------------------------------------------- fake ES
class _FakeIndices:
    def __init__(self) -> None:
        self.created: list[str] = []
        self.aliases: dict[str, set[str]] = {}

    async def create(self, index: str, aliases: dict | None = None, **_: Any) -> dict:
        if index in self.created:
            raise RuntimeError("resource_already_exists_exception: index already exists")
        self.created.append(index)
        for alias in aliases or {}:
            self.aliases.setdefault(index, set()).add(alias)
        return {"acknowledged": True}

    async def put_alias(self, index: str, name: str, **_: Any) -> dict:
        self.aliases.setdefault(index, set()).add(name)
        return {"acknowledged": True}


class FakeES:
    def __init__(self) -> None:
        self.indices = _FakeIndices()
        self.docs: dict[str, list[dict[str, Any]]] = {}  # alias -> _source list
        self.fail = False

    async def search(self, *, index: str, query: dict, size: int, **_: Any) -> dict:
        if self.fail:
            raise RuntimeError("es down")
        wanted = set(query["terms"]["event_id"])
        hits = [
            {"_index": index, "_id": doc.get("event_id"), "_source": doc}
            for doc in self.docs.get(index, [])
            if doc.get("event_id") in wanted
        ]
        return {"hits": {"hits": hits[:size]}}


# ------------------------------------------------------- stub entitlements
class StubEntitlements:
    def __init__(self, **overrides: Any) -> None:
        self.values: dict[str, Any] = {
            "endpoint_cap": 100,
            "retention_days": 14,
            "deep_investigation_daily_quota": 5,
            "response_mode": "recommend_only",
            "ingest_events_per_min": 5000,
        }
        self.values.update(overrides)
        self.unavailable = False

    async def get(self, tenant_id: Any) -> Any:
        if self.unavailable:
            from soc_entitlements import EntitlementsUnavailable

            raise EntitlementsUnavailable("stub: entitlements down")
        return SimpleNamespace(
            plan="trial",
            tenant_status="active",
            entitlements=SimpleNamespace(**self.values),
            as_of=datetime.now(UTC),
        )


# ----------------------------------------------------------------- helpers
GATEWAY_HEADERS = {"X-Gateway-Auth": GATEWAY_SECRET}


def make_csr() -> str:
    """Empty-subject PKCS#10, ECDSA P-256 — exactly what the agent sends."""
    device_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(device_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def agent_headers(
    tenant_id: UUID = TENANT_ID, device_id: str = "dev_TEST", serial: str = "serial1"
) -> dict[str, str]:
    return {
        **GATEWAY_HEADERS,
        "X-Device-Id": device_id,
        "X-Device-Tenant": str(tenant_id),
        "X-Client-Cert-Serial": serial,
    }


async def seed_device(
    redis,
    tenant_id: UUID = TENANT_ID,
    device_id: str = "dev_TEST",
    *,
    status: str = "active",
    cert_serial: str = "serial1",
    prev_cert_serial: str = "",
    prev_valid_until: str = "",
) -> None:
    await redis.hset(
        f"device:{tenant_id}:{device_id}",
        mapping={
            "status": status,
            "cert_serial": cert_serial,
            "prev_cert_serial": prev_cert_serial,
            "prev_valid_until": prev_valid_until,
        },
    )


async def seed_tenant_status(
    redis, tenant_id: UUID = TENANT_ID, *, status: str = "active", abuse_frozen: bool = False
) -> None:
    await redis.hset(
        f"tenantstatus:{tenant_id}",
        mapping={"status": status, "abuse_frozen": "1" if abuse_frozen else "0"},
    )


async def make_session(
    redis,
    tenant_id: UUID = TENANT_ID,
    *,
    role: str = "admin",
    user_id: UUID = USER_ID,
) -> tuple[str, str]:
    sid = f"sid-{uuid4().hex}"
    csrf = f"csrf-{uuid4().hex}"
    now = datetime.now(UTC)
    await redis.hset(
        f"sess:{sid}",
        mapping={
            "user_id": str(user_id),
            "tenant_id": str(tenant_id),
            "role": role,
            "csrf_token": csrf,
            "created_at": now.isoformat(),
            "absolute_expires_at": (now + timedelta(days=7)).isoformat(),
        },
    )
    return sid, csrf


def session_kwargs(sid: str, csrf: str | None = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"cookies": {"sid": sid}}
    if csrf is not None:
        kwargs["headers"] = {"X-CSRF-Token": csrf}
    return kwargs


def mint_ingest_key(tenant_id: UUID = TENANT_ID, key_id: str = "ik_TEST") -> tuple[str, str]:
    minted = mint_secret(key_id, tenant_id)
    return minted.wire_token, minted.secret_hash


def mint_enrollment_token(
    tenant_id: UUID = TENANT_ID, token_id: str = "et_TEST"
) -> tuple[str, str]:
    minted = mint_secret(token_id, tenant_id)
    return minted.wire_token, minted.secret_hash


def alert_row(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    row: dict[str, Any] = {
        "id": "al_01TESTALERT",
        "tenant_id": TENANT_ID,
        "state": "new",
        "rule_id": "win_susp_encoded_powershell",
        "rule_version": "1.2.0",
        "rule_title": "Suspicious encoded PowerShell",
        "rule_severity": "high",
        "mitre_technique_ids": ["T1059.001"],
        "entity_hostname": "fin-laptop-07",
        "entity_user": "sam.jones",
        "asset_id": uuid4(),
        "occurrence_count": 7,
        "first_seen": now - timedelta(hours=1),
        "last_seen": now,
        "correlation_group_id": None,
        "priority_score": 86,
        "priority_inputs": {"rule_severity": "high", "priority_formula_version": 1},
        "triage_status": "completed",
        "triage_summary": "Something suspicious happened.",
        "ai_severity": "high",
        "ai_severity_effective": "high",
        "triage_model_id": "fast-1",
        "triage_completed_at": now,
        "triage_attempts": 1,
        "close_reason": None,
        "close_comment": None,
        "closed_by": None,
        "closed_at": None,
        "acknowledged_by": None,
        "acknowledged_at": None,
        "created_at": now - timedelta(hours=1),
    }
    row.update(overrides)
    return row


def settings_with(settings: Settings, **overrides: Any) -> Settings:
    return replace(settings, **overrides)
